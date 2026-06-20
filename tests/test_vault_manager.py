# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.secrets — VaultManager authenticate and secret retrieval."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.core.secrets import SecretBundle, VaultManager


# ── SecretBundle dataclass ────────────────────────────────────────────────────


def test_secret_bundle_fields():
    bundle = SecretBundle(
        value="my-secret",
        version=3,
        lease_duration=3600,
        expires_at=time.time() + 3600,
    )
    assert bundle.value == "my-secret"
    assert bundle.version == 3
    assert bundle.lease_duration == 3600


# ── VaultManager construction ─────────────────────────────────────────────────


def test_vault_manager_strips_trailing_slash():
    vm = VaultManager(vault_url="https://vault.example.com/")
    assert vm.vault_url == "https://vault.example.com"


def test_vault_manager_with_token():
    vm = VaultManager(vault_url="https://vault.example.com", token="s.abc123")
    assert vm._token == "s.abc123"


def test_vault_manager_with_approle():
    vm = VaultManager(
        vault_url="https://vault.example.com",
        role_id="my-role",
        secret_id="my-secret-id",
    )
    assert vm.role_id == "my-role"
    assert vm.secret_id == "my-secret-id"


def test_vault_manager_empty_cache():
    vm = VaultManager(vault_url="https://vault.example.com", token="tok")
    assert vm._secrets_cache == {}


# ── authenticate ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_authenticate_with_existing_token_returns_true():
    vm = VaultManager(vault_url="https://vault.example.com", token="existing-token")
    result = await vm.authenticate()
    assert result is True


@pytest.mark.asyncio
async def test_authenticate_missing_approle_creds_returns_false():
    vm = VaultManager(vault_url="https://vault.example.com")
    result = await vm.authenticate()
    assert result is False


@pytest.mark.asyncio
async def test_authenticate_approle_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"auth": {"client_token": "s.newtoken"}}

    vm = VaultManager(
        vault_url="https://vault.example.com",
        role_id="role-x",
        secret_id="secret-y",
    )
    vm._async_auth_request = AsyncMock(return_value=mock_resp)
    result = await vm.authenticate()
    assert result is True
    assert vm._token == "s.newtoken"


@pytest.mark.asyncio
async def test_authenticate_approle_non_200_returns_false():
    mock_resp = MagicMock()
    mock_resp.status_code = 403

    vm = VaultManager(
        vault_url="https://vault.example.com",
        role_id="role-x",
        secret_id="secret-y",
    )
    vm._async_auth_request = AsyncMock(return_value=mock_resp)
    result = await vm.authenticate()
    assert result is False


@pytest.mark.asyncio
async def test_authenticate_approle_exception_returns_false():
    vm = VaultManager(
        vault_url="https://vault.example.com",
        role_id="role-x",
        secret_id="secret-y",
    )
    vm._async_auth_request = AsyncMock(side_effect=ConnectionError("network"))
    result = await vm.authenticate()
    assert result is False


# ── get_secret — cache hit ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_secret_cache_hit_returns_value():
    vm = VaultManager(vault_url="https://vault.example.com", token="tok")
    vm._secrets_cache["secret/myapp"] = SecretBundle(
        value="cached-value",
        version=1,
        lease_duration=3600,
        expires_at=time.time() + 3600,  # not expired
    )
    result = await vm.get_secret("secret/myapp", "value")
    assert result == "cached-value"


@pytest.mark.asyncio
async def test_get_secret_cache_key_mismatch_returns_none():
    vm = VaultManager(vault_url="https://vault.example.com", token="tok")
    vm._secrets_cache["secret/myapp"] = SecretBundle(
        value="cached-value",
        version=1,
        lease_duration=3600,
        expires_at=time.time() + 3600,
    )
    # Requesting a different key returns None from the simplified cache path
    result = await vm.get_secret("secret/myapp", "other_key")
    assert result is None


@pytest.mark.asyncio
async def test_get_secret_cache_expired_calls_rotate():
    vm = VaultManager(vault_url="https://vault.example.com", token="tok")
    vm._secrets_cache["secret/myapp"] = SecretBundle(
        value="old-value",
        version=1,
        lease_duration=3600,
        expires_at=time.time() - 1,  # already expired
    )
    vm._rotate_secret = AsyncMock(return_value="fresh-value")
    result = await vm.get_secret("secret/myapp", "value")
    assert result == "fresh-value"
    vm._rotate_secret.assert_called_once()


@pytest.mark.asyncio
async def test_get_secret_no_cache_calls_rotate():
    vm = VaultManager(vault_url="https://vault.example.com", token="tok")
    vm._rotate_secret = AsyncMock(return_value="rotated-value")
    result = await vm.get_secret("secret/myapp", "api_key")
    assert result == "rotated-value"


# ── _rotate_secret ────────────────────────────────────────────────────────────


def _make_mock_httpx_client(status_code: int, json_data: dict | None = None):
    """Build a mock httpx.AsyncClient context manager."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    if json_data is not None:
        mock_resp.json.return_value = json_data

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    class _Ctx:
        async def __aenter__(self_):
            return mock_client

        async def __aexit__(self_, *args):
            pass

    return _Ctx()


@pytest.mark.asyncio
async def test_rotate_secret_success():
    vm = VaultManager(vault_url="https://vault.example.com", token="s.test")
    mock_data = {"data": {"data": {"my-key": "super-secret-value"}}}

    ctx = _make_mock_httpx_client(200, mock_data)
    with patch("aegis.core.secrets.httpx.AsyncClient", return_value=ctx):
        result = await vm._rotate_secret("secret/data/myapp", "my-key")

    assert result == "super-secret-value"
    assert "secret/data/myapp" in vm._secrets_cache


@pytest.mark.asyncio
async def test_rotate_secret_non_200_returns_none():
    vm = VaultManager(vault_url="https://vault.example.com", token="s.test")

    ctx = _make_mock_httpx_client(403, {"errors": ["permission denied"]})
    with patch("aegis.core.secrets.httpx.AsyncClient", return_value=ctx):
        result = await vm._rotate_secret("secret/data/myapp", "my-key")

    assert result is None


@pytest.mark.asyncio
async def test_rotate_secret_network_error_returns_none():
    vm = VaultManager(vault_url="https://vault.example.com", token="s.test")

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=Exception("connection refused"))

    class _Ctx:
        async def __aenter__(self_):
            return mock_client

        async def __aexit__(self_, *args):
            pass

    with patch("aegis.core.secrets.httpx.AsyncClient", return_value=_Ctx()):
        result = await vm._rotate_secret("secret/data/myapp", "my-key")

    assert result is None


@pytest.mark.asyncio
async def test_rotate_secret_uses_token_header():
    vm = VaultManager(vault_url="https://vault.example.com", token="my-vault-token")
    mock_data = {"data": {"data": {"k": "v"}}}

    calls: list = []

    async def _mock_get(url, headers=None):
        calls.append({"url": url, "headers": headers})
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_data
        return mock_resp

    mock_client = AsyncMock()
    mock_client.get = _mock_get

    class _Ctx:
        async def __aenter__(self_):
            return mock_client

        async def __aexit__(self_, *args):
            pass

    with patch("aegis.core.secrets.httpx.AsyncClient", return_value=_Ctx()):
        await vm._rotate_secret("secret/data/myapp", "k")

    assert calls[0]["headers"].get("X-Vault-Token") == "my-vault-token"


@pytest.mark.asyncio
async def test_rotate_secret_no_token_empty_headers():
    vm = VaultManager(vault_url="https://vault.example.com")  # no token
    mock_data = {"data": {"data": {"k": "v"}}}

    calls: list = []

    async def _mock_get(url, headers=None):
        calls.append({"url": url, "headers": headers})
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_data
        return mock_resp

    mock_client = AsyncMock()
    mock_client.get = _mock_get

    class _Ctx:
        async def __aenter__(self_):
            return mock_client

        async def __aexit__(self_, *args):
            pass

    with patch("aegis.core.secrets.httpx.AsyncClient", return_value=_Ctx()):
        await vm._rotate_secret("secret/data/myapp", "k")

    assert calls[0]["headers"] == {}


# ── _async_auth_request ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_auth_request_posts_to_approle_endpoint():
    vm = VaultManager(
        vault_url="https://vault.example.com",
        role_id="r",
        secret_id="s",
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"auth": {"client_token": "s.tok"}}

    posts: list = []

    async def _mock_post(url, json=None):
        posts.append({"url": url, "json": json})
        return mock_resp

    mock_client = AsyncMock()
    mock_client.post = _mock_post

    class _Ctx:
        async def __aenter__(self_):
            return mock_client

        async def __aexit__(self_, *args):
            pass

    with patch("aegis.core.secrets.httpx.AsyncClient", return_value=_Ctx()):
        resp = await vm._async_auth_request({"role_id": "r", "secret_id": "s"})

    assert posts[0]["url"] == "https://vault.example.com/v1/auth/approle/login"
    assert resp.status_code == 200
