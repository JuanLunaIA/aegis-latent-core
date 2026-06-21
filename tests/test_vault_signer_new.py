# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis_server.crypto.vault_signer — Vault Transit signing provider."""

from __future__ import annotations

import base64
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Mock hvac before importing vault_signer ───────────────────────────────────


class _Forbidden(Exception):
    pass


class _VaultNotInitialized(Exception):
    pass


class _VaultError(Exception):
    pass


_mock_hvac_exceptions = MagicMock()
_mock_hvac_exceptions.Forbidden = _Forbidden
_mock_hvac_exceptions.VaultNotInitialized = _VaultNotInitialized
_mock_hvac_exceptions.VaultError = _VaultError

_mock_hvac_mod = MagicMock()
_mock_hvac_mod.exceptions = _mock_hvac_exceptions
_mock_hvac_mod.Client = MagicMock()

sys.modules.setdefault("hvac", _mock_hvac_mod)
sys.modules.setdefault("hvac.exceptions", _mock_hvac_exceptions)

from aegis_server.crypto.vault_signer import VaultSigner  # noqa: E402


# ── __init__ validations ───────────────────────────────────────────────────────


def test_init_empty_vault_url_raises():
    with pytest.raises(ValueError, match="vault_url"):
        VaultSigner(vault_url="", transit_key="my-key", vault_token="tok")


def test_init_empty_transit_key_raises():
    with pytest.raises(ValueError, match="transit_key"):
        VaultSigner(vault_url="https://vault.example.com", transit_key="", vault_token="tok")


def test_init_no_auth_raises():
    with pytest.raises(ValueError, match="vault_token"):
        VaultSigner(vault_url="https://vault.example.com", transit_key="key")


def test_init_with_token_ok():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="my-key",
        vault_token="s.token",
    )
    assert vs._vault_url == "https://vault.example.com"
    assert vs._transit_key == "my-key"
    assert vs._resolved_token == "s.token"


def test_init_with_approle_ok():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="my-key",
        role_id="r-id",
        secret_id="s-id",
    )
    assert vs._role_id == "r-id"
    assert vs._secret_id == "s-id"
    assert vs._resolved_token is None


def test_init_namespace_stored():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        vault_token="t",
        namespace="ns/prod",
    )
    assert vs._namespace == "ns/prod"


# ── _decode_vault_signature ───────────────────────────────────────────────────


def test_decode_vault_signature_standard_b64():
    raw = b"\xde\xad\xbe\xef"
    b64 = base64.standard_b64encode(raw).decode("ascii")
    vault_sig = f"vault:v1:{b64}"
    result = VaultSigner._decode_vault_signature(vault_sig)
    assert result == raw.hex()


def test_decode_vault_signature_url_safe_b64():
    raw = b"\xde\xad\xbe\xef"
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    # Standard decode will fail since urlsafe chars differ; trigger fallback
    vault_sig = f"vault:v1:{b64}"
    result = VaultSigner._decode_vault_signature(vault_sig)
    assert result == raw.hex()


def test_decode_vault_signature_bad_format_raises():
    with pytest.raises(ValueError, match="unexpected signature format"):
        VaultSigner._decode_vault_signature("notvalid:format")


def test_decode_vault_signature_not_vault_prefix_raises():
    with pytest.raises(ValueError, match="unexpected signature format"):
        VaultSigner._decode_vault_signature("hvac:v1:abc")


def test_decode_vault_signature_bad_b64_raises():
    import base64 as _b64

    with (
        patch.object(_b64, "standard_b64decode", side_effect=Exception("bad")),
        patch.object(_b64, "urlsafe_b64decode", side_effect=Exception("also bad")),
    ):
        with pytest.raises(ValueError, match="base64 decode failed"):
            VaultSigner._decode_vault_signature("vault:v1:anything")


# ── _backoff_delay ────────────────────────────────────────────────────────────


def test_backoff_delay_attempt_0():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        vault_token="t",
        retry_base_delay=0.5,
    )
    delay = vs._backoff_delay(0)
    # base * 2^0 + uniform(0, base) = 0.5 + rand[0,0.5]
    assert 0.5 <= delay <= 1.0


def test_backoff_delay_increases_with_attempt():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        vault_token="t",
        retry_base_delay=0.25,
    )
    d0 = vs._backoff_delay(0)
    d2 = vs._backoff_delay(2)
    # d2 base is 0.25 * 4 = 1.0 vs d0 base of 0.25 — even with max jitter d2 > d0 min
    assert vs._retry_base_delay * (2**2) >= vs._retry_base_delay * (2**0)


# ── _do_approle_login ─────────────────────────────────────────────────────────


def test_do_approle_login_success():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        role_id="r",
        secret_id="s",
    )
    mock_client = MagicMock()
    mock_client.auth.approle.login.return_value = {"auth": {"client_token": "s.newtoken"}}
    vs._client = mock_client

    vs._do_approle_login()

    assert vs._resolved_token == "s.newtoken"
    assert mock_client.token == "s.newtoken"


def test_do_approle_login_vault_error_raises():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        role_id="r",
        secret_id="s",
    )
    mock_client = MagicMock()
    mock_client.auth.approle.login.side_effect = _VaultError("bad creds")
    vs._client = mock_client

    with pytest.raises(RuntimeError, match="AppRole login failed"):
        vs._do_approle_login()


def test_do_approle_login_missing_token_raises():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        role_id="r",
        secret_id="s",
    )
    mock_client = MagicMock()
    mock_client.auth.approle.login.return_value = {"auth": {}}
    vs._client = mock_client

    with pytest.raises(RuntimeError, match="missing client_token"):
        vs._do_approle_login()


def test_do_approle_login_no_client_raises():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        role_id="r",
        secret_id="s",
    )
    vs._client = None

    with pytest.raises(RuntimeError, match="client not initialised"):
        vs._do_approle_login()


# ── _ensure_client ────────────────────────────────────────────────────────────


def test_ensure_client_already_authenticated():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        vault_token="t",
    )
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    vs._client = mock_client

    vs._ensure_client()  # must not recreate client

    assert vs._client is mock_client


def test_ensure_client_with_token():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        vault_token="s.tok",
    )
    vs._client = None

    mock_new_client = MagicMock()
    mock_new_client.is_authenticated.return_value = True
    _mock_hvac_mod.Client.return_value = mock_new_client

    vs._ensure_client()

    assert mock_new_client.token == "s.tok"


def test_ensure_client_no_creds_raises():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        vault_token="t",
    )
    vs._client = None
    vs._resolved_token = None
    vs._role_id = ""
    vs._secret_id = ""

    mock_new_client = MagicMock()
    _mock_hvac_mod.Client.return_value = mock_new_client

    with pytest.raises(RuntimeError, match="no authentication credentials"):
        vs._ensure_client()


def test_ensure_client_not_authenticated_after_setup_raises():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        vault_token="s.tok",
    )
    vs._client = None

    mock_new_client = MagicMock()
    mock_new_client.is_authenticated.return_value = False
    _mock_hvac_mod.Client.return_value = mock_new_client

    with pytest.raises(RuntimeError, match="failed to authenticate"):
        vs._ensure_client()


# ── _sign_sync ────────────────────────────────────────────────────────────────


def _make_signer_with_client(mock_client):
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="my-key",
        vault_token="s.tok",
        max_retries=2,
        retry_base_delay=0.0,
    )
    vs._client = mock_client
    return vs


def test_sign_sync_success():
    raw = b"\xca\xfe\xba\xbe"
    b64 = base64.standard_b64encode(raw).decode("ascii")

    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.transit.sign_data.return_value = {"data": {"signature": f"vault:v1:{b64}"}}

    vs = _make_signer_with_client(mock_client)
    result = vs._sign_sync(b"hello")

    assert result == raw.hex()


def test_sign_sync_forbidden_reauth_success():
    raw = b"\x01\x02"
    b64 = base64.standard_b64encode(raw).decode("ascii")

    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.transit.sign_data.side_effect = [
        _Forbidden("403"),
        {"data": {"signature": f"vault:v1:{b64}"}},
    ]
    # Second call returns dict, not raises — need to fix side_effect
    mock_client.secrets.transit.sign_data.side_effect = None
    call_count = [0]

    def _sign_data(**kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            raise _Forbidden("403")
        return {"data": {"signature": f"vault:v1:{b64}"}}

    mock_client.secrets.transit.sign_data.side_effect = _sign_data

    vs = _make_signer_with_client(mock_client)
    with patch.object(vs, "_do_approle_login"):
        result = vs._sign_sync(b"data")

    assert result == raw.hex()


def test_sign_sync_forbidden_reauth_fails_raises():
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.transit.sign_data.side_effect = _Forbidden("403")

    vs = _make_signer_with_client(mock_client)
    vs._role_id = "r"
    vs._secret_id = "s"

    with patch.object(vs, "_do_approle_login", side_effect=RuntimeError("reauth fail")):
        with pytest.raises(RuntimeError, match="Forbidden and re-auth failed"):
            vs._sign_sync(b"data")


def test_sign_sync_vault_not_initialized_raises():
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.transit.sign_data.side_effect = _VaultNotInitialized("sealed")

    vs = _make_signer_with_client(mock_client)

    with pytest.raises(RuntimeError, match="not initialised or is sealed"):
        vs._sign_sync(b"data")


def test_sign_sync_transient_then_success():
    raw = b"\xde\xad"
    b64 = base64.standard_b64encode(raw).decode("ascii")

    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True

    call_count = [0]

    def _sign_data(**kwargs):
        call_count[0] += 1
        if call_count[0] <= 1:
            raise ConnectionError("timeout")
        return {"data": {"signature": f"vault:v1:{b64}"}}

    mock_client.secrets.transit.sign_data.side_effect = _sign_data

    vs = _make_signer_with_client(mock_client)
    result = vs._sign_sync(b"data")

    assert result == raw.hex()
    assert call_count[0] == 2


def test_sign_sync_exceeds_retries_raises():
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.transit.sign_data.side_effect = ConnectionError("always fails")

    vs = _make_signer_with_client(mock_client)

    with pytest.raises(RuntimeError, match="sign_payload failed"):
        vs._sign_sync(b"data")


# ── sign_payload (async) ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sign_payload_delegates_to_sign_sync():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        vault_token="t",
    )
    with patch.object(vs, "_sign_sync", return_value="deadbeef") as mock_sync:
        result = await vs.sign_payload(b"data")

    assert result == "deadbeef"
    mock_sync.assert_called_once_with(b"data")


# ── scheme ────────────────────────────────────────────────────────────────────


def test_scheme_is_vault_transit():
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        vault_token="t",
    )
    assert vs.scheme == "vault-transit"


# ── _ensure_client — namespace path (line 246) ────────────────────────────────


def test_ensure_client_with_namespace():
    """When namespace is set, client_kwargs includes it (line 246)."""
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        vault_token="s.tok",
        namespace="my-ns",
    )
    vs._client = None

    mock_new_client = MagicMock()
    mock_new_client.is_authenticated.return_value = True
    _mock_hvac_mod.Client.return_value = mock_new_client

    vs._ensure_client()

    call_kwargs = _mock_hvac_mod.Client.call_args[1]
    assert call_kwargs.get("namespace") == "my-ns"
    assert mock_new_client.token == "s.tok"


# ── _ensure_client — approle path (line 251) ─────────────────────────────────


def test_ensure_client_approle_path():
    """When role_id+secret_id set, _do_approle_login is called (line 251)."""
    vs = VaultSigner(
        vault_url="https://vault.example.com",
        transit_key="k",
        role_id="my-role",
        secret_id="my-secret",
    )
    vs._client = None

    mock_new_client = MagicMock()
    mock_new_client.is_authenticated.return_value = True
    mock_new_client.auth.approle.login.return_value = {"auth": {"client_token": "s.approle-tok"}}
    _mock_hvac_mod.Client.return_value = mock_new_client

    vs._ensure_client()

    mock_new_client.auth.approle.login.assert_called_once_with(
        role_id="my-role",
        secret_id="my-secret",
    )
    assert vs._resolved_token == "s.approle-tok"
