# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Additional tests for aegis.auth.apikey — missing branch coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from aegis.auth.apikey import AuditKeyAuth, ProxyKeyAuth, build_audit_auth, build_proxy_auth
from aegis.config import AegisSettings


def _settings(**kwargs) -> AegisSettings:
    defaults = {
        "backend_api_key": "sk-test",
        "api_keys": "valid-key",
        "auth_disabled": False,
    }
    defaults.update(kwargs)
    return AegisSettings(**defaults)


# ── ProxyKeyAuth.validate_request — non-Bearer header (line 63) ───────────────


@pytest.mark.asyncio
async def test_proxy_validate_request_non_bearer_sets_none():
    auth = ProxyKeyAuth(_settings())
    request = MagicMock()
    request.headers.get.return_value = "Basic dXNlcjpwYXNz"  # non-Bearer

    with pytest.raises(HTTPException) as exc_info:
        await auth.validate_request(request)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


# ── AuditKeyAuth.validate_request — non-Bearer header (line 111) ─────────────


@pytest.mark.asyncio
async def test_audit_validate_request_non_bearer_sets_none():
    auth = AuditKeyAuth(_settings())
    request = MagicMock()
    request.headers.get.return_value = "Token abc"  # non-Bearer

    with pytest.raises(HTTPException) as exc_info:
        await auth.validate_request(request)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


# ── AuditKeyAuth.__call__ — auth disabled (line 120) ─────────────────────────


def test_audit_call_auth_disabled_returns_auth_disabled():
    settings = _settings(auth_disabled=True, debug_mode=True)
    auth = AuditKeyAuth(settings)
    result = auth(None)  # credentials=None, but disabled
    assert result == "auth-disabled"


# ── AuditKeyAuth.__call__ — invalid key (line 128) ───────────────────────────


def test_audit_call_invalid_key_raises():
    settings = _settings(api_keys="correct-key")
    auth = AuditKeyAuth(settings)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="wrong-key")

    with pytest.raises(HTTPException) as exc_info:
        auth(creds)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "audit" in exc_info.value.detail.lower()


# ── build_proxy_auth (lines 137-138) ─────────────────────────────────────────


def test_build_proxy_auth_returns_proxy_key_auth():
    settings = _settings()
    result = build_proxy_auth(settings)
    assert isinstance(result, ProxyKeyAuth)


def test_build_proxy_auth_no_settings_uses_get_settings():
    settings = _settings()
    with patch("aegis.auth.apikey.get_settings", return_value=settings):
        result = build_proxy_auth()
    assert isinstance(result, ProxyKeyAuth)


# ── build_audit_auth (lines 142-143) ─────────────────────────────────────────


def test_build_audit_auth_returns_audit_key_auth():
    settings = _settings()
    result = build_audit_auth(settings)
    assert isinstance(result, AuditKeyAuth)


def test_build_audit_auth_no_settings_uses_get_settings():
    settings = _settings()
    with patch("aegis.auth.apikey.get_settings", return_value=settings):
        result = build_audit_auth()
    assert isinstance(result, AuditKeyAuth)
