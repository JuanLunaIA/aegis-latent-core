# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.proxy.dependencies — mTLS + API-key auth dependencies."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException, status

from aegis.proxy.dependencies import validate_audit_auth, validate_proxy_auth

# ── helpers ───────────────────────────────────────────────────────────────────


def _make_request(
    *,
    proxy_auth_result="valid-key",
    audit_auth_result="valid-audit-key",
    mtls_auth=None,
    mtls_required=False,
):
    """Build a minimal mock FastAPI Request with app state wired up."""
    state = MagicMock()
    state.settings.mtls_required = mtls_required
    state.mtls_auth = mtls_auth

    # proxy_auth and audit_auth — validate_request returns the key string
    state.proxy_auth = MagicMock()
    state.proxy_auth.validate_request = AsyncMock(return_value=proxy_auth_result)
    state.audit_auth = MagicMock()
    state.audit_auth.validate_request = AsyncMock(return_value=audit_auth_result)

    request = MagicMock()
    request.app.state.aegis = state
    return request


# ── validate_proxy_auth — no mTLS configured ─────────────────────────────────


@pytest.mark.asyncio
async def test_validate_proxy_auth_no_mtls_uses_apikey():
    request = _make_request(mtls_auth=None)
    result = await validate_proxy_auth(request)
    assert result == "valid-key"


# ── validate_proxy_auth — mTLS success ───────────────────────────────────────


@pytest.mark.asyncio
async def test_validate_proxy_auth_mtls_success():
    mock_mtls = MagicMock()
    mock_mtls.validate_request = AsyncMock(return_value="spiffe://org/service")
    request = _make_request(mtls_auth=mock_mtls)

    result = await validate_proxy_auth(request)
    assert result == "spiffe://org/service"


# ── validate_proxy_auth — mTLS 401, mtls_required=False → fallback ────────────


@pytest.mark.asyncio
async def test_validate_proxy_auth_mtls_401_fallback_to_apikey():
    mock_mtls = MagicMock()
    mock_mtls.validate_request = AsyncMock(
        side_effect=HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="no cert")
    )
    request = _make_request(mtls_auth=mock_mtls, mtls_required=False)

    result = await validate_proxy_auth(request)
    assert result == "valid-key"


# ── validate_proxy_auth — mTLS 401, mtls_required=True → propagate ───────────


@pytest.mark.asyncio
async def test_validate_proxy_auth_mtls_401_required_raises():
    mock_mtls = MagicMock()
    mock_mtls.validate_request = AsyncMock(
        side_effect=HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="no cert")
    )
    request = _make_request(mtls_auth=mock_mtls, mtls_required=True)

    with pytest.raises(HTTPException) as exc_info:
        await validate_proxy_auth(request)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


# ── validate_proxy_auth — mTLS 403 always propagates ─────────────────────────


@pytest.mark.asyncio
async def test_validate_proxy_auth_mtls_403_always_propagates():
    mock_mtls = MagicMock()
    mock_mtls.validate_request = AsyncMock(
        side_effect=HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="bad cert")
    )
    request = _make_request(mtls_auth=mock_mtls, mtls_required=False)

    with pytest.raises(HTTPException) as exc_info:
        await validate_proxy_auth(request)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


# ── validate_audit_auth — no mTLS configured ─────────────────────────────────


@pytest.mark.asyncio
async def test_validate_audit_auth_no_mtls_uses_audit_apikey():
    request = _make_request(mtls_auth=None, audit_auth_result="audit-key")
    result = await validate_audit_auth(request)
    assert result == "audit-key"


# ── validate_audit_auth — mTLS success ───────────────────────────────────────


@pytest.mark.asyncio
async def test_validate_audit_auth_mtls_success():
    mock_mtls = MagicMock()
    mock_mtls.validate_request = AsyncMock(return_value="spiffe://org/audit")
    request = _make_request(mtls_auth=mock_mtls)

    result = await validate_audit_auth(request)
    assert result == "spiffe://org/audit"


# ── validate_audit_auth — mTLS 401, mtls_required=False → fallback ───────────


@pytest.mark.asyncio
async def test_validate_audit_auth_mtls_401_fallback():
    mock_mtls = MagicMock()
    mock_mtls.validate_request = AsyncMock(
        side_effect=HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="no cert")
    )
    request = _make_request(mtls_auth=mock_mtls, mtls_required=False, audit_auth_result="audit")

    result = await validate_audit_auth(request)
    assert result == "audit"


# ── validate_audit_auth — mTLS 401, mtls_required=True → propagate ────────────


@pytest.mark.asyncio
async def test_validate_audit_auth_mtls_401_required_raises():
    mock_mtls = MagicMock()
    mock_mtls.validate_request = AsyncMock(
        side_effect=HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="no cert")
    )
    request = _make_request(mtls_auth=mock_mtls, mtls_required=True)

    with pytest.raises(HTTPException) as exc_info:
        await validate_audit_auth(request)

    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


# ── validate_audit_auth — mTLS 403 always propagates ────────────────────────


@pytest.mark.asyncio
async def test_validate_audit_auth_mtls_403_propagates():
    mock_mtls = MagicMock()
    mock_mtls.validate_request = AsyncMock(
        side_effect=HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="bad cert")
    )
    request = _make_request(mtls_auth=mock_mtls, mtls_required=False)

    with pytest.raises(HTTPException) as exc_info:
        await validate_audit_auth(request)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
