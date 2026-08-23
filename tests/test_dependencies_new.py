# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for principal-first authorization dependencies."""

from __future__ import annotations

import pytest
from fastapi import HTTPException, status

from aegis.auth.principal import Principal, Role
from aegis.auth.scopes import SCOPE_AUDIT_READ, SCOPE_PROXY_COMPLETIONS
from aegis.proxy.dependencies import validate_audit_auth, validate_proxy_auth


def _principal(*, scopes: frozenset[str], roles: frozenset[Role]) -> Principal:
    return Principal(
        subject="subject",
        tenant_id="tenant-a",
        roles=roles,
        scopes=scopes,
        auth_method="test",
        credential_id="opaque-credential",
    )


@pytest.mark.asyncio
async def test_validate_proxy_auth_returns_authorized_principal() -> None:
    principal = _principal(
        scopes=frozenset({SCOPE_PROXY_COMPLETIONS}), roles=frozenset({Role.PROXY_USER})
    )
    assert await validate_proxy_auth(principal) is principal


@pytest.mark.asyncio
async def test_validate_proxy_auth_denies_missing_scope() -> None:
    principal = _principal(scopes=frozenset(), roles=frozenset({Role.PROXY_USER}))
    with pytest.raises(HTTPException) as exc_info:
        await validate_proxy_auth(principal)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_validate_audit_auth_returns_authorized_principal() -> None:
    principal = _principal(
        scopes=frozenset({SCOPE_AUDIT_READ}), roles=frozenset({Role.AUDIT_READER})
    )
    assert await validate_audit_auth(principal) is principal


@pytest.mark.asyncio
async def test_validate_audit_auth_denies_proxy_only_principal() -> None:
    principal = _principal(
        scopes=frozenset({SCOPE_PROXY_COMPLETIONS}), roles=frozenset({Role.PROXY_USER})
    )
    with pytest.raises(HTTPException) as exc_info:
        await validate_audit_auth(principal)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
