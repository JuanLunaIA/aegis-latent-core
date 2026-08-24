# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for principal-first authorization dependencies."""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
from fastapi import HTTPException, status
from starlette.requests import Request

from aegis.auth.principal import Principal, Role
from aegis.auth.scopes import SCOPE_AUDIT_READ, SCOPE_PROXY_COMPLETIONS
from aegis.config import AegisSettings
from aegis.proxy.dependencies import (
    authenticate_principal,
    validate_audit_auth,
    validate_proxy_auth,
)


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


def _request_for_api_key(settings: AegisSettings, key: str = "legacy-key") -> Request:
    app = SimpleNamespace(state=SimpleNamespace(aegis=SimpleNamespace(settings=settings)))
    return Request(
        {
            "type": "http",
            "app": app,
            "headers": [(b"authorization", f"Bearer {key}".encode())],
        }
    )


def _api_key_settings(**overrides: object) -> AegisSettings:
    values: dict[str, object] = {
        "api_keys": "legacy-key",
        "security_enforcement_mode": "development",
        "auth_identity_hmac_key": "identity-key-for-dependency-tests",
    }
    values.update(overrides)
    return AegisSettings(**values)


@pytest.mark.asyncio
async def test_unmapped_api_key_is_least_privileged_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGIS_ALLOW_LEGACY_UNMAPPED_API_KEY_PRINCIPALS", raising=False)
    settings = _api_key_settings(api_key_scopes="legacy-key:proxy:completions")

    principal = await authenticate_principal(_request_for_api_key(settings))

    assert principal.tenant_id == settings.development_tenant_id
    assert principal.roles == frozenset()
    assert principal.scopes == frozenset()
    assert principal.subject.startswith("api-key:")
    assert "legacy-key" not in principal.subject
    assert re.fullmatch(r"api-key:[0-9a-f]{64}", principal.credential_id)
    with pytest.raises(HTTPException) as exc_info:
        await validate_proxy_auth(principal)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_unmapped_api_key_legacy_compatibility_opt_in_honors_scopes() -> None:
    settings = _api_key_settings(
        allow_legacy_unmapped_api_key_principals=True,
        api_key_scopes="legacy-key:proxy:completions",
    )

    principal = await authenticate_principal(_request_for_api_key(settings))

    assert principal.roles == frozenset()
    assert principal.scopes == frozenset({SCOPE_PROXY_COMPLETIONS})
    assert await validate_proxy_auth(principal) is principal
    with pytest.raises(HTTPException) as exc_info:
        await validate_audit_auth(principal)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_strict_mode_rejects_unmapped_api_key_even_with_legacy_opt_in() -> None:
    settings = _api_key_settings(
        security_enforcement_mode="strict",
        allow_legacy_unmapped_api_key_principals=True,
    )

    with pytest.raises(HTTPException) as exc_info:
        await authenticate_principal(_request_for_api_key(settings))

    assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert exc_info.value.detail == "API-key principal mapping is incomplete"
