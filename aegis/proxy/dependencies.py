# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Principal-first FastAPI authentication and authorization dependencies."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from aegis.auth.apikey import constant_time_key_in
from aegis.auth.mtls import MTLSVerificationError
from aegis.auth.oidc import OIDCAuthenticationError, OIDCDependencyError
from aegis.auth.principal import Principal, Role
from aegis.auth.scopes import (
    ALL_SCOPES,
    SCOPE_AUDIT_ANALYTICS,
    SCOPE_AUDIT_EXPORT,
    SCOPE_AUDIT_READ,
    SCOPE_PROXY_COMPLETIONS,
    parse_scope_config,
)

_ROLE_SCOPES: dict[Role, frozenset[str]] = {
    Role.ADMIN: ALL_SCOPES,
    Role.PROXY_USER: frozenset({SCOPE_PROXY_COMPLETIONS}),
    Role.AUDITOR: frozenset({SCOPE_AUDIT_READ, SCOPE_AUDIT_EXPORT, SCOPE_AUDIT_ANALYTICS}),
    Role.AUDIT_READER: frozenset({SCOPE_AUDIT_READ}),
}


def permissions_for_roles(roles: frozenset[Role]) -> frozenset[str]:
    permissions: set[str] = set()
    for role in roles:
        permissions.update(_ROLE_SCOPES[role])
    return frozenset(permissions)


def _bearer(request: Request) -> str:
    value = request.headers.get("authorization", "")
    scheme, separator, credential = value.partition(" ")
    if not separator or scheme.lower() != "bearer" or not credential:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credential


def _opaque_credential_id(secret: str, domain: str, value: str) -> str:
    key = secret.encode("utf-8") if secret else b"aegis-development-identity-key"
    digest = hmac.new(key, f"{domain}\0{value}".encode(), hashlib.sha256).hexdigest()
    return f"{domain}:{digest}"


def _roles(value: object) -> frozenset[Role]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("roles must be a JSON string array")
    return frozenset(Role(item) for item in value)


def _scopes(value: object) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("scopes must be a JSON string array")
    scopes = frozenset(value)
    unknown = scopes - ALL_SCOPES
    if unknown:
        raise ValueError(f"unsupported scopes: {sorted(unknown)}")
    return scopes


def _api_key_principal(request: Request, key: str) -> Principal:
    state = request.app.state.aegis
    settings = state.settings
    valid_keys = settings.get_api_keys() | settings.get_audit_api_keys()
    if not valid_keys:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No API keys configured on server; authentication impossible.",
        )
    if not constant_time_key_in(key, valid_keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    key_digest = settings.api_key_principal_digest(key)
    configured = settings.get_api_key_principals().get(key_digest)
    if configured is None:
        if settings.security_enforcement_mode == "strict":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API-key principal mapping is incomplete",
            )
        if settings.allow_legacy_unmapped_api_key_principals:
            scopes = parse_scope_config(settings.api_key_scopes).get(key, ALL_SCOPES)
            roles = frozenset({Role.ADMIN}) if scopes == ALL_SCOPES else frozenset()
        else:
            roles = frozenset()
            scopes = frozenset()
        tenant_id = settings.development_tenant_id
    else:
        try:
            tenant_raw = configured.get("tenant_id")
            if not isinstance(tenant_raw, str) or not tenant_raw.strip():
                raise ValueError("tenant_id must be a non-empty string")
            tenant_id = tenant_raw
            roles = _roles(configured.get("roles", []))
            scopes = _scopes(configured.get("scopes", []))
            role_scopes = permissions_for_roles(roles)
            if not scopes.issubset(role_scopes):
                raise ValueError("configured scopes exceed role grants")
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API-key principal mapping is invalid",
            ) from exc
    return Principal(
        subject=f"api-key:{key_digest[:16]}",
        tenant_id=tenant_id,
        roles=roles,
        scopes=scopes,
        auth_method="api_key",
        credential_id=_opaque_credential_id(settings.auth_identity_hmac_key, "api-key", key),
    )


def _peer_certificate(request: Request) -> bytes | None:
    direct = request.scope.get("client_cert")
    if isinstance(direct, bytes):
        return direct
    ssl_object = request.scope.get("ssl_object")
    if ssl_object is not None and hasattr(ssl_object, "getpeercert"):
        value = ssl_object.getpeercert(binary_form=True)
        return value if isinstance(value, bytes) else None
    return None


def _mtls_principal(request: Request) -> Principal:
    state = request.app.state.aegis
    verifier = getattr(state, "enterprise_mtls_verifier", None)
    if verifier is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="mTLS verifier is not configured",
        )
    source_ip = request.client.host if request.client else ""
    try:
        principal = verifier.verify(
            source_ip=source_ip,
            peer_certificate=_peer_certificate(request),
            headers=request.headers,
        )
    except MTLSVerificationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client certificate authentication failed",
        ) from exc
    configured_roles = frozenset(
        Role(value.strip())
        for value in state.settings.mtls_default_roles.split(",")
        if value.strip()
    )
    return Principal(
        subject=principal.subject,
        tenant_id=principal.tenant_id,
        roles=configured_roles,
        scopes=permissions_for_roles(configured_roles),
        auth_method="mtls",
        credential_id=principal.credential_id,
        attributes=principal.attributes,
    )


def _combine(left: Principal, right: Principal, secret: str) -> Principal:
    if not hmac.compare_digest(left.tenant_id, right.tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Credential tenant mismatch"
        )
    roles = left.roles & right.roles
    scopes = left.scopes & right.scopes
    return Principal(
        subject=left.subject,
        tenant_id=left.tenant_id,
        roles=roles,
        scopes=scopes,
        auth_method=f"{left.auth_method}_{right.auth_method}",
        credential_id=_opaque_credential_id(
            secret,
            "composite",
            f"{len(left.credential_id)}:{left.credential_id}:{right.credential_id}",
        ),
    )


async def authenticate_principal(request: Request) -> Principal:
    """Authenticate exactly the configured mechanism and cache its immutable result."""

    cached = getattr(request.state, "aegis_principal", None)
    if isinstance(cached, Principal):
        return cached
    state = request.app.state.aegis
    settings = state.settings
    if settings.auth_disabled:
        principal = Principal(
            subject="local-development",
            tenant_id=settings.development_tenant_id,
            roles=frozenset({Role.ADMIN}),
            scopes=ALL_SCOPES,
            auth_method="development",
            credential_id="development",
        )
    else:
        mode = settings.auth_mode
        bearer_principal: Principal | None = None
        if mode in {"api_key", "api_key_mtls"}:
            bearer_principal = _api_key_principal(request, _bearer(request))
        elif mode in {"oidc", "oidc_mtls"}:
            manager = getattr(state, "oidc_manager", None)
            if manager is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="OIDC verifier is not configured",
                )
            try:
                bearer_principal = await manager.authenticate(_bearer(request))
            except OIDCDependencyError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="OIDC runtime dependency is unavailable",
                ) from exc
            except OIDCAuthenticationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="OIDC authentication failed",
                    headers={"WWW-Authenticate": "Bearer"},
                ) from exc
            bearer_principal = Principal(
                subject=bearer_principal.subject,
                tenant_id=bearer_principal.tenant_id,
                roles=bearer_principal.roles,
                scopes=permissions_for_roles(bearer_principal.roles),
                auth_method=bearer_principal.auth_method,
                credential_id=_opaque_credential_id(
                    settings.auth_identity_hmac_key,
                    "oidc",
                    f"{len(settings.oidc_issuer)}:{settings.oidc_issuer}:{bearer_principal.subject}",
                ),
                attributes=bearer_principal.attributes,
            )
        mtls_principal = _mtls_principal(request) if "mtls" in mode else None
        if bearer_principal is not None and mtls_principal is not None:
            principal = _combine(
                bearer_principal,
                mtls_principal,
                settings.auth_identity_hmac_key,
            )
        else:
            selected = bearer_principal or mtls_principal
            if selected is None:
                raise HTTPException(
                    status_code=500, detail="Authentication mode is not implemented"
                )
            principal = selected
        if principal is None:
            raise HTTPException(status_code=500, detail="Authentication mode is not implemented")
    request.state.aegis_principal = principal
    return principal


def require_scope(required_scope: str) -> Callable[..., Awaitable[Principal]]:
    if required_scope not in ALL_SCOPES:
        raise ValueError(f"unknown scope {required_scope!r}")

    async def dependency(
        principal: Annotated[Principal, Depends(authenticate_principal)],
    ) -> Principal:
        if required_scope not in principal.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Authenticated principal lacks required scope {required_scope}",
            )
        return principal

    return dependency


validate_proxy_auth = require_scope(SCOPE_PROXY_COMPLETIONS)
validate_audit_auth = require_scope(SCOPE_AUDIT_READ)
require_audit_export = require_scope(SCOPE_AUDIT_EXPORT)
require_audit_analytics = require_scope(SCOPE_AUDIT_ANALYTICS)


def principal_tenant(principal: Principal, requested_tenant: str | None = None) -> str | None:
    """Return an authorized tenant filter; only administrators may select another tenant."""

    if Role.ADMIN in principal.roles:
        return requested_tenant
    if requested_tenant is not None and not hmac.compare_digest(
        requested_tenant, principal.tenant_id
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant access denied")
    return principal.tenant_id


def request_time() -> datetime:
    """UTC timestamp seam for policy/audit integrations."""

    return datetime.now(UTC)


__all__ = [
    "authenticate_principal",
    "permissions_for_roles",
    "principal_tenant",
    "require_audit_analytics",
    "require_audit_export",
    "require_scope",
    "validate_audit_auth",
    "validate_proxy_auth",
]
