"""Immutable authenticated-principal model shared by enterprise auth mechanisms."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from aegis.auth.scopes import (
    ALL_SCOPES,
    SCOPE_AUDIT_ANALYTICS,
    SCOPE_AUDIT_EXPORT,
    SCOPE_AUDIT_READ,
    SCOPE_PROXY_COMPLETIONS,
)


class Role(StrEnum):
    """The four supported platform roles."""

    ADMIN = "admin"
    PROXY_USER = "proxy_user"
    AUDITOR = "auditor"
    AUDIT_READER = "audit_reader"


ROLE_ADMIN = Role.ADMIN
ROLE_PROXY_USER = Role.PROXY_USER
ROLE_AUDITOR = Role.AUDITOR
ROLE_AUDIT_READER = Role.AUDIT_READER
ALL_ROLES: frozenset[Role] = frozenset(Role)

# What each role may be granted. Lives with the principal model (not with the
# FastAPI dependencies) so the mapping generator below and the request path
# apply one rule without importing each other.
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


def parse_roles(value: object) -> frozenset[Role]:
    """Roles from a principal mapping entry: a JSON string array of role names."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("roles must be a JSON string array")
    return frozenset(Role(item) for item in value)


def parse_scopes(value: object) -> frozenset[str]:
    """Scopes from a principal mapping entry: a JSON string array of known scopes."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("scopes must be a JSON string array")
    scopes = frozenset(value)
    unknown = scopes - ALL_SCOPES
    if unknown:
        raise ValueError(f"unsupported scopes: {sorted(unknown)}")
    return scopes


@dataclass(frozen=True, slots=True)
class Principal:
    """An immutable, tenant-bound result of successful authentication."""

    subject: str
    tenant_id: str
    roles: frozenset[Role] = field(default_factory=frozenset)
    scopes: frozenset[str] = field(default_factory=frozenset)
    auth_method: str = "oidc"
    credential_id: str = ""
    attributes: Mapping[str, object] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        subject = self.subject.strip()
        tenant_id = self.tenant_id.strip()
        credential_id = self.credential_id.strip() or subject
        if not subject:
            raise ValueError("principal subject must not be empty")
        if not tenant_id:
            raise ValueError("principal tenant_id must not be empty")
        if not self.auth_method.strip():
            raise ValueError("principal auth_method must not be empty")
        normalized_roles = frozenset(Role(role) for role in self.roles)
        normalized_scopes = frozenset(scope.strip() for scope in self.scopes if scope.strip())
        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "credential_id", credential_id)
        object.__setattr__(self, "roles", normalized_roles)
        object.__setattr__(self, "scopes", normalized_scopes)
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))

    @property
    def subject_id(self) -> str:
        """Compatibility alias for policy engines that call the subject ``subject_id``."""

        return self.subject

    def has_role(self, role: Role | str) -> bool:
        """Return whether this principal was granted *role*."""

        try:
            return Role(role) in self.roles
        except ValueError:
            return False

    def require_role(self, role: Role | str) -> None:
        """Raise :class:`PermissionError` unless this principal holds *role*."""

        if not self.has_role(role):
            raise PermissionError(f"principal lacks required role {str(role)!r}")


def build_api_key_principals(
    identity_key: str, grants: Mapping[str, Mapping[str, object]]
) -> dict[str, dict[str, object]]:
    """Return the ``AEGIS_API_KEY_PRINCIPALS_JSON`` object for *grants*.

    *grants* maps each API key to ``{"tenant_id", "roles", "scopes"}``. Keys are
    replaced by the digest the gateway looks them up by
    (``AegisSettings.api_key_principal_digest``), and every entry is checked with
    the same role, scope and role-grant rules the gateway applies at request
    time, so a mapping that would be refused in production is refused here.
    Strict mode requires one entry per configured key (``validate_runtime_invariants``).
    """
    from aegis.config import AegisSettings

    if len(identity_key.encode("utf-8")) < 32:
        raise ValueError("AEGIS_AUTH_IDENTITY_HMAC_KEY must be at least 32 bytes")
    digester = AegisSettings.model_construct(auth_identity_hmac_key=identity_key)
    mapping: dict[str, dict[str, object]] = {}
    for position, (api_key, grant) in enumerate(grants.items(), start=1):
        label = f"entry {position}"  # never echo the key itself
        if not api_key.strip():
            raise ValueError(f"{label}: API key must not be empty")
        tenant_id = grant.get("tenant_id")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError(f"{label}: tenant_id must be a non-empty string")
        roles = parse_roles(grant.get("roles", []))
        scopes = parse_scopes(grant.get("scopes", []))
        if not scopes.issubset(permissions_for_roles(roles)):
            raise ValueError(f"{label}: scopes exceed what the roles grant")
        mapping[digester.api_key_principal_digest(api_key)] = {
            "tenant_id": tenant_id,
            "roles": sorted(roles),
            "scopes": sorted(scopes),
        }
    return mapping


def main(argv: list[str] | None = None) -> int:
    """``python -m aegis.auth.principal``: print a principal mapping for strict mode.

    Reads ``{"<api-key>": {"tenant_id": ..., "roles": [...], "scopes": [...]}}``
    on standard input and the identity key from ``AEGIS_AUTH_IDENTITY_HMAC_KEY``,
    so neither appears in a process listing or shell history. Writes the JSON
    object to set as ``AEGIS_API_KEY_PRINCIPALS_JSON``; it contains digests,
    never the keys.
    """
    import json
    import os
    import sys

    del argv
    identity_key = os.environ.get("AEGIS_AUTH_IDENTITY_HMAC_KEY", "")
    try:
        grants = json.loads(sys.stdin.read())
        if not isinstance(grants, dict) or not all(
            isinstance(key, str) and isinstance(value, dict) for key, value in grants.items()
        ):
            raise ValueError('input must be a JSON object: {"<api-key>": {...}, ...}')
        mapping = build_api_key_principals(identity_key, grants)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"principal mapping refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(mapping, sort_keys=True, separators=(",", ":")))
    return 0


__all__ = [
    "ALL_ROLES",
    "ROLE_ADMIN",
    "ROLE_AUDITOR",
    "ROLE_AUDIT_READER",
    "ROLE_PROXY_USER",
    "Principal",
    "Role",
    "build_api_key_principals",
    "parse_roles",
    "parse_scopes",
    "permissions_for_roles",
]


if __name__ == "__main__":
    raise SystemExit(main())
