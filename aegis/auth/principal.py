"""Immutable authenticated-principal model shared by enterprise auth mechanisms."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType


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


__all__ = [
    "ALL_ROLES",
    "ROLE_ADMIN",
    "ROLE_AUDITOR",
    "ROLE_AUDIT_READER",
    "ROLE_PROXY_USER",
    "Principal",
    "Role",
]
