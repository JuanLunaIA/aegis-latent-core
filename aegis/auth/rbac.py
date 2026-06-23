# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.auth.rbac — Role-Based Access Control with NIST SP 800-207 Zero Trust.

Layers a role abstraction over the permission vocabulary defined in
:mod:`aegis.auth.scopes`, then evaluates every access request against a dynamic,
deny-by-default policy that inspects subject, resource, action AND environmental
attributes — the NIST SP 800-207 "dynamic policy" tenet.

Design
------
* **Permissions** are the existing scope strings (``proxy:completions``,
  ``audit:read``, ``audit:export``, ``audit:analytics``).  RBAC does not invent a
  parallel vocabulary; a role is simply a named bundle of permissions.
* **Roles** (:class:`Role`) map a name to a frozenset of permissions.  A small set
  of built-in roles is provided; deployments may register custom roles.
* **Subjects** acquire roles three ways, unified by :class:`RoleRegistry`:
  direct subject→roles assignment, LDAP/AD group→role mapping (see
  :mod:`aegis.auth.ldap_auth`), and a configurable default role.
* **Zero Trust evaluation** (:class:`ZeroTrustPolicyEngine`) never grants access
  on role possession alone.  Each :class:`AccessRequest` carries an
  :class:`AccessContext` (auth method, mTLS verification, source IP, request
  time, …) and the engine applies *constraints* — e.g. audit export may require
  a verified mTLS client certificate, or a permission may be restricted to an
  IP allowlist or a time window.  The default decision is DENY.

NIST SP 800-207 tenets addressed
--------------------------------
* Tenet 3 — access granted per-session with least privilege (role bundles).
* Tenet 4 — access determined by *dynamic policy* including client identity and
  observable environmental attributes (auth method, mTLS posture, source IP,
  time-of-day).
* Tenet 6 — authentication & authorization strictly enforced before access
  (deny-by-default; explicit allow only on a satisfied constraint set).

Usage::

    registry = RoleRegistry(
        subject_roles={"alice": frozenset({"auditor"})},
        group_roles={"AegisAdmins": frozenset({"admin"})},
    )
    engine = ZeroTrustPolicyEngine(registry)
    engine.add_constraint(RequireMTLS(SCOPE_AUDIT_EXPORT))

    ctx = AccessContext(subject_id="alice", auth_method="ldap",
                        mtls_verified=False, ldap_groups=frozenset())
    decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ))
    assert decision.allowed         # auditor role grants audit:read
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from aegis.auth.scopes import (
    ALL_SCOPES,
    SCOPE_AUDIT_ANALYTICS,
    SCOPE_AUDIT_EXPORT,
    SCOPE_AUDIT_READ,
    SCOPE_PROXY_COMPLETIONS,
)


class RBACConfigError(ValueError):
    """Raised when role/registry configuration is invalid."""


# ── Roles ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Role:
    """A named bundle of permissions (scope strings).

    Parameters
    ----------
    name:
        Stable identifier (e.g. ``"auditor"``).
    permissions:
        Frozenset of scope strings this role grants.
    description:
        Human-readable purpose, surfaced in audit logs.
    """

    name: str
    permissions: frozenset[str]
    description: str = ""

    def grants(self, permission: str) -> bool:
        return permission in self.permissions


# Built-in roles keyed by name.  Deployments may extend via RoleRegistry.
ROLE_ADMIN = Role(
    name="admin",
    permissions=ALL_SCOPES,
    description="Full access to proxy and all audit operations.",
)
ROLE_PROXY_USER = Role(
    name="proxy_user",
    permissions=frozenset({SCOPE_PROXY_COMPLETIONS}),
    description="May call the inference proxy only.",
)
ROLE_AUDITOR = Role(
    name="auditor",
    permissions=frozenset({SCOPE_AUDIT_READ, SCOPE_AUDIT_EXPORT, SCOPE_AUDIT_ANALYTICS}),
    description="Read, export and run analytics over the audit chain.",
)
ROLE_AUDIT_READER = Role(
    name="audit_reader",
    permissions=frozenset({SCOPE_AUDIT_READ}),
    description="Read-only access to audit records.",
)

BUILTIN_ROLES: dict[str, Role] = {
    r.name: r for r in (ROLE_ADMIN, ROLE_PROXY_USER, ROLE_AUDITOR, ROLE_AUDIT_READER)
}


# ── Access context & request ────────────────────────────────────────────────


@dataclass(frozen=True)
class AccessContext:
    """Observable attributes of an access attempt (Zero Trust signal bundle).

    Everything the policy engine may reason about is captured here so the
    evaluation is a pure function of (context, requested permission).

    Parameters
    ----------
    subject_id:
        Authenticated principal (API-key id, EDIPI, LDAP user, …).
    auth_method:
        How the subject authenticated: ``"api_key"``, ``"mtls_cac_piv"``,
        ``"ldap"``, ``"anonymous"``.
    mtls_verified:
        True when a client certificate was presented and verified.
    source_ip:
        Caller IP as a string; empty when unknown.
    request_time:
        Timestamp of the request (UTC recommended).  Defaults to none → the
        engine treats time-window constraints as unevaluable and denies them.
    ldap_groups:
        Directory groups asserted for the subject (drives group→role mapping).
    direct_roles:
        Roles assigned out-of-band (e.g. from API-key configuration).
    """

    subject_id: str
    auth_method: str = "anonymous"
    mtls_verified: bool = False
    source_ip: str = ""
    request_time: datetime | None = None
    ldap_groups: frozenset[str] = field(default_factory=frozenset)
    direct_roles: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class AccessRequest:
    """A request to perform an action requiring *permission*."""

    context: AccessContext
    permission: str
    resource: str = ""


@dataclass(frozen=True)
class AccessDecision:
    """Outcome of a Zero Trust policy evaluation.

    ``allowed`` is the authoritative result; ``reason`` explains the decision for
    audit logging.  ``matched_role`` names the role that supplied the permission
    (empty when denied for lack of permission).
    """

    allowed: bool
    reason: str
    permission: str
    subject_id: str
    matched_role: str = ""

    def __bool__(self) -> bool:  # allow `if decision:` idiom
        return self.allowed


# ── Role registry ─────────────────────────────────────────────────────────────


class RoleRegistry:
    """Resolves the effective roles and permissions for a subject.

    Parameters
    ----------
    subject_roles:
        Direct mapping of subject id → role-name frozenset.
    group_roles:
        Mapping of LDAP/AD group (CN or DN) → role-name frozenset.
    roles:
        Role catalogue.  Defaults to :data:`BUILTIN_ROLES`; custom roles are
        merged in (custom names override built-ins of the same name).
    default_roles:
        Roles every authenticated subject receives regardless of mapping.
    """

    def __init__(
        self,
        subject_roles: dict[str, frozenset[str]] | None = None,
        group_roles: dict[str, frozenset[str]] | None = None,
        roles: Iterable[Role] | None = None,
        default_roles: frozenset[str] = frozenset(),
    ) -> None:
        self._catalogue: dict[str, Role] = dict(BUILTIN_ROLES)
        if roles is not None:
            for role in roles:
                self._catalogue[role.name] = role
        self._subject_roles = subject_roles or {}
        self._group_roles = group_roles or {}
        self._default_roles = default_roles

        # Validate that every referenced role exists in the catalogue.
        self._validate_references()

    def _validate_references(self) -> None:
        referenced: set[str] = set(self._default_roles)
        for names in self._subject_roles.values():
            referenced |= set(names)
        for names in self._group_roles.values():
            referenced |= set(names)
        unknown = referenced - self._catalogue.keys()
        if unknown:
            raise RBACConfigError(
                f"Unknown role(s) referenced but not in catalogue: {sorted(unknown)}"
            )

    def get_role(self, name: str) -> Role | None:
        return self._catalogue.get(name)

    def resolve_roles(self, context: AccessContext) -> frozenset[str]:
        """Return the set of role *names* effective for *context*.

        Combines default roles, direct context roles, configured subject→role
        assignments, and group→role mappings (case-insensitive on group name).
        """
        names: set[str] = set(self._default_roles)
        names |= set(context.direct_roles)
        names |= set(self._subject_roles.get(context.subject_id, frozenset()))

        if context.ldap_groups:
            lowered = {g.lower(): roles for g, roles in self._group_roles.items()}
            for group in context.ldap_groups:
                mapped = self._group_roles.get(group)
                if mapped is None:
                    mapped = lowered.get(group.lower())
                if mapped:
                    names |= set(mapped)

        # Keep only names that exist in the catalogue (defensive).
        return frozenset(n for n in names if n in self._catalogue)

    def resolve_permissions(self, context: AccessContext) -> frozenset[str]:
        """Return the union of permissions granted by the subject's roles."""
        perms: set[str] = set()
        for name in self.resolve_roles(context):
            role = self._catalogue[name]
            perms |= role.permissions
        return frozenset(perms)

    def find_granting_role(self, context: AccessContext, permission: str) -> str:
        """Return the name of a role granting *permission*, or '' if none."""
        for name in sorted(self.resolve_roles(context)):
            if self._catalogue[name].grants(permission):
                return name
        return ""


# ── Zero Trust constraints ──────────────────────────────────────────────────


class Constraint:
    """Base class for a dynamic, attribute-based access constraint.

    A constraint applies to a specific permission.  When it applies, the engine
    calls :meth:`check`; returning False denies the request even if the subject
    holds the permission via a role.
    """

    def applies_to(self, permission: str) -> bool:  # pragma: no cover - trivial
        raise NotImplementedError

    def check(self, context: AccessContext) -> bool:  # pragma: no cover - trivial
        raise NotImplementedError

    def denial_reason(self) -> str:  # pragma: no cover - trivial
        raise NotImplementedError


@dataclass
class RequireMTLS(Constraint):
    """Require a verified mTLS client certificate for *permission*."""

    permission: str

    def applies_to(self, permission: str) -> bool:
        return permission == self.permission

    def check(self, context: AccessContext) -> bool:
        return context.mtls_verified

    def denial_reason(self) -> str:
        return f"permission {self.permission!r} requires a verified mTLS client certificate"


@dataclass
class RequireAuthMethod(Constraint):
    """Require one of *allowed_methods* as the auth method for *permission*."""

    permission: str
    allowed_methods: frozenset[str]

    def applies_to(self, permission: str) -> bool:
        return permission == self.permission

    def check(self, context: AccessContext) -> bool:
        return context.auth_method in self.allowed_methods

    def denial_reason(self) -> str:
        return (
            f"permission {self.permission!r} requires auth method in {sorted(self.allowed_methods)}"
        )


@dataclass
class IPAllowlist(Constraint):
    """Restrict *permission* to source IPs within the given CIDR networks."""

    permission: str
    networks: tuple[str, ...]

    def __post_init__(self) -> None:
        self._nets = [ipaddress.ip_network(n, strict=False) for n in self.networks]

    def applies_to(self, permission: str) -> bool:
        return permission == self.permission

    def check(self, context: AccessContext) -> bool:
        if not context.source_ip:
            return False
        try:
            addr = ipaddress.ip_address(context.source_ip)
        except ValueError:
            return False
        return any(addr in net for net in self._nets)

    def denial_reason(self) -> str:
        return f"permission {self.permission!r} restricted to {list(self.networks)}"


@dataclass
class TimeWindow(Constraint):
    """Restrict *permission* to a daily UTC hour window [start_hour, end_hour).

    Windows that wrap past midnight are supported (e.g. 22→6).
    """

    permission: str
    start_hour: int
    end_hour: int

    def __post_init__(self) -> None:
        for h in (self.start_hour, self.end_hour):
            if not 0 <= h <= 24:
                raise RBACConfigError(f"hour out of range 0..24: {h}")

    def applies_to(self, permission: str) -> bool:
        return permission == self.permission

    def check(self, context: AccessContext) -> bool:
        if context.request_time is None:
            return False
        hour = context.request_time.hour
        if self.start_hour <= self.end_hour:
            return self.start_hour <= hour < self.end_hour
        # wraps midnight
        return hour >= self.start_hour or hour < self.end_hour

    def denial_reason(self) -> str:
        return (
            f"permission {self.permission!r} only permitted between "
            f"{self.start_hour:02d}:00 and {self.end_hour:02d}:00 UTC"
        )


# ── Policy engine ─────────────────────────────────────────────────────────────


class ZeroTrustPolicyEngine:
    """Deny-by-default policy engine combining RBAC with dynamic constraints.

    Evaluation order:
      1. Resolve the subject's roles → permissions (RBAC).
      2. If the permission is not granted by any role → DENY (no privilege).
      3. For every registered constraint that applies to the permission, call
         :meth:`Constraint.check`.  Any failing constraint → DENY.
      4. Otherwise → ALLOW, recording the granting role.

    Parameters
    ----------
    registry:
        The :class:`RoleRegistry` used to resolve roles/permissions.
    constraints:
        Optional initial constraint list.
    """

    def __init__(
        self,
        registry: RoleRegistry,
        constraints: Iterable[Constraint] | None = None,
    ) -> None:
        self._registry = registry
        self._constraints: list[Constraint] = list(constraints or [])

    def add_constraint(self, constraint: Constraint) -> None:
        self._constraints.append(constraint)

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        ctx = request.context
        perm = request.permission

        granting_role = self._registry.find_granting_role(ctx, perm)
        if not granting_role:
            return AccessDecision(
                allowed=False,
                reason=f"subject holds no role granting {perm!r}",
                permission=perm,
                subject_id=ctx.subject_id,
            )

        for constraint in self._constraints:
            if constraint.applies_to(perm) and not constraint.check(ctx):
                return AccessDecision(
                    allowed=False,
                    reason=constraint.denial_reason(),
                    permission=perm,
                    subject_id=ctx.subject_id,
                    matched_role=granting_role,
                )

        return AccessDecision(
            allowed=True,
            reason=f"granted by role {granting_role!r}",
            permission=perm,
            subject_id=ctx.subject_id,
            matched_role=granting_role,
        )

    def require(self, request: AccessRequest) -> AccessDecision:
        """Like :meth:`evaluate` but raises :exc:`PermissionError` on denial."""
        decision = self.evaluate(request)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        return decision
