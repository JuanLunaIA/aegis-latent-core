# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for RBAC + NIST SP 800-207 Zero Trust policy evaluation (aegis.auth.rbac)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis.auth.rbac import (
    BUILTIN_ROLES,
    ROLE_ADMIN,
    ROLE_AUDITOR,
    AccessContext,
    AccessDecision,
    AccessRequest,
    IPAllowlist,
    RBACConfigError,
    RequireAuthMethod,
    RequireMTLS,
    Role,
    RoleRegistry,
    TimeWindow,
    ZeroTrustPolicyEngine,
)
from aegis.auth.scopes import (
    SCOPE_AUDIT_ANALYTICS,
    SCOPE_AUDIT_EXPORT,
    SCOPE_AUDIT_READ,
    SCOPE_PROXY_COMPLETIONS,
)

# ── Role ────────────────────────────────────────────────────────────────────


class TestRole:
    def test_grants_true(self):
        assert ROLE_AUDITOR.grants(SCOPE_AUDIT_READ)

    def test_grants_false(self):
        assert not ROLE_AUDITOR.grants(SCOPE_PROXY_COMPLETIONS)

    def test_admin_grants_all(self):
        for scope in (
            SCOPE_PROXY_COMPLETIONS,
            SCOPE_AUDIT_READ,
            SCOPE_AUDIT_EXPORT,
            SCOPE_AUDIT_ANALYTICS,
        ):
            assert ROLE_ADMIN.grants(scope)

    def test_role_is_frozen(self):
        from dataclasses import FrozenInstanceError

        with pytest.raises(FrozenInstanceError):
            ROLE_AUDITOR.name = "x"  # type: ignore[misc]

    def test_builtin_roles_keyed_by_name(self):
        assert BUILTIN_ROLES["admin"] is ROLE_ADMIN
        assert BUILTIN_ROLES["auditor"] is ROLE_AUDITOR


# ── RoleRegistry ──────────────────────────────────────────────────────────────


class TestRoleRegistry:
    def test_resolve_direct_subject_role(self):
        reg = RoleRegistry(subject_roles={"alice": frozenset({"auditor"})})
        ctx = AccessContext(subject_id="alice")
        assert "auditor" in reg.resolve_roles(ctx)

    def test_resolve_context_direct_roles(self):
        reg = RoleRegistry()
        ctx = AccessContext(subject_id="bob", direct_roles=frozenset({"proxy_user"}))
        assert "proxy_user" in reg.resolve_roles(ctx)

    def test_resolve_group_roles(self):
        reg = RoleRegistry(group_roles={"AegisAdmins": frozenset({"admin"})})
        ctx = AccessContext(subject_id="carol", ldap_groups=frozenset({"AegisAdmins"}))
        assert "admin" in reg.resolve_roles(ctx)

    def test_resolve_group_roles_case_insensitive(self):
        reg = RoleRegistry(group_roles={"AegisAdmins": frozenset({"admin"})})
        ctx = AccessContext(subject_id="carol", ldap_groups=frozenset({"aegisadmins"}))
        assert "admin" in reg.resolve_roles(ctx)

    def test_default_roles_applied(self):
        reg = RoleRegistry(default_roles=frozenset({"audit_reader"}))
        ctx = AccessContext(subject_id="anyone")
        assert "audit_reader" in reg.resolve_roles(ctx)

    def test_resolve_permissions_union(self):
        reg = RoleRegistry(subject_roles={"dana": frozenset({"proxy_user", "audit_reader"})})
        ctx = AccessContext(subject_id="dana")
        perms = reg.resolve_permissions(ctx)
        assert SCOPE_PROXY_COMPLETIONS in perms
        assert SCOPE_AUDIT_READ in perms
        assert SCOPE_AUDIT_EXPORT not in perms

    def test_unknown_role_reference_raises(self):
        with pytest.raises(RBACConfigError):
            RoleRegistry(subject_roles={"x": frozenset({"nonexistent"})})

    def test_unknown_group_role_raises(self):
        with pytest.raises(RBACConfigError):
            RoleRegistry(group_roles={"G": frozenset({"ghost"})})

    def test_unknown_default_role_raises(self):
        with pytest.raises(RBACConfigError):
            RoleRegistry(default_roles=frozenset({"ghost"}))

    def test_custom_role_registered(self):
        custom = Role(name="dpo", permissions=frozenset({SCOPE_AUDIT_ANALYTICS}))
        reg = RoleRegistry(
            subject_roles={"e": frozenset({"dpo"})},
            roles=[custom],
        )
        ctx = AccessContext(subject_id="e")
        assert SCOPE_AUDIT_ANALYTICS in reg.resolve_permissions(ctx)

    def test_custom_role_overrides_builtin(self):
        # Redefine "auditor" with narrower permissions.
        narrow = Role(name="auditor", permissions=frozenset({SCOPE_AUDIT_READ}))
        reg = RoleRegistry(subject_roles={"f": frozenset({"auditor"})}, roles=[narrow])
        ctx = AccessContext(subject_id="f")
        perms = reg.resolve_permissions(ctx)
        assert perms == frozenset({SCOPE_AUDIT_READ})

    def test_get_role(self):
        reg = RoleRegistry()
        assert reg.get_role("admin") is ROLE_ADMIN
        assert reg.get_role("nope") is None

    def test_find_granting_role(self):
        reg = RoleRegistry(subject_roles={"g": frozenset({"auditor"})})
        ctx = AccessContext(subject_id="g")
        assert reg.find_granting_role(ctx, SCOPE_AUDIT_EXPORT) == "auditor"

    def test_find_granting_role_none(self):
        reg = RoleRegistry(subject_roles={"g": frozenset({"audit_reader"})})
        ctx = AccessContext(subject_id="g")
        assert reg.find_granting_role(ctx, SCOPE_PROXY_COMPLETIONS) == ""

    def test_unknown_role_in_context_ignored(self):
        # direct_roles referencing an unknown role is filtered out, not an error.
        reg = RoleRegistry()
        ctx = AccessContext(subject_id="h", direct_roles=frozenset({"ghost"}))
        assert reg.resolve_roles(ctx) == frozenset()


# ── ZeroTrustPolicyEngine — base RBAC ─────────────────────────────────────────


class TestZeroTrustBaseRBAC:
    def _engine(self, **kwargs) -> ZeroTrustPolicyEngine:
        reg = RoleRegistry(**kwargs)
        return ZeroTrustPolicyEngine(reg)

    def test_allow_when_role_grants(self):
        engine = self._engine(subject_roles={"alice": frozenset({"auditor"})})
        ctx = AccessContext(subject_id="alice")
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ))
        assert decision.allowed
        assert decision.matched_role == "auditor"

    def test_deny_by_default_no_role(self):
        engine = self._engine()
        ctx = AccessContext(subject_id="nobody")
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ))
        assert not decision.allowed
        assert "no role" in decision.reason

    def test_deny_when_role_lacks_permission(self):
        engine = self._engine(subject_roles={"p": frozenset({"proxy_user"})})
        ctx = AccessContext(subject_id="p")
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT))
        assert not decision.allowed

    def test_decision_bool_protocol(self):
        engine = self._engine(subject_roles={"a": frozenset({"admin"})})
        ctx = AccessContext(subject_id="a")
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT))
        assert bool(decision) is True

    def test_decision_records_subject(self):
        engine = self._engine(subject_roles={"a": frozenset({"admin"})})
        ctx = AccessContext(subject_id="a")
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ))
        assert decision.subject_id == "a"

    def test_require_raises_on_denial(self):
        engine = self._engine()
        ctx = AccessContext(subject_id="x")
        with pytest.raises(PermissionError):
            engine.require(AccessRequest(ctx, SCOPE_AUDIT_READ))

    def test_require_returns_decision_on_allow(self):
        engine = self._engine(subject_roles={"a": frozenset({"admin"})})
        ctx = AccessContext(subject_id="a")
        decision = engine.require(AccessRequest(ctx, SCOPE_AUDIT_READ))
        assert isinstance(decision, AccessDecision)
        assert decision.allowed


# ── Zero Trust constraints ────────────────────────────────────────────────────


class TestRequireMTLS:
    def _engine(self) -> ZeroTrustPolicyEngine:
        reg = RoleRegistry(subject_roles={"a": frozenset({"admin"})})
        engine = ZeroTrustPolicyEngine(reg)
        engine.add_constraint(RequireMTLS(SCOPE_AUDIT_EXPORT))
        return engine

    def test_denied_without_mtls(self):
        engine = self._engine()
        ctx = AccessContext(subject_id="a", mtls_verified=False)
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT))
        assert not decision.allowed
        assert "mTLS" in decision.reason

    def test_allowed_with_mtls(self):
        engine = self._engine()
        ctx = AccessContext(subject_id="a", mtls_verified=True)
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT))
        assert decision.allowed

    def test_constraint_only_applies_to_its_permission(self):
        engine = self._engine()
        # audit:read is not constrained → allowed even without mTLS
        ctx = AccessContext(subject_id="a", mtls_verified=False)
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ))
        assert decision.allowed


class TestRequireAuthMethod:
    def test_denied_wrong_method(self):
        reg = RoleRegistry(subject_roles={"a": frozenset({"admin"})})
        engine = ZeroTrustPolicyEngine(reg)
        engine.add_constraint(RequireAuthMethod(SCOPE_AUDIT_EXPORT, frozenset({"mtls_cac_piv"})))
        ctx = AccessContext(subject_id="a", auth_method="api_key", mtls_verified=True)
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT))
        assert not decision.allowed

    def test_allowed_correct_method(self):
        reg = RoleRegistry(subject_roles={"a": frozenset({"admin"})})
        engine = ZeroTrustPolicyEngine(reg)
        engine.add_constraint(
            RequireAuthMethod(SCOPE_AUDIT_EXPORT, frozenset({"mtls_cac_piv", "ldap"}))
        )
        ctx = AccessContext(subject_id="a", auth_method="ldap")
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT))
        assert decision.allowed


class TestIPAllowlist:
    def _engine(self, networks: tuple[str, ...]) -> ZeroTrustPolicyEngine:
        reg = RoleRegistry(subject_roles={"a": frozenset({"admin"})})
        engine = ZeroTrustPolicyEngine(reg)
        engine.add_constraint(IPAllowlist(SCOPE_AUDIT_READ, networks))
        return engine

    def test_allowed_in_range(self):
        engine = self._engine(("10.0.0.0/8",))
        ctx = AccessContext(subject_id="a", source_ip="10.1.2.3")
        assert engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ)).allowed

    def test_denied_out_of_range(self):
        engine = self._engine(("10.0.0.0/8",))
        ctx = AccessContext(subject_id="a", source_ip="192.168.1.1")
        assert not engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ)).allowed

    def test_denied_when_no_ip(self):
        engine = self._engine(("10.0.0.0/8",))
        ctx = AccessContext(subject_id="a", source_ip="")
        assert not engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ)).allowed

    def test_denied_invalid_ip(self):
        engine = self._engine(("10.0.0.0/8",))
        ctx = AccessContext(subject_id="a", source_ip="not-an-ip")
        assert not engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ)).allowed

    def test_ipv6_range(self):
        engine = self._engine(("2001:db8::/32",))
        ctx = AccessContext(subject_id="a", source_ip="2001:db8::1")
        assert engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ)).allowed


class TestTimeWindow:
    def _engine(self, start: int, end: int) -> ZeroTrustPolicyEngine:
        reg = RoleRegistry(subject_roles={"a": frozenset({"admin"})})
        engine = ZeroTrustPolicyEngine(reg)
        engine.add_constraint(TimeWindow(SCOPE_AUDIT_EXPORT, start, end))
        return engine

    def test_allowed_within_window(self):
        engine = self._engine(9, 17)
        ctx = AccessContext(
            subject_id="a",
            request_time=datetime(2026, 6, 21, 12, 0, tzinfo=UTC),
        )
        assert engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT)).allowed

    def test_denied_outside_window(self):
        engine = self._engine(9, 17)
        ctx = AccessContext(
            subject_id="a",
            request_time=datetime(2026, 6, 21, 20, 0, tzinfo=UTC),
        )
        assert not engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT)).allowed

    def test_denied_when_no_time(self):
        engine = self._engine(9, 17)
        ctx = AccessContext(subject_id="a", request_time=None)
        assert not engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT)).allowed

    def test_window_wraps_midnight_allowed(self):
        engine = self._engine(22, 6)
        ctx = AccessContext(
            subject_id="a",
            request_time=datetime(2026, 6, 21, 23, 0, tzinfo=UTC),
        )
        assert engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT)).allowed

    def test_window_wraps_midnight_denied(self):
        engine = self._engine(22, 6)
        ctx = AccessContext(
            subject_id="a",
            request_time=datetime(2026, 6, 21, 12, 0, tzinfo=UTC),
        )
        assert not engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT)).allowed

    def test_invalid_hour_raises(self):
        with pytest.raises(RBACConfigError):
            TimeWindow(SCOPE_AUDIT_EXPORT, 9, 25)


# ── Combined / integration scenarios ──────────────────────────────────────────


class TestZeroTrustIntegration:
    def test_multiple_constraints_all_must_pass(self):
        reg = RoleRegistry(subject_roles={"a": frozenset({"admin"})})
        engine = ZeroTrustPolicyEngine(reg)
        engine.add_constraint(RequireMTLS(SCOPE_AUDIT_EXPORT))
        engine.add_constraint(IPAllowlist(SCOPE_AUDIT_EXPORT, ("10.0.0.0/8",)))

        # mTLS ok but IP wrong → deny
        ctx1 = AccessContext(subject_id="a", mtls_verified=True, source_ip="192.168.0.1")
        assert not engine.evaluate(AccessRequest(ctx1, SCOPE_AUDIT_EXPORT)).allowed

        # both ok → allow
        ctx2 = AccessContext(subject_id="a", mtls_verified=True, source_ip="10.0.0.5")
        assert engine.evaluate(AccessRequest(ctx2, SCOPE_AUDIT_EXPORT)).allowed

    def test_ldap_group_to_role_zero_trust_flow(self):
        reg = RoleRegistry(group_roles={"AegisAuditors": frozenset({"auditor"})})
        engine = ZeroTrustPolicyEngine(reg)
        engine.add_constraint(RequireMTLS(SCOPE_AUDIT_EXPORT))

        ctx = AccessContext(
            subject_id="john.doe",
            auth_method="ldap",
            mtls_verified=True,
            ldap_groups=frozenset({"AegisAuditors"}),
        )
        # read allowed (no constraint), export allowed (mtls present)
        assert engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ)).allowed
        assert engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT)).allowed
        # proxy not granted by auditor role
        assert not engine.evaluate(AccessRequest(ctx, SCOPE_PROXY_COMPLETIONS)).allowed

    def test_constraint_passes_when_subject_lacks_permission_still_denied(self):
        # Permission check precedes constraint check; lacking role denies first.
        reg = RoleRegistry(subject_roles={"a": frozenset({"audit_reader"})})
        engine = ZeroTrustPolicyEngine(reg)
        engine.add_constraint(RequireMTLS(SCOPE_AUDIT_EXPORT))
        ctx = AccessContext(subject_id="a", mtls_verified=True)
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_EXPORT))
        assert not decision.allowed
        assert "no role" in decision.reason
