# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for SCIM 2.0 provisioning/deprovisioning lifecycle (aegis.auth.scim)."""

from __future__ import annotations

import pytest

from aegis.auth.scim import (
    SCHEMA_ERROR,
    SCHEMA_GROUP,
    SCHEMA_LIST_RESPONSE,
    SCHEMA_USER,
    ScimEmail,
    ScimError,
    ScimGroup,
    ScimListResponse,
    ScimPatchOp,
    ScimStore,
    ScimUser,
    _apply_filter,
)

# ── ScimError ─────────────────────────────────────────────────────────────────


class TestScimError:
    def test_status_and_detail(self):
        e = ScimError(404, "not found")
        assert e.status == 404
        assert e.detail == "not found"
        assert str(e) == "not found"

    def test_to_dict_no_scim_type(self):
        d = ScimError(404, "gone").to_dict()
        assert d["schemas"] == [SCHEMA_ERROR]
        assert d["status"] == "404"
        assert "scimType" not in d

    def test_to_dict_with_scim_type(self):
        d = ScimError(409, "dup", "uniqueness").to_dict()
        assert d["scimType"] == "uniqueness"

    def test_is_exception(self):
        with pytest.raises(ScimError):
            raise ScimError(400, "bad")


# ── ScimUser.to_dict ──────────────────────────────────────────────────────────


class TestScimUserDict:
    def _user(self, **kw) -> ScimUser:
        return ScimUser(id="u1", user_name="alice", **kw)

    def test_schema_present(self):
        assert SCHEMA_USER in self._user().to_dict()["schemas"]

    def test_required_fields(self):
        d = self._user().to_dict()
        assert d["id"] == "u1"
        assert d["userName"] == "alice"
        assert d["active"] is True

    def test_external_id_omitted_when_empty(self):
        assert "externalId" not in self._user().to_dict()

    def test_external_id_present_when_set(self):
        assert self._user(external_id="ext-1").to_dict()["externalId"] == "ext-1"

    def test_emails_serialized(self):
        user = self._user(emails=[ScimEmail(value="a@b.com", primary=True)])
        d = user.to_dict()
        assert d["emails"][0]["value"] == "a@b.com"
        assert d["emails"][0]["primary"] is True

    def test_group_ids_serialized(self):
        user = self._user(group_ids=frozenset({"g1", "g2"}))
        gids = {g["value"] for g in user.to_dict()["groups"]}
        assert gids == {"g1", "g2"}


# ── ScimGroup.to_dict ─────────────────────────────────────────────────────────


class TestScimGroupDict:
    def test_schema_present(self):
        g = ScimGroup(id="g1", display_name="AegisAdmins")
        assert SCHEMA_GROUP in g.to_dict()["schemas"]

    def test_members_serialized(self):
        g = ScimGroup(id="g1", display_name="X", member_ids=frozenset({"u1", "u2"}))
        mids = {m["value"] for m in g.to_dict()["members"]}
        assert mids == {"u1", "u2"}


# ── ScimListResponse.to_dict ──────────────────────────────────────────────────


class TestScimListResponseDict:
    def test_schema_and_counts(self):
        resp = ScimListResponse(total_results=2, resources=[], start_index=1, items_per_page=10)
        d = resp.to_dict()
        assert SCHEMA_LIST_RESPONSE in d["schemas"]
        assert d["totalResults"] == 2

    def test_resources_serialized(self):
        user = ScimUser(id="u1", user_name="bob")
        resp = ScimListResponse(total_results=1, resources=[user])
        assert resp.to_dict()["Resources"][0]["userName"] == "bob"


# ── Filter engine ─────────────────────────────────────────────────────────────


class TestFilter:
    def _users(self) -> list[ScimUser]:
        return [
            ScimUser(id="1", user_name="alice", display_name="Alice Smith", active=True),
            ScimUser(id="2", user_name="bob", display_name="Bob Jones", active=False),
            ScimUser(
                id="3",
                user_name="carol",
                display_name="Carol White",
                active=True,
                external_id="ext-3",
            ),
        ]

    def test_eq_username(self):
        result = _apply_filter(self._users(), 'userName eq "alice"')  # type: ignore[arg-type]
        assert len(result) == 1
        assert result[0].user_name == "alice"  # type: ignore[union-attr]

    def test_eq_active_false(self):
        result = _apply_filter(self._users(), 'active eq "false"')  # type: ignore[arg-type]
        assert len(result) == 1
        assert result[0].user_name == "bob"  # type: ignore[union-attr]

    def test_ne_username(self):
        result = _apply_filter(self._users(), 'userName ne "alice"')  # type: ignore[arg-type]
        assert len(result) == 2

    def test_co_displayname(self):
        result = _apply_filter(self._users(), 'displayName co "jones"')  # type: ignore[arg-type]
        assert len(result) == 1

    def test_sw_username(self):
        result = _apply_filter(self._users(), 'userName sw "al"')  # type: ignore[arg-type]
        assert len(result) == 1

    def test_ew_displayname(self):
        result = _apply_filter(self._users(), 'displayName ew "white"')  # type: ignore[arg-type]
        assert len(result) == 1

    def test_pr_externalid(self):
        result = _apply_filter(self._users(), "externalId pr")  # type: ignore[arg-type]
        assert len(result) == 1
        assert result[0].user_name == "carol"  # type: ignore[union-attr]

    def test_empty_filter_returns_all(self):
        assert len(_apply_filter(self._users(), "")) == 3  # type: ignore[arg-type]

    def test_invalid_filter_raises(self):
        with pytest.raises(ScimError) as exc_info:
            _apply_filter(self._users(), "not valid filter !!!")  # type: ignore[arg-type]
        assert exc_info.value.status == 400

    def test_group_filter_displayname(self):
        groups = [
            ScimGroup(id="g1", display_name="AegisAdmins"),
            ScimGroup(id="g2", display_name="AegisAuditors"),
        ]
        result = _apply_filter(groups, 'displayName co "Auditors"')  # type: ignore[arg-type]
        assert len(result) == 1
        assert result[0].display_name == "AegisAuditors"  # type: ignore[union-attr]


# ── ScimStore: User CRUD ──────────────────────────────────────────────────────


class TestScimStoreUserCRUD:
    def test_create_and_get(self):
        s = ScimStore()
        u = s.create_user("alice")
        assert u.user_name == "alice"
        assert u.active is True
        assert s.get_user(u.id).id == u.id

    def test_create_sets_meta(self):
        s = ScimStore()
        u = s.create_user("alice")
        assert u.meta is not None
        assert u.meta.resource_type == "User"
        assert u.meta.version.startswith('W/"')

    def test_create_duplicate_username_raises(self):
        s = ScimStore()
        s.create_user("alice")
        with pytest.raises(ScimError) as exc_info:
            s.create_user("Alice")  # case-insensitive
        assert exc_info.value.status == 409
        assert exc_info.value.scim_type == "uniqueness"

    def test_get_unknown_raises(self):
        s = ScimStore()
        with pytest.raises(ScimError) as exc_info:
            s.get_user("nonexistent")
        assert exc_info.value.status == 404

    def test_get_by_name(self):
        s = ScimStore()
        u = s.create_user("bob")
        assert s.get_user_by_name("bob").id == u.id

    def test_get_by_name_case_insensitive(self):
        s = ScimStore()
        u = s.create_user("Bob")
        assert s.get_user_by_name("bob").id == u.id

    def test_get_by_name_missing_raises(self):
        s = ScimStore()
        with pytest.raises(ScimError) as exc_info:
            s.get_user_by_name("ghost")
        assert exc_info.value.status == 404

    def test_replace_user(self):
        s = ScimStore()
        u = s.create_user("alice", display_name="Alice")
        updated = s.replace_user(
            u.id, user_name="alice", display_name="Alice Updated", active=False
        )
        assert updated.active is False
        assert updated.display_name == "Alice Updated"

    def test_replace_preserves_created_time(self):
        s = ScimStore()
        u = s.create_user("alice")
        original_created = u.meta.created
        updated = s.replace_user(u.id, user_name="alice")
        assert updated.meta.created == original_created

    def test_replace_username_conflict_raises(self):
        s = ScimStore()
        u1 = s.create_user("alice")
        s.create_user("bob")
        with pytest.raises(ScimError) as exc_info:
            s.replace_user(u1.id, user_name="bob")
        assert exc_info.value.status == 409

    def test_replace_preserves_group_membership(self):
        s = ScimStore()
        u = s.create_user("alice")
        g = s.create_group("AegisAdmins")
        s.add_member(g.id, u.id)
        updated = s.replace_user(u.id, user_name="alice-renamed")
        assert g.id in updated.group_ids

    def test_delete_user_sets_inactive(self):
        s = ScimStore()
        u = s.create_user("alice")
        s.delete_user(u.id)
        assert not s.get_user(u.id).active

    def test_delete_strips_group_membership(self):
        s = ScimStore()
        u = s.create_user("alice")
        g = s.create_group("AegisAdmins")
        s.add_member(g.id, u.id)
        s.delete_user(u.id)
        # User has no groups
        assert not s.get_user(u.id).group_ids
        # Group no longer lists user
        assert u.id not in s.get_group(g.id).member_ids

    def test_delete_unknown_raises(self):
        s = ScimStore()
        with pytest.raises(ScimError):
            s.delete_user("ghost")

    def test_create_with_emails(self):
        s = ScimStore()
        emails = [ScimEmail(value="alice@example.com", primary=True)]
        u = s.create_user("alice", emails=emails)
        assert u.emails[0].value == "alice@example.com"


# ── ScimStore: User PATCH ─────────────────────────────────────────────────────


class TestScimStoreUserPatch:
    def test_patch_active_false(self):
        s = ScimStore()
        u = s.create_user("alice")
        updated = s.patch_user(u.id, [ScimPatchOp(op="replace", path="active", value=False)])
        assert updated.active is False

    def test_patch_active_string(self):
        s = ScimStore()
        u = s.create_user("alice")
        updated = s.patch_user(u.id, [ScimPatchOp(op="replace", path="active", value="false")])
        assert updated.active is False

    def test_patch_display_name(self):
        s = ScimStore()
        u = s.create_user("alice")
        updated = s.patch_user(
            u.id, [ScimPatchOp(op="replace", path="displayName", value="Alice A.")]
        )
        assert updated.display_name == "Alice A."

    def test_patch_external_id(self):
        s = ScimStore()
        u = s.create_user("alice")
        updated = s.patch_user(u.id, [ScimPatchOp(op="replace", path="externalId", value="ext-42")])
        assert updated.external_id == "ext-42"

    def test_patch_remove_external_id(self):
        s = ScimStore()
        u = s.create_user("alice", external_id="old")
        updated = s.patch_user(u.id, [ScimPatchOp(op="remove", path="externalId")])
        assert updated.external_id == ""

    def test_patch_no_path_dict(self):
        s = ScimStore()
        u = s.create_user("alice")
        updated = s.patch_user(
            u.id,
            [ScimPatchOp(op="replace", value={"displayName": "New", "externalId": "ext-1"})],
        )
        assert updated.display_name == "New"
        assert updated.external_id == "ext-1"

    def test_patch_invalid_op_raises(self):
        s = ScimStore()
        u = s.create_user("alice")
        with pytest.raises(ScimError):
            s.patch_user(u.id, [ScimPatchOp(op="bogus", path="active", value=True)])

    def test_patch_immutable_attr_raises(self):
        s = ScimStore()
        u = s.create_user("alice")
        with pytest.raises(ScimError):
            s.patch_user(u.id, [ScimPatchOp(op="replace", path="id", value="hacked")])

    def test_patch_add_email(self):
        s = ScimStore()
        u = s.create_user("alice")
        updated = s.patch_user(
            u.id,
            [ScimPatchOp(op="add", path="emails", value=[{"value": "a@b.com", "type": "work"}])],
        )
        assert updated.emails[0].value == "a@b.com"

    def test_patch_remove_emails(self):
        s = ScimStore()
        emails = [ScimEmail(value="a@b.com")]
        u = s.create_user("alice", emails=emails)
        updated = s.patch_user(u.id, [ScimPatchOp(op="remove", path="emails")])
        assert updated.emails == []

    def test_patch_no_path_non_dict_raises(self):
        s = ScimStore()
        u = s.create_user("alice")
        with pytest.raises(ScimError):
            s.patch_user(u.id, [ScimPatchOp(op="replace", value="not-a-dict")])

    def test_patch_remove_without_path_raises(self):
        s = ScimStore()
        u = s.create_user("alice")
        with pytest.raises(ScimError):
            s.patch_user(u.id, [ScimPatchOp(op="remove")])


# ── ScimStore: List/Filter ────────────────────────────────────────────────────


class TestScimStoreList:
    def test_list_users_empty(self):
        s = ScimStore()
        resp = s.list_users()
        assert resp.total_results == 0
        assert resp.resources == []

    def test_list_users_all(self):
        s = ScimStore()
        s.create_user("alice")
        s.create_user("bob")
        resp = s.list_users()
        assert resp.total_results == 2

    def test_list_users_filter(self):
        s = ScimStore()
        s.create_user("alice")
        s.create_user("bob")
        resp = s.list_users(filter_str='userName eq "alice"')
        assert resp.total_results == 1

    def test_list_users_pagination(self):
        s = ScimStore()
        for i in range(5):
            s.create_user(f"user{i}")
        resp = s.list_users(start_index=2, count=2)
        assert len(resp.resources) == 2
        assert resp.start_index == 2

    def test_list_groups_filter(self):
        s = ScimStore()
        s.create_group("AegisAdmins")
        s.create_group("AegisAuditors")
        resp = s.list_groups(filter_str='displayName eq "aegisadmins"')
        assert resp.total_results == 1


# ── ScimStore: Group CRUD ─────────────────────────────────────────────────────


class TestScimStoreGroupCRUD:
    def test_create_and_get(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        assert g.display_name == "AegisAdmins"
        assert s.get_group(g.id).id == g.id

    def test_create_duplicate_display_name_raises(self):
        s = ScimStore()
        s.create_group("AegisAdmins")
        with pytest.raises(ScimError) as exc_info:
            s.create_group("AegisAdmins")
        assert exc_info.value.status == 409

    def test_create_with_roles(self):
        s = ScimStore()
        g = s.create_group("AegisAuditors", roles=frozenset({"auditor"}))
        assert "auditor" in g.roles

    def test_get_unknown_raises(self):
        s = ScimStore()
        with pytest.raises(ScimError) as exc_info:
            s.get_group("ghost")
        assert exc_info.value.status == 404

    def test_replace_group(self):
        s = ScimStore()
        g = s.create_group("OldName")
        updated = s.replace_group(g.id, display_name="NewName", roles=frozenset({"admin"}))
        assert updated.display_name == "NewName"
        assert "admin" in updated.roles

    def test_replace_group_preserves_members(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        u = s.create_user("alice")
        s.add_member(g.id, u.id)
        updated = s.replace_group(g.id, display_name="AegisAdmins")
        assert u.id in updated.member_ids

    def test_replace_displayname_conflict_raises(self):
        s = ScimStore()
        g1 = s.create_group("Group1")
        s.create_group("Group2")
        with pytest.raises(ScimError) as exc_info:
            s.replace_group(g1.id, display_name="Group2")
        assert exc_info.value.status == 409

    def test_delete_group(self):
        s = ScimStore()
        g = s.create_group("TempGroup")
        s.delete_group(g.id)
        with pytest.raises(ScimError):
            s.get_group(g.id)

    def test_delete_group_strips_from_members(self):
        s = ScimStore()
        g = s.create_group("TempGroup")
        u = s.create_user("alice")
        s.add_member(g.id, u.id)
        s.delete_group(g.id)
        assert g.id not in s.get_user(u.id).group_ids

    def test_delete_unknown_raises(self):
        s = ScimStore()
        with pytest.raises(ScimError):
            s.delete_group("ghost")


# ── ScimStore: Group PATCH ────────────────────────────────────────────────────


class TestScimStoreGroupPatch:
    def test_patch_add_member(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        u = s.create_user("alice")
        s.patch_group(g.id, [ScimPatchOp(op="add", path="members", value=[{"value": u.id}])])
        assert u.id in s.get_group(g.id).member_ids
        assert g.id in s.get_user(u.id).group_ids

    def test_patch_remove_member(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        u = s.create_user("alice")
        s.add_member(g.id, u.id)
        s.patch_group(g.id, [ScimPatchOp(op="remove", path="members", value=[{"value": u.id}])])
        assert u.id not in s.get_group(g.id).member_ids
        assert g.id not in s.get_user(u.id).group_ids

    def test_patch_replace_members(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        u1 = s.create_user("alice")
        u2 = s.create_user("bob")
        s.add_member(g.id, u1.id)
        # Replace: remove alice, add bob
        s.patch_group(
            g.id,
            [ScimPatchOp(op="replace", path="members", value=[{"value": u2.id}])],
        )
        assert u1.id not in s.get_group(g.id).member_ids
        assert u2.id in s.get_group(g.id).member_ids

    def test_patch_rename_group(self):
        s = ScimStore()
        g = s.create_group("OldName")
        s.patch_group(g.id, [ScimPatchOp(op="replace", path="displayName", value="NewName")])
        assert s.get_group(g.id).display_name == "NewName"

    def test_patch_remove_displayname_raises(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        with pytest.raises(ScimError):
            s.patch_group(g.id, [ScimPatchOp(op="remove", path="displayName")])

    def test_patch_no_path_dict(self):
        s = ScimStore()
        g = s.create_group("OldName")
        s.patch_group(
            g.id,
            [ScimPatchOp(op="replace", value={"displayName": "NewName", "externalId": "ext-9"})],
        )
        updated = s.get_group(g.id)
        assert updated.display_name == "NewName"
        assert updated.external_id == "ext-9"

    def test_patch_no_path_non_dict_raises(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        with pytest.raises(ScimError):
            s.patch_group(g.id, [ScimPatchOp(op="replace", value="bad")])

    def test_patch_unsupported_path_raises(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        with pytest.raises(ScimError):
            s.patch_group(g.id, [ScimPatchOp(op="replace", path="unknownAttr", value="x")])

    def test_patch_remove_all_members(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        u = s.create_user("alice")
        s.add_member(g.id, u.id)
        s.patch_group(g.id, [ScimPatchOp(op="remove", path="members", value=None)])
        assert not s.get_group(g.id).member_ids


# ── ScimStore: membership helpers ────────────────────────────────────────────


class TestMembershipHelpers:
    def test_add_member_bidirectional(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        u = s.create_user("alice")
        s.add_member(g.id, u.id)
        assert u.id in s.get_group(g.id).member_ids
        assert g.id in s.get_user(u.id).group_ids

    def test_remove_member_bidirectional(self):
        s = ScimStore()
        g = s.create_group("AegisAdmins")
        u = s.create_user("alice")
        s.add_member(g.id, u.id)
        s.remove_member(g.id, u.id)
        assert u.id not in s.get_group(g.id).member_ids
        assert g.id not in s.get_user(u.id).group_ids

    def test_user_groups_returns_groups(self):
        s = ScimStore()
        g1 = s.create_group("G1")
        g2 = s.create_group("G2")
        u = s.create_user("alice")
        s.add_member(g1.id, u.id)
        s.add_member(g2.id, u.id)
        names = {g.display_name for g in s.user_groups(u.id)}
        assert names == {"G1", "G2"}

    def test_user_groups_empty_for_no_membership(self):
        s = ScimStore()
        u = s.create_user("alice")
        assert s.user_groups(u.id) == []


# ── ScimStore: RBAC bridge ────────────────────────────────────────────────────


class TestToGroupRoles:
    def test_groups_with_no_roles_excluded(self):
        s = ScimStore()
        s.create_group("NoRoles")
        assert s.to_group_roles() == {}

    def test_groups_with_roles_included(self):
        s = ScimStore()
        s.create_group("AegisAuditors", roles=frozenset({"auditor"}))
        roles = s.to_group_roles()
        assert roles == {"AegisAuditors": frozenset({"auditor"})}

    def test_role_registry_integration(self):
        from aegis.auth.rbac import (
            AccessContext,
            AccessRequest,
            RoleRegistry,
            ZeroTrustPolicyEngine,
        )
        from aegis.auth.scopes import SCOPE_AUDIT_READ

        s = ScimStore()
        g = s.create_group("AegisAuditors", roles=frozenset({"auditor"}))
        u = s.create_user("alice")
        s.add_member(g.id, u.id)

        registry = RoleRegistry(group_roles=s.to_group_roles())
        engine = ZeroTrustPolicyEngine(registry)

        ctx = AccessContext(subject_id="alice", ldap_groups=frozenset({"AegisAuditors"}))
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ))
        assert decision.allowed

    def test_deprovisioned_user_loses_rbac(self):
        from aegis.auth.rbac import (
            AccessContext,
            AccessRequest,
            RoleRegistry,
            ZeroTrustPolicyEngine,
        )
        from aegis.auth.scopes import SCOPE_AUDIT_READ

        s = ScimStore()
        g = s.create_group("AegisAuditors", roles=frozenset({"auditor"}))
        u = s.create_user("alice")
        s.add_member(g.id, u.id)
        s.delete_user(u.id)

        # After deprovisioning the user has no group_ids; rebuild registry from groups
        # (the group still exists but alice is no longer a member)
        assert u.id not in s.get_group(g.id).member_ids

        registry = RoleRegistry(group_roles=s.to_group_roles())
        engine = ZeroTrustPolicyEngine(registry)
        # Without alice being in the group, no ldap_groups → no role → denied
        ctx = AccessContext(subject_id="alice", ldap_groups=frozenset())
        decision = engine.evaluate(AccessRequest(ctx, SCOPE_AUDIT_READ))
        assert not decision.allowed


# ── Integration: full provisioning lifecycle ──────────────────────────────────


class TestProvisioningLifecycle:
    def test_full_user_lifecycle(self):
        """CREATE → READ → PATCH → REPLACE → DELETE."""
        s = ScimStore()

        # CREATE
        u = s.create_user("john.doe", display_name="John Doe", external_id="hr-1001")
        assert u.active is True

        # READ
        fetched = s.get_user(u.id)
        assert fetched.display_name == "John Doe"

        # PATCH: deactivate
        patched = s.patch_user(u.id, [ScimPatchOp(op="replace", path="active", value=False)])
        assert not patched.active

        # REPLACE: reactivate with new display name
        replaced = s.replace_user(
            u.id, user_name="john.doe", display_name="John A. Doe", active=True
        )
        assert replaced.active is True
        assert replaced.display_name == "John A. Doe"

        # DELETE (soft)
        s.delete_user(u.id)
        assert not s.get_user(u.id).active

    def test_full_group_lifecycle(self):
        """CREATE group → ADD members → REMOVE member → DELETE group."""
        s = ScimStore()

        g = s.create_group("SecurityTeam", roles=frozenset({"auditor"}))
        u1 = s.create_user("alice")
        u2 = s.create_user("bob")

        s.add_member(g.id, u1.id)
        s.add_member(g.id, u2.id)
        assert s.get_group(g.id).member_ids == {u1.id, u2.id}

        s.remove_member(g.id, u1.id)
        assert u1.id not in s.get_group(g.id).member_ids

        s.delete_group(g.id)
        # bob's group_ids should be cleaned
        assert g.id not in s.get_user(u2.id).group_ids

    def test_idp_push_scenario(self):
        """Simulate IdP pushing a PATCH with member list to sync access."""
        s = ScimStore()
        g = s.create_group("IL6Users", roles=frozenset({"proxy_user"}))
        alice = s.create_user("alice")
        bob = s.create_user("bob")

        # IdP initial push: add both users
        s.patch_group(
            g.id,
            [ScimPatchOp(op="add", path="members", value=[{"value": alice.id}, {"value": bob.id}])],
        )
        assert s.get_group(g.id).member_ids == {alice.id, bob.id}

        # IdP revocation: remove alice (access terminated)
        s.patch_group(
            g.id,
            [ScimPatchOp(op="remove", path="members", value=[{"value": alice.id}])],
        )
        assert alice.id not in s.get_group(g.id).member_ids
        assert g.id not in s.get_user(alice.id).group_ids
        # bob stays
        assert bob.id in s.get_group(g.id).member_ids

    def test_uniqueness_enforced_across_operations(self):
        s = ScimStore()
        s.create_user("alice")
        # Even after patching alice's userName, the old slot should be freed
        u = s.create_user("alicia")
        s.patch_user(u.id, [ScimPatchOp(op="replace", path="userName", value="alicia-new")])
        # Now "alicia" slot is free
        s.create_user("alicia")  # should not raise
