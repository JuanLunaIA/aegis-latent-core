# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.auth.scim — SCIM 2.0 provisioning/deprovisioning lifecycle.

Implements the SCIM 2.0 core protocol (RFC 7643/RFC 7644) for automated
user and group lifecycle management driven by an external Identity Provider.

Resources
---------
* ``User``  — schema ``urn:ietf:params:scim:schemas:core:2.0:User``
* ``Group`` — schema ``urn:ietf:params:scim:schemas:core:2.0:Group``

Operations
----------
Both resource types support the full CRUD + PATCH lifecycle:

* **CREATE** (POST /Users, POST /Groups) — 201 with Location header
* **READ**   (GET /Users/{id}, GET /Groups/{id}) — 200 with ETag
* **LIST**   (GET /Users, GET /Groups) with ``filter``, ``startIndex``, ``count``
* **REPLACE** (PUT /Users/{id}) — full resource replace, group links preserved
* **PATCH**  (PATCH /Users/{id}, PATCH /Groups/{id}) — ``add``, ``remove``,
              ``replace`` operations per RFC 7644 §3.5.2
* **DELETE** (DELETE /Users/{id}, DELETE /Groups/{id}) — User: sets
              ``active=False`` and strips all group memberships (soft delete);
              Group: hard-deletes the group and strips it from members

Filtering (RFC 7644 §3.4.2.2)
-------------------------------
Simple single-attribute expressions are supported::

    userName eq "alice"
    active eq false
    displayName co "Aegis"
    externalId pr

Operators: ``eq``, ``ne``, ``co`` (contains), ``sw`` (starts-with),
``ew`` (ends-with), ``pr`` (present).  Compound expressions and
value-path filters are not implemented (not required for IdP provisioning).

Integration with :mod:`aegis.auth.rbac`
----------------------------------------
SCIM Groups carry an optional *roles* set (a :class:`ScimStore` extension
beyond the RFC 7643 schema).  Call :meth:`ScimStore.to_group_roles` to
derive the ``group_roles`` mapping for :class:`~aegis.auth.rbac.RoleRegistry`::

    store = ScimStore()
    group = store.create_group("AegisAuditors", roles=frozenset({"auditor"}))
    user  = store.create_user("alice")
    store.add_member(group.id, user.id)

    from aegis.auth.rbac import RoleRegistry
    registry = RoleRegistry(group_roles=store.to_group_roles())

The :class:`ScimStore` is transport-agnostic; the HTTP layer (FastAPI) wires
it to ``/scim/v2/Users`` and ``/scim/v2/Groups`` endpoints.
"""

from __future__ import annotations

import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# ── SCIM schema URNs ─────────────────────────────────────────────────────────

SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"


# ── Error type ────────────────────────────────────────────────────────────────


class ScimError(Exception):
    """SCIM-compliant error (RFC 7644 §3.12).

    Parameters
    ----------
    status:
        HTTP status code (400, 404, 409, …).
    detail:
        Human-readable error detail.
    scim_type:
        Optional SCIM error type keyword (e.g. ``"uniqueness"``,
        ``"invalidValue"``, ``"mutability"``).
    """

    def __init__(self, status: int, detail: str, scim_type: str = "") -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "schemas": [SCHEMA_ERROR],
            "status": str(self.status),
            "detail": self.detail,
        }
        if self.scim_type:
            d["scimType"] = self.scim_type
        return d


# ── Data models ───────────────────────────────────────────────────────────────


@dataclass
class ScimMeta:
    """SCIM resource metadata (RFC 7643 §3.1)."""

    resource_type: str
    created: datetime
    last_modified: datetime
    version: str = ""


@dataclass
class ScimEmail:
    """SCIM email sub-attribute (RFC 7643 §4.1.2)."""

    value: str
    type: str = "work"
    primary: bool = False


@dataclass
class ScimUser:
    """SCIM 2.0 User resource (RFC 7643 §4.1)."""

    id: str
    user_name: str
    display_name: str = ""
    active: bool = True
    external_id: str = ""
    emails: list[ScimEmail] = field(default_factory=list)
    group_ids: frozenset[str] = field(default_factory=frozenset)
    meta: ScimMeta | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "schemas": [SCHEMA_USER],
            "id": self.id,
            "userName": self.user_name,
            "displayName": self.display_name,
            "active": self.active,
            "emails": [
                {"value": e.value, "type": e.type, "primary": e.primary} for e in self.emails
            ],
            "groups": [{"value": gid} for gid in sorted(self.group_ids)],
        }
        if self.external_id:
            d["externalId"] = self.external_id
        if self.meta:
            d["meta"] = {
                "resourceType": self.meta.resource_type,
                "created": self.meta.created.isoformat(),
                "lastModified": self.meta.last_modified.isoformat(),
                "version": self.meta.version,
            }
        return d


@dataclass
class ScimGroup:
    """SCIM 2.0 Group resource (RFC 7643 §4.2).

    The ``roles`` field is an aegis extension: it maps this SCIM Group to
    a set of RBAC role names so that :meth:`ScimStore.to_group_roles` can
    feed group memberships into :class:`~aegis.auth.rbac.RoleRegistry`.
    """

    id: str
    display_name: str
    external_id: str = ""
    member_ids: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    meta: ScimMeta | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "schemas": [SCHEMA_GROUP],
            "id": self.id,
            "displayName": self.display_name,
            "members": [{"value": mid} for mid in sorted(self.member_ids)],
        }
        if self.external_id:
            d["externalId"] = self.external_id
        if self.meta:
            d["meta"] = {
                "resourceType": self.meta.resource_type,
                "created": self.meta.created.isoformat(),
                "lastModified": self.meta.last_modified.isoformat(),
                "version": self.meta.version,
            }
        return d


@dataclass
class ScimPatchOp:
    """A single PATCH operation (RFC 7644 §3.5.2).

    Parameters
    ----------
    op:
        ``"add"``, ``"remove"``, or ``"replace"`` (case-insensitive).
    path:
        Attribute path (e.g. ``"active"``, ``"members"``).  Empty string
        means the value dict covers all attributes.
    value:
        New value; omitted for ``remove`` without a path filter.
    """

    op: str
    path: str = ""
    value: Any = None


@dataclass
class ScimListResponse:
    """SCIM 2.0 ListResponse envelope (RFC 7644 §3.4.2)."""

    total_results: int
    resources: list[ScimUser | ScimGroup]
    start_index: int = 1
    items_per_page: int = 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemas": [SCHEMA_LIST_RESPONSE],
            "totalResults": self.total_results,
            "startIndex": self.start_index,
            "itemsPerPage": min(self.items_per_page, max(len(self.resources), 1)),
            "Resources": [r.to_dict() for r in self.resources],
        }


# ── Filter engine (RFC 7644 §3.4.2.2) ────────────────────────────────────────

_FILTER_RE = re.compile(
    r"^(?P<attr>\w+)\s+(?P<op>eq|ne|co|sw|ew|pr)(?:\s+(?P<val>\"[^\"]*\"|\S+))?$",
    re.IGNORECASE,
)


def _resolve_attr(resource: ScimUser | ScimGroup, attr: str) -> str:
    attr_l = attr.lower()
    if isinstance(resource, ScimUser):
        mapping: dict[str, str] = {
            "id": resource.id,
            "username": resource.user_name,
            "displayname": resource.display_name,
            "active": str(resource.active).lower(),
            "externalid": resource.external_id,
        }
    else:
        mapping = {
            "id": resource.id,
            "displayname": resource.display_name,
            "externalid": resource.external_id,
        }
    return mapping.get(attr_l, "")


def _apply_filter(
    resources: list[ScimUser | ScimGroup],
    filter_str: str,
) -> list[ScimUser | ScimGroup]:
    """Return resources matching the simple SCIM filter expression."""
    stripped = filter_str.strip()
    if not stripped:
        return resources

    m = _FILTER_RE.match(stripped)
    if not m:
        raise ScimError(400, f"unsupported filter expression: {filter_str!r}", "invalidFilter")

    attr = m.group("attr")
    op = m.group("op").lower()
    val_raw = m.group("val") or ""
    val = val_raw.strip('"').lower()

    def matches(r: ScimUser | ScimGroup) -> bool:
        rv = _resolve_attr(r, attr).lower()
        if op == "pr":
            return bool(rv)
        if op == "eq":
            return rv == val
        if op == "ne":
            return rv != val
        if op == "co":
            return val in rv
        if op == "sw":
            return rv.startswith(val)
        if op == "ew":
            return rv.endswith(val)
        return True  # unreachable given regex

    return [r for r in resources if matches(r)]


# ── ScimStore ─────────────────────────────────────────────────────────────────


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _new_id() -> str:
    return str(uuid.uuid4())


def _etag(resource_id: str, ts: datetime) -> str:
    return f'W/"{resource_id[:8]}-{int(ts.timestamp())}"'


class ScimStore:
    """Thread-safe in-memory SCIM 2.0 resource store.

    Maintains bidirectional User↔Group membership links.  All mutating
    methods acquire an internal lock so instances may be shared across
    request threads.

    For persistent storage, subclass or wrap this class and override the
    mutation methods to write through to a database.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._users: dict[str, ScimUser] = {}
        self._groups: dict[str, ScimGroup] = {}
        # Secondary indexes (case-insensitive)
        self._user_by_name: dict[str, str] = {}  # lower(userName) → id
        self._group_by_name: dict[str, str] = {}  # lower(displayName) → id

    # ── User: CREATE ─────────────────────────────────────────────────────────

    def create_user(
        self,
        user_name: str,
        *,
        display_name: str = "",
        external_id: str = "",
        emails: list[ScimEmail] | None = None,
        active: bool = True,
    ) -> ScimUser:
        """Provision a new User.

        Raises :exc:`ScimError` (409) when *user_name* is already registered.
        """
        with self._lock:
            key = user_name.lower()
            if key in self._user_by_name:
                raise ScimError(409, f"userName {user_name!r} already exists", "uniqueness")
            now = _now_utc()
            uid = _new_id()
            user = ScimUser(
                id=uid,
                user_name=user_name,
                display_name=display_name or user_name,
                active=active,
                external_id=external_id,
                emails=list(emails or []),
                group_ids=frozenset(),
                meta=ScimMeta(
                    resource_type="User",
                    created=now,
                    last_modified=now,
                    version=_etag(uid, now),
                ),
            )
            self._users[uid] = user
            self._user_by_name[key] = uid
            return user

    # ── User: READ ───────────────────────────────────────────────────────────

    def get_user(self, user_id: str) -> ScimUser:
        """Retrieve a User by *user_id*. Raises :exc:`ScimError` (404)."""
        with self._lock:
            return self._get_user_locked(user_id)

    def _get_user_locked(self, user_id: str) -> ScimUser:
        try:
            return self._users[user_id]
        except KeyError:
            raise ScimError(404, f"User {user_id!r} not found") from None

    def get_user_by_name(self, user_name: str) -> ScimUser:
        """Retrieve a User by *user_name*. Raises :exc:`ScimError` (404)."""
        with self._lock:
            uid = self._user_by_name.get(user_name.lower())
            if uid is None:
                raise ScimError(404, f"User with userName {user_name!r} not found")
            return self._users[uid]

    # ── User: REPLACE (PUT) ──────────────────────────────────────────────────

    def replace_user(
        self,
        user_id: str,
        *,
        user_name: str,
        display_name: str = "",
        external_id: str = "",
        emails: list[ScimEmail] | None = None,
        active: bool = True,
    ) -> ScimUser:
        """Full replacement (PUT).  Group memberships are preserved.

        Raises :exc:`ScimError` (404) when the user does not exist, or
        (409) when renaming to a *user_name* already taken by another user.
        """
        with self._lock:
            existing = self._get_user_locked(user_id)
            new_key = user_name.lower()
            old_key = existing.user_name.lower()
            if new_key != old_key and new_key in self._user_by_name:
                raise ScimError(409, f"userName {user_name!r} already exists", "uniqueness")
            now = _now_utc()
            updated = ScimUser(
                id=user_id,
                user_name=user_name,
                display_name=display_name or user_name,
                active=active,
                external_id=external_id,
                emails=list(emails or []),
                group_ids=existing.group_ids,
                meta=ScimMeta(
                    resource_type="User",
                    created=existing.meta.created if existing.meta else now,
                    last_modified=now,
                    version=_etag(user_id, now),
                ),
            )
            self._users[user_id] = updated
            if new_key != old_key:
                del self._user_by_name[old_key]
                self._user_by_name[new_key] = user_id
            return updated

    # ── User: PATCH ──────────────────────────────────────────────────────────

    def patch_user(self, user_id: str, ops: list[ScimPatchOp]) -> ScimUser:
        """Apply PATCH operations to a User (RFC 7644 §3.5.2).

        Supported paths: ``active``, ``displayName``, ``externalId``,
        ``userName``, ``emails``.
        """
        with self._lock:
            user = self._get_user_locked(user_id)
            state: dict[str, Any] = {
                "user_name": user.user_name,
                "display_name": user.display_name,
                "active": user.active,
                "external_id": user.external_id,
                "emails": list(user.emails),
            }
            for op in ops:
                _apply_user_op(state, op)
            now = _now_utc()
            new_key = state["user_name"].lower()
            old_key = user.user_name.lower()
            if new_key != old_key and new_key in self._user_by_name:
                raise ScimError(
                    409, f"userName {state['user_name']!r} already exists", "uniqueness"
                )
            updated = ScimUser(
                id=user_id,
                user_name=state["user_name"],
                display_name=state["display_name"],
                active=state["active"],
                external_id=state["external_id"],
                emails=state["emails"],
                group_ids=user.group_ids,
                meta=ScimMeta(
                    resource_type="User",
                    created=user.meta.created if user.meta else now,
                    last_modified=now,
                    version=_etag(user_id, now),
                ),
            )
            self._users[user_id] = updated
            if new_key != old_key:
                del self._user_by_name[old_key]
                self._user_by_name[new_key] = user_id
            return updated

    # ── User: DELETE (soft) ──────────────────────────────────────────────────

    def delete_user(self, user_id: str) -> None:
        """Deprovision a User: set ``active=False`` and strip all group links.

        The record is retained for audit purposes (soft delete).
        """
        with self._lock:
            user = self._get_user_locked(user_id)
            for gid in user.group_ids:
                if gid in self._groups:
                    g = self._groups[gid]
                    self._groups[gid] = _replace_group(g, member_ids=g.member_ids - {user_id})
            now = _now_utc()
            self._users[user_id] = ScimUser(
                id=user.id,
                user_name=user.user_name,
                display_name=user.display_name,
                active=False,
                external_id=user.external_id,
                emails=user.emails,
                group_ids=frozenset(),
                meta=ScimMeta(
                    resource_type="User",
                    created=user.meta.created if user.meta else now,
                    last_modified=now,
                    version=f'W/"{user_id[:8]}-deprovisioned"',
                ),
            )

    # ── User: LIST ───────────────────────────────────────────────────────────

    def list_users(
        self,
        filter_str: str = "",
        start_index: int = 1,
        count: int = 100,
    ) -> ScimListResponse:
        """List Users with optional filtering and pagination."""
        with self._lock:
            resources: list[ScimUser | ScimGroup] = list(self._users.values())
        filtered = _apply_filter(resources, filter_str)
        total = len(filtered)
        page = filtered[start_index - 1 : start_index - 1 + count]
        return ScimListResponse(
            total_results=total,
            resources=page,
            start_index=start_index,
            items_per_page=count,
        )

    # ── Group: CREATE ────────────────────────────────────────────────────────

    def create_group(
        self,
        display_name: str,
        *,
        external_id: str = "",
        roles: frozenset[str] = frozenset(),
    ) -> ScimGroup:
        """Provision a new Group.

        Raises :exc:`ScimError` (409) when *display_name* is already taken.
        """
        with self._lock:
            key = display_name.lower()
            if key in self._group_by_name:
                raise ScimError(409, f"displayName {display_name!r} already exists", "uniqueness")
            now = _now_utc()
            gid = _new_id()
            group = ScimGroup(
                id=gid,
                display_name=display_name,
                external_id=external_id,
                member_ids=frozenset(),
                roles=roles,
                meta=ScimMeta(
                    resource_type="Group",
                    created=now,
                    last_modified=now,
                    version=_etag(gid, now),
                ),
            )
            self._groups[gid] = group
            self._group_by_name[key] = gid
            return group

    # ── Group: READ ──────────────────────────────────────────────────────────

    def get_group(self, group_id: str) -> ScimGroup:
        """Retrieve a Group by *group_id*. Raises :exc:`ScimError` (404)."""
        with self._lock:
            return self._get_group_locked(group_id)

    def _get_group_locked(self, group_id: str) -> ScimGroup:
        try:
            return self._groups[group_id]
        except KeyError:
            raise ScimError(404, f"Group {group_id!r} not found") from None

    # ── Group: REPLACE (PUT) ─────────────────────────────────────────────────

    def replace_group(
        self,
        group_id: str,
        *,
        display_name: str,
        external_id: str = "",
        roles: frozenset[str] = frozenset(),
    ) -> ScimGroup:
        """Full replacement (PUT).  Member set is preserved.

        Raises :exc:`ScimError` (404) or (409) on conflict.
        """
        with self._lock:
            existing = self._get_group_locked(group_id)
            new_key = display_name.lower()
            old_key = existing.display_name.lower()
            if new_key != old_key and new_key in self._group_by_name:
                raise ScimError(409, f"displayName {display_name!r} already exists", "uniqueness")
            now = _now_utc()
            updated = ScimGroup(
                id=group_id,
                display_name=display_name,
                external_id=external_id,
                member_ids=existing.member_ids,
                roles=roles,
                meta=ScimMeta(
                    resource_type="Group",
                    created=existing.meta.created if existing.meta else now,
                    last_modified=now,
                    version=_etag(group_id, now),
                ),
            )
            self._groups[group_id] = updated
            if new_key != old_key:
                del self._group_by_name[old_key]
                self._group_by_name[new_key] = group_id
            return updated

    # ── Group: PATCH ─────────────────────────────────────────────────────────

    def patch_group(self, group_id: str, ops: list[ScimPatchOp]) -> ScimGroup:
        """Apply PATCH operations to a Group (RFC 7644 §3.5.2).

        Supported paths: ``members``, ``displayName``, ``externalId``.
        Member add/remove operations keep User.group_ids in sync.
        """
        with self._lock:
            group = self._get_group_locked(group_id)
            member_ids = set(group.member_ids)
            new_display = group.display_name
            new_external_id = group.external_id

            for op in ops:
                op_name = op.op.lower()
                if op_name not in ("add", "remove", "replace"):
                    raise ScimError(400, f"unknown PATCH op {op.op!r}", "invalidValue")
                path = (op.path or "").lower()

                if path == "":
                    # No path: value must be a dict of Group attributes
                    if not isinstance(op.value, dict):
                        raise ScimError(
                            400, "Group PATCH without path requires an object value", "invalidValue"
                        )
                    for k, v in op.value.items():
                        k_lower = k.lower()
                        if k_lower == "displayname":
                            new_display = str(v)
                        elif k_lower == "externalid":
                            new_external_id = str(v)
                        elif k_lower == "members":
                            member_ids = _patch_member_set(
                                self._users, group_id, member_ids, op_name, v
                            )

                elif path in ("members", "members.value"):
                    member_ids = _patch_member_set(
                        self._users, group_id, member_ids, op_name, op.value
                    )

                elif path == "displayname":
                    if op_name == "remove":
                        raise ScimError(400, "displayName is required; cannot remove", "mutability")
                    new_display = str(op.value)

                elif path == "externalid":
                    if op_name == "remove":
                        new_external_id = ""
                    else:
                        new_external_id = str(op.value)

                else:
                    raise ScimError(
                        400,
                        f"path {op.path!r} not supported for Group PATCH",
                        "invalidValue",
                    )

            # Rename index if displayName changed
            old_key = group.display_name.lower()
            new_key = new_display.lower()
            if new_key != old_key and new_key in self._group_by_name:
                raise ScimError(409, f"displayName {new_display!r} already exists", "uniqueness")

            now = _now_utc()
            updated = ScimGroup(
                id=group_id,
                display_name=new_display,
                external_id=new_external_id,
                member_ids=frozenset(member_ids),
                roles=group.roles,
                meta=ScimMeta(
                    resource_type="Group",
                    created=group.meta.created if group.meta else now,
                    last_modified=now,
                    version=_etag(group_id, now),
                ),
            )
            self._groups[group_id] = updated
            if new_key != old_key:
                del self._group_by_name[old_key]
                self._group_by_name[new_key] = group_id
            return updated

    # ── Group: DELETE ────────────────────────────────────────────────────────

    def delete_group(self, group_id: str) -> None:
        """Delete a Group and strip it from all member Users."""
        with self._lock:
            group = self._get_group_locked(group_id)
            for uid in group.member_ids:
                if uid in self._users:
                    u = self._users[uid]
                    self._users[uid] = _replace_user(u, group_ids=u.group_ids - {group_id})
            del self._groups[group_id]
            del self._group_by_name[group.display_name.lower()]

    # ── Group: LIST ──────────────────────────────────────────────────────────

    def list_groups(
        self,
        filter_str: str = "",
        start_index: int = 1,
        count: int = 100,
    ) -> ScimListResponse:
        """List Groups with optional filtering and pagination."""
        with self._lock:
            resources: list[ScimUser | ScimGroup] = list(self._groups.values())
        filtered = _apply_filter(resources, filter_str)
        total = len(filtered)
        page = filtered[start_index - 1 : start_index - 1 + count]
        return ScimListResponse(
            total_results=total,
            resources=page,
            start_index=start_index,
            items_per_page=count,
        )

    # ── Membership helpers ───────────────────────────────────────────────────

    def add_member(self, group_id: str, user_id: str) -> None:
        """Add *user_id* to *group_id* (bidirectional link)."""
        with self._lock:
            group = self._get_group_locked(group_id)
            user = self._get_user_locked(user_id)
            now = _now_utc()
            self._groups[group_id] = _replace_group(
                group,
                member_ids=group.member_ids | {user_id},
                last_modified=now,
            )
            self._users[user_id] = _replace_user(user, group_ids=user.group_ids | {group_id})

    def remove_member(self, group_id: str, user_id: str) -> None:
        """Remove *user_id* from *group_id* (bidirectional unlink)."""
        with self._lock:
            group = self._get_group_locked(group_id)
            user = self._get_user_locked(user_id)
            now = _now_utc()
            self._groups[group_id] = _replace_group(
                group,
                member_ids=group.member_ids - {user_id},
                last_modified=now,
            )
            self._users[user_id] = _replace_user(user, group_ids=user.group_ids - {group_id})

    def user_groups(self, user_id: str) -> list[ScimGroup]:
        """Return all Groups the user belongs to."""
        with self._lock:
            user = self._get_user_locked(user_id)
            return [self._groups[gid] for gid in user.group_ids if gid in self._groups]

    # ── RBAC bridge ─────────────────────────────────────────────────────────

    def to_group_roles(self) -> dict[str, frozenset[str]]:
        """Derive a ``group_roles`` mapping for :class:`~aegis.auth.rbac.RoleRegistry`.

        Returns ``{displayName: frozenset(roles)}`` for every Group that has at
        least one role assignment.  Pass this directly to::

            RoleRegistry(group_roles=store.to_group_roles())
        """
        with self._lock:
            return {g.display_name: g.roles for g in self._groups.values() if g.roles}


# ── Internal helpers ──────────────────────────────────────────────────────────


def _replace_user(user: ScimUser, **overrides: Any) -> ScimUser:
    """Return a copy of *user* with *overrides* applied."""
    return ScimUser(
        id=user.id,
        user_name=overrides.get("user_name", user.user_name),
        display_name=overrides.get("display_name", user.display_name),
        active=overrides.get("active", user.active),
        external_id=overrides.get("external_id", user.external_id),
        emails=overrides.get("emails", user.emails),
        group_ids=overrides.get("group_ids", user.group_ids),
        meta=overrides.get("meta", user.meta),
    )


def _replace_group(
    group: ScimGroup,
    *,
    member_ids: frozenset[str] | None = None,
    last_modified: datetime | None = None,
    **overrides: Any,
) -> ScimGroup:
    """Return a copy of *group* with *overrides* applied."""
    meta = group.meta
    if last_modified is not None and meta is not None:
        meta = ScimMeta(
            resource_type=meta.resource_type,
            created=meta.created,
            last_modified=last_modified,
            version=_etag(group.id, last_modified),
        )
    return ScimGroup(
        id=group.id,
        display_name=overrides.get("display_name", group.display_name),
        external_id=overrides.get("external_id", group.external_id),
        member_ids=member_ids if member_ids is not None else group.member_ids,
        roles=overrides.get("roles", group.roles),
        meta=meta,
    )


def _patch_member_set(
    users: dict[str, ScimUser],
    group_id: str,
    member_ids: set[str],
    op_name: str,
    value: Any,
) -> set[str]:
    """Apply an add/remove/replace PATCH to *member_ids* and sync User.group_ids."""
    if value is None and op_name == "remove":
        extracted: list[str] = list(member_ids)
    else:
        raw: list[Any] = value if isinstance(value, list) else [value]
        extracted = [
            v["value"] if isinstance(v, dict) and "value" in v else str(v)
            for v in raw
            if v is not None
        ]

    if op_name == "add":
        add_uids = set(extracted) - member_ids
        rm_uids: set[str] = set()
    elif op_name == "remove":
        add_uids = set()
        rm_uids = set(extracted)
    else:  # replace
        add_uids = set(extracted) - member_ids
        rm_uids = member_ids - set(extracted)

    for uid in add_uids:
        if uid in users:
            u = users[uid]
            users[uid] = _replace_user(u, group_ids=u.group_ids | {group_id})
    for uid in rm_uids:
        if uid in users:
            u = users[uid]
            users[uid] = _replace_user(u, group_ids=u.group_ids - {group_id})

    return (member_ids | add_uids) - rm_uids


def _apply_user_op(state: dict[str, Any], op: ScimPatchOp) -> None:
    """Apply a single PatchOp to a mutable user-attribute *state* dict."""
    op_name = op.op.lower()
    if op_name not in ("add", "remove", "replace"):
        raise ScimError(400, f"unknown PATCH op {op.op!r}", "invalidValue")

    path = (op.path or "").lower()

    if op_name == "remove" and not path:
        raise ScimError(400, "PATCH remove requires a path", "noTarget")

    if not path:
        # value must be a dict covering multiple attributes
        if not isinstance(op.value, dict):
            raise ScimError(400, "PATCH without path requires an object value", "invalidValue")
        for k, v in op.value.items():
            _apply_user_op(state, ScimPatchOp(op=op_name, path=k, value=v))
        return

    if path == "active":
        if op_name == "remove":
            raise ScimError(400, "active is required; cannot remove", "mutability")
        if isinstance(op.value, bool):
            state["active"] = op.value
        elif isinstance(op.value, str):
            state["active"] = op.value.lower() not in ("false", "0", "no")
        else:
            raise ScimError(400, "active must be boolean", "invalidValue")

    elif path == "displayname":
        if op_name == "remove":
            raise ScimError(400, "displayName is required; cannot remove", "mutability")
        state["display_name"] = str(op.value)

    elif path == "username":
        if op_name == "remove":
            raise ScimError(400, "userName is required; cannot remove", "mutability")
        state["user_name"] = str(op.value)

    elif path == "externalid":
        if op_name == "remove":
            state["external_id"] = ""
        else:
            state["external_id"] = str(op.value)

    elif path == "emails":
        if op_name == "remove":
            state["emails"] = []
        elif op_name == "replace":
            raw = op.value if isinstance(op.value, list) else [op.value]
            state["emails"] = [
                ScimEmail(
                    value=e["value"],
                    type=e.get("type", "work"),
                    primary=e.get("primary", False),
                )
                if isinstance(e, dict)
                else e
                for e in raw
            ]
        elif op_name == "add":
            raw = op.value if isinstance(op.value, list) else [op.value]
            state["emails"].extend(
                ScimEmail(
                    value=e["value"],
                    type=e.get("type", "work"),
                    primary=e.get("primary", False),
                )
                if isinstance(e, dict)
                else e
                for e in raw
            )

    else:
        raise ScimError(400, f"path {op.path!r} is not mutable via PATCH", "mutability")
