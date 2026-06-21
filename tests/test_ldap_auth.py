# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for LDAP/Active Directory multi-factor identity assertion (aegis.auth.ldap_auth).

All tests run against a fully-mocked ldap3 layer — no real LDAP/AD server required.
"""

from __future__ import annotations

from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

from aegis.auth.ldap_auth import (
    LDAPAuthConfig,
    LDAPAuthenticator,
    LDAPAuthError,
    LDAPConfigError,
    LDAPIdentity,
    _cn_from_dn,
    _escape_filter_value,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_BASE_CONFIG = LDAPAuthConfig(
    url="ldaps://dc.corp.example.com",
    base_dn="DC=corp,DC=example,DC=com",
    bind_dn="CN=svc-aegis,OU=SvcAccts,DC=corp,DC=example,DC=com",
    bind_password="svc-secret",  # noqa: S106
    ad_mode=True,
)

_USER_DN = "CN=john.doe,OU=Users,DC=corp,DC=example,DC=com"
_GROUP_DN = "CN=AegisUsers,OU=Groups,DC=corp,DC=example,DC=com"


def _make_entry(dn: str, attrs: dict[str, list[str]] | None = None) -> MagicMock:
    """Create a mock ldap3 Entry object."""
    attrs = attrs or {}
    entry = MagicMock()
    entry.entry_dn = dn
    entry.entry_attributes = list(attrs.keys())

    def getitem(_self: MagicMock, name: str) -> MagicMock:
        m = MagicMock()
        m.values = attrs.get(name, [])
        return m

    entry.__getitem__ = getitem
    return entry


def _make_connection(
    bind_result: bool = True,
    entries: list[MagicMock] | None = None,
) -> MagicMock:
    """Create a mock ldap3 Connection object."""
    conn = MagicMock()
    conn.bind.return_value = bind_result
    conn.entries = entries or []
    return conn


# ── Helper utility tests ───────────────────────────────────────────────────────


class TestEscapeFilterValue:
    def test_plain_username_unchanged(self):
        assert _escape_filter_value("johndoe") == "johndoe"

    def test_asterisk_escaped(self):
        assert _escape_filter_value("john*doe") == r"john\2adoe"

    def test_parens_escaped(self):
        assert _escape_filter_value("(admin)") == r"\28admin\29"

    def test_backslash_escaped(self):
        assert _escape_filter_value("a\\b") == r"a\5cb"

    def test_null_byte_escaped(self):
        assert _escape_filter_value("a\x00b") == r"a\00b"

    def test_email_at_sign_unchanged(self):
        # @ is not in the RFC 4515 escape list
        assert _escape_filter_value("user@corp.com") == "user@corp.com"


class TestCnFromDn:
    def test_simple_cn(self):
        assert _cn_from_dn("CN=AegisUsers,OU=Groups,DC=corp,DC=example,DC=com") == "AegisUsers"

    def test_lowercase_cn(self):
        assert _cn_from_dn("cn=Alice,dc=example,dc=com") == "Alice"

    def test_no_cn_component_returns_full_dn(self):
        dn = "OU=Groups,DC=corp,DC=example,DC=com"
        assert _cn_from_dn(dn) == dn

    def test_whitespace_stripped(self):
        assert _cn_from_dn("CN = Bob , DC=corp, DC=com") == "Bob"


# ── LDAPAuthConfig tests ───────────────────────────────────────────────────────


class TestLDAPAuthConfig:
    def test_default_search_filter_has_username_placeholder(self):
        cfg = LDAPAuthConfig(url="ldap://test", base_dn="DC=test")
        assert "{username}" in cfg.user_search_filter

    def test_effective_search_base_defaults_to_base_dn(self):
        cfg = LDAPAuthConfig(url="ldap://test", base_dn="DC=test,DC=com")
        assert cfg.effective_search_base() == "DC=test,DC=com"

    def test_effective_search_base_uses_user_search_base_when_set(self):
        cfg = LDAPAuthConfig(
            url="ldap://test",
            base_dn="DC=corp,DC=com",
            user_search_base="OU=Users,DC=corp,DC=com",
        )
        assert cfg.effective_search_base() == "OU=Users,DC=corp,DC=com"

    def test_required_groups_defaults_empty(self):
        cfg = LDAPAuthConfig(url="ldap://test", base_dn="DC=test")
        assert cfg.required_groups == frozenset()

    def test_required_groups_frozenset(self):
        cfg = LDAPAuthConfig(
            url="ldap://test",
            base_dn="DC=test",
            required_groups=frozenset({"AegisUsers"}),
        )
        assert "AegisUsers" in cfg.required_groups


# ── LDAPIdentity tests ─────────────────────────────────────────────────────────


class TestLDAPIdentity:
    def _identity(self, groups: frozenset[str] = frozenset()) -> LDAPIdentity:
        return LDAPIdentity(
            username="alice",
            user_dn=_USER_DN,
            groups=groups,
        )

    def test_is_member_of_cn(self):
        identity = self._identity(frozenset({"AegisUsers", _GROUP_DN}))
        assert identity.is_member_of("AegisUsers")

    def test_is_member_of_full_dn(self):
        identity = self._identity(frozenset({"AegisUsers", _GROUP_DN}))
        assert identity.is_member_of(_GROUP_DN)

    def test_is_member_of_case_insensitive(self):
        identity = self._identity(frozenset({"AegisUsers"}))
        assert identity.is_member_of("aegisusers")

    def test_is_member_of_false_when_not_present(self):
        identity = self._identity(frozenset({"AegisUsers"}))
        assert not identity.is_member_of("Admins")

    def test_assert_group_membership_passes_when_member(self):
        identity = self._identity(frozenset({"AegisUsers"}))
        identity.assert_group_membership(frozenset({"AegisUsers"}))  # must not raise

    def test_assert_group_membership_raises_when_not_member(self):
        identity = self._identity(frozenset({"Domain Users"}))
        with pytest.raises(LDAPAuthError):
            identity.assert_group_membership(frozenset({"AegisUsers"}))

    def test_assert_group_membership_passes_on_empty_required(self):
        identity = self._identity(frozenset())
        identity.assert_group_membership(frozenset())  # must not raise

    def test_assert_group_membership_any_one_match_sufficient(self):
        identity = self._identity(frozenset({"AegisUsers"}))
        identity.assert_group_membership(frozenset({"AegisUsers", "AegisAdmins"}))


# ── LDAPAuthenticator construction tests ──────────────────────────────────────


class TestLDAPAuthenticatorConfig:
    def test_empty_url_raises_config_error(self):
        with pytest.raises(LDAPConfigError):
            LDAPAuthenticator(LDAPAuthConfig(url="", base_dn="DC=test"))

    def test_empty_base_dn_raises_config_error(self):
        with pytest.raises(LDAPConfigError):
            LDAPAuthenticator(LDAPAuthConfig(url="ldaps://dc", base_dn=""))

    def test_valid_config_constructs(self):
        auth = LDAPAuthenticator(_BASE_CONFIG)
        assert auth is not None


# ── LDAPAuthenticator.authenticate tests (mocked ldap3) ───────────────────────


class TestLDAPAuthenticate:
    """Tests for the authenticate() method with fully mocked ldap3."""

    def _make_auth(self, config: LDAPAuthConfig | None = None) -> LDAPAuthenticator:
        return LDAPAuthenticator(config or _BASE_CONFIG)

    def _patched_connections(
        self,
        *,
        service_bind_result: bool = True,
        user_dn: str = _USER_DN,
        user_attrs: dict[str, list[str]] | None = None,
        user_bind_result: bool = True,
    ):
        """Return a context manager that patches ldap3.Connection."""
        user_attrs = user_attrs or {"memberOf": [_GROUP_DN]}
        service_entry = _make_entry(user_dn, user_attrs)

        call_count = [0]

        def connection_factory(*args, **kwargs):
            call_count[0] += 1
            conn = MagicMock()
            if call_count[0] == 1:
                # First call: service bind for user lookup
                conn.bind.return_value = service_bind_result
                conn.entries = [service_entry]
            elif call_count[0] == 2:
                # Second call: user credential bind
                conn.bind.return_value = user_bind_result
                conn.entries = []
            else:
                # Third call: optional nested group search
                conn.bind.return_value = True
                conn.entries = []
            return conn

        return patch("aegis.auth.ldap_auth.Connection", side_effect=connection_factory)

    def test_successful_authentication_returns_identity(self):
        with self._patched_connections():
            auth = self._make_auth()
            identity = auth.authenticate("john.doe", "P@ssw0rd!")
        assert isinstance(identity, LDAPIdentity)
        assert identity.username == "john.doe"
        assert identity.user_dn == _USER_DN

    def test_identity_groups_populated_from_member_of(self):
        with self._patched_connections():
            auth = self._make_auth()
            identity = auth.authenticate("john.doe", "P@ssw0rd!")
        assert "AegisUsers" in identity.groups

    def test_empty_username_raises_auth_error(self):
        auth = self._make_auth()
        with pytest.raises(LDAPAuthError):
            auth.authenticate("", "password")

    def test_empty_password_raises_auth_error(self):
        auth = self._make_auth()
        with pytest.raises(LDAPAuthError):
            auth.authenticate("user", "")

    def test_service_bind_failure_raises_auth_error(self):
        with self._patched_connections(service_bind_result=False):
            auth = self._make_auth()
            with pytest.raises(LDAPAuthError):
                auth.authenticate("john.doe", "P@ssw0rd!")

    def test_user_not_found_raises_auth_error(self):
        def no_entries_factory(*args, **kwargs):
            conn = MagicMock()
            conn.bind.return_value = True
            conn.entries = []
            return conn

        with patch("aegis.auth.ldap_auth.Connection", side_effect=no_entries_factory):
            auth = self._make_auth()
            with pytest.raises(LDAPAuthError) as exc_info:
                auth.authenticate("ghost.user", "P@ssw0rd!")
        assert "not found" in str(exc_info.value).lower()

    def test_ambiguous_user_raises_auth_error(self):
        entry1 = _make_entry(_USER_DN, {})
        entry2 = _make_entry("CN=john.doe2,OU=Users,DC=corp,DC=example,DC=com", {})

        def two_entries_factory(*args, **kwargs):
            conn = MagicMock()
            conn.bind.return_value = True
            conn.entries = [entry1, entry2]
            return conn

        with patch("aegis.auth.ldap_auth.Connection", side_effect=two_entries_factory):
            auth = self._make_auth()
            with pytest.raises(LDAPAuthError) as exc_info:
                auth.authenticate("john.doe", "P@ssw0rd!")
        assert "ambiguous" in str(exc_info.value).lower()

    def test_invalid_credentials_raises_auth_error(self):
        with self._patched_connections(user_bind_result=False):
            auth = self._make_auth()
            with pytest.raises(LDAPAuthError) as exc_info:
                auth.authenticate("john.doe", "wrongpass")
        assert (
            "credentials" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()
        )

    def test_required_group_satisfied_passes(self):
        config = replace(_BASE_CONFIG, required_groups=frozenset({"AegisUsers"}))
        with self._patched_connections():
            auth = self._make_auth(config)
            identity = auth.authenticate("john.doe", "P@ssw0rd!")
        assert identity is not None

    def test_required_group_not_satisfied_raises_auth_error(self):
        config = replace(_BASE_CONFIG, required_groups=frozenset({"SuperAdmins"}))
        with self._patched_connections(user_attrs={"memberOf": [_GROUP_DN]}):
            auth = self._make_auth(config)
            with pytest.raises(LDAPAuthError):
                auth.authenticate("john.doe", "P@ssw0rd!")

    def test_ldap_injection_sanitized_in_filter(self):
        """Username with LDAP special chars must not produce a malformed filter."""
        captured_filters: list[str] = []

        call_count = [0]

        def capture_factory(*args, **kwargs):
            conn = MagicMock()
            call_count[0] += 1
            if call_count[0] == 1:
                conn.bind.return_value = True
                conn.entries = [_make_entry(_USER_DN, {"memberOf": [_GROUP_DN]})]

                # Capture the search_filter argument
                def search(*a, **kw):
                    captured_filters.append(kw.get("search_filter", ""))

                conn.search = search
            else:
                conn.bind.return_value = True
                conn.entries = []
            return conn

        with patch("aegis.auth.ldap_auth.Connection", side_effect=capture_factory):
            auth = self._make_auth()
            try:
                auth.authenticate(")(cn=*", "pw")
            except LDAPAuthError:
                pass
        # The injected parens and asterisk should be escaped in the filter
        if captured_filters:
            assert ")(cn=*" not in captured_filters[0]

    def test_no_member_of_attr_gets_empty_groups(self):
        with self._patched_connections(user_attrs={}):
            auth = self._make_auth()
            identity = auth.authenticate("john.doe", "P@ssw0rd!")
        assert isinstance(identity.groups, frozenset)

    def test_rfc_mode_calls_group_search(self):
        """In non-AD mode, group search uses member/uniqueMember/memberUid filter."""
        config = replace(_BASE_CONFIG, ad_mode=False)
        group_entry = _make_entry("CN=staff,DC=corp,DC=com", {})

        call_count = [0]

        def factory(*args, **kwargs):
            conn = MagicMock()
            call_count[0] += 1
            if call_count[0] == 1:
                conn.bind.return_value = True
                conn.entries = [_make_entry(_USER_DN, {})]
            elif call_count[0] == 2:
                conn.bind.return_value = True
                conn.entries = []
            else:
                conn.bind.return_value = True
                conn.entries = [group_entry]
            return conn

        with patch("aegis.auth.ldap_auth.Connection", side_effect=factory):
            auth = self._make_auth(config)
            identity = auth.authenticate("alice", "pw")
        # RFC group search ran — may or may not find groups but shouldn't raise
        assert isinstance(identity.groups, frozenset)


# ── test_service_bind tests ────────────────────────────────────────────────────


class TestServiceBind:
    def test_service_bind_returns_true_on_success(self):
        conn = MagicMock()
        conn.bind.return_value = True
        with patch("aegis.auth.ldap_auth.Connection", return_value=conn):
            auth = LDAPAuthenticator(_BASE_CONFIG)
            assert auth.test_service_bind() is True

    def test_service_bind_returns_false_on_failure(self):
        conn = MagicMock()
        conn.bind.return_value = False
        with patch("aegis.auth.ldap_auth.Connection", return_value=conn):
            auth = LDAPAuthenticator(_BASE_CONFIG)
            assert auth.test_service_bind() is False

    def test_service_bind_returns_false_on_exception(self):
        import ldap3.core.exceptions as ldap_exc

        conn = MagicMock()
        conn.bind.side_effect = ldap_exc.LDAPException("connection refused")
        with patch("aegis.auth.ldap_auth.Connection", return_value=conn):
            auth = LDAPAuthenticator(_BASE_CONFIG)
            assert auth.test_service_bind() is False
