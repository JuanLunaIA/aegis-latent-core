# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The authentication helpers that decide, not the routes that call them.

`aegis/proxy/dependencies.py` turns a credential into a `Principal`. Most of its
decisions are made in small pure helpers, and each one is a fail-closed refusal:
a credential that is not presented as a Bearer token, an identity object whose
`roles`/`scopes` are not a JSON string array, a scope this build does not define,
two tenant identifiers that differ only in codepoints.

The tenant comparison is the one worth stating twice. `hmac.compare_digest`
raises `TypeError` when given a `str` holding non-ASCII, so comparing raw
identifiers turns a legitimate internationalized tenant — from an OIDC claim or a
certificate SAN — into an unhandled 500, and turns a client-supplied non-ASCII
`tenant_id` into the same. Encoding first makes the comparison total; these tests
pin both halves: non-ASCII identifiers compare without raising, and identifiers
that are *not* byte-identical deny rather than being normalised into a match.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from aegis.auth.principal import Role
from aegis.auth.scopes import ALL_SCOPES, SCOPE_AUDIT_READ, SCOPE_PROXY_COMPLETIONS
from aegis.proxy.dependencies import (
    _bearer,
    _opaque_credential_id,
    _roles,
    _same_tenant,
    _scopes,
    permissions_for_roles,
)


def _request(**headers: str) -> Any:
    return SimpleNamespace(headers=headers, app=SimpleNamespace(state=SimpleNamespace()))


class TestRolePermissions:
    def test_each_role_contributes_its_scopes(self) -> None:
        granted = permissions_for_roles(frozenset({Role.AUDITOR}))
        assert SCOPE_AUDIT_READ in granted

    def test_roles_compose_without_duplication(self) -> None:
        granted = permissions_for_roles(frozenset({Role.PROXY_USER, Role.AUDITOR}))
        assert {SCOPE_PROXY_COMPLETIONS, SCOPE_AUDIT_READ} <= granted

    def test_no_roles_grants_nothing(self) -> None:
        assert permissions_for_roles(frozenset()) == frozenset()

    def test_admin_receives_every_scope(self) -> None:
        assert permissions_for_roles(frozenset({Role.ADMIN})) == ALL_SCOPES


class TestBearerExtraction:
    def test_a_missing_header_is_refused_with_a_challenge(self) -> None:
        with pytest.raises(HTTPException) as caught:
            _bearer(_request())
        assert caught.value.status_code == 401
        assert caught.value.headers == {"WWW-Authenticate": "Bearer"}

    def test_a_non_bearer_scheme_is_refused(self) -> None:
        with pytest.raises(HTTPException):
            _bearer(_request(authorization="Basic dXNlcjpwYXNz"))

    def test_a_bare_scheme_without_a_credential_is_refused(self) -> None:
        with pytest.raises(HTTPException):
            _bearer(_request(authorization="Bearer "))

    def test_the_scheme_is_case_insensitive(self) -> None:
        assert _bearer(_request(authorization="bEaReR abc123")) == "abc123"

    def test_a_credential_containing_spaces_survives(self) -> None:
        """The header is partitioned once, so the credential keeps its spaces."""
        assert _bearer(_request(authorization="Bearer a b c")) == "a b c"


class TestTenantComparison:
    def test_identical_identifiers_match(self) -> None:
        assert _same_tenant("tenant-a", "tenant-a") is True

    def test_different_identifiers_deny(self) -> None:
        assert _same_tenant("tenant-a", "tenant-b") is False

    def test_a_non_ascii_identifier_does_not_raise(self) -> None:
        """`hmac.compare_digest` on raw str would raise TypeError here."""
        assert _same_tenant("locataire-é", "locataire-é") is True
        assert _same_tenant("locataire-é", "locataire-e") is False

    def test_a_precomposed_and_a_decomposed_identifier_do_not_match(self) -> None:
        """Normalising would resolve two codepoint sequences to one tenant."""
        precomposed = "tenant-é"  # é as one codepoint
        decomposed = "tenant-e\u0301"  # e + combining acute
        assert _same_tenant(precomposed, decomposed) is False


class TestIdentityObjectValidation:
    def test_a_roles_array_is_accepted(self) -> None:
        assert _roles(["admin"]) == frozenset({Role.ADMIN})

    def test_a_non_list_roles_value_is_refused(self) -> None:
        with pytest.raises(ValueError, match="roles must be a JSON string array"):
            _roles("admin")

    def test_a_roles_element_that_is_not_a_string_is_refused(self) -> None:
        with pytest.raises(ValueError, match="roles must be a JSON string array"):
            _roles(["admin", 1])

    def test_an_unknown_role_is_refused(self) -> None:
        with pytest.raises(ValueError):
            _roles(["not-a-role"])

    def test_a_scopes_array_is_accepted(self) -> None:
        assert _scopes([SCOPE_AUDIT_READ]) == frozenset({SCOPE_AUDIT_READ})

    def test_a_non_list_scopes_value_is_refused(self) -> None:
        with pytest.raises(ValueError, match="scopes must be a JSON string array"):
            _scopes(SCOPE_AUDIT_READ)

    def test_a_scope_this_build_does_not_define_is_refused(self) -> None:
        """An identity claiming an unknown scope is a configuration error, not a grant."""
        with pytest.raises(ValueError, match="unsupported scopes"):
            _scopes(["audit:read", "audit:everything"])


class TestOpaqueCredentialIds:
    def test_the_same_credential_yields_the_same_id(self) -> None:
        assert _opaque_credential_id("secret", "api-key", "abc") == _opaque_credential_id(
            "secret", "api-key", "abc"
        )

    def test_the_id_is_domain_separated(self) -> None:
        """The same credential presented as two domains must not collapse."""
        assert _opaque_credential_id("secret", "api-key", "abc") != _opaque_credential_id(
            "secret", "mtls", "abc"
        )

    def test_a_different_secret_yields_a_different_id(self) -> None:
        assert _opaque_credential_id("one", "api-key", "abc") != _opaque_credential_id(
            "two", "api-key", "abc"
        )

    def test_the_developable_default_key_is_used_when_no_secret_is_configured(self) -> None:
        """Development mode must not silently yield an identifier derived from b""."""
        assert _opaque_credential_id("", "api-key", "abc") == _opaque_credential_id(
            "", "api-key", "abc"
        )
        assert _opaque_credential_id("", "api-key", "abc") != _opaque_credential_id(
            "secret", "api-key", "abc"
        )

    def test_the_raw_credential_never_appears_in_the_id(self) -> None:
        identifier = _opaque_credential_id("secret", "api-key", "super-secret-value")
        assert "super-secret-value" not in identifier
        assert identifier.startswith("api-key:")
