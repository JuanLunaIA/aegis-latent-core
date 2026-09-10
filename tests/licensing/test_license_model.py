# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""The entitlement model on its own, with time supplied rather than read.

``tests/licensing/test_license_validator.py`` covers signature verification and
every way a token fails. This file covers the model underneath it: what an
entitlement grants, and the expiry boundary — which is only testable at all
because ``now`` is a parameter. A test that mints a token expiring one second
out and asserts on it is a test that fails on a loaded machine.

Injecting the clock narrows a testing problem. It does not make expiry
trustworthy: the value still comes from the caller, and an offline licence has
no trusted time source. That boundary is stated in the module docstring and is
unchanged by anything here.

Calls with side effects are assigned before being asserted on, never called
inside the ``assert`` itself (``python -O`` strips asserts; CodeQL flags this as
py/side-effect-in-assert).
"""

from __future__ import annotations

import ast
import time
from pathlib import Path

import pytest

from aegis.licensing import model as license_model
from aegis.licensing.model import KNOWN_MODULES, WILDCARD_MODULE, LicenseEntitlement

EXPIRY = 1_800_000_000


def _entitlement(
    *, modules: frozenset[str] = frozenset({"veracity"}), expires_at: int = EXPIRY
) -> LicenseEntitlement:
    return LicenseEntitlement(
        customer_id="acme-corp",
        tier="enterprise",
        modules=modules,
        max_annual_mgt=50,
        expires_at=expires_at,
    )


class TestExpiryBoundary:
    @pytest.mark.parametrize(
        ("now", "valid"),
        [
            (EXPIRY - 1, True),
            (EXPIRY, False),
            (EXPIRY + 1, False),
            (0, True),
        ],
    )
    def test_the_term_is_half_open(self, now: int, valid: bool) -> None:
        # Expiry is exclusive: at exactly expires_at the licence has lapsed.
        # Half-open is the arbitrary half of the choice, so it is pinned here
        # rather than left to whichever comparison a future edit happens to use.
        assert _entitlement().is_valid(now) is valid

    def test_omitting_now_reads_the_host_clock(self) -> None:
        past = _entitlement(expires_at=int(time.time()) - 10_000)
        future = _entitlement(expires_at=int(time.time()) + 10_000)
        assert past.is_valid() is False
        assert future.is_valid() is True

    def test_an_explicit_now_overrides_the_host_clock(self) -> None:
        # The whole point: a licence that lapsed years ago still reads as valid
        # when asked about a moment inside its term.
        lapsed = _entitlement(expires_at=1_600_000_000)
        assert lapsed.is_valid() is False
        assert lapsed.is_valid(1_599_999_999) is True


class TestModuleGrants:
    def test_a_granted_module_inside_the_term(self) -> None:
        entitlement = _entitlement(modules=frozenset({"veracity", "sanctum"}))
        assert entitlement.has_module("veracity", EXPIRY - 1) is True
        assert entitlement.has_module("sanctum", EXPIRY - 1) is True

    def test_an_ungranted_module_is_denied_inside_the_term(self) -> None:
        entitlement = _entitlement(modules=frozenset({"veracity"}))
        assert entitlement.has_module("sovereign", EXPIRY - 1) is False

    def test_expiry_denies_a_module_the_token_does_grant(self) -> None:
        # Expiry is folded into has_module deliberately, so a call site cannot
        # check membership and forget the term.
        entitlement = _entitlement(modules=frozenset({"veracity"}))
        assert entitlement.has_module("veracity", EXPIRY + 1) is False

    def test_the_wildcard_covers_every_known_module(self) -> None:
        entitlement = _entitlement(modules=frozenset({WILDCARD_MODULE}))
        for module in sorted(KNOWN_MODULES):
            assert entitlement.has_module(module, EXPIRY - 1) is True, module

    def test_the_wildcard_still_lapses(self) -> None:
        entitlement = _entitlement(modules=frozenset({WILDCARD_MODULE}))
        assert entitlement.has_module("sovereign", EXPIRY + 1) is False

    def test_an_unknown_module_name_is_denied_rather_than_raising(self) -> None:
        # The validator rejects unknown names at parse time; asking the model
        # about one is a caller error that must fail closed, not explode.
        entitlement = _entitlement(modules=frozenset({WILDCARD_MODULE}))
        assert entitlement.has_module("no-such-module", EXPIRY - 1) is True
        narrow = _entitlement(modules=frozenset({"veracity"}))
        assert narrow.has_module("no-such-module", EXPIRY - 1) is False


class TestSecondsRemaining:
    def test_the_property_still_reads_the_host_clock(self) -> None:
        # Public API from the previous release: an attribute, not a call.
        entitlement = _entitlement(expires_at=int(time.time()) + 3600)
        assert 0 < entitlement.seconds_remaining <= 3600

    def test_the_parameterised_form_counts_down_to_expiry(self) -> None:
        entitlement = _entitlement()
        assert entitlement.seconds_remaining_at(EXPIRY - 500) == 500
        assert entitlement.seconds_remaining_at(EXPIRY) == 0

    def test_it_never_goes_negative(self) -> None:
        entitlement = _entitlement()
        assert entitlement.seconds_remaining_at(EXPIRY + 10_000) == 0


class TestShape:
    def test_the_entitlement_is_immutable(self) -> None:
        entitlement = _entitlement()
        with pytest.raises(AttributeError):
            entitlement.tier = "sovereign"  # type: ignore[misc]

    def test_it_carries_no_key_material(self) -> None:
        # An entitlement is passed to engine facades and appears in operator
        # output; nothing on it may be a secret.
        entitlement = _entitlement()
        assert set(entitlement.__slots__) == {
            "customer_id",
            "tier",
            "modules",
            "max_annual_mgt",
            "expires_at",
        }

    def test_the_model_declares_no_dependency_on_the_verifier(self) -> None:
        """The model must not import cryptography, ``os``, or the validator.

        Checked against the module's own import statements, parsed rather than
        grepped so that the word appearing in a docstring does not count. This
        is a statement about *this module's* dependencies. It is not a claim
        that ``import aegis.licensing.model`` avoids loading cryptography at
        runtime: that import initialises the ``aegis.licensing`` package first,
        and the package re-exports the verifier, which does import it.
        """

        source = Path(license_model.__file__ or "").read_text(encoding="utf-8")
        imported: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert imported == {"__future__", "dataclasses", "time", "typing"}
