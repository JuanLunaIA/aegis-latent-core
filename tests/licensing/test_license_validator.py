# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Offline licence verification: what a token grants, and every way it fails.

The properties that carry the module are the negative ones. A licence check
that accepts a tampered payload, a token signed by the wrong key, or a token
padded with junk is worse than no check at all, because it reads as enforcement.

Calls that verify are assigned before being asserted on, never called inside
the ``assert`` itself: ``python -O`` strips assert statements, so
``assert LicenseEnforcement(...)`` would not construct anything and the test
would pass having exercised nothing (CodeQL py/side-effect-in-assert).
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.licensing.validator import (
    KNOWN_MODULES,
    LICENSE_TOKEN_ENV,
    ROOT_PUBKEY_ENV,
    LicenseEnforcement,
    LicenseEntitlement,
    LicenseExpiredError,
    LicenseMalformedError,
    LicenseSignatureError,
    load_entitlement_from_env,
    root_public_key_from_env,
)


def _public_hex(key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )


def _mint(
    key: Ed25519PrivateKey,
    *,
    sub: str = "acme-corp",
    tier: str = "enterprise",
    modules: list[str] | object = None,
    mgt: int = 50,
    ttl_seconds: int = 86_400,
    **overrides: object,
) -> str:
    """Sign a token the way the vendor CLI does."""

    payload: dict[str, object] = {
        "sub": sub,
        "tier": tier,
        "modules": ["veracity", "sanctum"] if modules is None else modules,
        "mgt": mgt,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_seconds,
    }
    payload.update(overrides)
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(payload_bytes + key.sign(payload_bytes), altchars=b"-_").decode("ascii")


@pytest.fixture
def vendor_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


class TestValidToken:
    def test_a_signed_token_decodes_to_its_entitlement(self, vendor_key):
        token = _mint(vendor_key)
        entitlement = LicenseEnforcement(token, _public_hex(vendor_key)).entitlement
        assert entitlement.customer_id == "acme-corp"
        assert entitlement.tier == "enterprise"
        assert entitlement.modules == frozenset({"veracity", "sanctum"})
        assert entitlement.max_annual_mgt == 50

    def test_granted_modules_are_allowed_and_others_are_not(self, vendor_key):
        token = _mint(vendor_key, modules=["veracity"])
        entitlement = LicenseEnforcement(token, _public_hex(vendor_key)).entitlement
        assert entitlement.has_module("veracity") is True
        assert entitlement.has_module("sanctum") is False
        assert entitlement.has_module("sovereign") is False

    def test_omnia_is_a_wildcard_over_every_module(self, vendor_key):
        token = _mint(vendor_key, modules=["omnia"])
        entitlement = LicenseEnforcement(token, _public_hex(vendor_key)).entitlement
        for module in sorted(KNOWN_MODULES):
            assert entitlement.has_module(module) is True, module

    def test_the_raw_public_key_bytes_are_accepted_too(self, vendor_key):
        token = _mint(vendor_key)
        entitlement = LicenseEnforcement(token, bytes.fromhex(_public_hex(vendor_key))).entitlement
        assert entitlement.customer_id == "acme-corp"

    def test_seconds_remaining_is_positive_and_never_negative(self, vendor_key):
        live = LicenseEnforcement(_mint(vendor_key, ttl_seconds=3600), _public_hex(vendor_key))
        assert 0 < live.entitlement.seconds_remaining <= 3600

        lapsed = LicenseEntitlement(
            customer_id="x",
            tier="core",
            modules=frozenset({"veracity"}),
            max_annual_mgt=1,
            expires_at=int(time.time()) - 10_000,
        )
        assert lapsed.seconds_remaining == 0


class TestRejection:
    """Every one of these must fail closed."""

    def test_a_tampered_payload_is_rejected(self, vendor_key):
        """Upgrade the tier in the payload and the signature stops matching."""

        raw = base64.b64decode(_mint(vendor_key, modules=["veracity"]), altchars=b"-_")
        payload, signature = raw[:-64], raw[-64:]
        forged_payload = payload.replace(b'"veracity"', b'"sovereign"')
        assert forged_payload != payload, "the fixture must actually change the payload"
        forged = base64.b64encode(forged_payload + signature, altchars=b"-_").decode("ascii")

        with pytest.raises(LicenseSignatureError):
            LicenseEnforcement(forged, _public_hex(vendor_key))

    def test_a_token_signed_by_another_key_is_rejected(self, vendor_key):
        attacker_key = Ed25519PrivateKey.generate()
        token = _mint(attacker_key, modules=["omnia"])
        with pytest.raises(LicenseSignatureError):
            LicenseEnforcement(token, _public_hex(vendor_key))

    def test_an_expired_token_is_rejected_even_though_it_verifies(self, vendor_key):
        token = _mint(vendor_key, ttl_seconds=-3600)
        with pytest.raises(LicenseExpiredError):
            LicenseEnforcement(token, _public_hex(vendor_key))

    def test_junk_outside_the_base64_alphabet_is_rejected(self, vendor_key):
        """The decoder must validate, not silently discard.

        ``base64.urlsafe_b64decode`` drops non-alphabet characters, so without
        ``validate=True`` a token could be padded with arbitrary bytes and still
        verify. This pins the strict decode.
        """

        token = _mint(vendor_key)
        with pytest.raises(LicenseMalformedError, match="base64url"):
            LicenseEnforcement(token + "!!!!", _public_hex(vendor_key))

    def test_a_truncated_token_is_rejected_before_slicing(self, vendor_key):
        with pytest.raises(LicenseMalformedError, match="too short"):
            LicenseEnforcement(
                base64.b64encode(b"tiny", altchars=b"-_").decode(), _public_hex(vendor_key)
            )

    def test_an_empty_token_is_rejected(self, vendor_key):
        with pytest.raises(LicenseMalformedError, match="empty"):
            LicenseEnforcement("   ", _public_hex(vendor_key))

    @pytest.mark.parametrize(
        ("bad_key", "expected"),
        [
            ("not-hex", "valid hex"),
            ("aabb", "Ed25519 requires"),
            ("ab" * 33, "Ed25519 requires"),
        ],
    )
    def test_a_malformed_root_key_is_rejected(self, vendor_key, bad_key, expected):
        token = _mint(vendor_key)
        with pytest.raises(LicenseMalformedError, match=expected):
            LicenseEnforcement(token, bad_key)

    def test_every_failure_is_catchable_as_permission_error(self, vendor_key):
        """A caller guarding with PermissionError must fail closed on all of them."""

        attacker_key = Ed25519PrivateKey.generate()
        for token in (
            _mint(attacker_key),  # wrong key
            _mint(vendor_key, ttl_seconds=-1),  # expired
            "not-a-token!!",  # malformed
        ):
            with pytest.raises(PermissionError):
                LicenseEnforcement(token, _public_hex(vendor_key))


class TestPayloadTypeValidation:
    """A signed payload is authentic, not well-formed. Types are still checked."""

    def test_modules_as_a_bare_string_is_rejected(self, vendor_key):
        """``set("veracity")`` would be eight single characters, silently wrong."""

        token = _mint(vendor_key, modules="veracity")
        with pytest.raises(LicenseMalformedError, match="list of strings"):
            LicenseEnforcement(token, _public_hex(vendor_key))

    def test_an_unknown_module_name_is_rejected(self, vendor_key):
        token = _mint(vendor_key, modules=["veracity", "telepathy"])
        with pytest.raises(LicenseMalformedError, match="unknown module"):
            LicenseEnforcement(token, _public_hex(vendor_key))

    def test_an_empty_module_list_is_rejected(self, vendor_key):
        token = _mint(vendor_key, modules=[])
        with pytest.raises(LicenseMalformedError, match="must not be empty"):
            LicenseEnforcement(token, _public_hex(vendor_key))

    def test_a_boolean_is_not_accepted_as_an_integer_field(self, vendor_key):
        """``bool`` subclasses ``int``; ``mgt: true`` is malformed, not ``1``."""

        token = _mint(vendor_key, mgt=True)
        with pytest.raises(LicenseMalformedError, match="must be an integer"):
            LicenseEnforcement(token, _public_hex(vendor_key))

    @pytest.mark.parametrize("field", ["sub", "tier"])
    def test_a_missing_string_field_is_rejected(self, vendor_key, field):
        token = _mint(vendor_key, **{field: ""})
        with pytest.raises(LicenseMalformedError, match="non-empty string"):
            LicenseEnforcement(token, _public_hex(vendor_key))

    def test_a_non_object_payload_is_rejected(self, vendor_key):
        payload_bytes = json.dumps([1, 2, 3]).encode("utf-8")
        token = base64.b64encode(
            payload_bytes + vendor_key.sign(payload_bytes), altchars=b"-_"
        ).decode("ascii")
        with pytest.raises(LicenseMalformedError, match="JSON object"):
            LicenseEnforcement(token, _public_hex(vendor_key))


class TestEnvironmentConfiguration:
    def test_no_token_configured_is_not_an_error(self):
        """The unlicensed AGPLv3 gateway is the ordinary case."""

        assert load_entitlement_from_env({}) is None

    def test_a_configured_token_is_verified(self, vendor_key):
        env = {
            LICENSE_TOKEN_ENV: _mint(vendor_key),
            ROOT_PUBKEY_ENV: _public_hex(vendor_key),
        }
        entitlement = load_entitlement_from_env(env)
        assert entitlement is not None
        assert entitlement.customer_id == "acme-corp"

    def test_a_bad_token_that_is_present_raises_rather_than_degrading(self, vendor_key):
        """A deployment that meant to be licensed must not silently run unlicensed."""

        env = {
            LICENSE_TOKEN_ENV: _mint(Ed25519PrivateKey.generate()),
            ROOT_PUBKEY_ENV: _public_hex(vendor_key),
        }
        with pytest.raises(LicenseSignatureError):
            load_entitlement_from_env(env)

    def test_there_is_no_compiled_in_root_key(self):
        """The whole point: an absent root key refuses instead of defaulting.

        A 32-byte placeholder loads as a perfectly valid Ed25519 key, so a
        hardcoded fallback would look authoritative while nobody held the
        private half. This asserts the absence.
        """

        with pytest.raises(LicenseMalformedError, match="no default"):
            root_public_key_from_env({})

    def test_a_token_without_a_root_key_configured_refuses(self, vendor_key):
        env = {LICENSE_TOKEN_ENV: _mint(vendor_key)}
        with pytest.raises(LicenseMalformedError, match="no default"):
            load_entitlement_from_env(env)
