# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Offline commercial license verification.

A license token is ``base64url(payload_json || ed25519_signature)``. Verifying
it needs the vendor's Ed25519 public key and nothing else — no network call, no
phone-home, no licence server. That is the point: an air-gapped deployment can
check its own entitlement, and the vendor learns nothing about when or how
often it runs.

    enforcement = LicenseEnforcement(token, root_public_key=vendor_key)
    enforcement.entitlement.has_module("veracity")   # -> bool

The entitlement itself lives in :mod:`aegis.licensing.model`, which imports no
cryptography and reads no environment. It is re-exported here so that every
existing ``from aegis.licensing.validator import LicenseEntitlement`` keeps
working.

There is no default root key
----------------------------

The key must be supplied by the caller or through ``AEGIS_LICENSE_ROOT_PUBKEY``.
A hardcoded fallback was deliberately rejected: a placeholder that happens to be
32 bytes loads as a perfectly good ``Ed25519PublicKey``, so it would not fail
loudly — it would sit in the source looking authoritative while no one held the
private half. An absent key raises here instead.

What a valid token establishes
------------------------------

That the vendor signed this payload, and that the current clock is before its
expiry. That is all, and each of the following is outside it:

- *Who is running it.* A token is a **bearer credential**. Copying it copies the
  entitlement. Offline licensing cannot do otherwise: binding to a machine
  needs either a phone-home or a hardware root, and this design has neither.
- *That the clock is honest.* Expiry is checked against ``time.time()``. A host
  whose clock is set backwards extends its own licence, and nothing offline can
  detect that. An operator needing tamper-evident expiry needs a trusted time
  source, which is a deployment control rather than a property of this module.
- *That usage stayed within* ``max_annual_mgt``. The field is carried so the
  contract can be read off the token; it is a commercial term, not a runtime
  quota, and nothing here counts or enforces transactions.
- *Revocation.* There is no CRL and no OCSP. A token is valid until it expires;
  revoking one before then requires rotating the root key and reissuing, which
  is a vendor process, not a code path.

Every failure raises :class:`LicenseError`, a ``PermissionError`` subclass, so a
caller that catches ``PermissionError`` fails closed on all of them.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Mapping
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis.licensing.model import KNOWN_MODULES, LicenseEntitlement

#: Environment variable holding the vendor's Ed25519 root public key, hex-encoded.
ROOT_PUBKEY_ENV: Final[str] = "AEGIS_LICENSE_ROOT_PUBKEY"

#: Environment variable holding the license token itself.
# noqa justification: this is the variable *name*, not a token. The token is
# read from the environment at call time and never appears in this source.
LICENSE_TOKEN_ENV: Final[str] = "AEGIS_LICENSE_TOKEN"  # noqa: S105

#: Ed25519 signatures are always exactly 64 bytes (RFC 8032 §5.1.6).
_SIGNATURE_BYTES: Final[int] = 64

#: Ed25519 public keys are always exactly 32 bytes.
_PUBLIC_KEY_BYTES: Final[int] = 32

#: Upper bound on a decoded token, so a hostile string cannot force a large
#: allocation before any check runs. Real tokens are a few hundred bytes.
_MAX_TOKEN_BYTES: Final[int] = 8192


class LicenseError(PermissionError):
    """Base class for every licence failure. Subclasses ``PermissionError``."""


class LicenseMalformedError(LicenseError):
    """The token is not structurally a licence, or a field has the wrong type."""


class LicenseSignatureError(LicenseError):
    """The signature did not verify under the supplied root key."""


class LicenseExpiredError(LicenseError):
    """The token verified, but its expiry has passed."""


def _decode_token_bytes(token: str) -> bytes:
    """Strict base64url decode.

    ``base64.urlsafe_b64decode`` does not validate: by default the decoder
    *discards* characters outside the alphabet, so ``"AAAA!!!!"`` and ``"AAAA"``
    decode identically. For a bearer credential that is the wrong behaviour —
    it lets a token be padded with junk and still verify — so this goes through
    ``b64decode`` with ``validate=True`` and the URL-safe alphabet.
    """

    stripped = token.strip()
    if not stripped:
        raise LicenseMalformedError("license token is empty")
    try:
        raw = base64.b64decode(stripped, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise LicenseMalformedError(f"license token is not valid base64url: {exc}") from exc
    if len(raw) > _MAX_TOKEN_BYTES:
        raise LicenseMalformedError(
            f"license token decodes to {len(raw)} bytes, over the {_MAX_TOKEN_BYTES}-byte bound"
        )
    if len(raw) <= _SIGNATURE_BYTES:
        raise LicenseMalformedError(
            f"license token is {len(raw)} bytes, too short to hold a payload and a "
            f"{_SIGNATURE_BYTES}-byte signature"
        )
    return raw


def _load_public_key(root_public_key: str | bytes | Ed25519PublicKey) -> Ed25519PublicKey:
    """Accept a key object, raw 32 bytes, or hex, and return the key object."""

    if isinstance(root_public_key, Ed25519PublicKey):
        return root_public_key
    if isinstance(root_public_key, str):
        try:
            key_bytes = bytes.fromhex(root_public_key.strip())
        except ValueError as exc:
            raise LicenseMalformedError(f"root public key is not valid hex: {exc}") from exc
    else:
        key_bytes = bytes(root_public_key)
    if len(key_bytes) != _PUBLIC_KEY_BYTES:
        raise LicenseMalformedError(
            f"root public key is {len(key_bytes)} bytes; Ed25519 requires {_PUBLIC_KEY_BYTES}"
        )
    try:
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    except ValueError as exc:  # pragma: no cover - depends on backend validation
        raise LicenseMalformedError(f"root public key is not a valid Ed25519 key: {exc}") from exc


def _require_str(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise LicenseMalformedError(f"license field {key!r} must be a non-empty string")
    return value


def _require_int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    # bool is an int subclass; a boolean here is a malformed licence, not a 0/1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise LicenseMalformedError(f"license field {key!r} must be an integer")
    return value


def _require_modules(payload: Mapping[str, Any]) -> frozenset[str]:
    """Validate ``modules`` as a list of strings.

    The type check is load-bearing rather than decorative. ``set("veracity")``
    is a set of eight single characters, so accepting a bare string here would
    silently produce an entitlement that grants nothing and denies everything —
    a fail-closed outcome, but for a reason no operator could diagnose.
    """

    value = payload.get("modules")
    if not isinstance(value, list):
        raise LicenseMalformedError("license field 'modules' must be a list of strings")
    modules: set[str] = set()
    for entry in value:
        if not isinstance(entry, str) or not entry:
            raise LicenseMalformedError("license field 'modules' must contain non-empty strings")
        if entry not in KNOWN_MODULES:
            raise LicenseMalformedError(
                f"license grants unknown module {entry!r}; known modules are "
                f"{sorted(KNOWN_MODULES)}"
            )
        modules.add(entry)
    if not modules:
        raise LicenseMalformedError("license field 'modules' must not be empty")
    return frozenset(modules)


class LicenseEnforcement:
    """Verifies a token and exposes the entitlement it carries.

    Construction verifies. A ``LicenseEnforcement`` that exists holds a
    signature-valid, unexpired entitlement; every other outcome raised.
    """

    def __init__(
        self,
        token: str,
        root_public_key: str | bytes | Ed25519PublicKey | None = None,
    ) -> None:
        if root_public_key is None:
            root_public_key = root_public_key_from_env()
        self._entitlement = self._verify_and_decode(token, root_public_key)

    @property
    def entitlement(self) -> LicenseEntitlement:
        return self._entitlement

    @staticmethod
    def _verify_and_decode(
        token: str, root_public_key: str | bytes | Ed25519PublicKey
    ) -> LicenseEntitlement:
        raw = _decode_token_bytes(token)
        public_key = _load_public_key(root_public_key)

        payload_bytes, signature = raw[:-_SIGNATURE_BYTES], raw[-_SIGNATURE_BYTES:]

        # Signature first: nothing in the payload is trusted until the vendor's
        # signature over these exact bytes verifies. Parsing before verifying
        # would run a JSON decoder over attacker-controlled input.
        try:
            public_key.verify(signature, payload_bytes)
        except InvalidSignature as exc:
            raise LicenseSignatureError(
                "license signature did not verify under the configured root key"
            ) from exc

        try:
            decoded = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LicenseMalformedError(f"license payload is not valid JSON: {exc}") from exc
        if not isinstance(decoded, dict):
            raise LicenseMalformedError("license payload must be a JSON object")

        entitlement = LicenseEntitlement(
            customer_id=_require_str(decoded, "sub"),
            tier=_require_str(decoded, "tier"),
            modules=_require_modules(decoded),
            max_annual_mgt=_require_int(decoded, "mgt"),
            expires_at=_require_int(decoded, "exp"),
        )
        if not entitlement.is_valid():
            raise LicenseExpiredError(
                f"license for {entitlement.customer_id!r} expired at "
                f"{entitlement.expires_at} (epoch seconds)"
            )
        return entitlement


def root_public_key_from_env(env: Mapping[str, str] | None = None) -> str:
    """Read the vendor root public key from the environment, or refuse.

    There is no fallback. See the module docstring: a hardcoded placeholder
    would load as a valid key and fail silently rather than loudly.
    """

    source = os.environ if env is None else env
    value = source.get(ROOT_PUBKEY_ENV, "").strip()
    if not value:
        raise LicenseMalformedError(
            f"{ROOT_PUBKEY_ENV} is not set. Commercial engine gating needs the vendor's "
            f"Ed25519 root public key; there is no default and none is compiled in."
        )
    return value


def load_entitlement_from_env(
    env: Mapping[str, str] | None = None,
) -> LicenseEntitlement | None:
    """Return the entitlement configured in the environment, or ``None``.

    ``None`` means *no licence was configured*, which is the ordinary state of
    the AGPLv3 gateway and is not an error. A token that is present but bad
    raises: a deployment that meant to be licensed and is not must find out.
    """

    source = os.environ if env is None else env
    token = source.get(LICENSE_TOKEN_ENV, "").strip()
    if not token:
        return None
    return LicenseEnforcement(token, root_public_key=root_public_key_from_env(source)).entitlement


__all__ = [
    "KNOWN_MODULES",
    "LICENSE_TOKEN_ENV",
    "ROOT_PUBKEY_ENV",
    "LicenseEnforcement",
    "LicenseEntitlement",
    "LicenseError",
    "LicenseExpiredError",
    "LicenseMalformedError",
    "LicenseSignatureError",
    "load_entitlement_from_env",
    "root_public_key_from_env",
]
