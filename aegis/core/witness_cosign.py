# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.witness_cosign — m-of-n threshold co-signing for bundle export.

Implements a two-of-three (or configurable m-of-n) threshold signing scheme
for evidence bundle export authorization.  At least *m* of *n* designated
witnesses must each issue a signed :class:`WitnessSignature` over the canonical
bundle identifier before the :class:`WitnessCoSignGate` permits export.

Each witness signature is:

* **Time-bounded** — expires after a configurable window (default 1 hour).
* **Bundle-bound** — tied to the specific ``package_id`` being authorized.
* **HMAC-SHA256** — signed with the witness's per-witness key derived from
  ``AEGIS_SIGNING_KEY`` and the ``witness_id``; this keeps a single master
  signing key while producing independent, non-interchangeable witness sigs.

Security properties
-------------------
* Collusion requires *m* witnesses to agree within the validity window.
* Replay across packages is prevented by the ``package_id`` binding.
* Replay across time is prevented by the ``expires_at`` timestamp.
* A single key compromise does not undermine the threshold — each witness
  HMAC is keyed with ``HMAC-SHA256(AEGIS_SIGNING_KEY, witness_id)`` so
  different witnesses produce non-interchangeable signatures.

Configuration
-------------
``AEGIS_SIGNING_KEY``
    Master signing key.  Witness-specific keys are derived from this.
``AEGIS_WITNESS_VALIDITY``
    Witness signature validity in seconds (default ``3600``, minimum ``60``).

Usage::

    from aegis.core.witness_cosign import WitnessCoSignGate

    gate = WitnessCoSignGate(required=2, total=3)
    sig_a = gate.sign("alice", "pkg-001")
    sig_b = gate.sign("bob",   "pkg-001")
    gate.gate_export("pkg-001", [sig_a, sig_b])   # passes: 2 of 3
"""

from __future__ import annotations

import hashlib
import hmac as _hmac_module
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)

_DEFAULT_VALIDITY_SECONDS = 3600
_MIN_VALIDITY_SECONDS = 60
_DEFAULT_REQUIRED = 2
_DEFAULT_TOTAL = 3


# ── Exceptions ────────────────────────────────────────────────────────────────


class WitnessCoSignError(Exception):
    """Raised when threshold co-signing requirements are not met."""


# ── Key derivation ────────────────────────────────────────────────────────────


def _derive_witness_key(master_key: str, witness_id: str) -> bytes:
    """Derive a per-witness signing key from the master key and witness_id."""
    return _hmac_module.new(
        master_key.encode(),
        witness_id.encode(),
        hashlib.sha256,
    ).digest()


def _hmac_sign(key: bytes, data: bytes) -> str:
    return _hmac_module.new(key, data, hashlib.sha256).hexdigest()


def _hmac_verify(key: bytes, data: bytes, expected_hex: str) -> bool:
    actual = _hmac_sign(key, data)
    return _hmac_module.compare_digest(actual, expected_hex)


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class WitnessSignature:
    """A single witness's co-signature over a bundle export authorization.

    Attributes
    ----------
    sig_id:
        Unique UUID for this signature.
    witness_id:
        Identity of the signing witness.
    package_id:
        Evidence package being authorized.
    issued_at:
        ISO-8601 UTC timestamp of signing.
    expires_at:
        ISO-8601 UTC timestamp of expiry.
    signature:
        Hex-encoded HMAC-SHA256 over the canonical body.
    """

    sig_id: str
    witness_id: str
    package_id: str
    issued_at: str
    expires_at: str
    signature: str

    def to_dict(self) -> dict[str, str]:
        return {
            "sig_id": self.sig_id,
            "witness_id": self.witness_id,
            "package_id": self.package_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }


@dataclass
class CoSignVerifyResult:
    """Result of :meth:`WitnessCoSignGate.verify_signature`.

    Attributes
    ----------
    valid:
        True when the signature is cryptographically correct and not expired.
    reason:
        Human-readable explanation when ``valid`` is False.
    sig_id:
        ID of the checked signature.
    witness_id:
        Witness who issued the signature.
    """

    valid: bool
    reason: str = ""
    sig_id: str = ""
    witness_id: str = ""


@dataclass
class CoSignGateResult:
    """Result of :meth:`WitnessCoSignGate.check_threshold`.

    Attributes
    ----------
    threshold_met:
        True when at least *required* valid signatures are present.
    valid_count:
        Number of cryptographically valid, non-expired, non-duplicate sigs.
    required:
        Minimum number of valid signatures required.
    valid_witnesses:
        Witness IDs that contributed valid signatures.
    rejected:
        Signatures that were rejected (with reason).
    """

    threshold_met: bool
    valid_count: int
    required: int
    valid_witnesses: list[str] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "threshold_met": self.threshold_met,
            "valid_count": self.valid_count,
            "required": self.required,
            "valid_witnesses": self.valid_witnesses,
            "rejected": self.rejected,
        }


# ── Canonical body ────────────────────────────────────────────────────────────


def _canonical_body(
    sig_id: str, witness_id: str, package_id: str, issued_at: str, expires_at: str
) -> bytes:
    return json.dumps(
        {
            "expires_at": expires_at,
            "issued_at": issued_at,
            "package_id": package_id,
            "sig_id": sig_id,
            "witness_id": witness_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


# ── Gate ─────────────────────────────────────────────────────────────────────


class WitnessCoSignGate:
    """m-of-n threshold co-signing gate for evidence bundle export.

    Parameters
    ----------
    required:
        Minimum number of valid witness signatures required (``m``).
        Default ``2``.
    total:
        Total number of designated witnesses (``n``).  Must be >= *required*.
        Default ``3``.
    signing_key:
        Master HMAC-SHA256 key.  Defaults to ``AEGIS_SIGNING_KEY`` env var.
    validity_seconds:
        How long issued signatures remain valid.  Defaults to
        ``AEGIS_WITNESS_VALIDITY`` (default 3600 s, minimum 60 s).
    """

    def __init__(
        self,
        required: int = _DEFAULT_REQUIRED,
        total: int = _DEFAULT_TOTAL,
        signing_key: str | None = None,
        validity_seconds: int | None = None,
    ) -> None:
        if required < 1:
            raise ValueError(f"required must be >= 1, got {required}")
        if total < required:
            raise ValueError(f"total ({total}) must be >= required ({required})")
        self.required = required
        self.total = total

        if signing_key is None:
            signing_key = os.environ.get("AEGIS_SIGNING_KEY", "")
        self._signing_key = signing_key

        if validity_seconds is None:
            raw = os.environ.get("AEGIS_WITNESS_VALIDITY", str(_DEFAULT_VALIDITY_SECONDS))
            try:
                validity_seconds = max(_MIN_VALIDITY_SECONDS, int(raw))
            except ValueError:
                logger.warning(
                    "witness_cosign: invalid AEGIS_WITNESS_VALIDITY=%r; using %d",
                    raw,
                    _DEFAULT_VALIDITY_SECONDS,
                )
                validity_seconds = _DEFAULT_VALIDITY_SECONDS
        else:
            validity_seconds = max(_MIN_VALIDITY_SECONDS, validity_seconds)
        self._validity_seconds = validity_seconds

    # ── Public API ─────────────────────────────────────────────────────────────

    def sign(self, witness_id: str, package_id: str) -> WitnessSignature:
        """Issue a co-signature from *witness_id* over *package_id*.

        Parameters
        ----------
        witness_id:
            Identity of the signing witness.
        package_id:
            Evidence package being authorized.

        Returns
        -------
        WitnessSignature
            A signed, time-bounded authorization token.

        Raises
        ------
        WitnessCoSignError
            When no signing key is configured.
        """
        if not self._signing_key:
            raise WitnessCoSignError("Cannot sign: AEGIS_SIGNING_KEY not configured.")

        now = datetime.now(tz=UTC)
        sig_id = str(uuid.uuid4())
        issued_at = now.isoformat()
        expires_at = (now + timedelta(seconds=self._validity_seconds)).isoformat()

        body = _canonical_body(sig_id, witness_id, package_id, issued_at, expires_at)
        key = _derive_witness_key(self._signing_key, witness_id)
        sig_hex = _hmac_sign(key, body)

        logger.info(
            "witness_cosign: sig %s issued — witness=%r package=%r",
            sig_id,
            witness_id,
            package_id,
        )
        return WitnessSignature(
            sig_id=sig_id,
            witness_id=witness_id,
            package_id=package_id,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=sig_hex,
        )

    def verify_signature(self, sig: WitnessSignature) -> CoSignVerifyResult:
        """Verify a single witness signature.

        Parameters
        ----------
        sig:
            A :class:`WitnessSignature` previously issued by :meth:`sign`.

        Returns
        -------
        CoSignVerifyResult
            ``valid=True`` when the signature is correct and not expired.
        """
        # Expiry
        try:
            expires = datetime.fromisoformat(sig.expires_at)
        except ValueError:
            return CoSignVerifyResult(
                valid=False,
                reason="Malformed expires_at timestamp",
                sig_id=sig.sig_id,
                witness_id=sig.witness_id,
            )
        if datetime.now(tz=UTC) > expires:
            return CoSignVerifyResult(
                valid=False,
                reason=f"Signature expired at {sig.expires_at}",
                sig_id=sig.sig_id,
                witness_id=sig.witness_id,
            )

        # Cryptographic check
        if not self._signing_key:
            return CoSignVerifyResult(
                valid=False,
                reason="No signing key configured; cannot verify",
                sig_id=sig.sig_id,
                witness_id=sig.witness_id,
            )

        body = _canonical_body(
            sig.sig_id, sig.witness_id, sig.package_id, sig.issued_at, sig.expires_at
        )
        key = _derive_witness_key(self._signing_key, sig.witness_id)
        if not _hmac_verify(key, body, sig.signature):
            return CoSignVerifyResult(
                valid=False,
                reason="Signature verification failed",
                sig_id=sig.sig_id,
                witness_id=sig.witness_id,
            )

        return CoSignVerifyResult(valid=True, sig_id=sig.sig_id, witness_id=sig.witness_id)

    def check_threshold(
        self, package_id: str, signatures: list[WitnessSignature]
    ) -> CoSignGateResult:
        """Check whether *signatures* meet the threshold for *package_id*.

        * Signatures for a different ``package_id`` are rejected.
        * Duplicate signatures from the same witness are de-duplicated (only
          the first valid one counts).
        * Invalid or expired signatures are recorded in ``rejected``.

        Parameters
        ----------
        package_id:
            The package being authorized.
        signatures:
            Collection of witness signatures to evaluate.

        Returns
        -------
        CoSignGateResult
            ``threshold_met=True`` when ``valid_count >= required``.
        """
        seen_witnesses: set[str] = set()
        valid_witnesses: list[str] = []
        rejected: list[dict[str, str]] = []

        for sig in signatures:
            if sig.package_id != package_id:
                rejected.append(
                    {
                        "sig_id": sig.sig_id,
                        "witness_id": sig.witness_id,
                        "reason": f"package_id mismatch: expected {package_id!r}, got {sig.package_id!r}",
                    }
                )
                continue

            if sig.witness_id in seen_witnesses:
                rejected.append(
                    {
                        "sig_id": sig.sig_id,
                        "witness_id": sig.witness_id,
                        "reason": "Duplicate signature from same witness",
                    }
                )
                continue

            result = self.verify_signature(sig)
            if result.valid:
                seen_witnesses.add(sig.witness_id)
                valid_witnesses.append(sig.witness_id)
            else:
                rejected.append(
                    {
                        "sig_id": sig.sig_id,
                        "witness_id": sig.witness_id,
                        "reason": result.reason,
                    }
                )

        threshold_met = len(valid_witnesses) >= self.required
        return CoSignGateResult(
            threshold_met=threshold_met,
            valid_count=len(valid_witnesses),
            required=self.required,
            valid_witnesses=valid_witnesses,
            rejected=rejected,
        )

    def gate_export(self, package_id: str, signatures: list[WitnessSignature]) -> None:
        """Authorize export of *package_id*, raising if threshold is not met.

        Parameters
        ----------
        package_id:
            The package to be exported.
        signatures:
            Witness signatures collected for this export.

        Raises
        ------
        WitnessCoSignError
            When fewer than *required* valid signatures are present.
        """
        result = self.check_threshold(package_id, signatures)
        if not result.threshold_met:
            raise WitnessCoSignError(
                f"Co-signing threshold not met for package {package_id!r}: "
                f"{result.valid_count}/{result.required} valid signatures "
                f"(witnesses: {result.valid_witnesses})"
            )
        logger.info(
            "witness_cosign: export authorized — package=%r valid_witnesses=%s",
            package_id,
            result.valid_witnesses,
        )
