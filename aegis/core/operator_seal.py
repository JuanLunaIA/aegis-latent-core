# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
r"""aegis.core.operator_seal — HSM-signed operator attestation gate for bundle export.

Before any evidence bundle can be exported, the operator must present a valid
:class:`OperatorAttestation`.  The attestation is signed with:

* **HMAC-SHA256** when no HSM is configured (software fallback, always available).
* **HSM-PKCS#11** when a :class:`~aegis.core.hsm.HSMSigningBackend` is injected;
  the hardware-derived signature is stored in ``signature`` and the scheme is
  ``"hsm-pkcs11"``.

Both schemes are explicitly permitted by the Aegis security policy
(HMAC-SHA256 and HSM-backed HMAC both qualify as "HMAC-SHA256 or ML-DSA").

Attestations are:

* **Time-bounded** — they expire after a configurable window (default 1 hour).
* **Package-bound** — optionally scoped to a specific ``package_id``; a
  broad attestation (``package_id=""``\ ) authorizes any package.
* **Non-reusable across packages** — the gate rejects attestations issued for
  a different package than the one being exported.

Typical usage::

    from aegis.core.operator_seal import OperatorSealGate

    gate = OperatorSealGate()          # reads AEGIS_SIGNING_KEY from env
    attestation = gate.create_attestation(operator_id="badge-1234", package_id="pkg-abc")
    gate.gate_export(package_id="pkg-abc", attestation=attestation)
    # … now safe to call build_evidence_package() …

Configuration
-------------
``AEGIS_SIGNING_KEY``
    HMAC-SHA256 signing key for operator attestations.  **Must be separate
    from API keys.**  Required when no HSM backend is provided.

``AEGIS_OPERATOR_SEAL_VALIDITY``
    Attestation validity window in seconds (default ``3600``; minimum ``60``).
"""

from __future__ import annotations

import hashlib
import hmac as _hmac_module
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)

_DEFAULT_VALIDITY_SECONDS = 3600
_MIN_VALIDITY_SECONDS = 60
_BUNDLE_EXPORT_ACTION = "bundle_export"


# ── Exceptions ────────────────────────────────────────────────────────────────


class OperatorSealError(Exception):
    """Raised when an operator attestation is missing, invalid, or expired."""


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class OperatorAttestation:
    """A signed operator authorization for a specific bundle export.

    Attributes
    ----------
    attestation_id:
        Unique UUID identifying this attestation.
    operator_id:
        Identity of the approving operator (badge number, user ID, etc.).
    package_id:
        Evidence package being authorized.  ``""`` = broad authorization.
    action:
        Always ``"bundle_export"`` — identifies what is being authorized.
    issued_at:
        ISO-8601 UTC timestamp of issuance.
    expires_at:
        ISO-8601 UTC timestamp after which the attestation is no longer valid.
    signature:
        Hex-encoded HMAC-SHA256 or HSM signature over the canonical body.
    signature_scheme:
        ``"hmac-sha256"`` or ``"hsm-pkcs11"``.
    """

    attestation_id: str
    operator_id: str
    package_id: str
    action: str
    issued_at: str
    expires_at: str
    signature: str
    signature_scheme: str

    def to_dict(self) -> dict[str, str]:
        return {
            "attestation_id": self.attestation_id,
            "operator_id": self.operator_id,
            "package_id": self.package_id,
            "action": self.action,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
            "signature_scheme": self.signature_scheme,
        }


@dataclass
class OperatorSealVerifyResult:
    """Result of :meth:`OperatorSealGate.verify_attestation`.

    Attributes
    ----------
    valid:
        True when the attestation signature is correct and not expired.
    reason:
        Human-readable explanation when ``valid`` is False.
    attestation_id:
        ID of the checked attestation.
    operator_id:
        Operator who issued the attestation.
    """

    valid: bool
    reason: str = ""
    attestation_id: str = ""
    operator_id: str = ""


# ── Signing helpers ───────────────────────────────────────────────────────────


def _canonical_body(
    attestation_id: str,
    operator_id: str,
    package_id: str,
    action: str,
    issued_at: str,
    expires_at: str,
) -> bytes:
    """Return deterministic JSON bytes that the signature covers."""
    return json.dumps(
        {
            "action": action,
            "attestation_id": attestation_id,
            "expires_at": expires_at,
            "issued_at": issued_at,
            "operator_id": operator_id,
            "package_id": package_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _hmac_sign(key: str, data: bytes) -> str:
    return _hmac_module.new(key.encode(), data, hashlib.sha256).hexdigest()


def _hmac_verify(key: str, data: bytes, expected_hex: str) -> bool:
    actual = _hmac_sign(key, data)
    return _hmac_module.compare_digest(actual, expected_hex)


# ── Gate ─────────────────────────────────────────────────────────────────────


class OperatorSealGate:
    """Gate requiring a signed operator attestation before evidence bundle export.

    Parameters
    ----------
    signing_key:
        HMAC-SHA256 key for signing attestations.  Defaults to
        ``AEGIS_SIGNING_KEY`` env var.  **Must not be the same as API keys.**
    hsm_backend:
        Optional :class:`~aegis.core.hsm.HSMSigningBackend` instance.  When
        available and operational, HSM signing is preferred over HMAC-SHA256.
    validity_seconds:
        How long issued attestations remain valid (default ``3600`` s, min
        ``60`` s).  Overridden by ``AEGIS_OPERATOR_SEAL_VALIDITY`` env var.
    """

    def __init__(
        self,
        signing_key: str | None = None,
        hsm_backend: object | None = None,
        validity_seconds: int | None = None,
    ) -> None:
        if signing_key is None:
            signing_key = os.environ.get("AEGIS_SIGNING_KEY", "")
        self._signing_key = signing_key
        self._hsm = hsm_backend

        if validity_seconds is None:
            raw = os.environ.get("AEGIS_OPERATOR_SEAL_VALIDITY", str(_DEFAULT_VALIDITY_SECONDS))
            try:
                validity_seconds = max(_MIN_VALIDITY_SECONDS, int(raw))
            except ValueError:
                logger.warning(
                    "operator_seal: invalid AEGIS_OPERATOR_SEAL_VALIDITY=%r; using %d",
                    raw,
                    _DEFAULT_VALIDITY_SECONDS,
                )
                validity_seconds = _DEFAULT_VALIDITY_SECONDS
        else:
            validity_seconds = max(_MIN_VALIDITY_SECONDS, validity_seconds)
        self._validity_seconds = validity_seconds

    # ── Public API ────────────────────────────────────────────────────────────

    def create_attestation(self, operator_id: str, package_id: str = "") -> OperatorAttestation:
        """Issue a signed attestation authorizing export of *package_id*.

        Parameters
        ----------
        operator_id:
            Identity of the approving operator (badge ID, username, etc.).
        package_id:
            The evidence package being authorized.  Pass ``""`` to issue a
            broad authorization (any package within the validity window).

        Returns
        -------
        OperatorAttestation
            Pass to :meth:`gate_export` to authorize the export.

        Raises
        ------
        OperatorSealError
            When neither a signing key nor an HSM backend is available.
        """
        if not self._signing_key and not self._hsm_available():
            raise OperatorSealError(
                "Cannot create attestation: AEGIS_SIGNING_KEY not configured and no HSM available."
            )

        now = datetime.now(tz=UTC)
        attestation_id = str(uuid.uuid4())
        issued_at = now.isoformat()
        expires_at = (now + timedelta(seconds=self._validity_seconds)).isoformat()

        body = _canonical_body(
            attestation_id, operator_id, package_id, _BUNDLE_EXPORT_ACTION, issued_at, expires_at
        )

        signature, scheme = self._sign(body)

        logger.info(
            "operator_seal: attestation %s issued for operator=%r package=%r scheme=%s",
            attestation_id,
            operator_id,
            package_id or "<any>",
            scheme,
        )
        return OperatorAttestation(
            attestation_id=attestation_id,
            operator_id=operator_id,
            package_id=package_id,
            action=_BUNDLE_EXPORT_ACTION,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature,
            signature_scheme=scheme,
        )

    def verify_attestation(self, attestation: OperatorAttestation) -> OperatorSealVerifyResult:
        """Verify signature and expiry of *attestation*.

        Does **not** check ``package_id`` binding — use :meth:`gate_export`
        for the full authorization check.

        Parameters
        ----------
        attestation:
            An :class:`OperatorAttestation` previously issued by
            :meth:`create_attestation`.

        Returns
        -------
        OperatorSealVerifyResult
            ``valid=True`` when the signature is correct and not expired.
        """
        aid = attestation.attestation_id
        oid = attestation.operator_id

        if attestation.action != _BUNDLE_EXPORT_ACTION:
            return OperatorSealVerifyResult(
                valid=False,
                reason=f"Unexpected action {attestation.action!r}; expected {_BUNDLE_EXPORT_ACTION!r}",
                attestation_id=aid,
                operator_id=oid,
            )

        # Expiry check
        try:
            expires = datetime.fromisoformat(attestation.expires_at)
        except ValueError:
            return OperatorSealVerifyResult(
                valid=False,
                reason="Malformed expires_at timestamp",
                attestation_id=aid,
                operator_id=oid,
            )
        if datetime.now(tz=UTC) > expires:
            return OperatorSealVerifyResult(
                valid=False,
                reason=f"Attestation expired at {attestation.expires_at}",
                attestation_id=aid,
                operator_id=oid,
            )

        # Signature check
        body = _canonical_body(
            attestation.attestation_id,
            attestation.operator_id,
            attestation.package_id,
            attestation.action,
            attestation.issued_at,
            attestation.expires_at,
        )

        if not self._verify_sig(body, attestation.signature, attestation.signature_scheme):
            if attestation.signature_scheme == "hsm-pkcs11" and not self._hsm_available():
                reason = "HSM not available to verify hsm-pkcs11 attestation"
            else:
                reason = f"Signature verification failed (scheme={attestation.signature_scheme})"
            return OperatorSealVerifyResult(
                valid=False,
                reason=reason,
                attestation_id=aid,
                operator_id=oid,
            )

        return OperatorSealVerifyResult(valid=True, attestation_id=aid, operator_id=oid)

    def gate_export(self, package_id: str, attestation: OperatorAttestation) -> None:
        """Authorize export of *package_id*, raising on any failure.

        Parameters
        ----------
        package_id:
            The evidence package about to be exported.
        attestation:
            Operator attestation issued by :meth:`create_attestation`.

        Raises
        ------
        OperatorSealError
            When the attestation is invalid, expired, or bound to a different
            package than *package_id*.
        """
        result = self.verify_attestation(attestation)
        if not result.valid:
            raise OperatorSealError(
                f"Operator attestation {attestation.attestation_id!r} rejected: {result.reason}"
            )

        if attestation.package_id and attestation.package_id != package_id:
            raise OperatorSealError(
                f"Attestation {attestation.attestation_id!r} is bound to package "
                f"{attestation.package_id!r}; cannot authorize export of {package_id!r}."
            )

        logger.info(
            "operator_seal: export authorized — operator=%r package=%r attestation=%s scheme=%s",
            attestation.operator_id,
            package_id or "<any>",
            attestation.attestation_id,
            attestation.signature_scheme,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _hsm_available(self) -> bool:
        return self._hsm is not None and getattr(self._hsm, "_available", False)

    def _sign(self, data: bytes) -> tuple[str, str]:
        """Return (signature_hex, scheme_name)."""
        if self._hsm_available():
            try:
                sig_bytes = self._hsm.sign(data)  # type: ignore[union-attr]
                return sig_bytes.hex(), "hsm-pkcs11"
            except Exception as exc:
                logger.warning(
                    "operator_seal: HSM sign failed (%s); falling back to HMAC-SHA256", exc
                )

        if not self._signing_key:
            raise OperatorSealError(
                "Cannot sign: AEGIS_SIGNING_KEY not configured and HSM unavailable."
            )
        return _hmac_sign(self._signing_key, data), "hmac-sha256"

    def _verify_sig(self, data: bytes, sig_hex: str, scheme: str) -> bool:
        """Verify *sig_hex* against *data* using the appropriate scheme."""
        if scheme == "hmac-sha256":
            if not self._signing_key:
                logger.warning(
                    "operator_seal: cannot verify hmac-sha256 attestation — AEGIS_SIGNING_KEY absent"
                )
                return False
            return _hmac_verify(self._signing_key, data, sig_hex)

        if scheme == "hsm-pkcs11":
            if not self._hsm_available():
                logger.warning(
                    "operator_seal: HSM not available to verify hsm-pkcs11 attestation; rejecting"
                )
                return False
            # For symmetric HMAC-based HSM mechanisms: re-sign and compare.
            # For asymmetric HSM keys, a dedicated C_Verify call with the exported
            # public key is required — this stub uses re-sign comparison.
            try:
                expected = self._hsm.sign(data)  # type: ignore[union-attr]
                return _hmac_module.compare_digest(expected.hex(), sig_hex)
            except Exception as exc:
                logger.warning("operator_seal: HSM verify failed: %s", exc)
                return False

        logger.warning("operator_seal: unknown signature scheme %r; rejecting", scheme)
        return False
