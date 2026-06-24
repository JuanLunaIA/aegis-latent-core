# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
r"""aegis.core.operator_seal — HSM-signed operator attestation gate for bundle export.

Before any evidence bundle can be exported, the operator must present a valid
:class:`OperatorAttestation`.  The attestation is signed with:

* **HMAC-SHA256** when no HSM is configured (software fallback, always available).
* **HSM-PKCS#11** when a :class:`~aegis.core.hsm.HSMSigningBackend` is injected;
  the hardware-derived asymmetric signature is stored in ``signature``, the
  exported public key (``SubjectPublicKeyInfo`` DER hex) in ``public_key``, and
  the precise scheme in ``signature_scheme`` (``"pkcs11-rsa-pss-sha256"`` or
  ``"pkcs11-ecdsa-sha256"``).  Verification is a real asymmetric check against
  the published public key (``cryptography``) and does **not** require the HSM
  to be present at verify time.

Both schemes are explicitly permitted by the Aegis security policy
(HMAC-SHA256, and asymmetric RSA-PSS/ECDSA, both qualify under the
"HMAC-SHA256 or asymmetric signature" rule).

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
        ``"hmac-sha256"``, ``"pkcs11-rsa-pss-sha256"``, or
        ``"pkcs11-ecdsa-sha256"``.
    public_key:
        Hex-encoded ``SubjectPublicKeyInfo`` DER of the signing key, for
        asymmetric (HSM) schemes.  Empty for symmetric ``hmac-sha256``.
        Carrying the public key makes asymmetric attestations verifiable
        **without** the HSM present at verify time (the whole point of an
        asymmetric scheme: anyone with the public key can verify).
    """

    attestation_id: str
    operator_id: str
    package_id: str
    action: str
    issued_at: str
    expires_at: str
    signature: str
    signature_scheme: str
    public_key: str = ""

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
            "public_key": self.public_key,
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


# Precise asymmetric HSM schemes produced by HSMSigningBackend.sign().
_PKCS11_RSA_SCHEME = "pkcs11-rsa-pss-sha256"
_PKCS11_EC_SCHEME = "pkcs11-ecdsa-sha256"
_ASYMMETRIC_SCHEMES = frozenset({_PKCS11_RSA_SCHEME, _PKCS11_EC_SCHEME})


def _verify_asymmetric(public_key_der: bytes, scheme: str, data: bytes, signature: bytes) -> bool:
    """Verify an asymmetric HSM signature using the published public key.

    Uses ``cryptography`` only — no HSM is required at verify time.

    * ``pkcs11-rsa-pss-sha256`` — RSA-PSS over SHA-256, MGF1-SHA-256, salt=32
      (matching ``CKM_SHA256_RSA_PKCS_PSS`` as emitted by the HSM backend).
    * ``pkcs11-ecdsa-sha256`` — ECDSA over SHA-256.  PKCS#11 ``CKM_ECDSA``
      emits the raw ``r ‖ s`` concatenation, whereas ``cryptography`` expects a
      DER-encoded signature, so we reconstruct the DER form before verifying.

    Returns ``False`` (never raises) on any malformed input, key-load failure,
    or signature mismatch.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    try:
        public_key = load_der_public_key(public_key_der)
    except Exception as exc:
        logger.warning("operator_seal: could not load public key for %s: %s", scheme, exc)
        return False

    try:
        if scheme == _PKCS11_RSA_SCHEME:
            public_key.verify(  # type: ignore[union-attr]
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
            return True
        if scheme == _PKCS11_EC_SCHEME:
            if len(signature) == 0 or len(signature) % 2 != 0:
                logger.warning(
                    "operator_seal: malformed raw ECDSA signature (length %d)", len(signature)
                )
                return False
            half = len(signature) // 2
            r = int.from_bytes(signature[:half], "big")
            s = int.from_bytes(signature[half:], "big")
            der_sig = asym_utils.encode_dss_signature(r, s)
            public_key.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]
            return True
    except InvalidSignature:
        return False
    except Exception as exc:
        logger.warning("operator_seal: asymmetric verify error (%s): %s", scheme, exc)
        return False

    logger.warning("operator_seal: unsupported asymmetric scheme %r", scheme)
    return False


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

        signature, scheme, public_key = self._sign(body)

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
            public_key=public_key,
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

        if not self._verify_sig(
            body,
            attestation.signature,
            attestation.signature_scheme,
            attestation.public_key,
        ):
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

    def _sign(self, data: bytes) -> tuple[str, str, str]:
        """Return ``(signature_hex, scheme_name, public_key_hex)``.

        When an HSM backend is available, the asymmetric signature, its precise
        scheme (``pkcs11-rsa-pss-sha256`` / ``pkcs11-ecdsa-sha256``), and the
        exported ``SubjectPublicKeyInfo`` DER are returned so the attestation is
        verifiable without the HSM.  Falls back to HMAC-SHA256 on any HSM error.
        """
        if self._hsm_available():
            try:
                # HSMSigningBackend.sign() -> (sig_bytes, public_key_hex, scheme).
                sig_bytes, pub_hex, scheme = self._hsm.sign(data)  # type: ignore[union-attr]
                if not pub_hex:
                    raise OperatorSealError(
                        f"HSM returned no public key for scheme {scheme!r}; "
                        "cannot issue a verifiable asymmetric attestation"
                    )
                return sig_bytes.hex(), scheme, pub_hex
            except Exception as exc:
                logger.warning(
                    "operator_seal: HSM sign failed (%s); falling back to HMAC-SHA256", exc
                )

        if not self._signing_key:
            raise OperatorSealError(
                "Cannot sign: AEGIS_SIGNING_KEY not configured and HSM unavailable."
            )
        return _hmac_sign(self._signing_key, data), "hmac-sha256", ""

    def _verify_sig(self, data: bytes, sig_hex: str, scheme: str, public_key_hex: str = "") -> bool:
        """Verify *sig_hex* against *data* using the appropriate scheme."""
        if scheme == "hmac-sha256":
            if not self._signing_key:
                logger.warning(
                    "operator_seal: cannot verify hmac-sha256 attestation — AEGIS_SIGNING_KEY absent"
                )
                return False
            return _hmac_verify(self._signing_key, data, sig_hex)

        if scheme in _ASYMMETRIC_SCHEMES:
            # Real asymmetric verification with the published public key — no HSM
            # needed at verify time. (The previous re-sign-and-compare approach
            # could never validate a randomized RSA-PSS / ECDSA signature.)
            if not public_key_hex:
                logger.warning(
                    "operator_seal: %s attestation carries no public key; cannot verify — rejecting",
                    scheme,
                )
                return False
            try:
                pub_der = bytes.fromhex(public_key_hex)
                sig = bytes.fromhex(sig_hex)
            except ValueError:
                logger.warning("operator_seal: malformed hex in %s attestation; rejecting", scheme)
                return False
            return _verify_asymmetric(pub_der, scheme, data, sig)

        if scheme == "hsm-pkcs11":
            # Legacy generic label (pre-asymmetric-verify). Without the precise
            # algorithm and the public key it is not soundly verifiable; reject
            # rather than fall back to the old broken re-sign comparison.
            logger.warning(
                "operator_seal: legacy 'hsm-pkcs11' scheme is not verifiable "
                "(no algorithm/public key); rejecting"
            )
            return False

        logger.warning("operator_seal: unknown signature scheme %r; rejecting", scheme)
        return False
