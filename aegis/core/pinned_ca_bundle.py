# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.pinned_ca_bundle — Domain 1.3 air-gapped certificate chain verification.

Verifies X.509 certificate chains against a set of pinned SHA-256 fingerprints
without any runtime CA fetch, OCSP request, or CRL download.  Intended for
air-gapped and disconnected deployments where the trust anchors are pre-loaded
at build time.

Trust model
-----------
A certificate (or a certificate anywhere in the chain) is trusted if and only
if its SHA-256 DER fingerprint appears in the pinned set.  Cryptographic path
validation (signature chains) is intentionally *not* performed here — the sole
criterion is fingerprint membership.  Callers that require full path validation
should layer this module on top of the ``cryptography`` library's X.509 path
builder.

Soft dependency
---------------
The ``cryptography`` package is required for PEM parsing and DER conversion.
When absent, ``HAS_CRYPTOGRAPHY`` is ``False`` and operations that require it
raise :class:`PinnedCAUnavailableError`.

Usage::

    bundle = PinnedCABundle.from_env()
    result = bundle.verify_cert(cert_pem)
    if not result.trusted:
        raise TLSError(result.reason)

    # Or add a cert at runtime:
    pinned = bundle.add_pinned_cert(root_ca_pem, label="internal-root")
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ── Optional cryptography import ──────────────────────────────────────────────

_x509: Any
_Encoding: Any
try:
    from cryptography import x509 as imported_x509
    from cryptography.hazmat.primitives.serialization import Encoding as ImportedEncoding

    _x509 = imported_x509
    _Encoding = ImportedEncoding
    HAS_CRYPTOGRAPHY: bool = True
except ModuleNotFoundError:
    _x509 = None
    _Encoding = None
    HAS_CRYPTOGRAPHY = False
    logger.warning(
        "cryptography package not installed — PinnedCABundle unavailable. "
        "Install with: pip install cryptography"
    )


# ── Exceptions ────────────────────────────────────────────────────────────────


class PinnedCAError(Exception):
    """Base error for pinned CA bundle failures."""


class PinnedCAUnavailableError(PinnedCAError):
    """Raised when the cryptography package is not installed."""


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PinnedCert:
    """An immutable record of a pinned certificate fingerprint.

    Attributes
    ----------
    sha256_fingerprint:
        Lowercase hex SHA-256 of the DER-encoded certificate (no colons).
    label:
        Human-readable label for the pinned entry (e.g. ``"internal-root"``).
    added_at:
        UTC epoch when this fingerprint was added to the bundle.
    """

    sha256_fingerprint: str
    label: str
    added_at: float


@dataclass
class CertVerificationResult:
    """Outcome of a certificate or chain verification.

    Attributes
    ----------
    trusted:
        True when a fingerprint in the pinned set matched.
    matched_fingerprint:
        The pinned fingerprint that produced a match, or ``None``.
    cert_subject:
        Subject DN string of the evaluated leaf certificate.
    cert_issuer:
        Issuer DN string of the evaluated leaf certificate.
    reason:
        Human-readable description of the outcome.
    """

    trusted: bool
    matched_fingerprint: str | None
    cert_subject: str
    cert_issuer: str
    reason: str


# ── Core class ────────────────────────────────────────────────────────────────


class PinnedCABundle:
    """Offline certificate chain verification against pinned SHA-256 fingerprints.

    Instantiate via :meth:`from_env` to read pinned fingerprints from the
    environment, or construct directly and call :meth:`add_pinned_cert` /
    :meth:`add_pinned_fingerprint` to build the trust set programmatically.
    """

    def __init__(self) -> None:
        self._pinned: list[PinnedCert] = []

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> PinnedCABundle:
        """Construct from environment variables.

        Reads
        -----
        ``AEGIS_PINNED_CA_FINGERPRINTS``
            Comma-separated lowercase hex SHA-256 fingerprints.
        ``AEGIS_PINNED_CA_LABELS``
            Optional comma-separated labels (must match fingerprint count if set).

        Returns
        -------
        PinnedCABundle
            Bundle pre-populated with the pinned fingerprints from the
            environment.  Returns an empty bundle when the variable is absent.
        """
        bundle = cls()
        raw_fps = os.environ.get("AEGIS_PINNED_CA_FINGERPRINTS", "")
        if not raw_fps:
            return bundle

        fingerprints = [fp.strip() for fp in raw_fps.split(",") if fp.strip()]
        raw_labels = os.environ.get("AEGIS_PINNED_CA_LABELS", "")
        labels: list[str] = []
        if raw_labels:
            labels = [lb.strip() for lb in raw_labels.split(",")]

        for i, fp in enumerate(fingerprints):
            label = labels[i] if i < len(labels) else ""
            bundle.add_pinned_fingerprint(fp, label=label)

        return bundle

    # ── Mutation ──────────────────────────────────────────────────────────────

    def add_pinned_cert(self, cert_pem: bytes, label: str = "") -> PinnedCert:
        """Compute the fingerprint of *cert_pem* and add it to the trust set.

        Parameters
        ----------
        cert_pem:
            PEM-encoded X.509 certificate bytes.
        label:
            Optional human-readable name for this entry.

        Returns
        -------
        PinnedCert
            The newly added pinned entry.
        """
        fingerprint = self.compute_fingerprint(cert_pem)
        return self.add_pinned_fingerprint(fingerprint, label=label)

    def add_pinned_fingerprint(self, sha256_hex: str, label: str = "") -> PinnedCert:
        """Add a raw hex fingerprint to the trust set without PEM parsing.

        Parameters
        ----------
        sha256_hex:
            Lowercase hex SHA-256 fingerprint (64 characters, no colons).
        label:
            Optional human-readable name for this entry.

        Returns
        -------
        PinnedCert
            The newly added pinned entry.
        """
        normalized = sha256_hex.lower().replace(":", "")
        if len(normalized) != 64:
            raise PinnedCAError(f"SHA-256 fingerprint must be 64 hex chars (got {len(normalized)})")
        pinned = PinnedCert(
            sha256_fingerprint=normalized,
            label=label,
            added_at=time.time(),
        )
        self._pinned.append(pinned)
        return pinned

    # ── Verification ──────────────────────────────────────────────────────────

    def verify_cert(self, cert_pem: bytes) -> CertVerificationResult:
        """Verify a single certificate against the pinned set.

        Parameters
        ----------
        cert_pem:
            PEM-encoded X.509 certificate bytes.

        Returns
        -------
        CertVerificationResult
            Trusted when the certificate's SHA-256 DER fingerprint is pinned.
        """
        _require_cryptography()
        cert = _x509.load_pem_x509_certificate(cert_pem)
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        fingerprint = self.compute_fingerprint(cert_pem)

        for pinned in self._pinned:
            if pinned.sha256_fingerprint == fingerprint:
                return CertVerificationResult(
                    trusted=True,
                    matched_fingerprint=fingerprint,
                    cert_subject=subject,
                    cert_issuer=issuer,
                    reason=f"fingerprint matched pinned entry: {pinned.label or fingerprint[:16]}",
                )

        return CertVerificationResult(
            trusted=False,
            matched_fingerprint=None,
            cert_subject=subject,
            cert_issuer=issuer,
            reason="certificate fingerprint not in pinned set",
        )

    def verify_cert_chain(self, cert_pem_list: list[bytes]) -> CertVerificationResult:
        """Trust if ANY certificate in the chain matches a pinned fingerprint.

        Parameters
        ----------
        cert_pem_list:
            Ordered list of PEM-encoded certificates (leaf first is conventional,
            but order does not affect the result).

        Returns
        -------
        CertVerificationResult
            Result based on the leaf certificate's metadata, trusted if any
            chain member matches a pinned fingerprint.
        """
        _require_cryptography()
        if not cert_pem_list:
            return CertVerificationResult(
                trusted=False,
                matched_fingerprint=None,
                cert_subject="",
                cert_issuer="",
                reason="empty certificate chain",
            )

        leaf_cert = _x509.load_pem_x509_certificate(cert_pem_list[0])
        leaf_subject = leaf_cert.subject.rfc4514_string()
        leaf_issuer = leaf_cert.issuer.rfc4514_string()

        pinned_fps = {p.sha256_fingerprint: p for p in self._pinned}

        for cert_pem in cert_pem_list:
            fp = self.compute_fingerprint(cert_pem)
            if fp in pinned_fps:
                pinned = pinned_fps[fp]
                return CertVerificationResult(
                    trusted=True,
                    matched_fingerprint=fp,
                    cert_subject=leaf_subject,
                    cert_issuer=leaf_issuer,
                    reason=(
                        f"chain member fingerprint matched pinned entry: {pinned.label or fp[:16]}"
                    ),
                )

        return CertVerificationResult(
            trusted=False,
            matched_fingerprint=None,
            cert_subject=leaf_subject,
            cert_issuer=leaf_issuer,
            reason="no chain member fingerprint found in pinned set",
        )

    # ── Inspection ────────────────────────────────────────────────────────────

    def list_pinned(self) -> list[PinnedCert]:
        """Return a copy of the list of all pinned certificates."""
        return list(self._pinned)

    def count(self) -> int:
        """Return the number of pinned fingerprints."""
        return len(self._pinned)

    # ── Static helpers ────────────────────────────────────────────────────────

    @staticmethod
    def compute_fingerprint(cert_pem: bytes) -> str:
        """Compute the SHA-256 fingerprint of a PEM certificate.

        Parameters
        ----------
        cert_pem:
            PEM-encoded X.509 certificate bytes.

        Returns
        -------
        str
            Lowercase hex SHA-256 of the DER-encoded certificate (no colons).
        """
        _require_cryptography()
        cert = _x509.load_pem_x509_certificate(cert_pem)
        der = cert.public_bytes(_Encoding.DER)
        return hashlib.sha256(der).hexdigest()


# ── Internal helpers ──────────────────────────────────────────────────────────


def _require_cryptography() -> None:
    if not HAS_CRYPTOGRAPHY:
        raise PinnedCAUnavailableError(
            "cryptography package is required for PinnedCABundle. "
            "Install with: pip install cryptography"
        )
