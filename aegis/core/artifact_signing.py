# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.artifact_signing — sign & verify deployment artifacts (supply-chain
integrity).

Each artifact is hashed (SHA-256) and signed under one of three **real** schemes,
recorded honestly in the metadata:

* ``HMAC_SHA512`` — symmetric MAC with a caller-supplied key (re-compute + verify).
* ``ML_DSA_65``  — real post-quantum ML-DSA-65 signature (FIPS 204) via
  :class:`aegis.core.pqc_signer.PQCSigner`; the public key is published in the
  metadata and verification is asymmetric (no private key required to verify).

The previous version labelled an HMAC computation as a post-quantum (ML-DSA)
signature and verified asymmetric signatures by re-signing and comparing — which
only works for symmetric MACs. Both issues are fixed: the scheme is recorded
truthfully and ML-DSA verification uses the published public key.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from aegis.core.pqc_signer import PQCSigner, PQCUnavailableError

logger = logging.getLogger(__name__)


# ── Schemes ───────────────────────────────────────────────────────────────────


class SignatureScheme(StrEnum):
    HMAC_SHA512 = "hmac-sha512"
    ML_DSA_65 = "ml-dsa-65"


class ArtifactSigningError(Exception):
    """Raised when an artifact cannot be signed under the requested scheme."""


# ── Metadata ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ArtifactMetadata:
    artifact_id: str
    sha256: str
    signature: str  # hex
    scheme: str
    timestamp: str
    version: str
    public_key: str = ""  # hex; populated for asymmetric (ML-DSA) signatures

    def to_dict(self) -> dict[str, str]:
        return {
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
            "signature": self.signature,
            "scheme": self.scheme,
            "timestamp": self.timestamp,
            "version": self.version,
            "public_key": self.public_key,
        }


# ── Signer ────────────────────────────────────────────────────────────────────


class ArtifactSigner:
    """Sign and verify deployment artifacts.

    Parameters
    ----------
    signing_key:
        Symmetric key for ``HMAC_SHA512``. Required for that scheme; must be kept
        separate from any audit/API key by the caller.
    scheme:
        Which real signature scheme to use.
    pqc_signer:
        Optional pre-built :class:`PQCSigner` for ``ML_DSA_65`` (so a single
        signing identity can sign multiple artifacts). One is created on demand
        otherwise.
    """

    def __init__(
        self,
        signing_key: bytes | None = None,
        *,
        scheme: SignatureScheme = SignatureScheme.HMAC_SHA512,
        pqc_signer: PQCSigner | None = None,
    ) -> None:
        self._scheme = SignatureScheme(scheme)
        self._signing_key = signing_key
        self._pqc = pqc_signer

        if self._scheme is SignatureScheme.HMAC_SHA512 and not signing_key:
            raise ArtifactSigningError("HMAC_SHA512 scheme requires a signing_key")
        if self._scheme is SignatureScheme.ML_DSA_65 and self._pqc is None:
            try:
                self._pqc = PQCSigner(require_real=True)
            except PQCUnavailableError as exc:
                raise ArtifactSigningError(
                    "ML_DSA_65 scheme requires the real ML-DSA backend (aegis_rust)"
                ) from exc

    @property
    def scheme(self) -> SignatureScheme:
        return self._scheme

    def sign_artifact(self, artifact_path: str, version: str) -> ArtifactMetadata:
        """Hash and sign the artifact at *artifact_path*, returning its metadata."""
        with open(artifact_path, "rb") as f:
            data = f.read()
        sha256 = hashlib.sha256(data).hexdigest()

        public_key = ""
        if self._scheme is SignatureScheme.HMAC_SHA512:
            assert self._signing_key is not None  # enforced in __init__
            signature = hmac.new(self._signing_key, sha256.encode(), hashlib.sha512).hexdigest()
        else:  # ML_DSA_65
            assert self._pqc is not None  # enforced in __init__
            signature = self._pqc.sign(sha256.encode()).hex()
            public_key = self._pqc.public_key.hex()

        timestamp = datetime.now(UTC).isoformat()
        return ArtifactMetadata(
            artifact_id=artifact_path,
            sha256=sha256,
            signature=signature,
            scheme=self._scheme.value,
            timestamp=timestamp,
            version=version,
            public_key=public_key,
        )

    def verify_artifact(self, artifact_path: str, metadata: ArtifactMetadata) -> bool:
        """Verify the artifact's content hash and signature against *metadata*."""
        with open(artifact_path, "rb") as f:
            data = f.read()
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(actual_sha256, metadata.sha256):
            logger.error("Artifact SHA-256 mismatch for %s", artifact_path)
            return False

        scheme = SignatureScheme(metadata.scheme)
        if scheme is SignatureScheme.HMAC_SHA512:
            if not self._signing_key:
                logger.error("HMAC verification requires the symmetric signing_key")
                return False
            expected = hmac.new(
                self._signing_key, actual_sha256.encode(), hashlib.sha512
            ).hexdigest()
            return hmac.compare_digest(expected, metadata.signature)

        # ML_DSA_65 — asymmetric verification with the published public key.
        try:
            signature = bytes.fromhex(metadata.signature)
            public_key = bytes.fromhex(metadata.public_key)
        except ValueError:
            logger.error("Malformed ML-DSA signature/public-key hex in metadata")
            return False
        return PQCSigner.verify(actual_sha256.encode(), signature, public_key)
