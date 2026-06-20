"""
aegis.core.artifact_signing — Digital signatures for immutable deployment.
Ensures that all binary artifacts are signed and verified before deployment.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ArtifactMetadata:
    artifact_id: str
    sha256: str
    signature: str
    timestamp: str
    version: str


class ArtifactSigner:
    """
    Handles the signing and verification of deployment artifacts.
    In production, the private key resides in a Hardware Security Module (HSM).
    """

    def __init__(self, signing_key: bytes | None = None):
        # If signing_key is provided, we use it (Legacy/Test mode)
        # Otherwise, we default to the HSM for production-grade security
        self._signing_key = signing_key
        self._hsm = None

        if signing_key is None:
            from aegis.core.hsm import HSMManager

            self._hsm = HSMManager()
            # In production, slot and pin would come from a secure vault/env
            self._hsm.open_session(slot_id=1, pin="FIPS_SECURE_PIN_2026")

    def sign_artifact(self, artifact_path: str, version: str) -> ArtifactMetadata:
        """Signs a binary artifact and returns its metadata."""
        with open(artifact_path, "rb") as f:
            data = f.read()

        sha256 = hashlib.sha256(data).hexdigest()

        # Simulate PQC Signature (ML-DSA)
        if self._hsm:
            signature = self._hsm.sign_data(key_handle=0x1, data=sha256.encode())
            # Convert bytes to hex for metadata
            signature = signature.hex()
        else:
            signature = hmac.new(self._signing_key, sha256.encode(), hashlib.sha512).hexdigest()

        from datetime import datetime

        timestamp = datetime.utcnow().isoformat() + "Z"

        return ArtifactMetadata(
            artifact_id=artifact_path,
            sha256=sha256,
            signature=signature,
            timestamp=timestamp,
            version=version,
        )

    def verify_artifact(self, artifact_path: str, metadata: ArtifactMetadata) -> bool:
        """Verifies the artifact against its metadata signature."""
        with open(artifact_path, "rb") as f:
            data = f.read()

        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != metadata.sha256:
            logger.error("Artifact SHA-256 mismatch for %s", artifact_path)
            return False

        # Verify signature
        if self._hsm:
            expected_sig_bytes = self._hsm.sign_data(key_handle=0x1, data=actual_sha256.encode())
            expected_sig = expected_sig_bytes.hex()
        else:
            expected_sig = hmac.new(
                self._signing_key, actual_sha256.encode(), hashlib.sha512
            ).hexdigest()
        return hmac.compare_digest(expected_sig, metadata.signature)
