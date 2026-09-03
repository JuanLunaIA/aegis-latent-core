"""Fail-closed coordinator for optional TPM and TEE evidence backends."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging

from aegis.core.tee_manager import TEEManager
from aegis.core.tpm import TPMManager

logger = logging.getLogger(__name__)


class SecureRuntime:
    """
    Coordinate measurement, enclave loading, and attestation when real provider
    backends exist. The current source has no enclave loader or quote verifier,
    so activation fails closed.
    """

    def __init__(self) -> None:
        self.tpm = TPMManager()
        self.tee = TEEManager()
        self._is_shielded = False

    def activate_shield(self, binary_path: str, golden_hash: str) -> bool:
        """Attempt the configured measurement and TEE evidence chain.

        The current source fails closed because no enclave loader or vendor quote
        verifier is integrated.
        """
        logger.info("Attempting configured hardware evidence chain")

        # Step 1: TPM Measurement
        if not self.tpm.verify_golden_hash(self.tpm.measure_binary(binary_path)):
            logger.critical("Shield Activation Failed: TPM measurement mismatch.")
            return False

        # Step 2: TEE Initialization
        if not self.tee.initialize_enclave():
            logger.critical("Shield Activation Failed: TEE Enclave could not be established.")
            return False

        # Step 3: Attestation
        report = self.tee.generate_attestation_quote()
        if not self.tee.verify_remote_attestation(report):
            logger.critical("Shield Activation Failed: Remote attestation failed.")
            return False

        logger.info("Hardware evidence policy accepted for the configured backends")
        self._is_shielded = True
        return True

    def is_shielded(self) -> bool:
        return self._is_shielded
