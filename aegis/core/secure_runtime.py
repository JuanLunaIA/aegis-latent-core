"""
aegis.core.secure_runtime — Integrates TEE and TPM for a fully shielded execution environment.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging

from aegis.core.tee_manager import TEEManager
from aegis.core.tpm import TPMManager

logger = logging.getLogger(__name__)


class SecureRuntime:
    """
    The SecureRuntime is the ultimate orchestration layer for hardware-backed security.
    It ensures the system is:
    1. Measured (TPM)
    2. Isolated (TEE)
    3. Attested (Remote Quote)
    """

    def __init__(self):
        self.tpm = TPMManager()
        self.tee = TEEManager()
        self._is_shielded = False

    def activate_shield(self, binary_path: str, golden_hash: str) -> bool:
        """
        Activates the full hardware shield.
        """
        logger.info("Activating Hardware Shield...")

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

        logger.info("HARDWARE SHIELD ACTIVE. Aegis Core is now running in an Inexpugnable state.")
        self._is_shielded = True
        return True

    def is_shielded(self) -> bool:
        return self._is_shielded
