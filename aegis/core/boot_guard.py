"""
aegis.core.boot_guard — Orchestrates the Measured Boot process.
Ensures that the system only enters a 'Ready' state if the TPM verifies the chain of trust.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging

from aegis.core.tpm import TPMManager

logger = logging.getLogger(__name__)


class BootGuard:
    """
    BootGuard ensures the Measured Boot chain: UEFI -> Kernel -> Aegis Core.
    It acts as the final gatekeeper before the system enables networking.
    """

    def __init__(self, binary_path: str, golden_hash: str):
        self.tpm = TPMManager(pcr_index=10)
        self.binary_path = binary_path
        self.golden_hash = golden_hash
        self.is_system_ready = False

    def execute_boot_sequence(self) -> bool:
        """
        Executes the chain of trust verification.
        """
        logger.info("Initiating Measured Boot sequence...")

        # 1. Measure the Aegis Core binary
        try:
            self.tpm.measure_binary(self.binary_path)
        except Exception as e:
            logger.critical("BootGuard: Failed to measure binary: %s", e)
            return False

        # 2. Verify against the Golden Hash
        if not self.tpm.verify_golden_hash(self.golden_hash):
            logger.critical("BootGuard: INTEGRITY CHECK FAILED. HALTING SYSTEM.")
            self.is_system_ready = False
            return False

        logger.info("BootGuard: System integrity verified. Enabling core services.")
        self.is_system_ready = True
        return True

    def get_system_status(self) -> str:
        return "READY" if self.is_system_ready else "LOCKED"
