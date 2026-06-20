"""
aegis.core.tpm — Trusted Platform Module (TPM 2.0) Interface.
Implements Measured Boot and PCR (Platform Configuration Register) verification.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import logging
import os

logger = logging.getLogger(__name__)


class TPMManager:
    """
    Interfaces with the system TPM 2.0 to ensure the integrity of the boot chain.
    Implements the logic for 'Measuring' the binary and verifying PCR states.
    """

    def __init__(self, pcr_index: int = 10):
        self.pcr_index = pcr_index
        # In a real system, we would use the 'tpm2-tss' library or 'tpm2-tools' CLI.
        self._simulated_pcr_value: str | None = None
        logger.info("TPMManager initialized monitoring PCR %d", pcr_index)

    def measure_binary(self, binary_path: str) -> str:
        """
        Simulates the TPM 'Extend' operation.
        PCR_new = SHA256(PCR_old || SHA256(binary))
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found for measurement: {binary_path}")

        with open(binary_path, "rb") as f:
            binary_hash = hashlib.sha256(f.read()).hexdigest()

        # Simulate TPM Extend operation
        current_val = self._simulated_pcr_value or "0" * 64
        combined = (current_val + binary_hash).encode()
        new_pcr_val = hashlib.sha256(combined).hexdigest()

        self._simulated_pcr_value = new_pcr_val
        logger.info(
            "TPM: Binary %s measured into PCR %d. New Value: %s",
            binary_path,
            self.pcr_index,
            new_pcr_val,
        )
        return new_pcr_val

    def verify_golden_hash(self, golden_hash: str) -> bool:
        """
        Verifies if the current PCR value matches the pre-calculated Golden Hash.
        If they differ, the system has been tampered with (Bootkit/Rootkit).
        """
        if not self._simulated_pcr_value:
            logger.error("TPM: No measurement found in PCR %d. Boot chain broken.", self.pcr_index)
            return False

        is_valid = self._simulated_pcr_value == golden_hash
        if not is_valid:
            logger.critical(
                "TPM INTEGRITY FAILURE: PCR %d mismatch! System compromised.", self.pcr_index
            )
        else:
            logger.info("TPM INTEGRITY VERIFIED: PCR %d matches Golden Hash.", self.pcr_index)

        return is_valid

    def get_pcr_value(self) -> str:
        """Returns the current value of the monitored PCR."""
        return self._simulated_pcr_value or "0" * 64
