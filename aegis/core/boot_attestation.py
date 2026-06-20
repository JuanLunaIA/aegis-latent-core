"""
aegis.core.boot_attestation — Trusted Boot Verification.
Ensures the system is in a known-good state before initializing the Proxy.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging

from aegis.core.tpm import TPMManager as tpm

logger = logging.getLogger(__name__)


class BootAttestationManager:
    """
    Handles the verification of the system state using TPM PCRs.
    """

    def __init__(self, expected_measurements: dict[int, str]):
        # expected_measurements: { PCR_INDEX: EXPECTED_HASH }
        self.expected_measurements = expected_measurements

    def measure_component(self, pcr_index: int, component_path: str):
        """
        Measures a file (binary, config, etc.) and extends it into a TPM PCR.
        """
        try:
            with open(component_path, "rb") as f:
                data = f.read()
            tpm.extend_pcr(pcr_index, data)
            logger.info("Component [%s] measured into PCR[%d]", component_path, pcr_index)
        except Exception as e:
            logger.error("Failed to measure %s: %s", component_path, e)
            raise RuntimeError(f"Boot integrity failure: {component_path}")

    def verify_boot_state(self) -> bool:
        """
        Verifies that all critical PCRs match the golden measurements.
        """
        for index, expected_hash in self.expected_measurements.items():
            actual_hash = tpm.read_pcr(index)
            if actual_hash != expected_hash:
                logger.critical("BOOT INTEGRITY VIOLATION: PCR[%d] mismatch!", index)
                logger.critical("Expected: %s | Actual: %s", expected_hash, actual_hash)
                return False

        logger.info("Boot state verified. System is in a TRUSTED state.")
        return True


# Example Golden Measurements (In production, these are signed by the vendor)
GOLDEN_MEASUREMENTS = {
    0: "a" * 64,  # SRK / Firmware
    1: "b" * 64,  # Kernel
    2: "c" * 64,  # Initrd / Config
}

attestor = BootAttestationManager(GOLDEN_MEASUREMENTS)
