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
import shutil
import subprocess  # noqa: S404  # nosec B404

logger = logging.getLogger(__name__)

_TPM2_PCREXTEND = "tpm2_pcrextend"
_TPM2_PCRREAD = "tpm2_pcrread"


def _tpm2_available() -> bool:
    return shutil.which(_TPM2_PCREXTEND) is not None and shutil.which(_TPM2_PCRREAD) is not None


class TPMManager:
    """
    Interfaces with the system TPM 2.0 to ensure the integrity of the boot chain.
    Implements the logic for 'Measuring' the binary and verifying PCR states.

    When tpm2-tools is installed and a TPM device is accessible, operations
    delegate to ``tpm2_pcrextend`` / ``tpm2_pcrread`` for hardware-backed
    measurements.  When the tooling or device is absent the manager operates
    in software-only mode, computing the same PCR extend formula
    (SHA256(PCR_old ‖ SHA256(binary))) in memory and logging an advisory.
    """

    def __init__(self, pcr_index: int = 10):
        self.pcr_index = pcr_index
        self._hardware = _tpm2_available()
        self._sw_pcr_value: str | None = None
        if self._hardware:
            logger.info("TPMManager: tpm2-tools found — using hardware TPM for PCR %d.", pcr_index)
        else:
            logger.warning(
                "TPMManager: tpm2-tools not found — falling back to software PCR extend "
                "(advisory only; install tpm2-tools and ensure /dev/tpm0 is accessible)."
            )
        logger.info("TPMManager initialized monitoring PCR %d", pcr_index)

    def measure_binary(self, binary_path: str) -> str:
        """
        Extends the PCR with the SHA-256 hash of the binary.
        PCR_new = SHA256(PCR_old ‖ SHA256(binary))

        On hardware: delegates to ``tpm2_pcrextend`` and reads back via ``tpm2_pcrread``.
        On software: computes the extend in-memory.
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found for measurement: {binary_path}")

        with open(binary_path, "rb") as f:
            binary_hash = hashlib.sha256(f.read()).hexdigest()

        if self._hardware:
            new_pcr_val = self._hw_extend(binary_hash)
        else:
            new_pcr_val = self._sw_extend(binary_hash)

        logger.info(
            "TPM: Binary %s measured into PCR %d. New Value: %s",
            binary_path,
            self.pcr_index,
            new_pcr_val,
        )
        return new_pcr_val

    def _hw_extend(self, binary_hash: str) -> str:
        """Extend PCR via tpm2_pcrextend and read back the new value."""
        extend_cmd = [
            _TPM2_PCREXTEND,
            f"{self.pcr_index}:sha256={binary_hash}",
        ]
        result = subprocess.run(  # noqa: S603 S607  # nosec B603 B607
            extend_cmd, capture_output=True, text=True
        )
        if result.returncode != 0:
            logger.error("tpm2_pcrextend failed: %s", result.stderr)
            raise RuntimeError(f"tpm2_pcrextend failed (rc={result.returncode}): {result.stderr}")

        read_cmd = [_TPM2_PCRREAD, f"sha256:{self.pcr_index}"]
        read_result = subprocess.run(  # noqa: S603 S607  # nosec B603 B607
            read_cmd, capture_output=True, text=True
        )
        if read_result.returncode != 0:
            logger.error("tpm2_pcrread failed: %s", read_result.stderr)
            raise RuntimeError(f"tpm2_pcrread failed (rc={read_result.returncode})")

        return self._parse_pcrread_output(read_result.stdout)

    def _parse_pcrread_output(self, output: str) -> str:
        """Extract the hex PCR value from tpm2_pcrread YAML-like output."""
        for line in output.splitlines():
            # tpm2_pcrread emits lines like: "  10: 0xABCD..."
            stripped = line.strip()
            if stripped.startswith(f"{self.pcr_index}:"):
                value = stripped.split(":", 1)[1].strip()
                return value.removeprefix("0x").lower()
        return "0" * 64

    def _sw_extend(self, binary_hash: str) -> str:
        """Software PCR extend — SHA256(PCR_old ‖ binary_hash) — advisory only."""
        current = self._sw_pcr_value or "0" * 64
        new_val = hashlib.sha256((current + binary_hash).encode()).hexdigest()
        self._sw_pcr_value = new_val
        return new_val

    def verify_golden_hash(self, golden_hash: str) -> bool:
        """
        Verifies if the current PCR value matches the pre-calculated Golden Hash.
        If they differ, the system has been tampered with (Bootkit/Rootkit).
        """
        current = self.get_pcr_value()
        if current == "0" * 64:
            logger.error("TPM: No measurement found in PCR %d. Boot chain broken.", self.pcr_index)
            return False

        is_valid = current == golden_hash
        if not is_valid:
            logger.critical(
                "TPM INTEGRITY FAILURE: PCR %d mismatch! System compromised.", self.pcr_index
            )
        else:
            logger.info("TPM INTEGRITY VERIFIED: PCR %d matches Golden Hash.", self.pcr_index)

        return is_valid

    def get_pcr_value(self) -> str:
        """Returns the current value of the monitored PCR."""
        if self._hardware:
            read_cmd = [_TPM2_PCRREAD, f"sha256:{self.pcr_index}"]
            result = subprocess.run(  # noqa: S603 S607  # nosec B603 B607
                read_cmd, capture_output=True, text=True
            )
            if result.returncode == 0:
                return self._parse_pcrread_output(result.stdout)
        return self._sw_pcr_value or "0" * 64
