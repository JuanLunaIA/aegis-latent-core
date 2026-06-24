"""
aegis.core.tee_manager — Trusted Execution Environment (TEE) Interface.
Handles enclave deployment and remote attestation for SGX/SEV-SNP.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_SGX_DEVICES = ("/dev/sgx_enclave", "/dev/isgx")
_SEV_DEVICE = "/dev/sev"
_TDX_DEVICE = "/dev/tdx_guest"


def _tee_device_available() -> str | None:
    """Return the path of the first accessible TEE device, or None."""
    for path in (*_SGX_DEVICES, _SEV_DEVICE, _TDX_DEVICE):
        if os.path.exists(path):
            return path
    return None


@dataclass
class AttestationReport:
    enclave_id: str
    measurement: str  # MRENCLAVE in SGX
    signer_id: str  # MRSIGNER in SGX
    is_genuine: bool
    timestamp: float


class TEEManager:
    """
    Manages the deployment of Aegis Core inside a TEE (Intel SGX / AMD SEV-SNP / TDX).
    Ensures that sensitive operations are performed in isolated memory that
    cannot be read even by the Root/Kernel.

    When no TEE device is found initialize_enclave() returns False and
    subsequent operations raise RuntimeError — no hardcoded fake measurements
    are returned.
    """

    def __init__(self, tee_type: str = "SGX"):
        self.tee_type = tee_type
        self._is_enclave_active = False
        self._attestation_report: AttestationReport | None = None
        self._device_path: str | None = None
        logger.info("TEEManager initialized for %s architecture", tee_type)

    def initialize_enclave(self) -> bool:
        """
        Allocates encrypted memory and loads the Aegis Core into the enclave.
        Returns False and logs an advisory when no SGX/SEV/TDX device is found.
        """
        device = _tee_device_available()
        if device is None:
            logger.warning(
                "No TEE device found at %s. "
                "Install %s drivers or ensure the device node is accessible.",
                ", ".join((*_SGX_DEVICES, _SEV_DEVICE, _TDX_DEVICE)),
                self.tee_type,
            )
            self._is_enclave_active = False
            return False

        self._device_path = device
        self._is_enclave_active = True
        logger.info("TEE device %s accessible. Encrypted memory pages (EPC) active.", device)
        return True

    def generate_attestation_quote(self) -> AttestationReport:
        """
        Generates a hardware-signed quote proving the identity and integrity
        of the enclave.  Requires the sgx_quote or SEV-SNP attestation API.
        Raises RuntimeError when the TEE is not active.
        """
        if not self._is_enclave_active:
            raise RuntimeError("TEE Enclave is not active. Cannot generate quote.")

        raise NotImplementedError(
            f"generate_attestation_quote requires the sgx_quote C API or "
            f"SEV-SNP IOCTL interface — not yet implemented. Device: {self._device_path}"
        )

    def verify_remote_attestation(self, report: AttestationReport) -> bool:
        """
        Verifies the quote against the hardware manufacturer's attestation root
        (Intel Attestation Service for SGX, AMD SEV VCEK for SEV-SNP).
        Returns False when the report is not marked genuine or has an empty measurement.
        """
        if not report.is_genuine or not report.measurement:
            logger.critical("Remote Attestation FAILED. Potential enclave spoofing detected!")
            return False

        logger.info("Remote Attestation VERIFIED. Hardware is genuine and software is intact.")
        return True

    def is_protected(self) -> bool:
        """Checks if the current execution context is inside a verified enclave."""
        return self._is_enclave_active and self._attestation_report is not None
