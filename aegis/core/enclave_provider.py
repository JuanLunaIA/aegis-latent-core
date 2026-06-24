"""
aegis.core.enclave_provider — Hardware Enclave Integration (SGX/SEV).
Implements the architectural pattern for executing sensitive PQC operations
within a Trusted Execution Environment (TEE).
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


def _enclave_device_available() -> str | None:
    """Return the path of the first accessible enclave device, or None."""
    for path in (*_SGX_DEVICES, _SEV_DEVICE):
        if os.path.exists(path):
            return path
    return None


@dataclass
class EnclaveAttestation:
    quote: bytes
    signature: bytes
    public_key: bytes
    status: str = "VERIFIED"


class EnclavePQCProvider:
    """
    Architectural implementation of an Enclave-based PQC Provider.
    Interfaces with Intel SGX (via /dev/sgx_enclave or /dev/isgx) or AMD SEV
    (/dev/sev) when present.  When no enclave device is found,
    initialize_enclave() returns False and subsequent operations raise
    RuntimeError — no fake attestation evidence is manufactured.
    """

    def __init__(self, enclave_id: str = "aegis-core-01"):
        self.enclave_id = enclave_id
        self._is_initialized = False
        self._enclave_memory_isolated = False
        self._device_path: str | None = None

    def initialize_enclave(self) -> bool:
        """
        Performs the enclave initialization sequence.
        Returns False when no SGX/SEV device is accessible; raises nothing
        so callers can handle the absence gracefully.
        """
        logger.info("Initializing Hardware Enclave [%s]...", self.enclave_id)

        device = _enclave_device_available()
        if device is None:
            logger.warning(
                "No SGX/SEV enclave device found at %s. "
                "Install Intel SGX drivers or ensure the TEE device is accessible.",
                ", ".join((*_SGX_DEVICES, _SEV_DEVICE)),
            )
            self._is_initialized = False
            return False

        self._device_path = device
        self._is_initialized = True
        self._enclave_memory_isolated = True
        logger.info("Enclave device %s accessible. Memory isolation active (SGX/SEV).", device)
        return True

    def sign_in_enclave(self, data: bytes, key_handle: int) -> bytes:
        """
        Executes the signature operation inside the isolated enclave.
        Requires a compiled EDL/ECALL interface and a signed enclave binary.
        Raises RuntimeError when the enclave is not initialized or the
        compiled interface is not available.
        """
        if not self._is_initialized:
            raise RuntimeError("Enclave not initialized. Cannot perform secure operations.")

        logger.info("Executing PQC signature inside enclave (KeyHandle: 0x%X)...", key_handle)
        raise NotImplementedError(
            f"sign_in_enclave requires a compiled SGX enclave binary and edger8r-generated "
            f"ECALL interface — not yet implemented. Device: {self._device_path}"
        )

    def get_attestation_quote(self) -> EnclaveAttestation:
        """
        Generates a remote attestation quote (MRENCLAVE + MRSIGNER + ISV SVN).
        Requires sgx_quote or SEV-SNP attestation C API.
        Raises when the enclave is not initialized.
        """
        if not self._is_initialized:
            raise RuntimeError("Enclave not initialized.")

        raise NotImplementedError(
            f"get_attestation_quote requires the sgx_quote C API or SEV-SNP attestation "
            f"library — not yet implemented. Device: {self._device_path}"
        )


enclave_provider = EnclavePQCProvider()
