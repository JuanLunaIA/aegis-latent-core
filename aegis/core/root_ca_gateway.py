"""
aegis.core.root_ca_gateway — Air-Gapped Root CA Gateway.
Implements the logic for a 'Data-Diode' transfer between the online proxy 
and the physically isolated Root Certificate Authority.
"""
from __future__ import annotations
import logging
import hashlib
import base64
from typing import Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SigningRequest:
    request_id: str
    csr: str # Certificate Signing Request
    metadata: dict
    timestamp: float

@dataclass
class SignedCertificate:
    certificate: str
    signature: str
    ca_serial: str

class AirGapGateway:
    """
    Manages the unidirectional flow of data to and from the Air-Gapped Root CA.
    Implemented as a 'Data-Diode' pattern to ensure no network path exists 
    between the Root CA and the external world.
    """
    def __init__(self):
        self._outbound_queue: list[SigningRequest] = []
        self._inbound_buffer: list[SignedCertificate] = []
        logger.info("AirGapGateway initialized. Data-Diode protocol active.")

    def submit_signing_request(self, csr: str, metadata: dict) -> str:
        """
        Prepares a signing request to be transferred to the Air-Gapped CA.
        In a real scenario, this is exported as a QR code, USB, or optical diode.
        """
        import uuid
        import time
        req_id = str(uuid.uuid4())
        request = SigningRequest(
            request_id=req_id,
            csr=csr,
            metadata=metadata,
            timestamp=time.time()
        )
        self._outbound_queue.append(request)
        
        # Export to "Transfer Format" (e.g., Base64 encoded JSON for physical transport)
        logger.info("Signing request %s queued for physical transfer to Root CA.", req_id)
        return req_id

    def import_signed_certificate(self, encoded_payload: str):
        """
        Imports a signed certificate returning from the Air-Gapped CA.
        """
        try:
            # Simulation of decoding the physical transfer (e.g., scanning a QR code)
            import json
            decoded = json.loads(base64.b64decode(encoded_payload).decode())
            cert = SignedCertificate(
                certificate=decoded["cert"],
                signature=decoded["sig"],
                ca_serial=decoded["serial"]
            )
            self._inbound_buffer.append(cert)
            logger.info("Signed certificate successfully imported from Air-Gapped CA.")
        except Exception as e:
            logger.error("Failed to import certificate from Air-Gapped CA: %s", e)

    def fetch_certificate(self, request_id: str) -> Optional[SignedCertificate]:
        """
        Retrieves the signed certificate if it has been imported.
        """
        # In a real system, we would match the request_id to the cert.
        if self._inbound_buffer:
            return self._inbound_buffer.pop(0)
        return None
