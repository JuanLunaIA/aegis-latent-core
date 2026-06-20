"""
aegis.proxy.mtls — Mutual TLS and SPIFFE Identity Validation.
Handles the extraction and verification of client certificates for mTLS.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status

from aegis.core.cac_piv import CACPIVCertError, CACPIVVerifier
from aegis.core.identity import SpiffeIdentityManager

logger = logging.getLogger(__name__)

_cac_piv_verifier = CACPIVVerifier()


class mTLSAuth:
    """
    mTLS Authentication provider using SPIFFE/SPIRE.
    Validates that the request comes from a workload with a valid SVID.
    """

    def __init__(self, identity_manager: SpiffeIdentityManager):
        self.identity_manager = identity_manager

    async def validate_request(self, request: Request) -> str:
        """
        Extracts the client certificate from the request (passed by the ingress/load balancer)
        and verifies its SPIFFE ID.
        """
        # In a production environment with a proxy (like Envoy/Nginx),
        # the client certificate is usually passed in headers (e.g., X-Forwarded-Client-Cert)
        # or via the ASGI scope.

        client_cert_header = request.headers.get("X-Forwarded-Client-Cert")
        if not client_cert_header:
            # Check if we are in a local dev environment without a proxy
            if not request.app.state.aegis.settings.auth_disabled:
                logger.warning("mTLS: No client certificate found in headers.")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="mTLS client certificate required.",
                )
            return "dev-unauthenticated"

        try:
            # The certificate is typically a PEM-encoded string
            cert_bytes = client_cert_header.encode("utf-8")

            # Verify the peer identity using the SPIFFE manager
            if not self.identity_manager.verify_peer_identity(cert_bytes):
                logger.error("mTLS: Peer certificate verification failed.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid or untrusted client certificate.",
                )

            spiffe_id = self.identity_manager.extract_spiffe_id(cert_bytes)
            if not spiffe_id:
                logger.error("mTLS: Valid certificate missing SPIFFE URI in SAN.")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Client certificate missing SPIFFE identity.",
                )
            return spiffe_id

        except Exception as e:
            logger.exception("mTLS: Error during certificate validation: %s", e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal error during mTLS validation.",
            ) from e


class CACPIVAuth:
    """mTLS authentication for DoD CAC and GSA PIV client certificates.

    Reads the PEM-encoded client certificate from the ``X-Forwarded-Client-Cert``
    header set by the TLS terminator (Envoy / Nginx) and delegates to
    :class:`~aegis.core.cac_piv.CACPIVVerifier` to check the certificate policy
    OIDs and extract the EDIPI (CAC) or UUID (PIV-I).

    The PKCS#11 interaction (private key stays on the smart card, hardware token
    signs the TLS challenge) happens entirely on the client side before the
    request reaches this middleware.
    """

    def __init__(self, verifier: CACPIVVerifier | None = None) -> None:
        self._verifier = verifier or _cac_piv_verifier

    async def validate_request(self, request: Request) -> str:
        """Extract, parse, and validate the client CAC/PIV certificate.

        Returns
        -------
        str
            The verified identity: EDIPI (DoD CAC) or UUID (PIV-I / GSA PIV).

        Raises
        ------
        HTTPException
            401 when no certificate header is present.
            403 when the certificate fails CAC/PIV policy checks.
        """
        pem_header = request.headers.get("X-Forwarded-Client-Cert")
        if not pem_header:
            logger.warning("CAC/PIV: No client certificate forwarded by TLS terminator.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="CAC/PIV client certificate required (X-Forwarded-Client-Cert missing).",
            )

        try:
            cert = self._verifier.parse_pem(pem_header.encode())
            identity = self._verifier.verify(cert)
        except CACPIVCertError as exc:
            logger.warning("CAC/PIV: Certificate rejected — %s", exc)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"CAC/PIV certificate rejected: {exc}",
            ) from exc
        except Exception as exc:
            logger.exception("CAC/PIV: Unexpected error parsing certificate: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal error during CAC/PIV certificate validation.",
            ) from exc

        logger.info("CAC/PIV: Authenticated identity=%s", identity)
        return identity
