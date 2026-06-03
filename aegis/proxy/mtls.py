"""
aegis.proxy.mtls — Mutual TLS and SPIFFE Identity Validation.
Handles the extraction and verification of client certificates for mTLS.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status

from aegis.core.identity import SpiffeIdentityManager

logger = logging.getLogger(__name__)


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

            # Extract the SPIFFE ID from the certificate (simplified for simulation)
            # In reality, this would be extracted from the SAN (Subject Alternative Name)
            spiffe_id = "spiffe://aegis.cluster.local/ns/aegis/sa/proxy"
            return spiffe_id

        except Exception as e:
            logger.exception("mTLS: Error during certificate validation: %s", e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal error during mTLS validation.",
            ) from e
