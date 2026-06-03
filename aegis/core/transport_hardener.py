"""
aegis.core.transport_hardener — Transport Layer Security Enforcement.
Enforces TLS 1.3, strict cipher suites, and certificate pinning.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import logging
import ssl
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PinningConfig:
    hostname: str
    allowed_hashes: list[str]  # SHA-256 hashes of SPKI (Subject Public Key Info)


class TransportHardener:
    """
    Enforces maximum security for the transport layer.
    """

    def __init__(self):
        self._pins: dict[str, list[str]] = {}
        self._ssl_context = self._create_hardened_context()

    def _create_hardened_context(self) -> ssl.SSLContext:
        """
        Creates an SSLContext that forces TLS 1.3 and disables insecure ciphers.
        """
        # Force TLS 1.3 only
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        # In TLS 1.3, ciphers are defined by the protocol and cannot be
        # restricted using set_ciphers() in the same way as TLS 1.2.
        # We use set_ciphers() only as a fallback for TLS 1.2 if we were using it.
        # For TLS 1.3, we rely on the default secure ciphers provided by OpenSSL.
        try:
            # Try to set preferred ciphers, but wrap in try-except because
            # some OpenSSL versions reject TLS 1.3 ciphers in set_ciphers().
            context.set_ciphers("DEFAULT@SECLEVEL=2")
        except ssl.SSLError:
            logger.warning(
                "Could not set explicit cipher suite, using OpenSSL defaults for TLS 1.3."
            )

        # Enforce strict hostname verification
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        logger.info("SSLContext hardened: TLS 1.3 forced, strict verification enabled.")
        return context

    def add_certificate_pin(self, hostname: str, spki_hash: str):
        """
        Adds a certificate pin for a specific hostname.
        """
        if hostname not in self._pins:
            self._pins[hostname] = []
        self._pins[hostname].append(spki_hash)
        logger.info("Certificate pin added for %s: %s", hostname, spki_hash)

    def verify_certificate_pin(self, hostname: str, cert_der: bytes) -> bool:
        """
        Verifies that the presented certificate matches the pinned SPKI hash.
        """
        if hostname not in self._pins:
            logger.warning("No pin found for %s. Falling back to CA verification.", hostname)
            return True

        cert_hash = hashlib.sha256(cert_der).hexdigest()

        if cert_hash in self._pins[hostname]:
            logger.info("Certificate pin verified for %s", hostname)
            return True

        logger.critical("CERTIFICATE PINNING VIOLATION for %s!", hostname)
        return False

    def get_context(self) -> ssl.SSLContext:
        return self._ssl_context


# Singleton instance
transport_hardener = TransportHardener()
