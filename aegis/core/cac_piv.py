# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.cac_piv — DoD CAC / GSA PIV client certificate verification.

Implements server-side identity extraction for DoD Common Access Card (CAC)
and NIST SP 800-73 Personal Identity Verification (PIV) smart-card client
certificates presented during mTLS handshake.

The private key never leaves the smart card token; this module only inspects
the X.509 certificate forwarded by the TLS terminator (e.g., in the
``X-Forwarded-Client-Cert`` header set by Envoy/Nginx after the hardware
token signs the TLS challenge via its PKCS#11 slot).

Certificate policy OID sets follow:
  - DoDI 8520.02 Annex 3 (DoD CAC)
  - NIST SP 800-73-4 (PIV / PIV-I)
  - GSA FPKI Certificate Policy (id-fpki)
"""
from __future__ import annotations

import logging
import re

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

logger = logging.getLogger(__name__)

# ── Certificate policy OIDs ───────────────────────────────────────────────────

_DOD_CAC_POLICY_OIDS: frozenset[str] = frozenset(
    {
        "2.16.840.1.101.2.1.11.5",   # id-dod-certpcy-basicAssurance
        "2.16.840.1.101.2.1.11.9",   # id-dod-certpcy-mediumAssurance
        "2.16.840.1.101.2.1.11.17",  # id-dod-certpcy-highAssurance
        "2.16.840.1.101.2.1.11.18",  # id-dod-certpcy-mediumNPE
        "2.16.840.1.101.2.1.11.19",  # id-dod-certpcy-EDIPI
        "2.16.840.1.101.2.1.11.31",  # id-dod-certpcy-mediumHardware
        "2.16.840.1.101.2.1.11.36",  # id-dod-certpcy-PIV-auth
        "2.16.840.1.101.2.1.11.37",  # id-dod-certpcy-PIV-hardware
        "2.16.840.1.101.2.1.11.38",  # id-dod-certpcy-PIV-cardAuth
        "2.16.840.1.101.2.1.11.39",  # id-dod-certpcy-PIV-contentSigning
        "2.16.840.1.101.2.1.11.40",  # id-dod-certpcy-PIV-basicAuth
    }
)

_PIV_POLICY_OIDS: frozenset[str] = frozenset(
    {
        "2.16.840.1.101.3.2.1.3.6",  # id-fpki-certpcy-pivi-hardware
        "2.16.840.1.101.3.2.1.3.7",  # id-fpki-certpcy-pivi-cardAuth
        "2.16.840.1.101.3.2.1.3.13", # id-fpki-certpcy-pivi-contentSigning
        "2.16.840.1.101.3.2.1.3.14", # id-fpki-certpcy-pivi-authKey
        "2.16.840.1.101.3.2.1.3.17", # id-fpki-certpcy-pivca
    }
)

ALL_CAC_PIV_OIDS: frozenset[str] = _DOD_CAC_POLICY_OIDS | _PIV_POLICY_OIDS

# FASC-N is embedded in the MSB of the SubjectKeyIdentifier for CAC certs or
# as a URI SAN with scheme "urn:fedramp:..." / "urn:dod:...".
# For PIV-I, the UUID lives in a uniformResourceIdentifier SAN.
_EDIPI_CN_RE = re.compile(r"\.(\d{10})$")  # "LAST.FIRST.MI.EDIPI" DoD CN format
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)


class CACPIVCertError(ValueError):
    """Raised when a certificate fails CAC/PIV validation."""


class CACPIVVerifier:
    """Server-side verifier for DoD CAC and GSA PIV client certificates.

    Instantiate once at application startup and call :meth:`verify` per
    request.  No PKCS#11 library required on the server — the hardware token
    interaction happens on the client side during the TLS handshake.

    Parameters
    ----------
    allowed_policy_oids:
        OID strings for certificate policies that constitute valid CAC/PIV
        credentials.  Defaults to the full union of DoD CAC and GSA PIV OIDs.
    require_client_auth_eku:
        When True (default), reject certificates that lack the Client
        Authentication extended key usage — prevents content-signing or
        card-authentication certificates from being accepted for proxy auth.
    """

    def __init__(
        self,
        allowed_policy_oids: frozenset[str] | None = None,
        require_client_auth_eku: bool = True,
    ) -> None:
        self._oids = allowed_policy_oids if allowed_policy_oids is not None else ALL_CAC_PIV_OIDS
        self._require_eku = require_client_auth_eku

    def verify(self, cert: x509.Certificate) -> str:
        """Verify *cert* is a valid CAC/PIV certificate and return its identity.

        Returns
        -------
        str
            The extracted identity: EDIPI (DoD CAC) or UUID (PIV-I / GSA PIV).

        Raises
        ------
        CACPIVCertError
            When the certificate does not carry an acceptable CAC/PIV policy OID,
            lacks the Client Auth EKU (when required), or has no extractable identity.
        """
        if not self._has_cac_piv_policy(cert):
            raise CACPIVCertError(
                "Certificate does not contain a recognized CAC/PIV policy OID"
            )

        if self._require_eku and not self._has_client_auth_eku(cert):
            raise CACPIVCertError(
                "Certificate lacks Client Authentication EKU (id-kp-clientAuth)"
            )

        identity = self._extract_identity(cert)
        if not identity:
            raise CACPIVCertError(
                "Certificate has no extractable CAC/PIV identity (EDIPI or UUID)"
            )

        logger.debug("CAC/PIV verified: identity=%s", identity)
        return identity

    def parse_pem(self, pem_bytes: bytes) -> x509.Certificate:
        """Parse PEM-encoded certificate bytes and return the x509 object."""
        from cryptography.hazmat.primitives.serialization import Encoding  # noqa: F401
        return x509.load_pem_x509_certificate(pem_bytes)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _has_cac_piv_policy(self, cert: x509.Certificate) -> bool:
        """Return True if the cert carries at least one allowed policy OID."""
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            for pi in ext.value:  # type: ignore[attr-defined]
                if pi.policy_identifier.dotted_string in self._oids:
                    return True
        except x509.ExtensionNotFound:
            pass
        return False

    def _has_client_auth_eku(self, cert: x509.Certificate) -> bool:
        """Return True if the cert's EKU includes id-kp-clientAuth."""
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            return ExtendedKeyUsageOID.CLIENT_AUTH in ext.value  # type: ignore[operator]
        except x509.ExtensionNotFound:
            return False

    def _extract_identity(self, cert: x509.Certificate) -> str:
        """Return EDIPI from CN, or UUID from SubjectAltName URI, or empty string."""
        # 1. Try EDIPI from Subject CN ("LAST.FIRST.MI.EDIPI" DoD format)
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn_attrs:
                cn = cn_attrs[0].value
                m = _EDIPI_CN_RE.search(cn)  # type: ignore[arg-type]
                if m:
                    return m.group(1)
        except Exception:
            pass

        # 2. Try UUID from SubjectAltName URI (PIV-I / GSA PIV cards)
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:  # type: ignore[attr-defined]
                if isinstance(name, x509.UniformResourceIdentifier):
                    m = _UUID_RE.search(name.value)
                    if m:
                        return m.group(0)
                # UPN in rfc822Name for email-based CAC identity
                if isinstance(name, x509.RFC822Name):
                    # UPN format: EDIPI@mil or EDIPI@domain
                    upn = name.value
                    local = upn.split("@")[0]
                    if local.isdigit() and len(local) == 10:
                        return local
        except x509.ExtensionNotFound:
            pass

        return ""

    @property
    def key_type(self) -> str:
        """For diagnostics only — not used in verification path."""
        return "cac_piv"
