# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.cac_piv — DoD CAC / GSA PIV certificate verification."""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from aegis.core.cac_piv import (
    _DOD_CAC_POLICY_OIDS,
    _PIV_POLICY_OIDS,
    ALL_CAC_PIV_OIDS,
    CACPIVCertError,
    CACPIVVerifier,
)

# ── Cert builder helpers ───────────────────────────────────────────────────────

_DOD_OID = "2.16.840.1.101.2.1.11.36"   # id-dod-certpcy-PIV-auth
_PIV_OID = "2.16.840.1.101.3.2.1.3.6"   # id-fpki-certpcy-pivi-hardware
_EDIPI = "1234567890"
_UUID = "550e8400-e29b-41d4-a716-446655440000"


def _keypair():
    return ec.generate_private_key(ec.SECP256R1())


def _base_builder(cn: str = f"DOE.JOHN.A.{_EDIPI}") -> tuple[x509.CertificateBuilder, ec.EllipticCurvePrivateKey]:
    key = _keypair()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    return builder, key


def _add_policy(builder: x509.CertificateBuilder, oid_str: str) -> x509.CertificateBuilder:
    policy = x509.PolicyInformation(x509.ObjectIdentifier(oid_str), None)
    return builder.add_extension(x509.CertificatePolicies([policy]), critical=False)


def _add_client_auth_eku(builder: x509.CertificateBuilder) -> x509.CertificateBuilder:
    return builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=False,
    )


def _add_san_uri(builder: x509.CertificateBuilder, uri: str) -> x509.CertificateBuilder:
    return builder.add_extension(
        x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]),
        critical=False,
    )


def _add_san_email(builder: x509.CertificateBuilder, email: str) -> x509.CertificateBuilder:
    return builder.add_extension(
        x509.SubjectAlternativeName([x509.RFC822Name(email)]),
        critical=False,
    )


def _sign(builder: x509.CertificateBuilder, key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    return builder.sign(key, hashes.SHA256())


def _to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _make_cac_cert(cn: str = f"DOE.JOHN.A.{_EDIPI}") -> x509.Certificate:
    """Standard DoD CAC cert with PIV-auth policy OID, Client Auth EKU, EDIPI in CN."""
    b, k = _base_builder(cn)
    b = _add_policy(b, _DOD_OID)
    b = _add_client_auth_eku(b)
    return _sign(b, k)


def _make_piv_cert(uuid: str = _UUID) -> x509.Certificate:
    """GSA PIV-I cert with PIV-hardware policy OID, Client Auth EKU, UUID in URI SAN."""
    b, k = _base_builder("PIV.USER")
    b = _add_policy(b, _PIV_OID)
    b = _add_client_auth_eku(b)
    b = _add_san_uri(b, f"urn:uuid:{uuid}")
    return _sign(b, k)


# ── OID constant tests ────────────────────────────────────────────────────────


class TestOIDConstants:
    def test_dod_oids_non_empty(self):
        assert len(_DOD_CAC_POLICY_OIDS) >= 11

    def test_piv_oids_non_empty(self):
        assert len(_PIV_POLICY_OIDS) >= 5

    def test_all_oids_is_union(self):
        assert ALL_CAC_PIV_OIDS == _DOD_CAC_POLICY_OIDS | _PIV_POLICY_OIDS

    def test_known_dod_oid_present(self):
        assert _DOD_OID in _DOD_CAC_POLICY_OIDS

    def test_known_piv_oid_present(self):
        assert _PIV_OID in _PIV_POLICY_OIDS


# ── CACPIVVerifier: policy checks ─────────────────────────────────────────────


class TestPolicyCheck:
    def test_valid_dod_oid_passes(self):
        cert = _make_cac_cert()
        v = CACPIVVerifier()
        assert v._has_cac_piv_policy(cert)

    def test_valid_piv_oid_passes(self):
        cert = _make_piv_cert()
        v = CACPIVVerifier()
        assert v._has_cac_piv_policy(cert)

    def test_no_policy_extension_fails(self):
        b, k = _base_builder()
        b = _add_client_auth_eku(b)
        cert = _sign(b, k)
        v = CACPIVVerifier()
        assert not v._has_cac_piv_policy(cert)

    def test_unrelated_policy_oid_fails(self):
        b, k = _base_builder()
        b = _add_policy(b, "1.2.3.4.5")
        b = _add_client_auth_eku(b)
        cert = _sign(b, k)
        v = CACPIVVerifier()
        assert not v._has_cac_piv_policy(cert)

    def test_custom_allowed_oids(self):
        custom_oid = "1.2.3.99"
        b, k = _base_builder()
        b = _add_policy(b, custom_oid)
        b = _add_client_auth_eku(b)
        cert = _sign(b, k)
        v = CACPIVVerifier(allowed_policy_oids=frozenset({custom_oid}))
        assert v._has_cac_piv_policy(cert)


# ── CACPIVVerifier: EKU checks ────────────────────────────────────────────────


class TestEKUCheck:
    def test_client_auth_eku_present(self):
        cert = _make_cac_cert()
        v = CACPIVVerifier()
        assert v._has_client_auth_eku(cert)

    def test_missing_eku_returns_false(self):
        b, k = _base_builder()
        b = _add_policy(b, _DOD_OID)
        cert = _sign(b, k)
        v = CACPIVVerifier()
        assert not v._has_client_auth_eku(cert)

    def test_require_eku_false_skips_check(self):
        b, k = _base_builder()
        b = _add_policy(b, _DOD_OID)
        cert = _sign(b, k)
        v = CACPIVVerifier(require_client_auth_eku=False)
        # Should not raise despite missing EKU
        identity = v.verify(cert)
        assert identity == _EDIPI

    def test_require_eku_true_rejects_missing(self):
        b, k = _base_builder()
        b = _add_policy(b, _DOD_OID)
        cert = _sign(b, k)
        v = CACPIVVerifier(require_client_auth_eku=True)
        with pytest.raises(CACPIVCertError, match="EKU"):
            v.verify(cert)


# ── CACPIVVerifier: identity extraction ───────────────────────────────────────


class TestIdentityExtraction:
    def test_edipi_extracted_from_cn(self):
        cert = _make_cac_cert()
        v = CACPIVVerifier()
        assert v._extract_identity(cert) == _EDIPI

    def test_uuid_extracted_from_san_uri(self):
        cert = _make_piv_cert()
        v = CACPIVVerifier()
        assert v._extract_identity(cert).lower() == _UUID.lower()

    def test_edipi_from_upn_rfc822name(self):
        b, k = _base_builder(cn="GENERIC.NAME")
        b = _add_policy(b, _DOD_OID)
        b = _add_client_auth_eku(b)
        b = _add_san_email(b, f"{_EDIPI}@mil")
        cert = _sign(b, k)
        v = CACPIVVerifier()
        assert v._extract_identity(cert) == _EDIPI

    def test_no_identity_returns_empty(self):
        b, k = _base_builder(cn="NO.EDIPI.HERE")
        b = _add_policy(b, _DOD_OID)
        b = _add_client_auth_eku(b)
        cert = _sign(b, k)
        v = CACPIVVerifier()
        assert v._extract_identity(cert) == ""

    def test_non_10digit_email_not_extracted(self):
        b, k = _base_builder(cn="NOBODY")
        b = _add_policy(b, _DOD_OID)
        b = _add_client_auth_eku(b)
        b = _add_san_email(b, "alice@example.com")
        cert = _sign(b, k)
        v = CACPIVVerifier()
        assert v._extract_identity(cert) == ""


# ── CACPIVVerifier.verify() end-to-end ───────────────────────────────────────


class TestVerify:
    def test_valid_cac_cert_returns_edipi(self):
        cert = _make_cac_cert()
        v = CACPIVVerifier()
        assert v.verify(cert) == _EDIPI

    def test_valid_piv_cert_returns_uuid(self):
        cert = _make_piv_cert()
        v = CACPIVVerifier()
        result = v.verify(cert)
        assert result.lower() == _UUID.lower()

    def test_no_policy_oid_raises(self):
        b, k = _base_builder()
        b = _add_client_auth_eku(b)
        cert = _sign(b, k)
        v = CACPIVVerifier()
        with pytest.raises(CACPIVCertError, match="policy OID"):
            v.verify(cert)

    def test_no_identity_raises(self):
        b, k = _base_builder(cn="NODOTEDIPI")
        b = _add_policy(b, _DOD_OID)
        b = _add_client_auth_eku(b)
        cert = _sign(b, k)
        v = CACPIVVerifier()
        with pytest.raises(CACPIVCertError, match="identity"):
            v.verify(cert)


# ── parse_pem round-trip ──────────────────────────────────────────────────────


class TestParsePem:
    def test_pem_roundtrip(self):
        cert = _make_cac_cert()
        pem = _to_pem(cert)
        v = CACPIVVerifier()
        parsed = v.parse_pem(pem)
        assert parsed.serial_number == cert.serial_number

    def test_verify_from_pem(self):
        cert = _make_cac_cert()
        pem = _to_pem(cert)
        v = CACPIVVerifier()
        parsed = v.parse_pem(pem)
        assert v.verify(parsed) == _EDIPI


# ── CACPIVAuth FastAPI middleware ─────────────────────────────────────────────


class TestCACPIVAuth:
    def _make_request(self, headers: dict) -> object:
        """Minimal Request-like object for testing middleware."""
        from unittest.mock import MagicMock
        req = MagicMock()
        req.headers = headers
        return req

    @pytest.mark.asyncio
    async def test_missing_header_raises_401(self):
        from fastapi import HTTPException

        from aegis.proxy.mtls import CACPIVAuth
        auth = CACPIVAuth()
        req = self._make_request({})
        with pytest.raises(HTTPException) as exc_info:
            await auth.validate_request(req)
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_cac_cert_returns_edipi(self):
        from aegis.proxy.mtls import CACPIVAuth
        cert = _make_cac_cert()
        pem = _to_pem(cert).decode()
        auth = CACPIVAuth()
        req = self._make_request({"X-Forwarded-Client-Cert": pem})
        result = await auth.validate_request(req)
        assert result == _EDIPI

    @pytest.mark.asyncio
    async def test_invalid_policy_oid_raises_403(self):
        from fastapi import HTTPException

        from aegis.proxy.mtls import CACPIVAuth
        b, k = _base_builder()
        b = _add_policy(b, "1.2.3.4.5")
        b = _add_client_auth_eku(b)
        cert = _sign(b, k)
        pem = _to_pem(cert).decode()
        auth = CACPIVAuth()
        req = self._make_request({"X-Forwarded-Client-Cert": pem})
        with pytest.raises(HTTPException) as exc_info:
            await auth.validate_request(req)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_valid_piv_cert_returns_uuid(self):
        from aegis.proxy.mtls import CACPIVAuth
        cert = _make_piv_cert()
        pem = _to_pem(cert).decode()
        auth = CACPIVAuth()
        req = self._make_request({"X-Forwarded-Client-Cert": pem})
        result = await auth.validate_request(req)
        assert result.lower() == _UUID.lower()
