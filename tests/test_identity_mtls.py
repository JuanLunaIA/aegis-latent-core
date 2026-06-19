# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aegis.core.identity import SpiffeIdentityManager


def _build_test_certificate(spiffe_id: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aegis-test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_verify_peer_identity_accepts_valid_pem_certificate() -> None:
    manager = SpiffeIdentityManager()
    pem = _build_test_certificate("spiffe://example.org/ns/test/sa/workload")
    assert manager.verify_peer_identity(pem) is True


def test_verify_peer_identity_rejects_garbage_bytes() -> None:
    manager = SpiffeIdentityManager()
    assert manager.verify_peer_identity(b"not-a-certificate") is False


def test_extract_spiffe_id_from_san() -> None:
    manager = SpiffeIdentityManager()
    spiffe_id = "spiffe://aegis.cluster.local/ns/aegis/sa/proxy"
    pem = _build_test_certificate(spiffe_id)
    assert manager.extract_spiffe_id(pem) == spiffe_id


def test_extract_spiffe_id_returns_none_without_san() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-san")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    manager = SpiffeIdentityManager()
    assert manager.extract_spiffe_id(pem) is None
