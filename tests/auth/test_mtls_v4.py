"""Deterministic mTLS verifier security tests."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aegis.auth.mtls import (
    MTLSVerificationConfig,
    MTLSVerificationError,
    MTLSVerifier,
    certificate_sha256,
)

NOW = datetime(2033, 5, 18, tzinfo=UTC)


def make_certificate(
    *,
    sans: tuple[str, ...] = ("client.example.test", "tenant:tenant-a"),
    not_before: datetime = NOW - timedelta(days=1),
    not_after: datetime = NOW + timedelta(days=1),
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "workload-7")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(value) for value in sans]), False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def verifier(pem: bytes, **overrides: object) -> MTLSVerifier:
    options: dict[str, object] = {
        "trusted_proxy_cidrs": ("10.20.0.0/16",),
        "allowed_sha256_fingerprints": frozenset({certificate_sha256(pem)}),
        "san_allowlist": frozenset({"client.example.test"}),
    }
    options.update(overrides)
    return MTLSVerifier(MTLSVerificationConfig(**options), clock=lambda: NOW)  # type: ignore[arg-type]


def test_direct_peer_certificate_is_verified_and_tenant_bound() -> None:
    pem = make_certificate()
    principal = verifier(pem).verify(
        source_ip="198.51.100.9", tenant_id="tenant-a", peer_certificate=pem
    )
    assert principal.subject == "workload-7"
    assert principal.auth_method == "mtls"
    assert principal.tenant_id == "tenant-a"
    assert principal.credential_id == f"mtls:{certificate_sha256(pem)}"


def test_untrusted_source_cannot_smuggle_forwarded_certificate() -> None:
    pem = make_certificate()
    headers = {
        "X-Forwarded-Client-Cert": pem.decode(),
        "X-Client-Cert-Sha256": certificate_sha256(pem),
    }
    with pytest.raises(MTLSVerificationError, match="required"):
        verifier(pem).verify(source_ip="10.19.255.255", tenant_id="tenant-a", headers=headers)


def test_trusted_proxy_may_forward_cert_and_matching_fingerprint() -> None:
    pem = make_certificate()
    principal = verifier(pem).verify(
        source_ip="10.20.3.4",
        tenant_id="tenant-a",
        headers={
            "x-forwarded-client-cert": pem.decode().replace("\n", "%0A"),
            "x-client-cert-sha256": certificate_sha256(pem).upper(),
        },
    )
    assert principal.subject == "workload-7"


def test_rejects_fingerprint_mismatch_and_non_allowlisted_fingerprint() -> None:
    pem = make_certificate()
    other = make_certificate(sans=("client.example.test", "tenant:tenant-a", "other"))
    with pytest.raises(MTLSVerificationError, match="fingerprint is not allowed"):
        verifier(pem).verify(source_ip="127.0.0.1", tenant_id="tenant-a", peer_certificate=other)
    with pytest.raises(MTLSVerificationError, match="fingerprint mismatch"):
        verifier(pem).verify(
            source_ip="10.20.1.1",
            tenant_id="tenant-a",
            headers={
                "x-forwarded-client-cert": pem.decode(),
                "x-client-cert-sha256": "00" * 32,
            },
        )


@pytest.mark.parametrize(
    "pem",
    [
        make_certificate(not_before=NOW + timedelta(seconds=1)),
        make_certificate(not_after=NOW),
    ],
)
def test_rejects_certificate_outside_validity_window(pem: bytes) -> None:
    with pytest.raises(MTLSVerificationError, match="not yet valid|expired"):
        verifier(pem).verify(source_ip="127.0.0.1", tenant_id="tenant-a", peer_certificate=pem)


def test_rejects_san_allowlist_and_tenant_mismatch() -> None:
    bad_san = make_certificate(sans=("evil.example.test", "tenant:tenant-a"))
    with pytest.raises(MTLSVerificationError, match="SAN is not allowed"):
        verifier(bad_san, san_allowlist=frozenset({"client.example.test"})).verify(
            source_ip="127.0.0.1", tenant_id="tenant-a", peer_certificate=bad_san
        )
    pem = make_certificate()
    with pytest.raises(MTLSVerificationError, match="expected tenant"):
        verifier(pem).verify(source_ip="127.0.0.1", tenant_id="tenant-b", peer_certificate=pem)


def test_rejects_ambiguous_tenant_sans() -> None:
    pem = make_certificate(sans=("client.example.test", "tenant:tenant-a", "tenant:tenant-b"))
    with pytest.raises(MTLSVerificationError, match="exactly one tenant"):
        verifier(pem).verify(source_ip="127.0.0.1", peer_certificate=pem)
