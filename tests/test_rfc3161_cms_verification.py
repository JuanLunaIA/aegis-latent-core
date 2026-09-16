"""
tests/test_rfc3161_cms_verification.py — a timestamp that is actually verified.

`RFC3161Timestamper.verify` used to check two things: that the stored imprint
matched the package, and that the token's first DER tag was `0x30`. A token
assembled by anyone — with no TSA involvement at all — satisfied both. The
module's own comment admitted it ("PKI trust requires the TSA cert chain"), but
the return value said `valid=True`.

These tests build genuine CMS `SignedData` tokens with a throwaway CA, so each
property can be falsified independently rather than asserted:

* a correctly signed token verifies;
* flipping one byte of the signature is rejected;
* a token signed by an untrusted CA is rejected once anchors are required;
* an expired signing certificate is rejected;
* a mismatched `messageImprint` is rejected even though the signature is valid.

The last one matters most: signature validity and *attesting to the right
document* are different claims, and a verifier that conflates them accepts a
real TSA signature over somebody else's evidence.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aegis.core.rfc3161_cms import CMSVerificationError, verify_timestamp_token

# ── Minimal DER writer, enough to assemble a real TimeStampToken ────────────


def _tlv(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + value


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(0x31, b"".join(items))


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = bytearray([part & 0x7F])
        part >>= 7
        while part:
            chunk.insert(0, (part & 0x7F) | 0x80)
            part >>= 7
        body += bytes(chunk)
    return _tlv(0x06, body)


def _int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=False)
    return _tlv(0x02, raw)


def _octet(value: bytes) -> bytes:
    return _tlv(0x04, value)


SHA256_ALG = _seq(_oid("2.16.840.1.101.3.4.2.1"), _tlv(0x05, b""))
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"


def _make_ca(name: str, *, days_valid: int = 3650):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_tsa(ca_key, ca_cert, *, not_before=None, not_after=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _tst_info(imprint: bytes) -> bytes:
    """A TSTInfo whose messageImprint is *imprint*."""
    return _seq(
        _int(1),
        _oid("1.2.3.4.1"),
        _seq(SHA256_ALG, _octet(imprint)),
        _int(42),
        _tlv(0x18, b"20260916000000Z"),
    )


def _build_token(tsa_key, tsa_cert, ca_cert, imprint: bytes, *, corrupt_sig=False) -> bytes:
    econtent = _tst_info(imprint)
    signed_attrs_items = [
        _seq(_oid("1.2.840.113549.1.9.3"), _set(_oid(OID_TST_INFO))),
        _seq(_oid("1.2.840.113549.1.9.4"), _set(_octet(hashlib.sha256(econtent).digest()))),
    ]
    # Signed as an explicit SET OF; carried as [0] IMPLICIT. CMS requires both.
    to_sign = _set(*signed_attrs_items)
    signature = tsa_key.sign(
        to_sign,
        __import__(
            "cryptography.hazmat.primitives.asymmetric.padding", fromlist=["PKCS1v15"]
        ).PKCS1v15(),
        hashes.SHA256(),
    )
    if corrupt_sig:
        signature = bytes([signature[0] ^ 0xFF]) + signature[1:]

    signer_info = _seq(
        _int(1),
        _seq(ca_cert.subject.public_bytes(), _int(tsa_cert.serial_number)),
        SHA256_ALG,
        _tlv(0xA0, b"".join(signed_attrs_items)),
        _seq(_oid("1.2.840.113549.1.1.1"), _tlv(0x05, b"")),
        _octet(signature),
    )
    certs = tsa_cert.public_bytes(serialization.Encoding.DER) + ca_cert.public_bytes(
        serialization.Encoding.DER
    )
    signed_data = _seq(
        _int(3),
        _set(SHA256_ALG),
        _seq(_oid(OID_TST_INFO), _tlv(0xA0, _octet(econtent))),
        _tlv(0xA0, certs),
        _set(signer_info),
    )
    return _seq(_oid("1.2.840.113549.1.7.2"), _tlv(0xA0, signed_data))


IMPRINT = hashlib.sha256(b"the evidence package").digest()


@pytest.fixture(scope="module")
def pki():
    ca_key, ca_cert = _make_ca("Test Root CA")
    tsa_key, tsa_cert = _make_tsa(ca_key, ca_cert)
    return ca_key, ca_cert, tsa_key, tsa_cert


def test_a_genuine_token_verifies_and_reports_the_chain(pki) -> None:
    ca_key, ca_cert, tsa_key, tsa_cert = pki
    token = _build_token(tsa_key, tsa_cert, ca_cert, IMPRINT)
    result = verify_timestamp_token(token, expected_imprint=IMPRINT, trust_anchors=[ca_cert])
    assert result.chain_verified is True
    assert result.message_imprint == IMPRINT
    assert result.signer.subject == tsa_cert.subject
    # Revocation is never claimed, so it must never read as done.
    assert result.revocation_checked is False


def test_a_tampered_signature_is_rejected(pki) -> None:
    ca_key, ca_cert, tsa_key, tsa_cert = pki
    token = _build_token(tsa_key, tsa_cert, ca_cert, IMPRINT, corrupt_sig=True)
    with pytest.raises(CMSVerificationError, match="signature does not verify"):
        verify_timestamp_token(token, expected_imprint=IMPRINT, trust_anchors=[ca_cert])


def test_a_valid_signature_over_the_wrong_imprint_is_rejected(pki) -> None:
    """Signature validity and attesting to *this* document are two claims."""
    ca_key, ca_cert, tsa_key, tsa_cert = pki
    other = hashlib.sha256(b"a different package").digest()
    token = _build_token(tsa_key, tsa_cert, ca_cert, other)
    with pytest.raises(CMSVerificationError, match="does not match expected"):
        verify_timestamp_token(token, expected_imprint=IMPRINT, trust_anchors=[ca_cert])


def test_an_untrusted_issuer_is_rejected(pki) -> None:
    """The spoofed-TSA case: structurally perfect, issued by a stranger."""
    _, _, _, _ = pki
    rogue_key, rogue_cert = _make_ca("Rogue CA")
    tsa_key, tsa_cert = _make_tsa(rogue_key, rogue_cert)
    token = _build_token(tsa_key, tsa_cert, rogue_cert, IMPRINT)

    _, real_ca, _, _ = pki
    with pytest.raises(CMSVerificationError, match="no trusted path"):
        verify_timestamp_token(token, expected_imprint=IMPRINT, trust_anchors=[real_ca])

    # Against its own CA it verifies — which is exactly why the anchor must be
    # supplied out of band rather than taken from the token.
    assert verify_timestamp_token(
        token, expected_imprint=IMPRINT, trust_anchors=[rogue_cert]
    ).chain_verified


def test_an_expired_signing_certificate_is_rejected(pki) -> None:
    ca_key, ca_cert, _, _ = pki
    past = datetime.now(UTC) - timedelta(days=400)
    tsa_key, tsa_cert = _make_tsa(
        ca_key, ca_cert, not_before=past, not_after=past + timedelta(days=30)
    )
    token = _build_token(tsa_key, tsa_cert, ca_cert, IMPRINT)
    with pytest.raises(CMSVerificationError, match="outside its validity window"):
        verify_timestamp_token(token, expected_imprint=IMPRINT, trust_anchors=[ca_cert])


def test_a_swapped_econtent_breaks_the_message_digest_binding(pki) -> None:
    """signedAttrs must not be liftable onto a different TSTInfo."""
    ca_key, ca_cert, tsa_key, tsa_cert = pki
    token = _build_token(tsa_key, tsa_cert, ca_cert, IMPRINT)
    other = _tst_info(hashlib.sha256(b"substituted").digest())
    swapped = token.replace(_tst_info(IMPRINT), other)
    assert swapped != token, "the swap must change the bytes"
    with pytest.raises(CMSVerificationError):
        verify_timestamp_token(swapped, expected_imprint=IMPRINT, trust_anchors=[ca_cert])


def test_without_anchors_the_chain_is_reported_unverified(pki) -> None:
    """A bare success must not imply trust it did not establish."""
    ca_key, ca_cert, tsa_key, tsa_cert = pki
    token = _build_token(tsa_key, tsa_cert, ca_cert, IMPRINT)
    result = verify_timestamp_token(token, expected_imprint=IMPRINT, trust_anchors=None)
    assert result.chain_verified is False


def test_garbage_is_rejected_rather_than_parsed() -> None:
    with pytest.raises(CMSVerificationError):
        verify_timestamp_token(b"\x30\x03\x02\x01\x00", expected_imprint=IMPRINT)
    with pytest.raises(CMSVerificationError):
        verify_timestamp_token(b"not der at all", expected_imprint=IMPRINT)
