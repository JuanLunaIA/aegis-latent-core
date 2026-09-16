"""CMS (RFC 5652) signature verification for RFC 3161 timestamp tokens.

`RFC3161Timestamper.verify` used to establish two things: that the stored
message imprint matched the package, and that the token's outermost DER tag was
a SEQUENCE. Neither involves the TSA's signature, so a token whose bytes were
produced by anyone at all passed — the module said so in a comment ("PKI trust
requires the TSA cert chain") rather than in its result.

This module supplies the missing half. A token is accepted only when:

1. it parses as a CMS ``SignedData`` carrying ``id-ct-TSTInfo`` content;
2. the ``messageDigest`` signed attribute equals SHA-256 of that content, which
   is what binds the attributes an attacker can see to the content they cannot
   change without detection;
3. the signer's signature over the DER re-encoding of ``signedAttrs`` verifies
   under the signing certificate's public key;
4. the ``messageImprint`` inside ``TSTInfo`` equals the caller's expected digest;
5. the signing certificate chains to a trust anchor **the caller supplied**, not
   one carried in the token.

Point 5 is the one that makes the rest mean anything: a chain validated against
certificates extracted from the same token proves self-consistency, which a
forger provides for free.

**Not established here** — and so not claimed anywhere: revocation. No OCSP or
CRL check is performed, because both require network calls at verification
time, and a forensic verifier is frequently offline. A certificate revoked
after issuance still validates here. That is a real gap, recorded as
`[CONFIGURATION-DEPENDENT]`: an operator who needs revocation must run it
outside this function against the returned certificate.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

#: OID 1.2.840.113549.1.7.2 — id-signedData
_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
#: OID 1.2.840.113549.1.9.16.1.4 — id-ct-TSTInfo
_OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
#: OID 1.2.840.113549.1.9.4 — id-messageDigest
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"


class CMSVerificationError(Exception):
    """The token is not a CMS SignedData that verifies as required."""


@dataclass(frozen=True)
class CMSVerificationResult:
    """What verification established, and explicitly what it did not."""

    signer: x509.Certificate
    tst_info: bytes
    message_imprint: bytes
    chain_verified: bool
    #: Always False. Present so a caller cannot mistake absence for success.
    revocation_checked: bool = False


def _tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Return ``(tag, value, next_offset)`` for one DER element."""
    if offset >= len(data):
        raise CMSVerificationError("truncated DER: no tag byte")
    tag = data[offset]
    index = offset + 1
    if index >= len(data):
        raise CMSVerificationError("truncated DER: no length byte")
    first = data[index]
    index += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise CMSVerificationError("unsupported DER length encoding")
        if index + count > len(data):
            raise CMSVerificationError("truncated DER length")
        length = int.from_bytes(data[index : index + count], "big")
        index += count
    else:
        length = first
    end = index + length
    if end > len(data):
        raise CMSVerificationError("DER length exceeds available bytes")
    return tag, data[index:end], end


def _children(value: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, child, offset = _tlv(value, offset)
        out.append((tag, child))
    return out


def _oid(value: bytes) -> str:
    """Decode a DER OBJECT IDENTIFIER body to dotted form."""
    if not value:
        raise CMSVerificationError("empty OID")
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


def _reencode(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + value


def _verify_signature(certificate: x509.Certificate, signature: bytes, payload: bytes) -> None:
    key = certificate.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, Ed25519PublicKey):
            key.verify(signature, payload)
        else:
            raise CMSVerificationError(f"unsupported TSA public key type: {type(key).__name__}")
    except InvalidSignature as exc:
        raise CMSVerificationError("TSA signature does not verify") from exc


def verify_timestamp_token(
    token: bytes,
    *,
    expected_imprint: bytes,
    trust_anchors: list[x509.Certificate] | None = None,
) -> CMSVerificationResult:
    """Verify a TimeStampToken, or raise :class:`CMSVerificationError`.

    Args:
        token: DER ``ContentInfo`` holding CMS ``SignedData``.
        expected_imprint: The SHA-256 digest the token must attest to.
        trust_anchors: Certificates the signer must chain to. **Supplying none
            means no chain is validated** — the signature is still checked, but
            against whatever certificate the token carries, which establishes
            internal consistency and nothing about who signed it. The result's
            ``chain_verified`` reports which case applied, so a caller cannot
            read a bare success as trust.
    """
    tag, content_info, _ = _tlv(token)
    if tag != 0x30:
        raise CMSVerificationError(f"token is not a DER SEQUENCE (tag=0x{tag:02X})")

    items = _children(content_info)
    if len(items) < 2 or items[0][0] != 0x06:
        raise CMSVerificationError("ContentInfo missing contentType OID")
    if _oid(items[0][1]) != _OID_SIGNED_DATA:
        raise CMSVerificationError("ContentInfo is not id-signedData")

    signed_data_children = _children(items[1][1])
    if not signed_data_children or signed_data_children[0][0] != 0x30:
        raise CMSVerificationError("SignedData is not a SEQUENCE")
    fields = _children(signed_data_children[0][1])

    econtent: bytes | None = None
    signer_infos: bytes | None = None
    cert_blob: bytes | None = None
    for field_tag, field_value in fields:
        if field_tag == 0xA0:  # [0] IMPLICIT CertificateSet
            cert_blob = field_value
        elif field_tag == 0x30:  # EncapsulatedContentInfo
            parts = _children(field_value)
            if parts and parts[0][0] == 0x06 and _oid(parts[0][1]) == _OID_TST_INFO:
                if len(parts) < 2:
                    raise CMSVerificationError("eContentInfo carries no eContent")
                inner = _children(parts[1][1])
                if not inner or inner[0][0] != 0x04:
                    raise CMSVerificationError("eContent is not an OCTET STRING")
                econtent = inner[0][1]
        elif field_tag == 0x31:  # SET OF SignerInfo
            signer_infos = field_value

    if econtent is None:
        raise CMSVerificationError("token carries no id-ct-TSTInfo content")
    if signer_infos is None:
        raise CMSVerificationError("SignedData carries no SignerInfo")

    # Decode the CertificateSet in place rather than re-parsing the whole token
    # through a PKCS#7 helper: the elements are already located, and each is a
    # complete DER Certificate.
    if cert_blob is None:
        raise CMSVerificationError("token carries no certificates")
    certificates: list[x509.Certificate] = []
    offset = 0
    while offset < len(cert_blob):
        _, _, end = _tlv(cert_blob, offset)
        try:
            certificates.append(x509.load_der_x509_certificate(cert_blob[offset:end]))
        except Exception as exc:  # noqa: BLE001 - any decode failure is a bad token
            raise CMSVerificationError(f"malformed certificate in token: {exc}") from exc
        offset = end
    if not certificates:
        raise CMSVerificationError("token carries no certificates")

    signer_children = _children(signer_infos)
    if not signer_children:
        raise CMSVerificationError("empty SignerInfo set")
    info = _children(signer_children[0][1])

    signed_attrs_raw: bytes | None = None
    signature: bytes | None = None
    for attr_tag, attr_value in info:
        if attr_tag == 0xA0:  # [0] IMPLICIT signedAttrs
            signed_attrs_raw = attr_value
        elif attr_tag == 0x04:
            signature = attr_value
    if signed_attrs_raw is None:
        raise CMSVerificationError("SignerInfo has no signedAttrs")
    if signature is None:
        raise CMSVerificationError("SignerInfo has no signature")

    # messageDigest must equal SHA-256 of eContent. Without this, signedAttrs
    # could be lifted onto a different TSTInfo.
    digest_attr: bytes | None = None
    for _, attribute in _children(signed_attrs_raw):
        parts = _children(attribute)
        if len(parts) >= 2 and parts[0][0] == 0x06 and _oid(parts[0][1]) == _OID_MESSAGE_DIGEST:
            values = _children(parts[1][1])
            if values and values[0][0] == 0x04:
                digest_attr = values[0][1]
    if digest_attr is None:
        raise CMSVerificationError("signedAttrs has no messageDigest attribute")
    if digest_attr != hashlib.sha256(econtent).digest():
        raise CMSVerificationError("messageDigest does not match eContent")

    # CMS signs the DER re-encoding of signedAttrs as an explicit SET OF,
    # not the [0] IMPLICIT form that appears in the token.
    signer_cert = certificates[0]
    _verify_signature(signer_cert, signature, _reencode(0x31, signed_attrs_raw))

    imprint = _extract_message_imprint(econtent)
    if imprint != expected_imprint:
        raise CMSVerificationError(
            f"TSTInfo messageImprint {imprint.hex()[:16]}… does not match expected "
            f"{expected_imprint.hex()[:16]}…"
        )

    chain_verified = False
    if trust_anchors:
        _verify_chain(signer_cert, certificates, trust_anchors)
        chain_verified = True

    return CMSVerificationResult(
        signer=signer_cert,
        tst_info=econtent,
        message_imprint=imprint,
        chain_verified=chain_verified,
    )


def _extract_message_imprint(tst_info: bytes) -> bytes:
    """Pull ``messageImprint.hashedMessage`` out of a DER ``TSTInfo``."""
    tag, body, _ = _tlv(tst_info)
    if tag != 0x30:
        raise CMSVerificationError("TSTInfo is not a SEQUENCE")
    for field_tag, field_value in _children(body):
        if field_tag != 0x30:
            continue
        parts = _children(field_value)
        # MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
        #                               hashedMessage OCTET STRING }
        if len(parts) == 2 and parts[0][0] == 0x30 and parts[1][0] == 0x04:
            return parts[1][1]
    raise CMSVerificationError("TSTInfo carries no messageImprint")


def _verify_chain(
    signer: x509.Certificate,
    intermediates: list[x509.Certificate],
    trust_anchors: list[x509.Certificate],
) -> None:
    """Validate *signer* to a supplied anchor, checking validity windows.

    A full RFC 5280 path builder is deliberately not reimplemented here. What
    this does check is issuer/subject linkage, signature at each hop, and that
    every certificate in the resulting path is inside its validity window — the
    properties a forged or expired TSA certificate fails.
    """
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    anchors = {anchor.subject: anchor for anchor in trust_anchors}
    pool = {cert.subject: cert for cert in intermediates}

    current = signer
    for _ in range(8):  # bounded: a path longer than this is refused, not walked
        if current.not_valid_before_utc > now or current.not_valid_after_utc < now:
            raise CMSVerificationError(
                f"certificate '{current.subject.rfc4514_string()}' is outside its "
                f"validity window (not_after={current.not_valid_after_utc.isoformat()})"
            )
        issuer = anchors.get(current.issuer)
        if issuer is not None:
            _verify_issued_by(current, issuer)
            if issuer.not_valid_after_utc < now:
                raise CMSVerificationError("trust anchor has expired")
            return
        issuer = pool.get(current.issuer)
        if issuer is None or issuer.subject == current.subject:
            raise CMSVerificationError(
                f"no trusted path: '{current.subject.rfc4514_string()}' was issued by "
                f"'{current.issuer.rfc4514_string()}', which is not a supplied anchor"
            )
        _verify_issued_by(current, issuer)
        current = issuer
    raise CMSVerificationError("certificate chain exceeds the supported depth")


def _verify_issued_by(child: x509.Certificate, issuer: x509.Certificate) -> None:
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,  # type: ignore[arg-type]
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),  # type: ignore[arg-type]
            )
        elif isinstance(key, Ed25519PublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes)
        else:
            raise CMSVerificationError(f"unsupported issuer key: {type(key).__name__}")
    except InvalidSignature as exc:
        raise CMSVerificationError(
            f"'{child.subject.rfc4514_string()}' is not validly signed by "
            f"'{issuer.subject.rfc4514_string()}'"
        ) from exc
