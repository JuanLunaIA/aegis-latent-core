# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Known-answer tests for the primitives the evidence chain depends on.

Every digest, MAC, seal and signature in a forensic bundle rests on SHA-256,
HMAC-SHA256, AES-256-GCM and Ed25519. A wrong primitive would produce records
that verify against themselves and against nothing else, so these tests pin
each one to vectors published by its standard (FIPS 180-4 examples, RFC 4231,
the GCM specification test cases, RFC 8032). Known-answer testing is what
ISO/IEC 18367 describes; this is not a validation of any module, and ML-DSA-65
is not covered here.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aegis.core.crypto_audit import _hmac_sign, _hmac_verify
from aegis.core.evidence_hash import sha256_hex

# FIPS 180-4 / NIST CSRC SHA-256 examples.
SHA256_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
]

# RFC 4231 test cases 1 and 2 (the gateway's HMAC takes a text key).
HMAC_VECTORS = [
    ("\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (
        "Jefe",
        b"what do ya want for nothing?",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    ),
]

# GCM specification (McGrew and Viega) test cases 13 and 14: 256-bit zero key, zero IV.
GCM_VECTORS = [
    (b"", "530f8afbc74536b9a963b4f1c4cb738b"),
    (bytes(16), "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"),
]

# RFC 8032 section 7.1, test 1 (empty message).
ED25519_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
ED25519_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
ED25519_SIGNATURE = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065"
    "224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


@pytest.mark.parametrize(("message", "expected"), SHA256_VECTORS)
def test_evidence_digests_match_the_published_sha256_vectors(message: bytes, expected: str) -> None:
    assert sha256_hex(message) == expected


@pytest.mark.parametrize(("key", "message", "expected"), HMAC_VECTORS)
def test_node_signatures_match_the_rfc_4231_vectors(
    key: str, message: bytes, expected: str
) -> None:
    assert _hmac_sign(key, message) == expected
    assert _hmac_verify(key, message, expected)
    assert not _hmac_verify(key, message + b".", expected)


@pytest.mark.parametrize(("plaintext", "expected"), GCM_VECTORS)
def test_sealing_matches_the_gcm_specification_vectors(plaintext: bytes, expected: str) -> None:
    aead = AESGCM(bytes(32))
    sealed = aead.encrypt(bytes(12), plaintext, None)

    assert sealed.hex() == expected
    assert aead.decrypt(bytes(12), sealed, None) == plaintext


def test_bundle_signatures_match_the_rfc_8032_vector() -> None:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ED25519_SEED))

    assert key.public_key().public_bytes_raw().hex() == ED25519_PUBLIC
    assert key.sign(b"").hex() == ED25519_SIGNATURE
