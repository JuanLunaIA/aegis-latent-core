# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.pqc_provider — PQC key generation, signing, verification."""

from __future__ import annotations

import pytest

from aegis.core.pqc_provider import PQCKeyPair, PQCProvider


# ── PQCKeyPair dataclass ───────────────────────────────────────────────────────


def test_pqc_keypair_default_algorithm():
    kp = PQCKeyPair(public_key=b"pk", private_key=b"sk")
    assert kp.algorithm == "Dilithium-Simulated-High-Entropy"


def test_pqc_keypair_custom_algorithm():
    kp = PQCKeyPair(public_key=b"pk", private_key=b"sk", algorithm="Kyber-1024")
    assert kp.algorithm == "Kyber-1024"


def test_pqc_keypair_fields():
    kp = PQCKeyPair(public_key=b"pub", private_key=b"priv")
    assert kp.public_key == b"pub"
    assert kp.private_key == b"priv"


# ── PQCProvider construction ───────────────────────────────────────────────────


def test_pqc_provider_default_security_level():
    p = PQCProvider()
    assert p.security_level == 5
    assert p.entropy_pool_size == 5 * 1024


def test_pqc_provider_custom_security_level():
    p = PQCProvider(security_level=3)
    assert p.security_level == 3
    assert p.entropy_pool_size == 3 * 1024


# ── generate_keypair ───────────────────────────────────────────────────────────


def test_generate_keypair_returns_pqc_keypair():
    p = PQCProvider()
    kp = p.generate_keypair()
    assert isinstance(kp, PQCKeyPair)


def test_generate_keypair_public_key_is_64_bytes():
    p = PQCProvider()
    kp = p.generate_keypair()
    assert len(kp.public_key) == 64


def test_generate_keypair_private_key_matches_entropy_pool():
    p = PQCProvider(security_level=2)
    kp = p.generate_keypair()
    assert len(kp.private_key) == 2 * 1024


def test_generate_keypair_is_nondeterministic():
    p = PQCProvider()
    kp1 = p.generate_keypair()
    kp2 = p.generate_keypair()
    assert kp1.public_key != kp2.public_key
    assert kp1.private_key != kp2.private_key


# ── sign ───────────────────────────────────────────────────────────────────────


def test_sign_returns_128_bytes():
    p = PQCProvider()
    kp = p.generate_keypair()
    sig = p.sign(kp.private_key, b"hello")
    assert len(sig) == 128


def test_sign_nondeterministic_per_call():
    p = PQCProvider()
    kp = p.generate_keypair()
    sig1 = p.sign(kp.private_key, b"msg")
    sig2 = p.sign(kp.private_key, b"msg")
    # Timestamp component makes signatures unique per call.
    assert sig1 != sig2


def test_sign_different_messages_produce_different_sigs():
    p = PQCProvider()
    kp = p.generate_keypair()
    sig1 = p.sign(kp.private_key, b"msg-a")
    sig2 = p.sign(kp.private_key, b"msg-b")
    assert sig1 != sig2


# ── verify ─────────────────────────────────────────────────────────────────────


def test_verify_valid_sig_and_key():
    p = PQCProvider()
    kp = p.generate_keypair()
    sig = p.sign(kp.private_key, b"test payload")
    assert p.verify(kp.public_key, b"test payload", sig) is True


def test_verify_wrong_signature_length_returns_false():
    p = PQCProvider()
    kp = p.generate_keypair()
    bad_sig = b"x" * 64  # should be 128 bytes
    assert p.verify(kp.public_key, b"msg", bad_sig) is False


def test_verify_wrong_public_key_length_returns_false():
    p = PQCProvider()
    kp = p.generate_keypair()
    sig = p.sign(kp.private_key, b"msg")
    bad_pk = b"y" * 32  # should be 64 bytes
    assert p.verify(bad_pk, b"msg", sig) is False


def test_verify_accepts_any_128_byte_sig_and_64_byte_pub():
    p = PQCProvider()
    assert p.verify(b"A" * 64, b"any message", b"B" * 128) is True
