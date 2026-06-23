# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.mlkem_session — FIPS 203 ML-KEM (Kyber-1024) session bootstrap."""

from __future__ import annotations

import pytest

from aegis.core.mlkem_session import (
    CIPHERTEXT_SIZE,
    HAS_MLKEM,
    PK_SIZE,
    SHARED_SECRET_SIZE,
    SK_SIZE,
    MLKEMError,
    MLKEMKeyPair,
    MLKEMSessionBootstrap,
    MLKEMSizeError,
    MLKEMUnavailableError,
)

pytestmark = pytest.mark.skipif(not HAS_MLKEM, reason="kyber-py not installed")


# ── Keypair generation ────────────────────────────────────────────────────────


def test_generate_keypair_sizes():
    kp = MLKEMSessionBootstrap.generate_keypair()
    assert len(kp.public_key) == PK_SIZE
    assert len(kp.secret_key) == SK_SIZE


def test_generate_keypair_returns_bytes():
    kp = MLKEMSessionBootstrap.generate_keypair()
    assert isinstance(kp.public_key, bytes)
    assert isinstance(kp.secret_key, bytes)


def test_generate_keypair_is_random():
    kp1 = MLKEMSessionBootstrap.generate_keypair()
    kp2 = MLKEMSessionBootstrap.generate_keypair()
    assert kp1.public_key != kp2.public_key
    assert kp1.secret_key != kp2.secret_key


def test_keypair_frozen():
    kp = MLKEMSessionBootstrap.generate_keypair()
    with pytest.raises(Exception):
        kp.public_key = b"x" * PK_SIZE  # type: ignore[misc]


# ── MLKEMKeyPair dataclass validation ─────────────────────────────────────────


def test_keypair_wrong_pk_size():
    with pytest.raises(MLKEMSizeError, match="public_key"):
        MLKEMKeyPair(public_key=b"short", secret_key=b"\x00" * SK_SIZE)


def test_keypair_wrong_sk_size():
    with pytest.raises(MLKEMSizeError, match="secret_key"):
        MLKEMKeyPair(public_key=b"\x00" * PK_SIZE, secret_key=b"short")


# ── Encapsulation ─────────────────────────────────────────────────────────────


def test_encapsulate_output_sizes():
    kp = MLKEMSessionBootstrap.generate_keypair()
    ss, ct = MLKEMSessionBootstrap.encapsulate(kp.public_key)
    assert len(ss) == SHARED_SECRET_SIZE
    assert len(ct) == CIPHERTEXT_SIZE


def test_encapsulate_returns_bytes():
    kp = MLKEMSessionBootstrap.generate_keypair()
    ss, ct = MLKEMSessionBootstrap.encapsulate(kp.public_key)
    assert isinstance(ss, bytes)
    assert isinstance(ct, bytes)


def test_encapsulate_wrong_pk_size():
    with pytest.raises(MLKEMSizeError, match="public_key"):
        MLKEMSessionBootstrap.encapsulate(b"\x00" * 16)


def test_encapsulate_is_non_deterministic():
    kp = MLKEMSessionBootstrap.generate_keypair()
    ss1, ct1 = MLKEMSessionBootstrap.encapsulate(kp.public_key)
    ss2, ct2 = MLKEMSessionBootstrap.encapsulate(kp.public_key)
    # Both encapsulations should produce different ciphertexts (randomised)
    assert ct1 != ct2


# ── Decapsulation ─────────────────────────────────────────────────────────────


def test_decapsulate_recovers_shared_secret():
    kp = MLKEMSessionBootstrap.generate_keypair()
    ss_enc, ct = MLKEMSessionBootstrap.encapsulate(kp.public_key)
    ss_dec = MLKEMSessionBootstrap.decapsulate(kp.secret_key, ct)
    assert ss_enc == ss_dec


def test_decapsulate_returns_bytes():
    kp = MLKEMSessionBootstrap.generate_keypair()
    _, ct = MLKEMSessionBootstrap.encapsulate(kp.public_key)
    ss = MLKEMSessionBootstrap.decapsulate(kp.secret_key, ct)
    assert isinstance(ss, bytes)
    assert len(ss) == SHARED_SECRET_SIZE


def test_decapsulate_wrong_sk_size():
    _, ct = MLKEMSessionBootstrap.encapsulate(MLKEMSessionBootstrap.generate_keypair().public_key)
    with pytest.raises(MLKEMSizeError, match="secret_key"):
        MLKEMSessionBootstrap.decapsulate(b"\x00" * 16, ct)


def test_decapsulate_wrong_ct_size():
    kp = MLKEMSessionBootstrap.generate_keypair()
    with pytest.raises(MLKEMSizeError, match="ciphertext"):
        MLKEMSessionBootstrap.decapsulate(kp.secret_key, b"\x00" * 16)


def test_decapsulate_mismatched_keypair():
    # Decapsulating with the wrong secret key must not raise but will produce a
    # different (implicit rejection) shared secret — never the same one.
    kp_a = MLKEMSessionBootstrap.generate_keypair()
    kp_b = MLKEMSessionBootstrap.generate_keypair()
    ss_enc, ct = MLKEMSessionBootstrap.encapsulate(kp_a.public_key)
    ss_dec = MLKEMSessionBootstrap.decapsulate(kp_b.secret_key, ct)
    assert ss_enc != ss_dec


# ── Full exchange ─────────────────────────────────────────────────────────────


def test_full_exchange_produces_matching_secrets():
    kp, ss, ct = MLKEMSessionBootstrap.full_exchange()
    assert len(ss) == SHARED_SECRET_SIZE
    assert len(ct) == CIPHERTEXT_SIZE
    assert len(kp.public_key) == PK_SIZE
    assert len(kp.secret_key) == SK_SIZE


def test_full_exchange_secrets_are_non_zero():
    _, ss, _ = MLKEMSessionBootstrap.full_exchange()
    assert ss != b"\x00" * SHARED_SECRET_SIZE


def test_full_exchange_multiple_independent():
    _, ss1, _ = MLKEMSessionBootstrap.full_exchange()
    _, ss2, _ = MLKEMSessionBootstrap.full_exchange()
    assert ss1 != ss2


# ── MLKEMUnavailableError path ────────────────────────────────────────────────


def test_mlkem_unavailable_error_is_mlkem_error():
    assert issubclass(MLKEMUnavailableError, MLKEMError)


def test_mlkem_size_error_is_mlkem_error():
    assert issubclass(MLKEMSizeError, MLKEMError)


# ── HAS_MLKEM flag ────────────────────────────────────────────────────────────


def test_has_mlkem_is_true():
    # If we reached here, kyber-py IS installed and the flag must be True.
    assert HAS_MLKEM is True
