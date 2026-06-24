# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.pqc_tls — REAL X25519 + ML-KEM-1024 hybrid key exchange.

Replaces the simulated module whose "DH" was sha256(priv || pub) (the two parties
could never agree on a secret) and which provided zero post-quantum security.
These tests prove the real property: initiator and responder independently derive
the *same* 32-byte secret, and any tampering breaks agreement.

The post-quantum half (ML-KEM-1024) requires kyber-py; tests skip cleanly when it
is absent, consistent with tests/test_mlkem_session.py.
"""

from __future__ import annotations

import pytest

from aegis.core.pqc_tls import (
    HYBRID_SECRET_BYTES,
    MLKEM_CIPHERTEXT_BYTES,
    X25519_PUBLIC_BYTES,
    HybridKEMError,
    HybridKEMUnavailableError,
    HybridPQCExchange,
    HybridPublicKey,
    HybridResponderMessage,
    backend_available,
)

requires_mlkem = pytest.mark.skipif(
    not backend_available(), reason="ML-KEM-1024 backend (kyber-py) not installed"
)


# ── Honesty contract (no silent classical downgrade) ──────────────────────────


class TestHonestyContract:
    def test_backend_available_is_bool(self):
        assert isinstance(backend_available(), bool)

    def test_constructor_refuses_without_mlkem(self, monkeypatch):
        import aegis.core.pqc_tls as mod

        monkeypatch.setattr(mod, "HAS_MLKEM", False)
        with pytest.raises(HybridKEMUnavailableError):
            mod.HybridPQCExchange()

    def test_responder_refuses_without_mlkem(self, monkeypatch):
        import aegis.core.pqc_tls as mod

        monkeypatch.setattr(mod, "HAS_MLKEM", False)
        fake_pub = HybridPublicKey(x25519_pk=b"\x00" * 32, mlkem_pk=b"\x00" * 1568)
        with pytest.raises(HybridKEMUnavailableError):
            mod.HybridPQCExchange.responder_respond(fake_pub)

    @requires_mlkem
    def test_verify_quantum_resistance_true_when_real(self):
        assert HybridPQCExchange().verify_quantum_resistance() is True


# ── Public-key shapes ─────────────────────────────────────────────────────────


class TestPublicKeys:
    @requires_mlkem
    def test_public_key_sizes(self):
        pub = HybridPQCExchange().get_public_keys()
        assert len(pub.x25519_pk) == X25519_PUBLIC_BYTES
        assert len(pub.mlkem_pk) == 1568

    @requires_mlkem
    def test_distinct_initiators_have_distinct_keys(self):
        a = HybridPQCExchange().get_public_keys()
        b = HybridPQCExchange().get_public_keys()
        assert a.x25519_pk != b.x25519_pk
        assert a.mlkem_pk != b.mlkem_pk


# ── The real property: both sides agree on the secret ─────────────────────────


class TestKeyAgreement:
    @requires_mlkem
    def test_initiator_and_responder_agree(self):
        initiator = HybridPQCExchange()
        msg, responder_secret = HybridPQCExchange.responder_respond(initiator.get_public_keys())
        initiator_secret = initiator.initiator_derive(msg)
        assert initiator_secret.secret == responder_secret.secret
        assert len(initiator_secret.secret) == HYBRID_SECRET_BYTES
        assert initiator_secret.pqc_verified is True

    @requires_mlkem
    def test_responder_message_shapes(self):
        initiator = HybridPQCExchange()
        msg, _ = HybridPQCExchange.responder_respond(initiator.get_public_keys())
        assert len(msg.x25519_pk) == X25519_PUBLIC_BYTES
        assert len(msg.mlkem_ciphertext) == MLKEM_CIPHERTEXT_BYTES

    @requires_mlkem
    def test_independent_sessions_differ(self):
        i1 = HybridPQCExchange()
        i2 = HybridPQCExchange()
        m1, s1 = HybridPQCExchange.responder_respond(i1.get_public_keys())
        m2, s2 = HybridPQCExchange.responder_respond(i2.get_public_keys())
        assert s1.secret != s2.secret
        assert i1.initiator_derive(m1).secret == s1.secret
        assert i2.initiator_derive(m2).secret == s2.secret

    @requires_mlkem
    def test_secret_is_not_raw_concatenation(self):
        # The secret must be the HKDF output (32 bytes), not a raw 64-byte concat.
        initiator = HybridPQCExchange()
        _, secret = HybridPQCExchange.responder_respond(initiator.get_public_keys())
        assert len(secret.secret) == 32


# ── Tampering breaks agreement (hybrid integrity) ─────────────────────────────


class TestTamperResistance:
    @requires_mlkem
    def test_tampered_ciphertext_breaks_agreement(self):
        initiator = HybridPQCExchange()
        msg, responder_secret = HybridPQCExchange.responder_respond(initiator.get_public_keys())
        ct = bytearray(msg.mlkem_ciphertext)
        ct[0] ^= 0xFF
        tampered = HybridResponderMessage(x25519_pk=msg.x25519_pk, mlkem_ciphertext=bytes(ct))
        # ML-KEM implicit rejection yields a different decapsulated secret →
        # the initiator derives a secret that does NOT match the responder's.
        assert initiator.initiator_derive(tampered).secret != responder_secret.secret

    @requires_mlkem
    def test_tampered_x25519_breaks_agreement(self):
        initiator = HybridPQCExchange()
        msg, responder_secret = HybridPQCExchange.responder_respond(initiator.get_public_keys())
        other_x = HybridPQCExchange().get_public_keys().x25519_pk
        tampered = HybridResponderMessage(x25519_pk=other_x, mlkem_ciphertext=msg.mlkem_ciphertext)
        assert initiator.initiator_derive(tampered).secret != responder_secret.secret


# ── Input validation ──────────────────────────────────────────────────────────


class TestInputValidation:
    @requires_mlkem
    def test_responder_rejects_bad_x25519_length(self):
        bad = HybridPublicKey(x25519_pk=b"\x00" * 16, mlkem_pk=b"\x00" * 1568)
        with pytest.raises(HybridKEMError):
            HybridPQCExchange.responder_respond(bad)

    @requires_mlkem
    def test_initiator_rejects_bad_x25519_length(self):
        initiator = HybridPQCExchange()
        bad = HybridResponderMessage(x25519_pk=b"\x00" * 16, mlkem_ciphertext=b"\x00" * 1568)
        with pytest.raises(HybridKEMError):
            initiator.initiator_derive(bad)
