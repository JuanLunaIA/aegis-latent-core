# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.pqc_signer — REAL ML-DSA-65 (FIPS 204) signing.

These replace the deleted tests/test_pqc_provider.py, which exercised a
*simulated* provider whose verify() accepted any signature. The tests below
prove the real cryptographic property the old module faked: a forged or
tampered signature is rejected, and signatures verify only under the matching
public key.

The signing backend is the Rust `pqcrypto-mldsa` extension; tests skip cleanly
when the extension is not built (pure-Python install), consistent with
tests/test_rust_extension.py.
"""

from __future__ import annotations

import pytest

from aegis.core.pqc_signer import (
    ALGORITHM,
    PRIVATE_KEY_BYTES,
    PUBLIC_KEY_BYTES,
    SIGNATURE_BYTES,
    PQCSigner,
    PQCUnavailableError,
    backend_available,
)

_REAL = backend_available()
requires_real = pytest.mark.skipif(not _REAL, reason="aegis_rust ML-DSA-65 backend not installed")


# ── FIPS 204 ML-DSA-65 parameter constants ────────────────────────────────────


class TestParameters:
    def test_algorithm_label(self):
        assert ALGORITHM == "ml-dsa-65"

    def test_fips204_sizes(self):
        # Fixed by FIPS 204 ML-DSA-65.
        assert PUBLIC_KEY_BYTES == 1952
        assert PRIVATE_KEY_BYTES == 4032
        assert SIGNATURE_BYTES == 3309


# ── Availability / honesty contract ──────────────────────────────────────────


class TestHonestyContract:
    @requires_real
    def test_real_backend_reports_available(self):
        s = PQCSigner()
        assert s.is_available is True
        assert s.backend == "ml-dsa-65-rust"
        assert s.algorithm == "ml-dsa-65"

    @requires_real
    def test_require_real_succeeds_with_backend(self):
        s = PQCSigner(require_real=True)
        assert s.is_available is True

    def test_backend_label_is_never_a_simulation(self):
        # Whatever the environment, the label must be real or honestly "unavailable" —
        # never a "simulated"/"high-entropy" euphemism like the deleted modules used.
        s = PQCSigner()
        assert s.backend in {"ml-dsa-65-rust", "unavailable"}

    def test_unavailable_signer_raises_on_sign(self):
        # Force the no-backend state without a real keypair.
        s = PQCSigner.__new__(PQCSigner)
        s._kp = None
        s._backend = "unavailable"
        assert s.is_available is False
        with pytest.raises(PQCUnavailableError):
            s.sign(b"data")
        with pytest.raises(PQCUnavailableError):
            _ = s.public_key

    def test_require_real_raises_without_backend(self, monkeypatch):
        import aegis.core.pqc_signer as mod

        monkeypatch.setattr(mod, "_HAS_RUST", False)
        with pytest.raises(PQCUnavailableError):
            PQCSigner(require_real=True)


# ── Real key material ─────────────────────────────────────────────────────────


class TestKeyMaterial:
    @requires_real
    def test_public_key_size(self):
        s = PQCSigner()
        assert len(s.public_key) == PUBLIC_KEY_BYTES

    @requires_real
    def test_distinct_signers_have_distinct_keys(self):
        a, b = PQCSigner(), PQCSigner()
        assert a.public_key != b.public_key


# ── Real signing / verification (the property the fake module faked) ──────────


class TestSignVerifyKAT:
    @requires_real
    def test_roundtrip_verifies(self):
        s = PQCSigner()
        msg = b"aegis-forensic-audit-node:state_id=abc123"
        sig = s.sign(msg)
        assert len(sig) == SIGNATURE_BYTES
        assert PQCSigner.verify(msg, sig, s.public_key) is True

    @requires_real
    def test_signing_is_randomized_but_both_verify(self):
        # ML-DSA hedged signing is non-deterministic; both still verify.
        s = PQCSigner()
        msg = b"same-message"
        sig1, sig2 = s.sign(msg), s.sign(msg)
        assert sig1 != sig2
        assert PQCSigner.verify(msg, sig1, s.public_key)
        assert PQCSigner.verify(msg, sig2, s.public_key)

    @requires_real
    def test_tampered_message_rejected(self):
        s = PQCSigner()
        sig = s.sign(b"original")
        assert PQCSigner.verify(b"tampered", sig, s.public_key) is False

    @requires_real
    def test_tampered_signature_rejected(self):
        s = PQCSigner()
        msg = b"original"
        sig = bytearray(s.sign(msg))
        sig[0] ^= 0xFF
        assert PQCSigner.verify(msg, bytes(sig), s.public_key) is False

    @requires_real
    def test_wrong_public_key_rejected(self):
        signer, other = PQCSigner(), PQCSigner()
        msg = b"bound-to-signer"
        sig = signer.sign(msg)
        assert PQCSigner.verify(msg, sig, other.public_key) is False

    @requires_real
    def test_forged_signature_rejected(self):
        # The deleted fake accepted any 128-byte blob; the real one must not.
        s = PQCSigner()
        forged = b"\x00" * SIGNATURE_BYTES
        assert PQCSigner.verify(b"x", forged, s.public_key) is False

    @requires_real
    def test_truncated_signature_rejected(self):
        s = PQCSigner()
        msg = b"msg"
        sig = s.sign(msg)
        assert PQCSigner.verify(msg, sig[:-1], s.public_key) is False

    @requires_real
    def test_empty_message_signs_and_verifies(self):
        s = PQCSigner()
        sig = s.sign(b"")
        assert PQCSigner.verify(b"", sig, s.public_key) is True


# ── verify() input hardening ──────────────────────────────────────────────────


class TestVerifyHardening:
    @requires_real
    def test_verify_rejects_non_bytes(self):
        s = PQCSigner()
        sig = s.sign(b"m")
        assert PQCSigner.verify("m", sig, s.public_key) is False  # type: ignore[arg-type]
        assert PQCSigner.verify(b"m", None, s.public_key) is False  # type: ignore[arg-type]

    def test_verify_returns_false_without_backend(self, monkeypatch):
        import aegis.core.pqc_signer as mod

        monkeypatch.setattr(mod, "_HAS_RUST", False)
        assert mod.PQCSigner.verify(b"m", b"s", b"pk") is False

    @requires_real
    def test_sign_rejects_non_bytes(self):
        s = PQCSigner()
        with pytest.raises(TypeError):
            s.sign("not-bytes")  # type: ignore[arg-type]


# ── Persistent identity: export + from_keys round-trip (P0.1) ─────────────────


class TestPersistentIdentity:
    @requires_real
    def test_export_private_key_size(self):
        s = PQCSigner()
        assert len(s.export_private_key()) == PRIVATE_KEY_BYTES

    @requires_real
    def test_export_raises_without_keypair(self):
        s = PQCSigner.__new__(PQCSigner)
        s._kp = None
        s._backend = "unavailable"
        with pytest.raises(PQCUnavailableError):
            s.export_private_key()

    @requires_real
    def test_reloaded_identity_has_same_public_key(self):
        original = PQCSigner()
        pk, sk = original.public_key, original.export_private_key()
        reloaded = PQCSigner.from_keys(pk, sk)
        assert reloaded.is_available is True
        assert reloaded.backend == "ml-dsa-65-rust"
        assert reloaded.public_key == pk

    @requires_real
    def test_reloaded_identity_signs_verifiably(self):
        # A persisted-then-reloaded identity must produce signatures that verify
        # under the original published public key.
        original = PQCSigner()
        pk, sk = original.public_key, original.export_private_key()
        reloaded = PQCSigner.from_keys(pk, sk)
        msg = b"persistent-signing-identity:state_id=xyz"
        sig = reloaded.sign(msg)
        assert PQCSigner.verify(msg, sig, pk) is True

    @requires_real
    def test_from_keys_rejects_malformed_bytes(self):
        with pytest.raises(ValueError):
            PQCSigner.from_keys(b"too-short-pk", b"\x00" * PRIVATE_KEY_BYTES)
        with pytest.raises(ValueError):
            PQCSigner.from_keys(b"\x00" * PUBLIC_KEY_BYTES, b"too-short-sk")

    @requires_real
    def test_from_keys_rejects_non_bytes(self):
        with pytest.raises(TypeError):
            PQCSigner.from_keys("pk", b"\x00" * PRIVATE_KEY_BYTES)  # type: ignore[arg-type]

    def test_from_keys_raises_without_backend(self, monkeypatch):
        import aegis.core.pqc_signer as mod

        monkeypatch.setattr(mod, "_HAS_RUST", False)
        with pytest.raises(PQCUnavailableError):
            mod.PQCSigner.from_keys(b"pk", b"sk")
