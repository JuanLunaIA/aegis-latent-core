# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.phi_encryption — AES-256-GCM PHI payload encryption."""
from __future__ import annotations

import os

import pytest

from aegis.core.phi_encryption import PHIEncryptionError, PHIPayloadEncryptor

_MASTER_KEY = os.urandom(32)


class TestPHIPayloadEncryptor:
    def _enc(self, master_key: bytes = _MASTER_KEY, salt: bytes | None = None) -> PHIPayloadEncryptor:
        return PHIPayloadEncryptor(master_key=master_key, salt=salt)

    # ── Construction ─────────────────────────────────────────────────────────

    def test_wrong_key_length_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            PHIPayloadEncryptor(master_key=b"tooshort")

    def test_31_byte_key_raises(self):
        with pytest.raises(ValueError):
            PHIPayloadEncryptor(master_key=b"x" * 31)

    def test_33_byte_key_raises(self):
        with pytest.raises(ValueError):
            PHIPayloadEncryptor(master_key=b"x" * 33)

    def test_32_byte_key_accepted(self):
        enc = PHIPayloadEncryptor(master_key=b"a" * 32)
        assert enc is not None

    # ── Round-trip ────────────────────────────────────────────────────────────

    def test_roundtrip_basic(self):
        enc = self._enc()
        pt = b"PHI payload: DOB 1990-01-01, SSN 123-45-6789"
        ct = enc.encrypt("tenant-a", pt)
        assert enc.decrypt("tenant-a", ct) == pt

    def test_roundtrip_empty_payload(self):
        enc = self._enc()
        ct = enc.encrypt("t1", b"")
        assert enc.decrypt("t1", ct) == b""

    def test_roundtrip_large_payload(self):
        enc = self._enc()
        pt = os.urandom(65536)
        ct = enc.encrypt("t1", pt)
        assert enc.decrypt("t1", ct) == pt

    def test_roundtrip_binary_payload(self):
        enc = self._enc()
        pt = bytes(range(256)) * 4
        ct = enc.encrypt("t1", pt)
        assert enc.decrypt("t1", ct) == pt

    # ── Ciphertext properties ────────────────────────────────────────────────

    def test_ciphertext_longer_than_plaintext(self):
        """AES-GCM adds 12-byte nonce + 16-byte tag = 28 bytes overhead."""
        enc = self._enc()
        pt = b"secret"
        ct = enc.encrypt("t1", pt)
        assert len(ct) == len(pt) + 12 + 16

    def test_same_plaintext_different_ciphertext_each_call(self):
        """Random nonce ensures ciphertexts differ even for identical inputs."""
        enc = self._enc()
        pt = b"same payload"
        ct1 = enc.encrypt("t1", pt)
        ct2 = enc.encrypt("t1", pt)
        assert ct1 != ct2

    def test_ciphertext_is_bytes(self):
        enc = self._enc()
        ct = enc.encrypt("t1", b"data")
        assert isinstance(ct, bytes)

    # ── Tenant key isolation ─────────────────────────────────────────────────

    def test_different_tenants_different_ciphertexts(self):
        enc = self._enc()
        pt = b"same payload"
        ct_a = enc.encrypt("tenant-a", pt)
        ct_b = enc.encrypt("tenant-b", pt)
        assert ct_a != ct_b

    def test_wrong_tenant_decryption_fails(self):
        enc = self._enc()
        pt = b"PHI data"
        ct = enc.encrypt("tenant-a", pt)
        with pytest.raises(PHIEncryptionError):
            enc.decrypt("tenant-b", ct)

    def test_two_encryptors_same_key_interoperable(self):
        """Two encryptors with the same master_key and salt can cross-decrypt."""
        key = os.urandom(32)
        enc1 = PHIPayloadEncryptor(master_key=key)
        enc2 = PHIPayloadEncryptor(master_key=key)
        pt = b"shared secret"
        ct = enc1.encrypt("t1", pt)
        assert enc2.decrypt("t1", ct) == pt

    def test_different_master_keys_not_interoperable(self):
        """Different master keys produce different DEKs — cross-decrypt fails."""
        enc1 = PHIPayloadEncryptor(master_key=os.urandom(32))
        enc2 = PHIPayloadEncryptor(master_key=os.urandom(32))
        ct = enc1.encrypt("t1", b"secret")
        with pytest.raises(PHIEncryptionError):
            enc2.decrypt("t1", ct)

    # ── Tamper detection ─────────────────────────────────────────────────────

    def test_bit_flip_in_ciphertext_raises(self):
        enc = self._enc()
        pt = b"sensitive record"
        ct = bytearray(enc.encrypt("t1", pt))
        ct[-1] ^= 0xFF  # flip last byte of GCM tag
        with pytest.raises(PHIEncryptionError):
            enc.decrypt("t1", bytes(ct))

    def test_truncated_ciphertext_raises(self):
        enc = self._enc()
        ct = enc.encrypt("t1", b"data")
        with pytest.raises(PHIEncryptionError, match="too short"):
            enc.decrypt("t1", ct[:10])

    def test_empty_ciphertext_raises(self):
        enc = self._enc()
        with pytest.raises(PHIEncryptionError, match="too short"):
            enc.decrypt("t1", b"")

    # ── Salt parameter ────────────────────────────────────────────────────────

    def test_same_salt_same_dek(self):
        salt = os.urandom(16)
        enc1 = PHIPayloadEncryptor(master_key=_MASTER_KEY, salt=salt)
        enc2 = PHIPayloadEncryptor(master_key=_MASTER_KEY, salt=salt)
        pt = b"data"
        ct = enc1.encrypt("t1", pt)
        assert enc2.decrypt("t1", ct) == pt

    def test_different_salt_different_dek(self):
        enc1 = PHIPayloadEncryptor(master_key=_MASTER_KEY, salt=os.urandom(16))
        enc2 = PHIPayloadEncryptor(master_key=_MASTER_KEY, salt=os.urandom(16))
        ct = enc1.encrypt("t1", b"secret")
        with pytest.raises(PHIEncryptionError):
            enc2.decrypt("t1", ct)

    # ── DEK caching ──────────────────────────────────────────────────────────

    def test_dek_cached_after_first_call(self):
        enc = self._enc()
        enc._derive_dek("t1")
        enc._derive_dek("t1")
        assert "t1" in enc._dek_cache

    def test_distinct_tenants_have_distinct_deks(self):
        enc = self._enc()
        dek_a = enc._derive_dek("tenant-a")
        dek_b = enc._derive_dek("tenant-b")
        assert dek_a != dek_b

    def test_dek_is_32_bytes(self):
        enc = self._enc()
        dek = enc._derive_dek("t1")
        assert len(dek) == 32
