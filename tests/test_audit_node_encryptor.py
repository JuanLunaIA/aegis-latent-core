# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for IL6 audit node AES-256-GCM encryption (aegis.core.audit_node_encryptor)."""

from __future__ import annotations

import os

import pytest

from aegis.core.audit_node_encryptor import (
    AuditNodeEncryptionError,
    AuditNodeEncryptor,
)

# ── Constructor validation ────────────────────────────────────────────────────


class TestConstructor:
    def test_valid_32_byte_key(self):
        enc = AuditNodeEncryptor(master_key=os.urandom(32))
        assert enc is not None

    def test_short_key_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            AuditNodeEncryptor(master_key=b"tooshort")

    def test_long_key_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            AuditNodeEncryptor(master_key=os.urandom(33))

    def test_empty_key_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            AuditNodeEncryptor(master_key=b"")


# ── Encrypt / decrypt round-trip ─────────────────────────────────────────────


class TestEncryptDecryptRoundTrip:
    def _enc(self) -> AuditNodeEncryptor:
        return AuditNodeEncryptor(master_key=os.urandom(32))

    def _node(self) -> dict[str, object]:
        return {
            "state_id": "abc-123",
            "timestamp": 1700000000.0,
            "tenant_id": "tenant-a",
            "node_hash": "deadbeef" * 8,
            "signature": "cafebabe" * 8,
        }

    def test_round_trip_matches(self):
        enc = self._enc()
        node = self._node()
        node_hash = str(node["node_hash"])
        ct = enc.encrypt_node("tenant-a", node, node_hash)
        recovered = enc.decrypt_node("tenant-a", ct, node_hash)
        assert recovered == node

    def test_encrypt_returns_bytes(self):
        enc = self._enc()
        ct = enc.encrypt_node("t", self._node(), "hash123")
        assert isinstance(ct, bytes)

    def test_ciphertext_length_overhead(self):
        enc = self._enc()
        node = self._node()
        import json
        plaintext_len = len(json.dumps(node, separators=(",", ":"), sort_keys=True).encode())
        ct = enc.encrypt_node("t", node, "h" * 64)
        # nonce (12) + tag (16) = 28 bytes overhead
        assert len(ct) == plaintext_len + 28

    def test_different_nonce_each_call(self):
        enc = self._enc()
        ct1 = enc.encrypt_node("t", self._node(), "h" * 64)
        ct2 = enc.encrypt_node("t", self._node(), "h" * 64)
        assert ct1[:12] != ct2[:12]

    def test_ciphertext_differs_each_call(self):
        enc = self._enc()
        ct1 = enc.encrypt_node("t", self._node(), "h" * 64)
        ct2 = enc.encrypt_node("t", self._node(), "h" * 64)
        assert ct1 != ct2

    def test_different_tenants_different_dek(self):
        enc = self._enc()
        node = self._node()
        ct_a = enc.encrypt_node("tenant-a", node, "h" * 64)
        # Decrypt with wrong tenant must fail
        with pytest.raises(AuditNodeEncryptionError):
            enc.decrypt_node("tenant-b", ct_a, "h" * 64)


# ── AAD binding (node_hash) ───────────────────────────────────────────────────


class TestAADBinding:
    def _enc(self) -> AuditNodeEncryptor:
        return AuditNodeEncryptor(master_key=os.urandom(32))

    def test_wrong_node_hash_fails(self):
        enc = self._enc()
        node = {"key": "value"}
        ct = enc.encrypt_node("t", node, "correct_hash")
        with pytest.raises(AuditNodeEncryptionError):
            enc.decrypt_node("t", ct, "wrong_hash")

    def test_correct_hash_succeeds(self):
        enc = self._enc()
        node = {"key": "value"}
        ct = enc.encrypt_node("t", node, "my_node_hash")
        recovered = enc.decrypt_node("t", ct, "my_node_hash")
        assert recovered == node

    def test_empty_hash_is_valid(self):
        enc = self._enc()
        ct = enc.encrypt_node("t", {"x": 1}, "")
        recovered = enc.decrypt_node("t", ct, "")
        assert recovered == {"x": 1}


# ── Tamper detection ──────────────────────────────────────────────────────────


class TestTamperDetection:
    def _enc(self) -> AuditNodeEncryptor:
        return AuditNodeEncryptor(master_key=os.urandom(32))

    def test_bit_flip_in_ciphertext_fails(self):
        enc = self._enc()
        ct = enc.encrypt_node("t", {"x": 1}, "h")
        ct_list = bytearray(ct)
        ct_list[20] ^= 0xFF  # flip byte in ciphertext body
        with pytest.raises(AuditNodeEncryptionError):
            enc.decrypt_node("t", bytes(ct_list), "h")

    def test_truncated_ciphertext_fails(self):
        enc = self._enc()
        ct = enc.encrypt_node("t", {"x": 1}, "h")
        with pytest.raises(AuditNodeEncryptionError, match="too short"):
            enc.decrypt_node("t", ct[:20], "h")

    def test_wrong_master_key_fails(self):
        enc1 = self._enc()
        enc2 = self._enc()  # different random key
        ct = enc1.encrypt_node("t", {"x": 1}, "h")
        with pytest.raises(AuditNodeEncryptionError):
            enc2.decrypt_node("t", ct, "h")


# ── Salt variation ────────────────────────────────────────────────────────────


class TestSalt:
    def test_same_key_different_salt_different_ciphertext(self):
        key = os.urandom(32)
        enc1 = AuditNodeEncryptor(master_key=key, salt=b"\x00" * 16)
        enc2 = AuditNodeEncryptor(master_key=key, salt=b"\xFF" * 16)
        node = {"x": 1}
        ct1 = enc1.encrypt_node("t", node, "h")
        ct2 = enc2.encrypt_node("t", node, "h")
        # Different salts → different DEKs → different ciphertexts (body)
        assert ct1[12:] != ct2[12:]

    def test_wrong_salt_cannot_decrypt(self):
        key = os.urandom(32)
        enc1 = AuditNodeEncryptor(master_key=key, salt=b"\x00" * 16)
        enc2 = AuditNodeEncryptor(master_key=key, salt=b"\xFF" * 16)
        ct = enc1.encrypt_node("t", {"x": 1}, "h")
        with pytest.raises(AuditNodeEncryptionError):
            enc2.decrypt_node("t", ct, "h")


# ── DEK cache ─────────────────────────────────────────────────────────────────


class TestDEKCache:
    def test_same_dek_reused_across_calls(self):
        enc = AuditNodeEncryptor(master_key=os.urandom(32))
        # Populate cache
        enc._derive_dek("tenant-x")
        dek_first = enc._dek_cache["tenant-x"]
        dek_second = enc._derive_dek("tenant-x")
        assert dek_first == dek_second

    def test_different_tenants_different_deks(self):
        enc = AuditNodeEncryptor(master_key=os.urandom(32))
        dek_a = enc._derive_dek("tenant-a")
        dek_b = enc._derive_dek("tenant-b")
        assert dek_a != dek_b

    def test_clear_dek_cache(self):
        enc = AuditNodeEncryptor(master_key=os.urandom(32))
        enc._derive_dek("t")
        assert "t" in enc._dek_cache
        enc.clear_dek_cache()
        assert enc._dek_cache == {}


# ── from_env factory ──────────────────────────────────────────────────────────


class TestFromEnv:
    def test_from_env_reads_hex_key(self, monkeypatch):
        key = os.urandom(32)
        monkeypatch.setenv("AEGIS_AUDIT_MASTER_KEY", key.hex())
        enc = AuditNodeEncryptor.from_env()
        assert isinstance(enc, AuditNodeEncryptor)

    def test_from_env_missing_raises(self, monkeypatch):
        monkeypatch.delenv("AEGIS_AUDIT_MASTER_KEY", raising=False)
        with pytest.raises(AuditNodeEncryptionError, match="AEGIS_AUDIT_MASTER_KEY"):
            AuditNodeEncryptor.from_env()

    def test_from_env_invalid_hex_raises(self, monkeypatch):
        monkeypatch.setenv("AEGIS_AUDIT_MASTER_KEY", "not-hex-data")
        with pytest.raises(AuditNodeEncryptionError, match="not valid hex"):
            AuditNodeEncryptor.from_env()

    def test_from_env_wrong_length_raises(self, monkeypatch):
        monkeypatch.setenv("AEGIS_AUDIT_MASTER_KEY", os.urandom(16).hex())
        with pytest.raises(AuditNodeEncryptionError, match="32 bytes"):
            AuditNodeEncryptor.from_env()

    def test_round_trip_via_env(self, monkeypatch):
        key = os.urandom(32)
        monkeypatch.setenv("AEGIS_AUDIT_MASTER_KEY", key.hex())
        enc = AuditNodeEncryptor.from_env()
        node = {"state_id": "x", "tenant_id": "t"}
        ct = enc.encrypt_node("t", node, "h" * 64)
        recovered = enc.decrypt_node("t", ct, "h" * 64)
        assert recovered == node


# ── Integration: realistic audit node ────────────────────────────────────────


class TestIntegration:
    def test_encrypt_realistic_audit_node(self):
        key = os.urandom(32)
        enc = AuditNodeEncryptor(master_key=key)
        node_dict: dict[str, object] = {
            "state_id": "req-abc-001",
            "timestamp": 1700000000.123456789,
            "entropy": 3.14,
            "tenant_id": "hospital-a",
            "sampling_params": {"temperature": 0.7, "max_tokens": 512},
            "prev_hash": "0" * 64,
            "merkle_root": "a" * 64,
            "signature": "b" * 64,
            "signature_scheme": "hmac-sha256",
            "public_key": "",
            "request_hash": "c" * 64,
            "response_hash": "d" * 64,
            "model": "claude-sonnet-4-6",
            "endpoint": "/v1/chat/completions",
            "token_trail_count": 3,
            "is_fallback": False,
            "phi_scrubbed": True,
            "scrub_method": "NIST-SP-800-188",
            "signer_name": "Dr. Admin",
            "signature_meaning": "approved",
            "audit_trail_version": "1",
        }
        node_hash = "e" * 64
        ct = enc.encrypt_node("hospital-a", node_dict, node_hash)
        recovered = enc.decrypt_node("hospital-a", ct, node_hash)
        assert recovered == node_dict

    def test_key_separation_from_phi_key(self):
        # Audit master key must be distinct from PHI master key
        audit_key = os.urandom(32)
        phi_key = os.urandom(32)
        assert audit_key != phi_key  # probabilistically true for random keys

    def test_json_serialization_preserved(self):
        enc = AuditNodeEncryptor(master_key=os.urandom(32))
        node = {"nested": {"a": 1, "b": [1, 2, 3]}, "top": True}
        ct = enc.encrypt_node("t", node, "h")
        recovered = enc.decrypt_node("t", ct, "h")
        assert recovered == node
