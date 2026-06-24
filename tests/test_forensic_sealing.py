# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.forensic_sealing — real XMSS-style hash-based sealing."""

from __future__ import annotations

import pytest

from aegis.core.forensic_sealing import QuantumForensicSealer, XMSSSignature


def _small_sealer() -> QuantumForensicSealer:
    return QuantumForensicSealer(tree_height=4)  # 16 leaves — fast for tests


class TestMerkleTree:
    def test_root_is_hex_string(self):
        s = _small_sealer()
        assert len(s._root) == 64
        assert all(c in "0123456789abcdef" for c in s._root)

    def test_tree_has_correct_depth(self):
        s = _small_sealer()
        assert len(s._tree) == 5  # 4 interior levels + leaf level

    def test_leaf_level_has_correct_count(self):
        s = _small_sealer()
        assert len(s._tree[0]) == 16

    def test_different_seeds_produce_different_roots(self):
        s1 = _small_sealer()
        s2 = _small_sealer()
        assert s1._root != s2._root  # urandom seeds differ


class TestSealLogEntry:
    def test_returns_xmss_signature(self):
        s = _small_sealer()
        sig = s.seal_log_entry(b"test data")
        assert isinstance(sig, XMSSSignature)

    def test_signature_index_zero_on_first_call(self):
        s = _small_sealer()
        sig = s.seal_log_entry(b"data")
        assert sig.index == 0

    def test_index_increments(self):
        s = _small_sealer()
        s1 = s.seal_log_entry(b"a")
        s2 = s.seal_log_entry(b"b")
        assert s2.index == s1.index + 1

    def test_auth_path_length_equals_tree_height(self):
        s = _small_sealer()
        sig = s.seal_log_entry(b"entry")
        assert len(sig.auth_path) == 4

    def test_auth_path_entries_are_32_bytes(self):
        s = _small_sealer()
        sig = s.seal_log_entry(b"entry")
        assert all(len(p) == 32 for p in sig.auth_path)

    def test_ots_key_is_32_bytes(self):
        s = _small_sealer()
        sig = s.seal_log_entry(b"data")
        assert len(sig.ots_key) == 32

    def test_ots_signature_is_32_bytes(self):
        s = _small_sealer()
        sig = s.seal_log_entry(b"data")
        assert len(sig.ots_signature) == 32

    def test_different_data_produce_different_signatures(self):
        s = _small_sealer()
        sig1 = s.seal_log_entry(b"aaa")
        sig2 = s.seal_log_entry(b"bbb")
        assert sig1.ots_signature != sig2.ots_signature

    def test_index_consumed_not_reused(self):
        s = _small_sealer()
        sig1 = s.seal_log_entry(b"x")
        sig2 = s.seal_log_entry(b"y")
        assert sig1.index not in s._used_indices or sig1.index != sig2.index

    def test_exhausted_tree_raises(self):
        s = QuantumForensicSealer(tree_height=1)  # only 2 leaves
        s.seal_log_entry(b"a")
        s.seal_log_entry(b"b")
        with pytest.raises(RuntimeError, match="Key Exhausted"):
            s.seal_log_entry(b"c")


class TestVerifySeal:
    def test_valid_signature_verifies(self):
        s = _small_sealer()
        data = b"important log"
        sig = s.seal_log_entry(data)
        assert s.verify_seal(data, sig, s._root) is True

    def test_tampered_data_fails(self):
        s = _small_sealer()
        data = b"original"
        sig = s.seal_log_entry(data)
        assert s.verify_seal(b"tampered", sig, s._root) is False

    def test_wrong_root_fails(self):
        s = _small_sealer()
        data = b"log"
        sig = s.seal_log_entry(data)
        fake_root = "00" * 32
        assert s.verify_seal(data, sig, fake_root) is False

    def test_mutated_ots_key_fails(self):
        import copy

        s = _small_sealer()
        data = b"data"
        sig = s.seal_log_entry(data)
        bad_sig = copy.copy(sig)
        bad_sig.ots_key = bytes(b ^ 0xFF for b in sig.ots_key)
        assert s.verify_seal(data, bad_sig, s._root) is False

    def test_mutated_auth_path_fails(self):
        import copy

        s = _small_sealer()
        data = b"data"
        sig = s.seal_log_entry(data)
        bad_sig = copy.copy(sig)
        bad_sig.auth_path = [b"\x00" * 32] * len(sig.auth_path)
        assert s.verify_seal(data, bad_sig, s._root) is False

    def test_consecutive_seals_both_verify(self):
        s = _small_sealer()
        for i in range(4):
            msg = f"entry {i}".encode()
            sig = s.seal_log_entry(msg)
            assert s.verify_seal(msg, sig, s._root), f"entry {i} failed to verify"

    def test_cross_seal_swap_fails(self):
        s = _small_sealer()
        sig1 = s.seal_log_entry(b"msg1")
        sig2 = s.seal_log_entry(b"msg2")
        # sig1 used on msg2 data — HMAC mismatch
        assert s.verify_seal(b"msg2", sig1, s._root) is False
