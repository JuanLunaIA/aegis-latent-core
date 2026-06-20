# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
tests/test_mmr_branch.py — 100% branch coverage for aegis/core/mmr.py.

Covers: IndexError/ValueError raises, trivial consistency-proof cases,
reconstruction fallback, RustBackedMMR class (via module reload with mocked
aegis_rust), and the module-level except-Exception fallback.
"""

from __future__ import annotations

import importlib
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.mmr import MerkleMountainRange

# ── Helpers ───────────────────────────────────────────────────────────────────


def _mmr_with_leaves(*payloads: bytes) -> MerkleMountainRange:
    mmr = MerkleMountainRange()
    for p in payloads:
        mmr.add_leaf(p)
    return mmr


# ── get_inclusion_proof — IndexError branches (line ~97) ──────────────────────


class TestInclusionProofBounds:
    def test_negative_index_raises(self):
        """Arrange: MMR with one leaf. Act: get_inclusion_proof(-1). Assert: IndexError."""
        mmr = _mmr_with_leaves(b"leaf0")
        with pytest.raises(IndexError, match="Leaf index out of range"):
            mmr.get_inclusion_proof(-1)

    def test_index_equals_count_raises(self):
        """Index == _leaf_count is out of range."""
        mmr = _mmr_with_leaves(b"leaf0")
        with pytest.raises(IndexError):
            mmr.get_inclusion_proof(1)

    def test_index_far_beyond_count_raises(self):
        mmr = _mmr_with_leaves(b"a", b"b", b"c")
        with pytest.raises(IndexError):
            mmr.get_inclusion_proof(99)


# ── get_consistency_proof — ValueError and trivial branches ───────────────────


class TestConsistencyProofBranches:
    def test_negative_old_count_raises(self):
        """old_count < 0 → ValueError."""
        mmr = _mmr_with_leaves(b"A", b"B", b"C")
        with pytest.raises(ValueError, match="old_count=-1 out of valid range"):
            mmr.get_consistency_proof("any", -1)

    def test_old_count_greater_than_current_raises(self):
        """old_count > leaf_count → ValueError."""
        mmr = _mmr_with_leaves(b"A")
        with pytest.raises(ValueError, match="old_count=5 out of valid range"):
            mmr.get_consistency_proof("any", 5)

    def test_old_count_zero_returns_empty_proof(self):
        """Trivial case: old_count=0 → (current_root, [])."""
        mmr = _mmr_with_leaves(b"X", b"Y")
        current_root, proof = mmr.get_consistency_proof("ignored", 0)
        assert current_root == mmr.get_root_hash()
        assert proof == []

    def test_old_count_equals_current_returns_current_peaks(self):
        """Trivial case: old_count == leaf_count → proof is current peaks."""
        mmr = _mmr_with_leaves(b"P", b"Q", b"R")
        root, proof = mmr.get_consistency_proof("ignored", mmr._leaf_count)
        assert root == mmr.get_root_hash()
        assert proof == [p.hash for p in mmr.peaks]

    def test_old_root_mismatch_logs_warning(self, caplog):
        """When reconstructed old_root ≠ provided old_root → warning is logged."""
        import logging

        mmr = _mmr_with_leaves(b"A", b"B", b"C", b"D")
        with caplog.at_level(logging.WARNING, logger="aegis.core.mmr"):
            _, _ = mmr.get_consistency_proof("wrong_root_hash" * 4, 2)
        assert any("old_root mismatch" in r.message for r in caplog.records)

    def test_reconstruct_fails_fallback_to_current_peaks(self, monkeypatch):
        """
        If _reconstruct_peaks_at raises, the except block falls back to
        current peaks (lines ~203-206).
        """
        mmr = _mmr_with_leaves(b"A", b"B", b"C", b"D")

        def _raise(*_a: Any, **_kw: Any) -> None:
            raise RuntimeError("simulated reconstruction failure")

        monkeypatch.setattr(mmr, "_reconstruct_peaks_at", _raise)
        root, proof = mmr.get_consistency_proof("any", 2)
        assert root == mmr.get_root_hash()
        assert proof == [p.hash for p in mmr.peaks]


# ── _reconstruct_peaks_at — ValueError branch (line ~242) ────────────────────


class TestReconstructPeaksAt:
    def test_target_count_exceeds_available_nodes_raises(self):
        """
        Calling _reconstruct_peaks_at with a count that needs more nodes
        than currently in self.nodes raises ValueError.
        """
        mmr = _mmr_with_leaves(b"A")
        # Forcibly shrink nodes so total_nodes_at_target > len(nodes).
        mmr.nodes = []
        with pytest.raises(ValueError, match="Cannot reconstruct peaks"):
            mmr._reconstruct_peaks_at(1)

    def test_reconstruct_valid_prefix(self):
        """Happy path: reconstruct peaks at count=2 from an MMR with 4 leaves."""
        mmr = _mmr_with_leaves(b"A", b"B", b"C", b"D")
        peaks_at_2 = mmr._reconstruct_peaks_at(2)
        assert isinstance(peaks_at_2, list)
        # At count=2, there should be exactly one merged peak.
        assert len(peaks_at_2) == 1

    def test_reconstruct_odd_leaf_count_has_multiple_peaks(self):
        """At count=3, peaks are 2 mountains: one of height 1 and one leaf."""
        mmr = _mmr_with_leaves(b"A", b"B", b"C", b"D", b"E")
        peaks_at_3 = mmr._reconstruct_peaks_at(3)
        # 3 = 0b11 → two peaks (heights 1 and 0)
        assert len(peaks_at_3) == 2


# ── RustBackedMMR — via module reload (lines ~281-315) ───────────────────────


class TestRustBackedMMR:
    """
    The RustBackedMMR class is only defined when has_rust() returns True.
    We reload aegis.core.mmr with a mocked Rust extension to exercise its methods.
    """

    @pytest.fixture
    def rust_backed_module(self):
        """Yield a reloaded mmr module where RustBackedMMR is available."""
        mock_acc = MagicMock()
        mock_acc.add_leaf.return_value = "a" * 64
        mock_acc.get_root_hash.return_value = "b" * 64
        mock_acc.get_leaf_count.return_value = 1

        mock_rust = MagicMock()
        mock_rust.MmrAccumulator.return_value = mock_acc

        import aegis.core.mmr as mmr_mod

        with (
            patch.dict("sys.modules", {"aegis_rust": mock_rust}),
            patch("aegis.core.rust_integration.has_rust", return_value=True),
        ):
            importlib.reload(mmr_mod)
            yield mmr_mod

        # Restore original module state.
        importlib.reload(mmr_mod)

    def test_rust_backed_add_leaf(self, rust_backed_module):
        if not hasattr(rust_backed_module, "RustBackedMMR"):
            pytest.skip("RustBackedMMR not defined after reload")
        rbm = rust_backed_module.RustBackedMMR()
        root = rbm.add_leaf(b"data")
        assert isinstance(root, str)

    def test_rust_backed_get_root_hash(self, rust_backed_module):
        if not hasattr(rust_backed_module, "RustBackedMMR"):
            pytest.skip("RustBackedMMR not defined after reload")
        rbm = rust_backed_module.RustBackedMMR()
        rbm.add_leaf(b"data")
        root = rbm.get_root_hash()
        assert isinstance(root, str)

    def test_rust_backed_get_leaf_count(self, rust_backed_module):
        if not hasattr(rust_backed_module, "RustBackedMMR"):
            pytest.skip("RustBackedMMR not defined after reload")
        rbm = rust_backed_module.RustBackedMMR()
        rbm.add_leaf(b"data")
        count = rbm.get_leaf_count()
        assert isinstance(count, int)

    def test_rust_backed_get_inclusion_proof(self, rust_backed_module):
        if not hasattr(rust_backed_module, "RustBackedMMR"):
            pytest.skip("RustBackedMMR not defined after reload")
        rbm = rust_backed_module.RustBackedMMR()
        rbm.add_leaf(b"leaf0")
        proof = rbm.get_inclusion_proof(0)
        assert isinstance(proof, list)

    def test_rust_backed_verify_inclusion(self, rust_backed_module):
        if not hasattr(rust_backed_module, "RustBackedMMR"):
            pytest.skip("RustBackedMMR not defined after reload")
        rbm = rust_backed_module.RustBackedMMR()
        rbm.add_leaf(b"leaf0")
        root = rbm.get_root_hash()
        proof = rbm.get_inclusion_proof(0)
        result = rbm.verify_inclusion(b"leaf0", 0, proof, root)
        assert isinstance(result, bool)

    def test_rust_backed_get_consistency_proof(self, rust_backed_module):
        if not hasattr(rust_backed_module, "RustBackedMMR"):
            pytest.skip("RustBackedMMR not defined after reload")
        rbm = rust_backed_module.RustBackedMMR()
        rbm.add_leaf(b"A")
        rbm.add_leaf(b"B")
        root = rbm.get_root_hash()
        _, proof = rbm.get_consistency_proof(root, 1)
        assert isinstance(proof, list)


# ── Module-level except Exception fallback (lines ~318-320) ──────────────────


def test_module_fallback_on_rust_integration_error():
    """
    If has_rust() import or call raises, the module-level except catches it
    and assigns mmr_manager = MerkleMountainRange() (lines ~318-320).
    """
    import aegis.core.mmr as mmr_mod

    with patch("aegis.core.rust_integration.has_rust", side_effect=RuntimeError("fail")):
        importlib.reload(mmr_mod)
        # After reload, check using the reloaded module's own class reference
        # (importlib.reload creates a new class object, so we must compare to
        # the reloaded module's MerkleMountainRange, not the one imported at top).
        assert isinstance(mmr_mod.mmr_manager, mmr_mod.MerkleMountainRange)

    # Restore.
    importlib.reload(mmr_mod)


# ── verify_inclusion — direction branches ─────────────────────────────────────


def test_verify_inclusion_correct_proof():
    """Inclusion proof for leaf at index 0 in a 4-leaf MMR verifies correctly."""
    mmr = _mmr_with_leaves(b"A", b"B", b"C", b"D")
    root = mmr.get_root_hash()
    proof = mmr.get_inclusion_proof(0)
    assert mmr.verify_inclusion(b"A", 0, proof, root) is True


def test_verify_inclusion_wrong_data():
    """verify_inclusion returns False when leaf data does not match proof."""
    mmr = _mmr_with_leaves(b"A", b"B")
    root = mmr.get_root_hash()
    proof = mmr.get_inclusion_proof(0)
    assert mmr.verify_inclusion(b"WRONG", 0, proof, root) is False


def test_verify_inclusion_right_child_branch():
    """Exercises the 'L' direction branch by verifying the right child."""
    mmr = _mmr_with_leaves(b"A", b"B")
    root = mmr.get_root_hash()
    proof = mmr.get_inclusion_proof(1)
    # Index 1 is right child → direction in proof is "L"
    assert any(d == "L" for _, d in proof)
    assert mmr.verify_inclusion(b"B", 1, proof, root) is True


# ── get_root_hash — empty MMR branch ─────────────────────────────────────────


def test_get_root_hash_empty_mmr():
    """Empty MMR returns 64 zeros."""
    mmr = MerkleMountainRange()
    assert mmr.get_root_hash() == "0" * 64
