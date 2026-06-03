"""Unit tests for MerkleMountainRange consistency proofs.
These tests cover canonical reconstruction of old roots from returned peaks.
"""
import hashlib
from aegis.core.mmr import MerkleMountainRange


def test_consistency_proof_basic():
    mmr = MerkleMountainRange()
    # Add initial set of leaves
    for i in range(7):
        mmr.add_leaf(f"leaf-{i}".encode())
    old_root = mmr.get_root_hash()
    old_count = 7

    # Append more leaves so current root evolves
    for i in range(7, 12):
        mmr.add_leaf(f"leaf-{i}".encode())

    current_root, proof = mmr.get_consistency_proof(old_root, old_count)
    assert current_root == mmr.get_root_hash()

    # Proof contains the old peaks in canonical order (height desc). Recompute old root.
    combined = "".join(proof).encode()
    assert hashlib.sha256(combined).hexdigest() == old_root


def test_consistency_proof_empty():
    mmr = MerkleMountainRange()
    cur_before = mmr.get_root_hash()
    cur, proof = mmr.get_consistency_proof(cur_before, 0)
    assert cur == mmr.get_root_hash()
    assert proof == []
