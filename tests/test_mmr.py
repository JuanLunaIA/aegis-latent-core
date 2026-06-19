"""Unit tests for MMR and optional Rust integration.

These tests exercise the pure-Python MerkleMountainRange implementation and
validate that the rust_integration helpers are well-behaved (no exceptions,
returning expected types) whether or not the Rust extension is installed.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from aegis.core import rust_integration
from aegis.core.mmr import MerkleMountainRange, mmr_manager


def test_merkle_add_and_inclusion():
    m = MerkleMountainRange()
    # Empty MMR root is canonical 64-hex zeros
    assert m.get_root_hash() == "0" * 64

    root1 = m.add_leaf(b"hello")
    assert isinstance(root1, str)
    assert len(root1) == 64

    root2 = m.add_leaf(b"world")
    assert root2 != root1

    proof = m.get_inclusion_proof(0)
    assert isinstance(proof, list)

    current_root = m.get_root_hash()
    assert m.verify_inclusion(b"hello", 0, proof, current_root)


def test_consistency_proof_basic():
    m = MerkleMountainRange()
    m.add_leaf(b"a")
    m.add_leaf(b"b")
    old_root = m.get_root_hash()

    m.add_leaf(b"c")
    current_root, old_peaks = m.get_consistency_proof(old_root, 2)

    assert current_root == m.get_root_hash()
    assert isinstance(old_peaks, list)


def test_mmr_manager_interface():
    # mmr_manager may be a Rust-backed instance or Python fallback.
    assert hasattr(mmr_manager, "add_leaf")
    assert hasattr(mmr_manager, "get_root_hash")

    r = mmr_manager.get_root_hash()
    assert isinstance(r, str)
    assert len(r) == 64


def test_rust_integration_no_crash():
    # Ensure rust_integration helpers behave and don't raise.
    has = rust_integration.has_rust()
    assert isinstance(has, bool)

    kp = rust_integration.generate_pqc_keypair()
    assert (kp is None) or isinstance(kp, (bytes, bytearray))

    rust_integration.new_rust_forwarder("https://example", "key")
    # Call above must not raise; return value (None or foreign object) is unused.

    sig_ok = rust_integration.verify_pqc_signature(b"hi", b"", b"")
    assert isinstance(sig_ok, bool)
