# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
import os
import sys

# FORCE LOCAL IMPORT
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis.core.mmr import MerkleMountainRange


def test_mmr_integrity():
    print("--- Starting MMR Integrity Test ---")
    mmr = MerkleMountainRange()

    # 1. Add leaves
    data_leaves = [b"leaf0", b"leaf1", b"leaf2", b"leaf3", b"leaf4"]
    for d in data_leaves:
        mmr.add_leaf(d)

    root = mmr.get_root_hash()
    print(f"Root Hash: {root}")
    print(f"Leaf Count: {mmr._leaf_count}")

    # 2. Test Inclusion Proof for leaf 1
    leaf_idx = 1
    proof = mmr.get_inclusion_proof(leaf_idx)
    print(f"Proof for leaf {leaf_idx}: {proof}")

    # 3. Verify valid inclusion
    is_valid = mmr.verify_inclusion(data_leaves[leaf_idx], leaf_idx, proof, root)
    print(f"Verification (Valid Case): {'PASSED' if is_valid else 'FAILED'}")
    assert is_valid is True

    # 4. Verify invalid inclusion (wrong data)
    is_valid_wrong_data = mmr.verify_inclusion(b"wrong_data", leaf_idx, proof, root)
    print(f"Verification (Wrong Data Case): {'PASSED' if not is_valid_wrong_data else 'FAILED'}")
    assert is_valid_wrong_data is False

    # 5. Verify invalid inclusion (wrong index)
    # We'll use a proof for index 1 but try to verify index 2
    is_valid_wrong_idx = mmr.verify_inclusion(data_leaves[2], leaf_idx, proof, root)
    print(f"Verification (Wrong Index Case): {'PASSED' if not is_valid_wrong_idx else 'FAILED'}")
    # Note: This might return True if the hash happens to align, but with SHA256 it's statistically impossible.
    # For the purpose of this test, we check if it's False.
    assert is_valid_wrong_idx is False

    print("--- MMR Integrity Test COMPLETED SUCCESSFULLY ---")


if __name__ == "__main__":
    try:
        test_mmr_integrity()
    except Exception as e:
        print(f"TEST FAILED with error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
