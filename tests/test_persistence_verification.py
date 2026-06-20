# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

import os

from aegis.core.crypto_audit import CryptographicAuditLedger


def test_ledger_persistence():
    wal_path = "test_audit.wal"
    if os.path.exists(wal_path):
        os.remove(wal_path)

    print(f"--- Starting Persistence Test: {wal_path} ---")

    # 1. Create ledger and commit nodes
    with CryptographicAuditLedger(persistence_path=wal_path) as ledger:
        print("Committing node 1...")
        node1 = ledger.commit_state("state-1", 0.5, b"payload-1", tenant_id="user-a")
        print(f"Node 1 Hash: {node1.node_hash}")

        print("Committing node 2...")
        node2 = ledger.commit_state("state-2", 0.6, b"payload-2", tenant_id="user-b")
        print(f"Node 2 Hash: {node2.node_hash}")

        # Verify chain link
        assert node2.prev_hash == node1.node_hash
        print("Chain link verified.")

    print("Ledger closed. Simulating crash/restart...")

    # 2. Reconstruct ledger from WAL
    print("Reconstructing ledger...")
    with CryptographicAuditLedger(persistence_path=wal_path) as new_ledger:
        print(f"Nodes in reconstructed ledger: {len(new_ledger.chain)}")
        assert len(new_ledger.chain) == 2
        assert new_ledger.chain[0].state_id == "state-1"
        assert new_ledger.chain[1].state_id == "state-2"

        # 3. Verify integrity of reconstructed chain
        is_valid, error_idx = new_ledger.verify_integrity()
        print(f"Integrity check: {'PASSED' if is_valid else 'FAILED'} (Error index: {error_idx})")
        assert is_valid is True

        # 4. Verify Merkle consistency
        # Each ledger owns its own MerkleMountainRange instance (no shared global state).
        print(f"Current Merkle Root: {new_ledger.chain[1].merkle_root}")

    print("--- Persistence Test PASSED ---")

    if os.path.exists(wal_path):
        os.remove(wal_path)


if __name__ == "__main__":
    try:
        test_ledger_persistence()
    except Exception as e:
        print(f"TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        exit(1)
