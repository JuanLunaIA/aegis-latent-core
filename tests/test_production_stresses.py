# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
import os
import tempfile
import threading
import time
import unittest

import numpy as np
import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.telemetry import LogitEntropyMonitor


class TestProductionStresses(unittest.TestCase):
    def setUp(self):
        self.tmp_file = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.tmp_file.close()
        self.path = self.tmp_file.name
        self.ledgers = []

    def tearDown(self):
        for ledger in self.ledgers:
            try:
                ledger.close()
            except Exception:
                pass
        if os.path.exists(self.path):
            os.unlink(self.path)

    def create_ledger(self, *args, **kwargs) -> CryptographicAuditLedger:
        ledger = CryptographicAuditLedger(*args, **kwargs)
        self.ledgers.append(ledger)
        return ledger

    def test_NEW_01_EMA_Contamination(self):
        """
        Verify that a shared monitor instance leaks EMA state between tenants.
        """
        monitor = LogitEntropyMonitor(ema_alpha=0.5)

        for _ in range(2):
            monitor.update_ema(1.0)
        ema_a = monitor.current_ema

        for _ in range(2):
            monitor.update_ema(10.0)
        ema_b = monitor.current_ema

        self.assertAlmostEqual(ema_a, 1.0, delta=0.01)
        self.assertAlmostEqual(ema_b, 7.75, delta=0.1)
        self.assertNotAlmostEqual(ema_b, 10.0, delta=0.5)

    def test_NEW_02_Payload_Limit(self):
        """Verify that payloads exceeding MAX_PAYLOAD_BYTES are rejected."""
        from aegis.core.crypto_audit import MAX_PAYLOAD_BYTES

        ledger = self.create_ledger(persistence_path=self.path)
        large_payload = b"X" * (MAX_PAYLOAD_BYTES + 1)
        with pytest.raises(ValueError) as ctx:
            ledger.commit_state("s0", 1.0, large_payload)
        self.assertIn("exceeds 1 MiB", str(ctx.value))

    def test_NEW_04_Deque_Ceiling(self):
        """Verify that the chain does not grow beyond max_memory_nodes."""
        limit = 100
        ledger = self.create_ledger(persistence_path=self.path, max_memory_nodes=limit)
        for i in range(limit + 50):
            ledger.commit_state(f"s{i}", 1.0, b"data")

        self.assertEqual(len(ledger.chain), limit)
        self.assertEqual(ledger.chain[0].state_id, "s50")

    def test_NEW_16_Near_Saturated_KL(self):
        """Verify near_saturated activates for gaps around 50."""
        monitor = LogitEntropyMonitor()
        p = np.array([50.0, 0.0])
        q = np.array([0.0, 50.0])
        result = monitor.compute_kl_divergence(p, q)

        self.assertTrue(result.near_saturated)
        self.assertFalse(result.saturated)

    def test_NEW_10_StateID_Collision(self):
        """Verify that long state_ids do not collide via truncation."""
        ledger = self.create_ledger(persistence_path=self.path)
        id1 = "A" * 64
        id2 = "A" * 100

        node1 = ledger.commit_state(id1, 1.0, b"data")
        node2 = ledger.commit_state(id2, 1.0, b"data")

        self.assertNotEqual(node1.node_hash, node2.node_hash)

    def test_NEW_07_FD_Leak(self):
        """Verify that using context manager closes file descriptors."""
        for _ in range(10):
            with self.create_ledger(persistence_path=self.path) as ledger:
                ledger.commit_state("s", 1.0, b"d")

        ledger = self.create_ledger(persistence_path=self.path)
        ledger.close()
        self.assertIsNone(ledger._wal_handle)

    def test_NEW_03_Concurrent_Latency(self):
        """
        Stress test concurrent commits to measure Lock/fsync contention.
        """
        ledger = self.create_ledger(persistence_path=self.path)
        num_threads = 10
        commits_per_thread = 20
        errors = []

        start_time = time.time()

        def worker(tid: int) -> None:
            for i in range(commits_per_thread):
                try:
                    ledger.commit_state(f"t{tid}_c{i}", 1.0, b"data")
                except Exception as exc:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        end_time = time.time()
        self.assertEqual(len(errors), 0, f"Worker errors: {errors}")

        duration = end_time - start_time
        avg_lat = duration / (num_threads * commits_per_thread)
        print(f"\n[STRESS] Avg commit latency under contention: {avg_lat * 1000:.3f}ms")
        ledger.close()


if __name__ == "__main__":
    unittest.main()
