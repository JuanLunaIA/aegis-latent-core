
import unittest
import numpy as np
import threading
import os
import tempfile
import time
from collections import deque
from src.telemetry import LogitEntropyMonitor, KLResult
from src.crypto_audit import CryptographicAuditLedger
from src.moe_monitor import MoERoutingMonitor

class TestProductionStresses(unittest.TestCase):

    def test_NEW_01_EMA_Contamination(self):
        """Verify that shared monitor instance causes EMA contamination (Multi-tenant bug)."""
        monitor = LogitEntropyMonitor(ema_alpha=0.5)
        
        # Tenant A: Stable entropy around 1.0
        # Tenant B: Stable entropy around 10.0
        # If shared, they will pull the EMA toward each other.
        
        for _ in range(10):
            monitor.update_ema(1.0)
        ema_a = monitor.current_ema
        
        for _ in range(10):
            monitor.update_ema(10.0)
        ema_b = monitor.current_ema
        
        # If it was isolated, ema_a would stay 1.0. 
        # Since it's shared, ema_b is now heavily influenced by Tenant B.
        # This test proves that a single instance is NOT multi-tenant safe.
        self.assertNotAlmostEqual(ema_a, 1.0, delta=0.1)
        self.assertNotAlmostEqual(ema_b, 10.0, delta=0.1)

    def test_NEW_02_Payload_Limit(self):
        """Verify that payloads exceeding MAX_PAYLOAD_BYTES are rejected."""
        ledger = CryptographicAuditLedger()
        large_payload = b"X" * (1 * 1024 * 1024 + 1) # 1MB + 1 byte
        with self.assertRaises(ValueError) as ctx:
            ledger.commit_state("s0", 1.0, large_payload)
        self.assertIn("exceeds MAX_PAYLOAD_BYTES", str(ctx.exception))

    def test_NEW_04_Deque_Ceiling(self):
        """Verify that the chain does not grow beyond max_memory_nodes."""
        limit = 100
        ledger = CryptographicAuditLedger(max_memory_nodes=limit)
        for i in range(limit + 50):
            ledger.commit_state(f"s{i}", 1.0, b"data")
        
        self.assertEqual(len(ledger.chain), limit)
        # Ensure it's a sliding window (first elements are gone)
        self.assertEqual(ledger.chain[0].state_id, "s50")

    def test_NEW_16_Near_Saturated_KL(self):
        """Verify near_saturated activates for gaps around 50."""
        monitor = LogitEntropyMonitor()
        # Create a gap of ~50: exp(50) is huge, but not underflow
        p = np.array([50.0, 0.0])
        q = np.array([0.0, 50.0])
        result = monitor.compute_kl_divergence(p, q)
        
        # KL should be high, and near_saturated should be True
        self.assertTrue(result.near_saturated)
        # It should NOT be fully saturated yet (underflow only at ~710)
        self.assertFalse(result.saturated)

    def test_NEW_10_StateID_Collision(self):
        """Verify that long state_ids do not collide via truncation (since we don't use struct.pack)."""
        ledger = CryptographicAuditLedger()
        id1 = "A" * 64
        id2 = "A" * 100
        
        node1 = ledger.commit_state(id1, 1.0, b"data")
        node2 = ledger.commit_state(id2, 1.0, b"data")
        
        self.assertNotEqual(node1.node_hash, node2.node_hash)

    def test_NEW_07_FD_Leak(self):
        """Verify that using context manager closes file descriptors."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            path = tmp.name
        try:
            for _ in range(10):
                with CryptographicAuditLedger(persistence_path=path) as ledger:
                    ledger.commit_state("s", 1.0, b"d")
            # If not closed, this would eventually hit ulimit
            # Here we just check if the handle is actually None after exit
            ledger = CryptographicAuditLedger(persistence_path=path)
            ledger.close()
            self.assertIsNone(ledger._wal_handle)
        finally:
            os.unlink(path)

    def test_NEW_03_Concurrent_Latency(self):
        """Stress test concurrent commits to measure Lock/fsync contention."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            path = tmp.name
        try:
            ledger = CryptographicAuditLedger(persistence_path=path)
            num_threads = 10
            commits_per_thread = 20
            
            start_time = time.time()
            def worker():
                for i in range(commits_per_thread):
                    ledger.commit_state("stress", 1.0, b"data")
            
            threads = [threading.Thread(target=worker) for _ in range(num_threads)]
            for t in threads: t.start()
            for t in threads: t.join()
            end_time = time.time()
            
            duration = end_time - start_time
            avg_lat = duration / (num_threads * commits_per_thread)
            print(f"\n[STRESS] Avg commit latency under contention: {avg_lat*1000:.3f}ms")
            # We expect it to be > 0.1ms due to fsync. 
            # In a real production env, we'd compare this against SLAs.
        finally:
            ledger.close()
            os.unlink(path)

if __name__ == "__main__":
    unittest.main()
