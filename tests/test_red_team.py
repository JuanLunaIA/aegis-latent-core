import unittest
import os
import tempfile
import threading
import numpy as np
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.telemetry import LogitEntropyMonitor

class RedTeamStressTests(unittest.TestCase):

    def setUp(self):
        self.tmp_file = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.tmp_file.close()
        self.path = self.tmp_file.name

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_S1_Massive_Concurrency_Burst(self):
        """Scenario: 100+ threads hammering the ledger to find race conditions."""
        ledger = CryptographicAuditLedger(persistence_path=self.path)
        num_threads = 100
        commits_per_thread = 50
        
        def worker(tid):
            for i in range(commits_per_thread):
                ledger.commit_state(f"t{tid}_s{i}", 1.0, b"payload")
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads: t.start()
        for t in threads: t.join()
        
        self.assertEqual(len(ledger.chain), num_threads * commits_per_thread)
        is_valid, err = ledger.verify_integrity()
        self.assertTrue(is_valid, f"Chain corrupted at node {err}")
        ledger.close()

    def test_S2_WAL_Partial_Write_Recovery(self):
        """Scenario: Process crashes mid-write. WAL contains a truncated JSON line."""
        ledger = CryptographicAuditLedger(persistence_path=self.path)
        ledger.commit_state("test", 1.0, b"data")
        ledger.close()
        
        # Corrupt the WAL by appending a half-line
        with open(self.path, "a") as f:
            f.write('{"state_id": "corrupt", "timestamp": 12345, "entropy": 0.5, ')
        
        # Re-load the ledger. It should handle the corruption gracefully.
        new_ledger = CryptographicAuditLedger(persistence_path=self.path)
        # Check that we recovered the previous valid node
        self.assertTrue(len(new_ledger.chain) >= 1)
        new_ledger.close()

    def test_S3_Adversarial_UTF8_Injection(self):
        """Scenario: State IDs with complex Unicode/Emojis to test NULL-byte robustness."""
        ledger = CryptographicAuditLedger(persistence_path=self.path)
        adversarial_ids = ["🚀_state_1", "state\u200B_zero_width", "state|with|pipe", "state\nwith\nnewline", "A" * 1000, "ID\x01\x02\x03"]
        hashes = set()
        for sid in adversarial_ids:
            try:
                node = ledger.commit_state(sid, 1.0, b"data")
                hashes.add(node.node_hash)
            except ValueError:
                # Some might be rejected (like NULL bytes)
                pass
        self.assertTrue(len(hashes) > 0)
        ledger.close()

    def test_S4_Extreme_Logit_Skew(self):
        """Scenario: Logits that are practically identical or extremely disparate."""
        monitor = LogitEntropyMonitor()
        logits_unif = np.ones(1000)
        self.assertAlmostEqual(monitor.compute_shannon_entropy(logits_unif), np.log2(1000), places=5)
        logits_skew = np.array([-100.0] * 999 + [1000.0])
        self.assertAlmostEqual(monitor.compute_shannon_entropy(logits_skew), 0.0, places=5)

if __name__ == "__main__":
    unittest.main()
