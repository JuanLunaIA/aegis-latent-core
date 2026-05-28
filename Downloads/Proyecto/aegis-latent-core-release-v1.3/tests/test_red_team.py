
import unittest
import numpy as np
import threading
import os
import tempfile
import json
import time
from collections import deque
from src.telemetry import LogitEntropyMonitor, KLResult
from src.crypto_audit import CryptographicAuditLedger

class RedTeamStressTests(unittest.TestCase):

    def test_S1_Massive_Concurrency_Burst(self):
        """Scenario: 100+ threads hammering the ledger to find race conditions."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            path = tmp.name
        try:
            ledger = CryptographicAuditLedger(persistence_path=path)
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
        finally:
            ledger.close()
            os.unlink(path)

    def test_S2_WAL_Partial_Write_Recovery(self):
        """Scenario: Process crashes mid-write. WAL contains a truncated JSON line."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            path = tmp.name
        try:
            # Use a real ledger to generate valid hashes for the synthetic WAL
            temp_ledger = CryptographicAuditLedger()
            nodes = []
            for i in range(3):
                nodes.append(temp_ledger.commit_state(f"s{i}", 1.0, b"data"))
            
            with open(path, "w", encoding="utf-8") as f:
                for i, node in enumerate(nodes):
                    rec = {
                        "schema_version": "1.1", "index": i, "timestamp": node.timestamp, 
                        "state_id": node.state_id, "entropy": node.entropy, 
                        "payload_hash": node.payload_hash, "previous_hash": node.previous_hash, 
                        "node_hash": node.node_hash, "pqc_signature": node.pqc_anchor.signature_placeholder
                    }
                    f.write(json.dumps(rec) + "\n")
                # Append a truncated line
                f.write('{"schema_version": "1.1", "index": 3, "timestamp": ' + str(time.time())) 
            
            # Recovery should succeed and ignore the truncated line
            loaded = CryptographicAuditLedger.load_from_wal(path)
            self.assertEqual(len(loaded.chain), 3)
            is_valid, err = loaded.verify_integrity()
            self.assertTrue(is_valid)
            loaded.close()
        finally:
            os.unlink(path)

    def test_S3_Adversarial_UTF8_Injection(self):
        """Scenario: State IDs with complex Unicode/Emojis to test NULL-byte robustness."""
        ledger = CryptographicAuditLedger()
        adversarial_ids = ["🚀_state_1", "state\u200B_zero_width", "state|with|pipe", "state\nwith\nnewline", "A" * 1000, "ID\x01\x02\x03"]
        hashes = set()
        for sid in adversarial_ids:
            node = ledger.commit_state(sid, 1.0, b"data")
            hashes.add(node.node_hash)
        self.assertEqual(len(hashes), len(adversarial_ids))

    def test_S4_Extreme_Logit_Skew(self):
        """Scenario: Logits that are practically identical or extremely disparate."""
        monitor = LogitEntropyMonitor()
        logits_unif = np.ones(1000)
        self.assertAlmostEqual(monitor.compute_shannon_entropy(logits_unif), np.log2(1000), places=5)
        logits_skew = np.array([-100.0] * 999 + [1000.0])
        self.assertAlmostEqual(monitor.compute_shannon_entropy(logits_skew), 0.0, places=5)

if __name__ == "__main__":
    unittest.main()
