
import unittest
import numpy as np
import os
import tempfile
import time
from src.crypto_audit import CryptographicAuditLedger
from src.telemetry import LogitEntropyMonitor

class WorldReadyValidation(unittest.TestCase):

    def test_V13_Async_Durability_Ack(self):
        """Verify that Async mode correctly resolves Futures upon durability."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            path = tmp.name
        try:
            ledger = CryptographicAuditLedger(persistence_path=path, async_mode=True)
            node, fut = ledger.commit_state("async_token", 1.0, b"data")
            result = fut.result(timeout=2.0)
            self.assertTrue(result)
            ledger.close()
        finally:
            os.unlink(path)

    def test_V13_Backpressure(self):
        """Verify that the system prevents OOM by enforcing max_queue_depth."""
        ledger = CryptographicAuditLedger(async_mode=True, max_queue_depth=10)
        try:
            for i in range(100):
                ledger.commit_state(f"s{i}", 1.0, b"data")
        except RuntimeError as e:
            self.assertIn("backpressure", str(e))
            return
        self.fail("System did not trigger backpressure")

    def test_V13_Sync_Forensic_Mode(self):
        """Verify that Sync mode provides immediate durability."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            path = tmp.name
        try:
            ledger = CryptographicAuditLedger(persistence_path=path, async_mode=False)
            node, fut = ledger.commit_state("sync_token", 1.0, b"data")
            self.assertIsNone(fut)
            with open(path, "r") as f:
                self.assertIn("sync_token", f.read())
            ledger.close()
        finally:
            os.unlink(path)

if __name__ == "__main__":
    unittest.main()
