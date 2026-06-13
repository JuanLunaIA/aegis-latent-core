"""
tests/test_forensic.py — Forensic ledger: request/response capture and HMAC signatures.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import os
import tempfile
import unittest

from aegis.core.crypto_audit import RUST_AVAILABLE, CryptographicAuditLedger
from aegis.core.forensic import build_merkle_leaf, sha256_hex

_TEST_SIGNING_KEY = "unit-test-ledger-signing-key-do-not-use-in-production"


class TestForensicLedger(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.temp_path = self.temp_file.name
        self.temp_file.close()
        self.ledgers = []

    def tearDown(self) -> None:
        for ledger in self.ledgers:
            try:
                ledger.close()
            except Exception:
                pass
        if os.path.exists(self.temp_path):
            os.unlink(self.temp_path)

    def _ledger(self) -> CryptographicAuditLedger:
        ledger = CryptographicAuditLedger(
            self.temp_path,
            signing_key=_TEST_SIGNING_KEY,
            max_forensic_bytes=4096,
        )
        self.ledgers.append(ledger)
        return ledger

    def test_commit_forensic_request_and_response(self) -> None:
        ledger = self._ledger()
        req = b'{"messages":[{"role":"user","content":"hello"}]}'
        resp = b'{"choices":[{"message":{"content":"hi"}}]}'
        node = ledger.commit_forensic(
            state_id="req-1",
            request_bytes=req,
            response_bytes=resp,
            entropy=2.5,
            tenant_id="tenant-a",
            model="gpt-test",
            endpoint="chat.completions",
            token_trail=[{"index": 0, "token": "hi", "logprob": -0.1}],
            usage={"total_tokens": 10},
        )
        self.assertEqual(node.request_hash, sha256_hex(req))
        self.assertEqual(node.response_hash, sha256_hex(resp))
        self.assertEqual(node.model, "gpt-test")
        self.assertEqual(node.token_trail_count, 1)
        expected_scheme = "pqc-ml-dsa" if RUST_AVAILABLE else "hmac-sha256"
        self.assertEqual(node.signature_scheme, expected_scheme)
        is_valid, err = ledger.verify_integrity()
        self.assertTrue(is_valid, msg=f"integrity failed at {err}")

    def test_signature_tamper_detected(self) -> None:
        ledger = self._ledger()
        node = ledger.commit_forensic(
            state_id="req-2",
            request_bytes=b"req",
            response_bytes=b"resp",
            entropy=1.0,
            tenant_id="t",
            model="m",
            endpoint="chat.completions",
        )
        node.signature = "0" * 64
        is_valid, index = ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertEqual(index, 0)

    def test_legal_admissibility_high_with_signing_key(self) -> None:
        ledger = self._ledger()
        self.assertEqual(ledger.legal_admissibility, "High")
        ledger.commit_forensic(
            state_id="x",
            request_bytes=b"a",
            response_bytes=b"b",
            entropy=1.0,
            tenant_id="t",
            model="m",
            endpoint="chat.completions",
        )
        self.assertEqual(ledger.legal_admissibility, "High")

    def test_merkle_leaf_deterministic(self) -> None:
        leaf_a = build_merkle_leaf(
            state_id="id",
            request_bytes=b"req",
            response_bytes=b"resp",
            model="m",
            endpoint="e",
            max_bytes=1024,
        )
        leaf_b = build_merkle_leaf(
            state_id="id",
            request_bytes=b"req",
            response_bytes=b"resp",
            model="m",
            endpoint="e",
            max_bytes=1024,
        )
        self.assertEqual(leaf_a, leaf_b)

    def test_wal_roundtrip_preserves_forensic_fields(self) -> None:
        with self._ledger() as ledger:
            ledger.commit_forensic(
                state_id="wal-1",
                request_bytes=b"request",
                response_bytes=b"response",
                entropy=3.0,
                tenant_id="tenant",
                model="llama",
                endpoint="chat.completions",
                token_trail=[{"index": 0, "token": "x"}],
            )
        loaded = self._ledger()
        self.assertEqual(len(loaded.chain), 1)
        n = loaded.chain[0]
        self.assertEqual(n.response_hash, sha256_hex(b"response"))
        self.assertEqual(n.token_trail_count, 1)
        self.assertTrue(loaded.verify_integrity()[0])


if __name__ == "__main__":
    unittest.main()
