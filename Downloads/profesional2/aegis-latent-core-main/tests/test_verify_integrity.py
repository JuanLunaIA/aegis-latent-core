"""Unit tests for CryptographicAuditLedger.verify_integrity()."""
from aegis.core.crypto_audit import CryptographicAuditLedger


def test_verify_integrity_ok(tmp_path):
    wal = tmp_path / "wal_ok.jsonl"
    ledger = CryptographicAuditLedger(str(wal), signing_key="secret", max_memory_nodes=100)
    ledger.commit_state(state_id="s1", entropy=0.1, payload=b"p1")
    ledger.commit_state(state_id="s2", entropy=0.2, payload=b"p2")
    ok, idx = ledger.verify_integrity()
    assert ok and idx is None


def test_verify_integrity_detects_tamper(tmp_path):
    wal = tmp_path / "wal_tamper.jsonl"
    ledger = CryptographicAuditLedger(str(wal), signing_key="secret", max_memory_nodes=100)
    ledger.commit_state(state_id="s1", entropy=0.1, payload=b"p1")
    ledger.commit_state(state_id="s2", entropy=0.2, payload=b"p2")
    # Tamper with the second node's merkle_root to simulate corruption
    ledger.chain[1].merkle_root = "0" * 64
    ok, idx = ledger.verify_integrity()
    assert ok is False and idx == 1
