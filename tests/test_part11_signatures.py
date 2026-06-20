# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""21 CFR Part 11 electronic signature annotation fields (ROADMAP Domain 2.2)."""
from __future__ import annotations

import json

from aegis.core.crypto_audit import AuditNode, CryptographicAuditLedger


class TestAuditNodePart11Fields:
    def _ledger(self, tmp_path) -> CryptographicAuditLedger:
        return CryptographicAuditLedger(str(tmp_path / "audit.wal.jsonl"), signing_key="k")

    def test_defaults_empty(self, tmp_path):
        ledger = self._ledger(tmp_path)
        node = ledger.commit_state("s1", 0.0, b"payload")
        ledger.close()
        assert node.signer_name == ""
        assert node.signature_meaning == ""

    def test_signer_name_stored(self, tmp_path):
        ledger = self._ledger(tmp_path)
        node = ledger.commit_state("s1", 0.0, b"payload", signer_name="alice")
        ledger.close()
        assert node.signer_name == "alice"

    def test_signature_meaning_stored(self, tmp_path):
        ledger = self._ledger(tmp_path)
        node = ledger.commit_state("s1", 0.0, b"payload", signature_meaning="authored")
        ledger.close()
        assert node.signature_meaning == "authored"

    def test_both_fields_via_commit_forensic(self, tmp_path):
        ledger = self._ledger(tmp_path)
        node = ledger.commit_forensic(
            state_id="s1",
            request_bytes=b"data",
            entropy=0.5,
            signer_name="tenant-42",
            signature_meaning="reviewed",
        )
        ledger.close()
        assert node.signer_name == "tenant-42"
        assert node.signature_meaning == "reviewed"

    def test_fields_not_in_node_hash(self, tmp_path):
        """signer_name and signature_meaning must not appear in the hash content string."""
        ledger = self._ledger(tmp_path)
        node = ledger.commit_state("s1", 0.0, b"payload", signer_name="alice", signature_meaning="authored")
        ledger.close()
        hash_content = "|".join([
            node.prev_hash, node.state_id, f"{node.timestamp:.9f}",
            str(node.entropy), node.tenant_id, node.merkle_root,
            node.signature, node.request_hash, node.response_hash,
        ])
        assert "alice" not in hash_content
        assert "authored" not in hash_content

    def test_fields_persisted_in_wal(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        ledger.commit_state("s1", 0.0, b"x", signer_name="bob", signature_meaning="approved")
        ledger.close()

        with open(wal) as f:
            rec = json.loads(f.readline())
        assert rec["signer_name"] == "bob"
        assert rec["signature_meaning"] == "approved"

    def test_fields_loaded_from_wal(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        ledger.commit_state("s1", 0.0, b"x", signer_name="carol", signature_meaning="authored")
        ledger.close()

        ledger2 = CryptographicAuditLedger(wal, signing_key="k")
        assert ledger2.chain[0].signer_name == "carol"
        assert ledger2.chain[0].signature_meaning == "authored"
        ledger2.close()

    def test_from_dict_defaults_for_old_records(self):
        """Old WAL records without Part 11 fields deserialise with empty strings."""
        rec = {
            "state_id": "s1",
            "timestamp": 1.0,
            "entropy": 0.0,
            "tenant_id": "default",
            "sampling_params": {},
            "prev_hash": "0" * 64,
            "merkle_root": "a" * 64,
            "signature": "sig",
            "signature_scheme": "hmac-sha256",
            "public_key": "",
            "request_hash": "r" * 64,
            "response_hash": "",
            "model": "unknown",
            "endpoint": "chat.completions",
            "token_trail_count": 0,
            "is_fallback": False,
        }
        node = AuditNode.from_dict(rec)
        assert node.signer_name == ""
        assert node.signature_meaning == ""

    def test_integrity_valid_with_part11_fields(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        ledger.commit_state("s1", 0.0, b"a", signer_name="alice", signature_meaning="authored")
        ledger.commit_state("s2", 0.0, b"b", signer_name="bob", signature_meaning="reviewed")
        ledger.close()

        ledger2 = CryptographicAuditLedger(wal, signing_key="k")
        valid, idx = ledger2.verify_integrity()
        ledger2.close()
        assert valid
        assert idx is None


class TestExportPart11Signatures:
    def test_export_returns_all_nodes(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        ledger.commit_state("s1", 0.0, b"x", signer_name="alice", signature_meaning="authored")
        ledger.commit_state("s2", 0.0, b"y", signer_name="bob", signature_meaning="reviewed")
        records = ledger.export_part11_signatures()
        ledger.close()
        assert len(records) == 2

    def test_record_contains_mandatory_part11_fields(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        ledger.commit_state("s1", 0.0, b"x", signer_name="alice", signature_meaning="authored")
        records = ledger.export_part11_signatures()
        ledger.close()

        rec = records[0]
        # Three mandatory Part 11 §11.50(a) fields
        assert rec["signer_name"] == "alice"
        assert rec["signature_meaning"] == "authored"
        assert "timestamp_iso" in rec
        assert "T" in rec["timestamp_iso"]  # ISO-8601 date-time separator
        assert rec["timestamp_iso"].endswith("+00:00")  # UTC timezone

    def test_record_contains_cryptographic_binding(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        node = ledger.commit_state("s1", 0.0, b"x")
        records = ledger.export_part11_signatures()
        ledger.close()

        rec = records[0]
        assert rec["node_hash"] == node.node_hash
        assert rec["signature"] == node.signature
        assert rec["signature_scheme"] == node.signature_scheme
        assert rec["state_id"] == "s1"

    def test_empty_ledger_returns_empty_list(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        records = ledger.export_part11_signatures()
        ledger.close()
        assert records == []

    def test_export_includes_nodes_without_signer(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        ledger.commit_state("s1", 0.0, b"x")  # no signer_name
        records = ledger.export_part11_signatures()
        ledger.close()
        assert len(records) == 1
        assert records[0]["signer_name"] == ""

    def test_meaning_values_preserved(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        for meaning in ("authored", "reviewed", "approved"):
            ledger.commit_state(f"s-{meaning}", 0.0, b"x", signature_meaning=meaning)
        records = ledger.export_part11_signatures()
        ledger.close()

        meanings = [r["signature_meaning"] for r in records]
        assert meanings == ["authored", "reviewed", "approved"]
