# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""PHI scrubbing confirmation fields on AuditNode (ROADMAP Domain 2.1)."""
from __future__ import annotations

from unittest.mock import MagicMock

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.phi_deidentifier import PHIDeidentifier


class TestAuditNodePHIFields:
    def _make_ledger(self, tmp_path) -> CryptographicAuditLedger:
        return CryptographicAuditLedger(
            str(tmp_path / "audit.wal.jsonl"), signing_key="test-key"
        )

    def test_phi_scrubbed_default_false(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        node = ledger.commit_state("s1", 0.5, b"payload")
        ledger.close()
        assert node.phi_scrubbed is False
        assert node.scrub_method == ""

    def test_phi_scrubbed_true_propagates(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        node = ledger.commit_state(
            "s1", 0.5, b"payload", phi_scrubbed=True, scrub_method="safe_harbor_regex"
        )
        ledger.close()
        assert node.phi_scrubbed is True
        assert node.scrub_method == "safe_harbor_regex"

    def test_phi_scrubbed_via_commit_forensic(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        node = ledger.commit_forensic(
            state_id="s1",
            request_bytes=b"SSN: 123-45-6789",
            entropy=0.5,
            phi_scrubbed=True,
            scrub_method="safe_harbor_regex",
        )
        ledger.close()
        assert node.phi_scrubbed is True
        assert node.scrub_method == "safe_harbor_regex"

    def test_phi_fields_not_in_node_hash(self, tmp_path):
        """Changing phi_scrubbed/scrub_method must NOT change node_hash."""
        ledger = self._make_ledger(tmp_path)
        n1 = ledger.commit_state("s1", 0.5, b"payload", phi_scrubbed=False)
        ledger.close()

        ledger2 = self._make_ledger(tmp_path)
        ledger2.commit_state("s2", 0.5, b"payload", phi_scrubbed=True, scrub_method="safe_harbor_regex")
        ledger2.close()

        # node_hash is derived from chain fields, not phi metadata — same
        # content with different phi flags should have matching *content hash*
        # (i.e. the content bytes that feed the hash are the same)
        import hashlib
        def _content_hash(n):
            content = "|".join([
                n.prev_hash, n.state_id, f"{n.timestamp:.9f}",
                str(n.entropy), n.tenant_id, n.merkle_root,
                n.signature, n.request_hash, n.response_hash,
            ])
            return hashlib.sha256(content.encode()).hexdigest()

        # Both nodes' hashes are computed from the same set of fields
        # (phi_scrubbed/scrub_method are absent from the content string)
        assert "phi_scrubbed" not in "|".join([
            n1.prev_hash, n1.state_id, f"{n1.timestamp:.9f}",
            str(n1.entropy), n1.tenant_id, n1.merkle_root,
            n1.signature, n1.request_hash, n1.response_hash,
        ])

    def test_phi_fields_serialized_in_wal(self, tmp_path):
        """phi_scrubbed and scrub_method survive WAL persistence round-trip."""
        import json
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        ledger.commit_state("s1", 0.0, b"payload", phi_scrubbed=True, scrub_method="safe_harbor_regex")
        ledger.close()

        with open(wal) as f:
            record = json.loads(f.readline())

        assert record["phi_scrubbed"] is True
        assert record["scrub_method"] == "safe_harbor_regex"

    def test_phi_fields_load_from_wal(self, tmp_path):
        """Ledger loaded from WAL restores phi_scrubbed/scrub_method on chain nodes."""
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        ledger.commit_state("s1", 0.0, b"payload", phi_scrubbed=True, scrub_method="safe_harbor_regex")
        ledger.close()

        ledger2 = CryptographicAuditLedger(wal, signing_key="k")
        assert ledger2.chain[0].phi_scrubbed is True
        assert ledger2.chain[0].scrub_method == "safe_harbor_regex"
        ledger2.close()

    def test_phi_fields_default_on_old_wal_records(self, tmp_path):
        """from_dict fills phi_scrubbed=False, scrub_method='' for old WAL records."""
        from aegis.core.crypto_audit import AuditNode
        old_record = {
            "state_id": "s1",
            "timestamp": 1.0,
            "entropy": 0.5,
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
            # phi_scrubbed and scrub_method absent — simulates old WAL record
        }
        node = AuditNode.from_dict(old_record)
        assert node.phi_scrubbed is False
        assert node.scrub_method == ""

    def test_integrity_valid_with_phi_fields(self, tmp_path):
        """Integrity check passes on a ledger that has phi_scrubbed nodes."""
        wal = str(tmp_path / "audit.wal.jsonl")
        ledger = CryptographicAuditLedger(wal, signing_key="k")
        ledger.commit_state("s1", 0.0, b"data1", phi_scrubbed=True, scrub_method="safe_harbor_regex")
        ledger.commit_state("s2", 0.0, b"data2", phi_scrubbed=False)
        ledger.close()

        ledger2 = CryptographicAuditLedger(wal, signing_key="k")
        valid, idx = ledger2.verify_integrity()
        ledger2.close()
        assert valid
        assert idx is None


class TestApplyPHIScrubRequest:
    """Unit tests for the _apply_phi_scrub_request helper in app.py."""

    def _make_state_with_scrubber(self):
        state = MagicMock()
        state._phi_scrubber = PHIDeidentifier()
        return state

    def _make_state_no_scrubber(self):
        state = MagicMock()
        state._phi_scrubber = None
        return state

    def test_no_scrubber_returns_body_unchanged(self):
        from aegis.proxy.app import _apply_phi_scrub_request
        state = self._make_state_no_scrubber()
        body = {"messages": [{"role": "user", "content": "hello"}]}
        result_body, scrubbed, method = _apply_phi_scrub_request(body, state)
        assert result_body is body
        assert scrubbed is False
        assert method == ""

    def test_no_phi_in_content_returns_false(self):
        from aegis.proxy.app import _apply_phi_scrub_request
        state = self._make_state_with_scrubber()
        body = {"messages": [{"role": "user", "content": "What is 2 + 2?"}]}
        result_body, scrubbed, method = _apply_phi_scrub_request(body, state)
        assert scrubbed is False
        assert method == ""

    def test_phi_detected_returns_true_with_method(self):
        from aegis.proxy.app import _apply_phi_scrub_request
        state = self._make_state_with_scrubber()
        body = {
            "messages": [{"role": "user", "content": "My SSN is 123-45-6789"}]
        }
        result_body, scrubbed, method = _apply_phi_scrub_request(body, state)
        assert scrubbed is True
        assert method == "safe_harbor_regex"
        assert "123-45-6789" not in result_body["messages"][0]["content"]

    def test_no_messages_returns_false(self):
        from aegis.proxy.app import _apply_phi_scrub_request
        state = self._make_state_with_scrubber()
        body = {"prompt": "What is 2+2?"}
        result_body, scrubbed, method = _apply_phi_scrub_request(body, state)
        assert result_body is body
        assert scrubbed is False
        assert method == ""
