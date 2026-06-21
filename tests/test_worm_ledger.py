# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for WORM (Write-Once Read-Many) audit ledger enforcement
(aegis.core.worm_ledger)."""

from __future__ import annotations

import json
import os
import stat
import time

import pytest

from aegis.core.worm_ledger import (
    WORMEnforcer,
    WORMSealRecord,
    WORMViolationError,
    count_nodes_in_segment,
)

# ── WORMViolationError ────────────────────────────────────────────────────────


class TestWORMViolationError:
    def test_is_exception_subclass(self):
        assert issubclass(WORMViolationError, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(WORMViolationError, match="test"):
            raise WORMViolationError("test message")

    def test_message_preserved(self):
        exc = WORMViolationError("immutable")
        assert "immutable" in str(exc)


# ── WORMSealRecord ────────────────────────────────────────────────────────────


class TestWORMSealRecord:
    def test_defaults(self):
        r = WORMSealRecord()
        assert r.record_type == "worm_seal"
        assert r.sealed_by == "WORMEnforcer"
        assert r.node_count == 0
        assert isinstance(r.sealed_at, float)
        assert r.sealed_at > 0

    def test_to_dict_structure(self):
        r = WORMSealRecord(sealed_at=1_000_000.0, sealed_by="test", node_count=42)
        d = r.to_dict()
        assert d["record_type"] == "worm_seal"
        assert d["sealed_at"] == 1_000_000.0
        assert d["sealed_by"] == "test"
        assert d["node_count"] == 42

    def test_to_dict_json_serializable(self):
        r = WORMSealRecord(sealed_at=time.time(), node_count=100)
        json.dumps(r.to_dict())

    def test_from_dict_round_trip(self):
        original = WORMSealRecord(sealed_at=12345.0, sealed_by="unit", node_count=7)
        reconstructed = WORMSealRecord.from_dict(original.to_dict())
        assert reconstructed.record_type == original.record_type
        assert reconstructed.sealed_at == original.sealed_at
        assert reconstructed.sealed_by == original.sealed_by
        assert reconstructed.node_count == original.node_count

    def test_from_dict_defaults_for_missing_keys(self):
        r = WORMSealRecord.from_dict({})
        assert r.record_type == "worm_seal"
        assert r.sealed_at == 0.0
        assert r.sealed_by == ""
        assert r.node_count == 0

    def test_node_count_zero_is_valid(self):
        r = WORMSealRecord(node_count=0)
        assert r.node_count == 0


# ── WORMEnforcer.seal ─────────────────────────────────────────────────────────


class TestWORMEnforcerSeal:
    def test_seal_returns_worm_seal_record(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text('{"state_id":"s1"}\n')
        enforcer = WORMEnforcer()
        result = enforcer.seal(str(f))
        assert isinstance(result, WORMSealRecord)

    def test_seal_writes_sentinel_line(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text('{"state_id":"s1"}\n')
        enforcer = WORMEnforcer()
        enforcer.seal(str(f), node_count=1)
        # Restore permissions for reading in cleanup
        os.chmod(str(f), 0o600)
        content = f.read_text()
        last_line = [line for line in content.splitlines() if line.strip()][-1]
        data = json.loads(last_line)
        assert data["record_type"] == "worm_seal"
        assert data["node_count"] == 1

    def test_seal_sets_readonly_permissions(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        enforcer.seal(str(f))
        mode = stat.S_IMODE(os.stat(str(f)).st_mode)
        assert mode == 0o400
        enforcer.unseal_for_testing(str(f))

    def test_seal_tracks_path_in_sealed_segments(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        enforcer.seal(str(f))
        assert os.path.abspath(str(f)) in enforcer.sealed_segments
        enforcer.unseal_for_testing(str(f))

    def test_seal_sealed_by_stored_in_record(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer(sealed_by="operator-alpha")
        result = enforcer.seal(str(f))
        assert result.sealed_by == "operator-alpha"
        enforcer.unseal_for_testing(str(f))

    def test_seal_nonexistent_path_raises_filenotfounderror(self, tmp_path):
        enforcer = WORMEnforcer()
        with pytest.raises(FileNotFoundError):
            enforcer.seal(str(tmp_path / "does_not_exist.wal"))

    def test_seal_already_sealed_raises_worm_violation(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        enforcer.seal(str(f))
        with pytest.raises(WORMViolationError, match="already sealed"):
            enforcer.seal(str(f))
        enforcer.unseal_for_testing(str(f))

    def test_seal_empty_file(self, tmp_path):
        f = tmp_path / "empty.wal"
        f.write_text("")
        enforcer = WORMEnforcer()
        result = enforcer.seal(str(f), node_count=0)
        assert result.node_count == 0
        enforcer.unseal_for_testing(str(f))

    def test_seal_sealed_at_is_recent(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        before = time.time()
        enforcer = WORMEnforcer()
        result = enforcer.seal(str(f))
        after = time.time()
        assert before <= result.sealed_at <= after
        enforcer.unseal_for_testing(str(f))

    def test_seal_multiple_segments(self, tmp_path):
        f1 = tmp_path / "seg1.wal"
        f2 = tmp_path / "seg2.wal"
        f1.write_text("data1\n")
        f2.write_text("data2\n")
        enforcer = WORMEnforcer()
        enforcer.seal(str(f1))
        enforcer.seal(str(f2))
        assert len(enforcer.sealed_segments) == 2
        enforcer.unseal_for_testing(str(f1))
        enforcer.unseal_for_testing(str(f2))


# ── WORMEnforcer.verify ───────────────────────────────────────────────────────


class TestWORMEnforcerVerify:
    def test_verify_sealed_segment_returns_true(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text('{"state_id":"s1"}\n')
        enforcer = WORMEnforcer()
        enforcer.seal(str(f))
        assert enforcer.verify(str(f)) is True
        enforcer.unseal_for_testing(str(f))

    def test_verify_unsealed_file_returns_false(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text('{"state_id":"s1"}\n')
        enforcer = WORMEnforcer()
        assert enforcer.verify(str(f)) is False

    def test_verify_nonexistent_returns_false(self, tmp_path):
        enforcer = WORMEnforcer()
        assert enforcer.verify(str(tmp_path / "missing.wal")) is False

    def test_verify_wrong_permissions_returns_false(self, tmp_path):
        f = tmp_path / "seg.wal"
        seal_record = json.dumps({"record_type": "worm_seal"}) + "\n"
        f.write_text(seal_record)
        os.chmod(str(f), 0o600)
        enforcer = WORMEnforcer()
        assert enforcer.verify(str(f)) is False

    def test_verify_no_seal_record_returns_false(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text('{"state_id":"s1"}\n')
        os.chmod(str(f), 0o400)
        enforcer = WORMEnforcer()
        assert enforcer.verify(str(f)) is False
        os.chmod(str(f), 0o600)

    def test_verify_corrupt_last_line_returns_false(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("not valid json\n")
        os.chmod(str(f), 0o400)
        enforcer = WORMEnforcer()
        assert enforcer.verify(str(f)) is False
        os.chmod(str(f), 0o600)

    def test_verify_wrong_record_type_returns_false(self, tmp_path):
        f = tmp_path / "seg.wal"
        bad_record = json.dumps({"record_type": "audit_node"}) + "\n"
        f.write_text(bad_record)
        os.chmod(str(f), 0o400)
        enforcer = WORMEnforcer()
        assert enforcer.verify(str(f)) is False
        os.chmod(str(f), 0o600)


# ── WORMEnforcer.is_sealed ────────────────────────────────────────────────────


class TestWORMEnforcerIsSealed:
    def test_is_sealed_after_seal_call(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        enforcer.seal(str(f))
        assert enforcer.is_sealed(str(f)) is True
        enforcer.unseal_for_testing(str(f))

    def test_is_sealed_via_on_disk_verification(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        sealer = WORMEnforcer()
        sealer.seal(str(f))
        # A different enforcer instance that doesn't have the path in memory
        fresh_enforcer = WORMEnforcer()
        assert fresh_enforcer.is_sealed(str(f)) is True
        sealer.unseal_for_testing(str(f))

    def test_is_sealed_unknown_path_returns_false(self, tmp_path):
        f = tmp_path / "plain.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        assert enforcer.is_sealed(str(f)) is False

    def test_is_sealed_nonexistent_returns_false(self, tmp_path):
        enforcer = WORMEnforcer()
        assert enforcer.is_sealed(str(tmp_path / "no.wal")) is False


# ── WORMEnforcer.enforce_immutability ─────────────────────────────────────────


class TestWORMEnforcerEnforceImmutability:
    def test_raises_for_in_memory_sealed_path(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        enforcer.seal(str(f))
        with pytest.raises(WORMViolationError, match="sealed"):
            enforcer.enforce_immutability(str(f))
        enforcer.unseal_for_testing(str(f))

    def test_raises_for_on_disk_sealed_segment(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        sealer = WORMEnforcer()
        sealer.seal(str(f))
        # New enforcer with empty memory
        checker = WORMEnforcer()
        with pytest.raises(WORMViolationError):
            checker.enforce_immutability(str(f))
        sealer.unseal_for_testing(str(f))

    def test_no_raise_for_unsealed_segment(self, tmp_path):
        f = tmp_path / "active.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        enforcer.enforce_immutability(str(f))  # should not raise

    def test_error_message_mentions_compliance(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        enforcer.seal(str(f))
        with pytest.raises(WORMViolationError) as exc_info:
            enforcer.enforce_immutability(str(f))
        assert "AU-9" in str(exc_info.value) or "Annex 11" in str(exc_info.value)
        enforcer.unseal_for_testing(str(f))


# ── WORMEnforcer.delete_node ──────────────────────────────────────────────────


class TestWORMEnforcerDeleteNode:
    def test_delete_node_always_raises(self):
        enforcer = WORMEnforcer()
        with pytest.raises(WORMViolationError):
            enforcer.delete_node("some-state-id")

    def test_delete_node_raises_with_no_args(self):
        enforcer = WORMEnforcer()
        with pytest.raises(WORMViolationError):
            enforcer.delete_node()

    def test_delete_node_raises_with_kwargs(self):
        enforcer = WORMEnforcer()
        with pytest.raises(WORMViolationError):
            enforcer.delete_node(state_id="abc", tenant_id="t1")

    def test_delete_node_error_message_mentions_immutability(self):
        enforcer = WORMEnforcer()
        with pytest.raises(WORMViolationError) as exc_info:
            enforcer.delete_node("abc123")
        msg = str(exc_info.value)
        assert "immutable" in msg.lower() or "deleted" in msg.lower()

    def test_delete_node_error_mentions_compliance_standards(self):
        enforcer = WORMEnforcer()
        with pytest.raises(WORMViolationError) as exc_info:
            enforcer.delete_node()
        msg = str(exc_info.value)
        assert "AU-9" in msg or "Part 11" in msg


# ── WORMEnforcer.sealed_segments ─────────────────────────────────────────────


class TestWORMEnforcerSealedSegments:
    def test_empty_initially(self):
        enforcer = WORMEnforcer()
        assert enforcer.sealed_segments == frozenset()

    def test_contains_sealed_path_as_absolute(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        enforcer.seal(str(f))
        assert os.path.abspath(str(f)) in enforcer.sealed_segments
        enforcer.unseal_for_testing(str(f))

    def test_is_frozenset(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        enforcer.seal(str(f))
        result = enforcer.sealed_segments
        assert isinstance(result, frozenset)
        enforcer.unseal_for_testing(str(f))

    def test_immutable_copy_returned(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text("data\n")
        enforcer = WORMEnforcer()
        enforcer.seal(str(f))
        snapshot = enforcer.sealed_segments
        # Sealing a second file doesn't mutate the snapshot
        f2 = tmp_path / "seg2.wal"
        f2.write_text("data2\n")
        enforcer.seal(str(f2))
        assert len(snapshot) == 1
        assert len(enforcer.sealed_segments) == 2
        enforcer.unseal_for_testing(str(f))
        enforcer.unseal_for_testing(str(f2))


# ── count_nodes_in_segment ────────────────────────────────────────────────────


class TestCountNodesInSegment:
    def test_counts_audit_node_lines(self, tmp_path):
        f = tmp_path / "seg.wal"
        lines = [
            json.dumps({"state_id": f"s{i}", "record_type": None}) for i in range(5)
        ]
        f.write_text("\n".join(lines) + "\n")
        assert count_nodes_in_segment(str(f)) == 5

    def test_excludes_worm_seal_record(self, tmp_path):
        f = tmp_path / "seg.wal"
        node_lines = [json.dumps({"state_id": f"s{i}"}) for i in range(3)]
        seal_line = json.dumps({"record_type": "worm_seal", "node_count": 3})
        content = "\n".join(node_lines + [seal_line]) + "\n"
        f.write_text(content)
        assert count_nodes_in_segment(str(f)) == 3

    def test_empty_file_returns_zero(self, tmp_path):
        f = tmp_path / "empty.wal"
        f.write_text("")
        assert count_nodes_in_segment(str(f)) == 0

    def test_nonexistent_file_returns_zero(self, tmp_path):
        assert count_nodes_in_segment(str(tmp_path / "no.wal")) == 0

    def test_skips_blank_lines(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text('\n{"state_id":"s1"}\n\n{"state_id":"s2"}\n\n')
        assert count_nodes_in_segment(str(f)) == 2

    def test_skips_corrupt_lines(self, tmp_path):
        f = tmp_path / "seg.wal"
        f.write_text('{"state_id":"s1"}\nnot json\n{"state_id":"s2"}\n')
        # Corrupt lines are skipped (not counted, not fatal)
        assert count_nodes_in_segment(str(f)) == 2


# ── Integration: WORM with CryptographicAuditLedger ──────────────────────────


class TestWORMIntegrationWithLedger:
    """Verify that WORMEnforcer correctly seals real WAL segments produced by
    CryptographicAuditLedger."""

    _KEY = "worm-test-signing-key-do-not-use-in-prod"

    def _make_ledger(self, tmp_path, **kwargs):
        from aegis.core.crypto_audit import CryptographicAuditLedger

        wal = str(tmp_path / "audit.wal.jsonl")
        return CryptographicAuditLedger(wal, signing_key=self._KEY, **kwargs)

    def test_seal_active_wal_after_commits(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        try:
            for i in range(5):
                ledger.commit_state(f"sid{i}", 1.5, b"payload" * 10)
        finally:
            ledger.close()

        wal_path = str(tmp_path / "audit.wal.jsonl")
        enforcer = WORMEnforcer(sealed_by="test-operator")
        enforcer.seal(wal_path, node_count=5)
        assert enforcer.is_sealed(wal_path)
        enforcer.unseal_for_testing(wal_path)

    def test_sealed_wal_has_correct_node_count(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        try:
            for i in range(8):
                ledger.commit_state(f"sid{i}", 1.0, b"x" * 64)
        finally:
            ledger.close()

        wal_path = str(tmp_path / "audit.wal.jsonl")
        actual_count = count_nodes_in_segment(wal_path)
        assert actual_count == 8

        enforcer = WORMEnforcer()
        enforcer.seal(wal_path, node_count=actual_count)
        # Restore for test cleanup
        enforcer.unseal_for_testing(wal_path)

    def test_enforce_blocks_deletion_of_sealed_wal(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        try:
            ledger.commit_state("sid0", 1.0, b"payload")
        finally:
            ledger.close()

        wal_path = str(tmp_path / "audit.wal.jsonl")
        enforcer = WORMEnforcer()
        enforcer.seal(wal_path)

        # Simulating an attempted deletion via enforce_immutability check
        with pytest.raises(WORMViolationError):
            enforcer.enforce_immutability(wal_path)

        enforcer.unseal_for_testing(wal_path)

    def test_sealed_segment_node_count_matches_actual(self, tmp_path):
        """count_nodes_in_segment correctly excludes the worm_seal sentinel."""
        ledger = self._make_ledger(tmp_path, max_wal_bytes=2048)
        try:
            for i in range(20):
                ledger.commit_state(f"sid{i}", 1.0, b"x" * 200)
        finally:
            ledger.close()

        segments = list(ledger.archived_segments)
        assert segments, "expected at least one rotated segment"

        enforcer = WORMEnforcer()
        for seg in segments:
            # Count nodes before sealing
            n = count_nodes_in_segment(seg)
            assert n > 0
            enforcer.seal(seg, node_count=n)
            # After sealing: sentinel must not inflate the count
            enforcer.unseal_for_testing(seg)
            os.chmod(seg, 0o400)
            after_count = count_nodes_in_segment(seg)
            assert after_count == n
            os.chmod(seg, 0o600)

    def test_delete_node_refuses_always(self, tmp_path):
        enforcer = WORMEnforcer()
        # Even without sealing anything, delete_node must refuse
        with pytest.raises(WORMViolationError):
            enforcer.delete_node("sid0")

    def test_worm_seal_record_readable_from_sealed_file(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        try:
            ledger.commit_state("sid0", 1.0, b"payload-data")
        finally:
            ledger.close()

        wal_path = str(tmp_path / "audit.wal.jsonl")
        enforcer = WORMEnforcer(sealed_by="qa-operator")
        enforcer.seal(wal_path, node_count=1)

        # Temporarily restore permissions to read
        os.chmod(wal_path, 0o600)
        with open(wal_path) as fh:
            lines = [ln for ln in fh.readlines() if ln.strip()]
        last = json.loads(lines[-1])
        assert last["record_type"] == "worm_seal"
        assert last["sealed_by"] == "qa-operator"
        assert last["node_count"] == 1
        enforcer.unseal_for_testing(wal_path)

    def test_fresh_enforcer_recognizes_on_disk_seal(self, tmp_path):
        """A WORMEnforcer created after sealing must detect the seal via verify()."""
        ledger = self._make_ledger(tmp_path)
        try:
            ledger.commit_state("sid0", 1.0, b"payload")
        finally:
            ledger.close()

        wal_path = str(tmp_path / "audit.wal.jsonl")
        sealer = WORMEnforcer()
        sealer.seal(wal_path)

        # New process/instance scenario
        fresh = WORMEnforcer()
        assert fresh.is_sealed(wal_path)
        with pytest.raises(WORMViolationError):
            fresh.enforce_immutability(wal_path)

        sealer.unseal_for_testing(wal_path)
