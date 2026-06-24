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
    SEC_17A4_BROKER_DEALER,
    SEC_17A4_THREE_YEAR,
    WORMAttestationBundle,
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
        lines = [json.dumps({"state_id": f"s{i}", "record_type": None}) for i in range(5)]
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


# ── RetentionPolicy ───────────────────────────────────────────────────────────

_SIGNING_KEY = b"test-signing-key-32-bytes-padded"


class TestRetentionPolicy:
    def test_accessible_until_is_accessible_years_after_seal(self):
        policy = SEC_17A4_BROKER_DEALER
        sealed_at = 1_000_000.0
        until = policy.accessible_until(sealed_at)
        assert until > sealed_at
        # 3 years ≈ 94,608,000 s (Julian year)
        delta = until - sealed_at
        assert 94_600_000 < delta < 94_700_000

    def test_purge_eligible_at_is_total_years_after_seal(self):
        policy = SEC_17A4_BROKER_DEALER
        sealed_at = 1_000_000.0
        purge = policy.purge_eligible_at(sealed_at)
        # 6 Julian years = 6 * 365.25 * 86400 = 189,345,600 s
        delta = purge - sealed_at
        assert 189_300_000 < delta < 189_400_000

    def test_retention_status_accessible(self):
        policy = SEC_17A4_BROKER_DEALER
        sealed_at = time.time() - 86400  # sealed 1 day ago
        assert policy.retention_status(sealed_at) == "ACCESSIBLE"

    def test_retention_status_long_term(self):
        policy = SEC_17A4_BROKER_DEALER
        # sealed 4 years ago (> accessible_years=3, < total_years=6)
        sealed_at = time.time() - 4 * 365.25 * 86400
        assert policy.retention_status(sealed_at) == "LONG_TERM"

    def test_retention_status_purge_eligible(self):
        policy = SEC_17A4_BROKER_DEALER
        # sealed 7 years ago
        sealed_at = time.time() - 7 * 365.25 * 86400
        assert policy.retention_status(sealed_at) == "PURGE_ELIGIBLE"

    def test_three_year_policy_constants(self):
        assert SEC_17A4_THREE_YEAR.accessible_years == 2.0
        assert SEC_17A4_THREE_YEAR.total_years == 3.0
        assert "SEC Rule 17a-4(b)(2)" in SEC_17A4_THREE_YEAR.citations

    def test_broker_dealer_policy_constants(self):
        assert SEC_17A4_BROKER_DEALER.total_years == 6.0
        assert "FINRA Rule 4511" in SEC_17A4_BROKER_DEALER.citations

    def test_policy_is_frozen(self):
        with pytest.raises((AttributeError, TypeError)):
            SEC_17A4_BROKER_DEALER.total_years = 99  # type: ignore[misc]


# ── WORMAttestationBundle ─────────────────────────────────────────────────────


class TestWORMAttestationBundle:
    def test_to_dict_contains_expected_keys(self):
        bundle = WORMAttestationBundle(
            generated_at=1_000_000.0,
            generated_by="test",
            regulatory_citations=("SEC Rule 17a-4(b)(1)",),
            segments=[],
            bundle_hmac="abc",
        )
        d = bundle.to_dict()
        assert "generated_at" in d
        assert "regulatory_citations" in d
        assert "segments" in d
        assert "bundle_hmac" in d

    def test_to_json_is_valid_json(self):
        bundle = WORMAttestationBundle()
        parsed = json.loads(bundle.to_json())
        assert isinstance(parsed, dict)

    def test_verify_bundle_hmac_valid(self, tmp_path):
        enforcer = WORMEnforcer()
        seg = tmp_path / "seg.wal"
        seg.write_text("")
        enforcer.seal(str(seg))
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert bundle.verify_bundle_hmac(_SIGNING_KEY) is True
        enforcer.unseal_for_testing(str(seg))

    def test_verify_bundle_hmac_wrong_key(self, tmp_path):
        enforcer = WORMEnforcer()
        seg = tmp_path / "seg.wal"
        seg.write_text("")
        enforcer.seal(str(seg))
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert bundle.verify_bundle_hmac(b"wrong-key") is False
        enforcer.unseal_for_testing(str(seg))

    def test_tampered_segment_fails_hmac(self, tmp_path):
        enforcer = WORMEnforcer()
        seg = tmp_path / "seg.wal"
        seg.write_text("")
        enforcer.seal(str(seg))
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        # Tamper with a segment record
        bundle.segments[0].node_count = 9999
        assert bundle.verify_bundle_hmac(_SIGNING_KEY) is False
        enforcer.unseal_for_testing(str(seg))


# ── WORMEnforcer.attest ───────────────────────────────────────────────────────


class TestWORMEnforcerAttest:
    def _make_sealed_segment(self, tmp_path, name: str, node_count: int = 5) -> tuple:
        path = tmp_path / name
        path.write_text('{"record_type":"audit_node","id":"x"}\n' * node_count)
        enforcer = WORMEnforcer(sealed_by="test-enforcer")
        record = enforcer.seal(str(path), node_count=node_count)
        return str(path), enforcer, record

    def test_attest_returns_bundle(self, tmp_path):
        path, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert isinstance(bundle, WORMAttestationBundle)
        enforcer.unseal_for_testing(path)

    def test_attest_segments_count(self, tmp_path):
        p1, e, _ = self._make_sealed_segment(tmp_path, "a.wal")
        p2 = tmp_path / "b.wal"
        p2.write_text("")
        e.seal(str(p2))
        bundle = e.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert len(bundle.segments) == 2
        e.unseal_for_testing(p1)
        e.unseal_for_testing(str(p2))

    def test_attest_segment_path_is_absolute(self, tmp_path):
        path, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert os.path.isabs(bundle.segments[0].segment_path)
        enforcer.unseal_for_testing(path)

    def test_attest_node_count_matches_seal(self, tmp_path):
        path, enforcer, record = self._make_sealed_segment(tmp_path, "a.wal", node_count=7)
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert bundle.segments[0].node_count == record.node_count
        enforcer.unseal_for_testing(path)

    def test_attest_regulatory_citations_from_policy(self, tmp_path):
        path, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert "SEC Rule 17a-4(b)(1)" in bundle.regulatory_citations
        assert "FINRA Rule 4511" in bundle.regulatory_citations
        enforcer.unseal_for_testing(path)

    def test_attest_bundle_hmac_non_empty(self, tmp_path):
        path, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert len(bundle.bundle_hmac) == 64  # SHA-256 hex = 64 chars
        enforcer.unseal_for_testing(path)

    def test_attest_seal_hmac_non_empty(self, tmp_path):
        path, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert len(bundle.segments[0].seal_hmac) == 64
        enforcer.unseal_for_testing(path)

    def test_attest_different_keys_produce_different_hmacs(self, tmp_path):
        path, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        b1 = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        b2 = enforcer.attest(SEC_17A4_BROKER_DEALER, b"other-key-32-bytes-padded00000000")
        assert b1.bundle_hmac != b2.bundle_hmac
        enforcer.unseal_for_testing(path)

    def test_attest_explicit_segment_paths(self, tmp_path):
        p1, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        p2 = tmp_path / "b.wal"
        p2.write_text("")
        enforcer.seal(str(p2))
        # Attest only the first segment
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY, segment_paths=[p1])
        assert len(bundle.segments) == 1
        assert bundle.segments[0].segment_path == os.path.abspath(p1)
        enforcer.unseal_for_testing(p1)
        enforcer.unseal_for_testing(str(p2))

    def test_attest_status_accessible_for_new_segment(self, tmp_path):
        path, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert bundle.segments[0].status == "ACCESSIBLE"
        enforcer.unseal_for_testing(path)

    def test_attest_status_purge_eligible_for_old_segment(self, tmp_path):
        path, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        old_now = time.time() + 7 * 365.25 * 86400  # pretend it's 7 years later
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY, now=old_now)
        assert bundle.segments[0].status == "PURGE_ELIGIBLE"
        enforcer.unseal_for_testing(path)

    def test_attest_to_json_round_trip(self, tmp_path):
        path, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        parsed = json.loads(bundle.to_json())
        assert parsed["generated_by"] == "test-enforcer"
        assert len(parsed["segments"]) == 1
        assert parsed["segments"][0]["retention_policy"] == "SEC_17A4_BROKER_DEALER"
        enforcer.unseal_for_testing(path)

    def test_attest_bundle_generated_by_matches_enforcer(self, tmp_path):
        path, enforcer, _ = self._make_sealed_segment(tmp_path, "a.wal")
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert bundle.generated_by == "test-enforcer"
        enforcer.unseal_for_testing(path)

    def test_attest_empty_enforcer_produces_empty_bundle(self):
        enforcer = WORMEnforcer()
        bundle = enforcer.attest(SEC_17A4_BROKER_DEALER, _SIGNING_KEY)
        assert bundle.segments == []
        assert len(bundle.bundle_hmac) == 64  # still has a valid bundle HMAC
