# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for PHI de-identification audit trail (ScrubAuditRecord, scrub_with_audit)."""

from __future__ import annotations

from aegis.core.phi_deidentifier import PHIDeidentifier, ScrubAuditRecord, ScrubResult


class TestScrubAuditRecord:
    def test_to_dict_has_required_keys(self):
        record = ScrubAuditRecord(
            timestamp_iso="2026-06-20T00:00:00+00:00",
            entity_hits={"SSN": 1},
            confidence_scores={"SSN": 0.99},
            method="safe_harbor_regex",
            total_redactions=1,
        )
        d = record.to_dict()
        assert "timestamp_iso" in d
        assert "entity_hits" in d
        assert "confidence_scores" in d
        assert "method" in d
        assert "total_redactions" in d

    def test_to_dict_values_preserved(self):
        record = ScrubAuditRecord(
            timestamp_iso="2026-06-20T12:00:00+00:00",
            entity_hits={"EMAIL": 2},
            confidence_scores={"EMAIL": 0.99},
            total_redactions=2,
        )
        d = record.to_dict()
        assert d["entity_hits"] == {"EMAIL": 2}
        assert d["confidence_scores"] == {"EMAIL": 0.99}
        assert d["total_redactions"] == 2

    def test_default_method(self):
        record = ScrubAuditRecord(timestamp_iso="ts")
        assert record.method == "safe_harbor_regex"


class TestScrubWithAudit:
    def _scrubber(self) -> PHIDeidentifier:
        return PHIDeidentifier()

    def test_returns_tuple_of_correct_types(self):
        s = self._scrubber()
        result, audit = s.scrub_with_audit("call me at 555-123-4567")
        assert isinstance(result, ScrubResult)
        assert isinstance(audit, ScrubAuditRecord)

    def test_scrub_result_unchanged_behavior(self):
        s = self._scrubber()
        result, _ = s.scrub_with_audit("email me at bob@example.com")
        assert "[REDACTED:EMAIL]" in result.text
        assert result.hits["EMAIL"] >= 1

    def test_audit_entity_hits_match_scrub_hits(self):
        s = self._scrubber()
        result, audit = s.scrub_with_audit("SSN: 123-45-6789 and phone 555-987-6543")
        assert audit.entity_hits == result.hits

    def test_audit_timestamp_is_utc_iso(self):
        s = self._scrubber()
        _, audit = s.scrub_with_audit("test")
        assert "T" in audit.timestamp_iso
        assert "+00:00" in audit.timestamp_iso

    def test_confidence_scores_populated_for_each_hit(self):
        s = self._scrubber()
        _, audit = s.scrub_with_audit("SSN: 123-45-6789 and email test@example.com")
        for label in audit.entity_hits:
            assert label in audit.confidence_scores
            assert 0.0 < audit.confidence_scores[label] <= 1.0

    def test_ssn_confidence_high(self):
        s = self._scrubber()
        _, audit = s.scrub_with_audit("SSN: 123-45-6789")
        assert audit.confidence_scores.get("SSN", 0) >= 0.95

    def test_zip_confidence_lower_than_ssn(self):
        s = self._scrubber()
        _, audit_ssn = s.scrub_with_audit("SSN: 123-45-6789")
        _, audit_zip = s.scrub_with_audit("ZIP code 90210")
        ssn_conf = audit_ssn.confidence_scores.get("SSN", 0)
        zip_conf = audit_zip.confidence_scores.get("ZIP", 0)
        assert ssn_conf > zip_conf

    def test_total_redactions_matches(self):
        s = self._scrubber()
        _, audit = s.scrub_with_audit("SSN: 123-45-6789 email test@example.com")
        assert audit.total_redactions == sum(audit.entity_hits.values())

    def test_no_phi_empty_audit(self):
        s = self._scrubber()
        result, audit = s.scrub_with_audit("hello world no PHI here")
        assert audit.entity_hits == {}
        assert audit.confidence_scores == {}
        assert audit.total_redactions == 0
        assert result.text == "hello world no PHI here"

    def test_empty_text(self):
        s = self._scrubber()
        result, audit = s.scrub_with_audit("")
        assert result.text == ""
        assert audit.entity_hits == {}
        assert audit.total_redactions == 0

    def test_audit_method_matches(self):
        s = self._scrubber()
        result, audit = s.scrub_with_audit("test")
        assert audit.method == result.method == "safe_harbor_regex"

    def test_multiple_categories_all_scored(self):
        s = self._scrubber()
        text = "call 555-123-4567 or email alice@example.com ZIP 12345"
        _, audit = s.scrub_with_audit(text)
        for label in audit.entity_hits:
            assert label in audit.confidence_scores

    def test_audit_record_contains_no_phi_values(self):
        """The audit record metadata must not contain the actual redacted value."""
        s = self._scrubber()
        ssn_value = "123-45-6789"  # noqa: S105
        _, audit = s.scrub_with_audit(f"SSN: {ssn_value}")
        serialized = str(audit.to_dict())
        assert ssn_value not in serialized

    def test_to_dict_is_json_serializable(self):
        import json

        s = self._scrubber()
        _, audit = s.scrub_with_audit("SSN: 123-45-6789")
        json.dumps(audit.to_dict())  # must not raise
