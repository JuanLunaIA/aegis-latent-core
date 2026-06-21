# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for PII confidence scoring per response (aegis.core.pii_confidence)."""

from __future__ import annotations

import pytest

from aegis.core.pii_confidence import (
    PIIAction,
    PIIConfidenceFilter,
    PIIConfidenceResult,
    PIIConfidenceThreshold,
)

# ── PIIConfidenceThreshold ────────────────────────────────────────────────────


class TestPIIConfidenceThreshold:
    def test_defaults(self):
        t = PIIConfidenceThreshold()
        assert t.block == 0.95
        assert t.flag == 0.80

    def test_custom(self):
        t = PIIConfidenceThreshold(block=0.90, flag=0.70)
        assert t.block == 0.90
        assert t.flag == 0.70

    def test_block_out_of_range_raises(self):
        with pytest.raises(ValueError, match="block"):
            PIIConfidenceThreshold(block=1.5, flag=0.80)

    def test_flag_out_of_range_raises(self):
        with pytest.raises(ValueError, match="flag"):
            PIIConfidenceThreshold(block=0.95, flag=-0.1)

    def test_flag_exceeds_block_raises(self):
        with pytest.raises(ValueError, match="flag threshold"):
            PIIConfidenceThreshold(block=0.70, flag=0.80)

    def test_equal_thresholds_allowed(self):
        t = PIIConfidenceThreshold(block=0.80, flag=0.80)
        assert t.block == t.flag

    def test_frozen(self):
        from dataclasses import FrozenInstanceError

        t = PIIConfidenceThreshold()
        with pytest.raises(FrozenInstanceError):
            t.block = 0.5  # type: ignore[misc]


# ── PIIConfidenceResult ───────────────────────────────────────────────────────


class TestPIIConfidenceResult:
    def _result(self, action: PIIAction, confidence: float = 0.99) -> PIIConfidenceResult:
        return PIIConfidenceResult(
            text="sample",
            action=action,
            max_confidence=confidence,
            triggered_label="SSN",
        )

    def test_blocked_property(self):
        assert self._result(PIIAction.BLOCK).blocked is True
        assert self._result(PIIAction.FLAG).blocked is False
        assert self._result(PIIAction.LOG).blocked is False

    def test_flagged_property(self):
        assert self._result(PIIAction.FLAG).flagged is True
        assert self._result(PIIAction.BLOCK).flagged is False

    def test_to_dict_contains_action(self):
        d = self._result(PIIAction.BLOCK).to_dict()
        assert d["action"] == "block"
        assert d["max_confidence"] == 0.99
        assert d["triggered_label"] == "SSN"

    def test_to_dict_no_text(self):
        d = self._result(PIIAction.LOG).to_dict()
        assert "text" not in d


# ── PIIConfidenceFilter: empty / no PII ──────────────────────────────────────


class TestPIIConfidenceFilterNoPII:
    def test_empty_text_logs(self):
        f = PIIConfidenceFilter()
        r = f.evaluate("")
        assert r.action is PIIAction.LOG
        assert r.max_confidence == 0.0
        assert r.triggered_label == ""

    def test_plain_text_no_pii_logs(self):
        f = PIIConfidenceFilter()
        r = f.evaluate("The weather today is sunny and warm.")
        assert r.action is PIIAction.LOG
        assert r.max_confidence == 0.0
        assert not r.entity_hits

    def test_no_pii_reason_mentions_not_detected(self):
        r = PIIConfidenceFilter().evaluate("Hello world")
        assert "no PII" in r.reason


# ── PIIConfidenceFilter: BLOCK path ──────────────────────────────────────────


class TestPIIConfidenceFilterBlock:
    def test_ssn_triggers_block(self):
        # SSN confidence = 0.99 ≥ default block threshold 0.95
        f = PIIConfidenceFilter()
        r = f.evaluate("Patient SSN: 123-45-6789")
        assert r.action is PIIAction.BLOCK
        assert r.triggered_label == "SSN"
        assert r.max_confidence == 0.99

    def test_email_triggers_block(self):
        # EMAIL confidence = 0.99 ≥ 0.95
        f = PIIConfidenceFilter()
        r = f.evaluate("Contact alice@example.com for details.")
        assert r.action is PIIAction.BLOCK

    def test_url_triggers_block(self):
        # URL confidence = 0.98 ≥ 0.95
        f = PIIConfidenceFilter()
        r = f.evaluate("Visit https://example.com/secret-path for info.")
        assert r.action is PIIAction.BLOCK

    def test_blocked_result_has_entity_scores(self):
        r = PIIConfidenceFilter().evaluate("SSN: 123-45-6789")
        assert "SSN" in r.entity_scores
        assert "SSN" in r.entity_hits
        assert r.entity_hits["SSN"] >= 1

    def test_block_reason_mentions_threshold(self):
        r = PIIConfidenceFilter().evaluate("email: bob@corp.com")
        assert "block threshold" in r.reason
        assert "EMAIL" in r.reason

    def test_block_property_true(self):
        r = PIIConfidenceFilter().evaluate("SSN 123-45-6789")
        assert r.blocked is True

    def test_to_dict_action_is_block(self):
        r = PIIConfidenceFilter().evaluate("user@test.org")
        assert r.to_dict()["action"] == "block"


# ── PIIConfidenceFilter: FLAG path ───────────────────────────────────────────


class TestPIIConfidenceFilterFlag:
    def _flag_threshold_filter(self) -> PIIConfidenceFilter:
        # Raise block threshold above any entity confidence so FLAG is reachable
        return PIIConfidenceFilter(threshold=PIIConfidenceThreshold(block=1.0, flag=0.80))

    def test_date_triggers_flag_with_high_block_threshold(self):
        # DATE confidence = 0.88, between flag=0.80 and block=1.0
        f = self._flag_threshold_filter()
        r = f.evaluate("Patient DOB 1990-01-23")
        assert r.action is PIIAction.FLAG
        assert r.triggered_label == "DATE"

    def test_name_triggers_flag_with_high_block_threshold(self):
        # NAME confidence = 0.80, exactly at flag threshold
        f = PIIConfidenceFilter(threshold=PIIConfidenceThreshold(block=1.0, flag=0.80))
        r = f.evaluate("Dr. John Smith was admitted.")
        assert r.action is PIIAction.FLAG

    def test_flag_reason_mentions_flag_threshold(self):
        f = self._flag_threshold_filter()
        r = f.evaluate("DOB: 2000-06-15")
        assert "flag threshold" in r.reason

    def test_flagged_property_true(self):
        f = self._flag_threshold_filter()
        r = f.evaluate("Birthday: January 5, 1985")
        assert r.flagged is True


# ── PIIConfidenceFilter: LOG path ─────────────────────────────────────────────


class TestPIIConfidenceFilterLog:
    def test_zip_below_flag_threshold_logs(self):
        # ZIP confidence = 0.75, below default flag=0.80
        f = PIIConfidenceFilter()
        # Use text that only matches ZIP (no SSN/email/URL)
        r = f.evaluate("The office is at ZIP 90210.")
        # ZIP (0.75) < flag threshold (0.80) → LOG
        assert r.action is PIIAction.LOG

    def test_log_reason_mentions_below_flag(self):
        f = PIIConfidenceFilter()
        r = f.evaluate("ZIP code 12345 applies.")
        if r.triggered_label == "ZIP":
            assert "below flag threshold" in r.reason

    def test_low_threshold_logs_all(self):
        # Set both thresholds to 1.0 → nothing can BLOCK or FLAG
        f = PIIConfidenceFilter(threshold=PIIConfidenceThreshold(block=1.0, flag=1.0))
        r = f.evaluate("SSN: 123-45-6789 and email alice@example.com")
        assert r.action is PIIAction.LOG


# ── PIIConfidenceFilter: custom thresholds ───────────────────────────────────


class TestCustomThresholds:
    def test_custom_block_threshold_lower_catches_address(self):
        # ADDRESS confidence = 0.85; set block=0.82 → BLOCK
        f = PIIConfidenceFilter(threshold=PIIConfidenceThreshold(block=0.82, flag=0.70))
        r = f.evaluate("Patient lives at 123 Main Street")
        assert r.action is PIIAction.BLOCK

    def test_custom_flag_threshold_catches_vin(self):
        # VIN confidence = 0.80; set flag=0.75, block=0.95 → FLAG
        f = PIIConfidenceFilter(threshold=PIIConfidenceThreshold(block=0.95, flag=0.75))
        r = f.evaluate("VIN: 1HGBH41JXMN109186")
        # VIN 0.80 ≥ flag 0.75 and < block 0.95 → FLAG
        assert r.action is PIIAction.FLAG

    def test_highest_confidence_wins_among_multiple_entities(self):
        # Both SSN (0.99) and DATE (0.88) present — SSN should trigger
        f = PIIConfidenceFilter()
        r = f.evaluate("SSN 123-45-6789, DOB 1990-01-01")
        assert r.triggered_label == "SSN"
        assert r.max_confidence == 0.99

    def test_multiple_entities_all_in_scores(self):
        f = PIIConfidenceFilter()
        r = f.evaluate("email alice@example.com and phone 555-123-4567")
        assert "EMAIL" in r.entity_scores
        assert "PHONE" in r.entity_scores


# ── PIIConfidenceFilter.from_config ──────────────────────────────────────────


class TestFromConfig:
    def test_from_config_uses_defaults_when_no_env(self, monkeypatch):
        monkeypatch.delenv("AEGIS_PII_BLOCK_THRESHOLD", raising=False)
        monkeypatch.delenv("AEGIS_PII_FLAG_THRESHOLD", raising=False)
        f = PIIConfidenceFilter.from_config()
        assert f._threshold.block == 0.95
        assert f._threshold.flag == 0.80

    def test_from_config_reads_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_PII_BLOCK_THRESHOLD", "0.98")
        monkeypatch.setenv("AEGIS_PII_FLAG_THRESHOLD", "0.85")
        f = PIIConfidenceFilter.from_config()
        assert f._threshold.block == 0.98
        assert f._threshold.flag == 0.85

    def test_from_config_returns_filter_instance(self):
        f = PIIConfidenceFilter.from_config()
        assert isinstance(f, PIIConfidenceFilter)


# ── evaluate_messages ─────────────────────────────────────────────────────────


class TestEvaluateMessages:
    def test_each_message_evaluated(self):
        f = PIIConfidenceFilter()
        msgs = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "SSN: 123-45-6789"},
        ]
        results = f.evaluate_messages(msgs)
        assert len(results) == 2
        assert results[0].action is PIIAction.LOG
        assert results[1].action is PIIAction.BLOCK

    def test_non_string_content_logs(self):
        f = PIIConfidenceFilter()
        msgs = [{"role": "tool", "content": None}]
        results = f.evaluate_messages(msgs)
        assert results[0].action is PIIAction.LOG

    def test_missing_content_key_logs(self):
        f = PIIConfidenceFilter()
        msgs = [{"role": "system"}]
        results = f.evaluate_messages(msgs)
        assert results[0].action is PIIAction.LOG

    def test_empty_messages_list(self):
        f = PIIConfidenceFilter()
        assert f.evaluate_messages([]) == []


# ── worst_case ────────────────────────────────────────────────────────────────


class TestWorstCase:
    def _r(self, action: PIIAction) -> PIIConfidenceResult:
        return PIIConfidenceResult(text="", action=action, max_confidence=0.5)

    def test_block_dominates_flag_and_log(self):
        results = [self._r(PIIAction.LOG), self._r(PIIAction.FLAG), self._r(PIIAction.BLOCK)]
        assert PIIConfidenceFilter().worst_case(results).action is PIIAction.BLOCK

    def test_flag_dominates_log(self):
        results = [self._r(PIIAction.LOG), self._r(PIIAction.FLAG)]
        assert PIIConfidenceFilter().worst_case(results).action is PIIAction.FLAG

    def test_all_log_returns_log(self):
        results = [self._r(PIIAction.LOG), self._r(PIIAction.LOG)]
        assert PIIConfidenceFilter().worst_case(results).action is PIIAction.LOG


# ── Integration: full pipeline scenario ──────────────────────────────────────


class TestIntegrationScenarios:
    def test_clinical_note_blocked(self):
        """A clinical note containing SSN and email is BLOCKED."""
        note = (
            "Patient: Dr. Jane Smith, SSN: 987-65-4321, "
            "email: jane.smith@hospital.org, DOB: 1975-03-22"
        )
        r = PIIConfidenceFilter().evaluate(note)
        assert r.blocked

    def test_anonymized_summary_passes(self):
        """A summary with no PII passes through as LOG."""
        summary = (
            "The model provided a response indicating that the requested "
            "diagnostic procedure carries a standard risk profile."
        )
        r = PIIConfidenceFilter().evaluate(summary)
        assert r.action is PIIAction.LOG
        assert r.max_confidence == 0.0

    def test_multi_message_response_worst_case(self):
        """Full multi-message evaluation with worst-case aggregation."""
        f = PIIConfidenceFilter()
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "assistant", "content": "The patient report looks good."},
            {"role": "assistant", "content": "Please contact jane@example.com for follow-up."},
        ]
        results = f.evaluate_messages(messages)
        worst = f.worst_case(results)
        assert worst.action is PIIAction.BLOCK  # email triggers block
        assert worst.triggered_label == "EMAIL"
