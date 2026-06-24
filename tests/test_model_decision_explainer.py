# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for Basel-aligned model-decision explainability record keeper
(aegis.core.model_decision_explainer)."""

from __future__ import annotations

import json
import time
import uuid

from aegis.core.model_decision_explainer import (
    DecisionDomain,
    DecisionOutcome,
    DecisionRecord,
    ExplainabilityExport,
    ModelDecisionExplainer,
)

_KEY = b"test-aegis-signing-key-32-padded"
_ALT_KEY = b"other-key-32-bytes-padded0000000"


def _explainer(**kwargs) -> ModelDecisionExplainer:
    defaults = dict(model_id="credit-llm/v1", policy_version="2026-Q2", signing_key=_KEY)
    defaults.update(kwargs)
    return ModelDecisionExplainer(**defaults)


def _record(explainer: ModelDecisionExplainer, **kwargs) -> DecisionRecord:
    defaults = dict(
        session_id="sess-1",
        client_id="client-A",
        input_features={"income_band": "40k-60k", "dti": "0.38"},
        outcome=DecisionOutcome.DENY,
        confidence=0.87,
        principal_reasons=["dti_exceeds_threshold"],
    )
    defaults.update(kwargs)
    return explainer.record(**defaults)


# ── Enumerations ──────────────────────────────────────────────────────────────


class TestEnums:
    def test_outcome_values(self):
        assert DecisionOutcome.APPROVE == "approve"
        assert DecisionOutcome.DENY == "deny"
        assert DecisionOutcome.REFER == "refer"
        assert DecisionOutcome.NOT_APPLICABLE == "not_applicable"

    def test_domain_values(self):
        assert DecisionDomain.CREDIT == "credit"
        assert DecisionDomain.INSURANCE == "insurance"
        assert DecisionDomain.INVESTMENT == "investment"
        assert DecisionDomain.GENERAL == "general"

    def test_enums_are_str(self):
        assert isinstance(DecisionOutcome.APPROVE, str)
        assert isinstance(DecisionDomain.CREDIT, str)


# ── ModelDecisionExplainer.record ─────────────────────────────────────────────


class TestRecord:
    def test_record_returns_decision_record(self):
        exp = _explainer()
        rec = _record(exp)
        assert isinstance(rec, DecisionRecord)

    def test_record_id_is_uuid(self):
        exp = _explainer()
        rec = _record(exp)
        uuid.UUID(rec.record_id)

    def test_recorded_at_is_recent(self):
        before = time.time()
        exp = _explainer()
        rec = _record(exp)
        after = time.time()
        assert before <= rec.recorded_at <= after

    def test_now_parameter(self):
        exp = _explainer()
        rec = _record(exp, now=1_000_000.0)
        assert rec.recorded_at == 1_000_000.0

    def test_session_id_stored(self):
        exp = _explainer()
        rec = _record(exp, session_id="sess-xyz")
        assert rec.session_id == "sess-xyz"

    def test_client_id_stored(self):
        exp = _explainer()
        rec = _record(exp, client_id="client-B")
        assert rec.client_id == "client-B"

    def test_model_id_stored(self):
        exp = _explainer(model_id="model-v2")
        rec = _record(exp)
        assert rec.model_id == "model-v2"

    def test_policy_version_stored(self):
        exp = _explainer(policy_version="v3")
        rec = _record(exp)
        assert rec.policy_version == "v3"

    def test_outcome_stored(self):
        exp = _explainer()
        rec = _record(exp, outcome=DecisionOutcome.APPROVE)
        assert rec.outcome == DecisionOutcome.APPROVE

    def test_confidence_stored(self):
        exp = _explainer()
        rec = _record(exp, confidence=0.75)
        assert abs(rec.confidence - 0.75) < 1e-9

    def test_confidence_clamped_above(self):
        exp = _explainer()
        rec = _record(exp, confidence=2.5)
        assert rec.confidence == 1.0

    def test_confidence_clamped_below(self):
        exp = _explainer()
        rec = _record(exp, confidence=-0.1)
        assert rec.confidence == 0.0

    def test_principal_reasons_stored(self):
        exp = _explainer()
        rec = _record(exp, principal_reasons=["r1", "r2"])
        assert rec.principal_reasons == ["r1", "r2"]

    def test_principal_reasons_truncated_to_5(self):
        exp = _explainer()
        reasons = [f"r{i}" for i in range(10)]
        rec = _record(exp, principal_reasons=reasons)
        assert len(rec.principal_reasons) == 5

    def test_counterfactual_hint_stored(self):
        exp = _explainer()
        rec = _record(exp, counterfactual_hint="Reduce DTI by 5%")
        assert rec.counterfactual_hint == "Reduce DTI by 5%"

    def test_counterfactual_hint_truncated(self):
        exp = _explainer()
        long_hint = "x" * 1000
        rec = _record(exp, counterfactual_hint=long_hint)
        assert len(rec.counterfactual_hint) == 500

    def test_input_features_hashed(self):
        exp = _explainer()
        rec = _record(exp, input_features={"income": "50000"})
        assert len(rec.input_feature_hashes) == 1
        assert len(rec.input_feature_hashes[0]) == 64  # SHA-256 hex

    def test_raw_values_not_in_record(self):
        exp = _explainer()
        rec = _record(exp, input_features={"income": "50000_secret"})
        d = rec.to_dict()
        canonical = json.dumps(d)
        assert "50000_secret" not in canonical

    def test_domain_default_general(self):
        exp = _explainer()
        rec = _record(exp)
        assert rec.domain == DecisionDomain.GENERAL

    def test_domain_from_explainer(self):
        exp = _explainer(domain=DecisionDomain.CREDIT)
        rec = _record(exp)
        assert rec.domain == DecisionDomain.CREDIT

    def test_domain_override_per_record(self):
        exp = _explainer(domain=DecisionDomain.CREDIT)
        rec = _record(exp, domain=DecisionDomain.INSURANCE)
        assert rec.domain == DecisionDomain.INSURANCE

    def test_records_accumulate(self):
        exp = _explainer()
        _record(exp, session_id="s1")
        _record(exp, session_id="s2")
        assert len(exp.records) == 2

    def test_records_property_copy(self):
        exp = _explainer()
        _record(exp)
        r = exp.records
        r.clear()
        assert len(exp.records) == 1


# ── HMAC signing ──────────────────────────────────────────────────────────────


class TestHMACRecord:
    def test_signed_record_has_hmac(self):
        exp = _explainer(signing_key=_KEY)
        rec = _record(exp)
        assert len(rec.record_hmac) == 64

    def test_verify_hmac_valid(self):
        exp = _explainer(signing_key=_KEY)
        rec = _record(exp)
        assert rec.verify_hmac(_KEY) is True

    def test_verify_hmac_wrong_key(self):
        exp = _explainer(signing_key=_KEY)
        rec = _record(exp)
        assert rec.verify_hmac(_ALT_KEY) is False

    def test_verify_hmac_no_signing_key(self):
        exp = _explainer(signing_key=None)
        rec = _record(exp)
        assert rec.record_hmac == ""
        assert rec.verify_hmac(_KEY) is False

    def test_per_record_signing_key_override(self):
        exp = _explainer(signing_key=None)
        rec = _record(exp, signing_key=_KEY)
        assert len(rec.record_hmac) == 64
        assert rec.verify_hmac(_KEY) is True


# ── DecisionRecord properties ─────────────────────────────────────────────────


class TestDecisionRecordProperties:
    def test_requires_adverse_action_notice_deny_credit(self):
        exp = _explainer(domain=DecisionDomain.CREDIT)
        rec = _record(exp, outcome=DecisionOutcome.DENY)
        assert rec.requires_adverse_action_notice is True

    def test_no_adverse_notice_approve_credit(self):
        exp = _explainer(domain=DecisionDomain.CREDIT)
        rec = _record(exp, outcome=DecisionOutcome.APPROVE)
        assert rec.requires_adverse_action_notice is False

    def test_no_adverse_notice_deny_non_credit(self):
        exp = _explainer(domain=DecisionDomain.INSURANCE)
        rec = _record(exp, outcome=DecisionOutcome.DENY, domain=DecisionDomain.INSURANCE)
        assert rec.requires_adverse_action_notice is False

    def test_to_dict_contains_all_fields(self):
        exp = _explainer()
        rec = _record(exp)
        d = rec.to_dict()
        for f in [
            "record_id",
            "recorded_at",
            "session_id",
            "client_id",
            "model_id",
            "policy_version",
            "domain",
            "outcome",
            "confidence",
            "principal_reasons",
            "counterfactual_hint",
            "input_feature_hashes",
            "record_hmac",
        ]:
            assert f in d

    def test_to_json_valid(self):
        exp = _explainer()
        rec = _record(exp)
        parsed = json.loads(rec.to_json())
        assert isinstance(parsed, dict)
        assert "record_id" in parsed


# ── ExplainabilityExport ──────────────────────────────────────────────────────


class TestExplainabilityExport:
    def _filled_explainer(self, n: int = 3) -> ModelDecisionExplainer:
        exp = _explainer()
        for i in range(n):
            _record(exp, session_id=f"s{i}")
        return exp

    def test_export_returns_explainability_export(self):
        exp = self._filled_explainer()
        ex = exp.export()
        assert isinstance(ex, ExplainabilityExport)

    def test_export_id_is_uuid(self):
        exp = self._filled_explainer()
        ex = exp.export()
        uuid.UUID(ex.export_id)

    def test_export_generated_at_recent(self):
        before = time.time()
        exp = self._filled_explainer()
        ex = exp.export()
        after = time.time()
        assert before <= ex.generated_at <= after

    def test_export_record_count(self):
        exp = self._filled_explainer(4)
        ex = exp.export()
        assert ex.record_count == 4
        assert len(ex.records) == 4

    def test_export_model_id(self):
        exp = _explainer(model_id="my-model")
        _record(exp)
        ex = exp.export()
        assert ex.model_id == "my-model"

    def test_export_policy_version(self):
        exp = _explainer(policy_version="v9")
        _record(exp)
        ex = exp.export()
        assert ex.policy_version == "v9"

    def test_export_bundle_hmac_64_char(self):
        exp = self._filled_explainer()
        ex = exp.export(_KEY)
        assert len(ex.bundle_hmac) == 64

    def test_export_verify_bundle_hmac_valid(self):
        exp = self._filled_explainer()
        ex = exp.export(_KEY)
        assert ex.verify_bundle_hmac(_KEY) is True

    def test_export_verify_bundle_hmac_wrong_key(self):
        exp = self._filled_explainer()
        ex = exp.export(_KEY)
        assert ex.verify_bundle_hmac(_ALT_KEY) is False

    def test_tampered_record_fails_bundle_hmac(self):
        exp = self._filled_explainer()
        ex = exp.export(_KEY)
        ex.records[0].confidence = 0.0
        assert ex.verify_bundle_hmac(_KEY) is False

    def test_export_empty_explainer(self):
        exp = _explainer()
        ex = exp.export(_KEY)
        assert ex.records == []
        assert ex.record_count == 0
        assert len(ex.bundle_hmac) == 64

    def test_export_no_signing_key_no_bundle_hmac(self):
        exp = _explainer(signing_key=None)
        _record(exp)
        ex = exp.export()
        assert ex.bundle_hmac == ""

    def test_export_explicit_records(self):
        exp = self._filled_explainer(5)
        subset = exp.records[:2]
        ex = exp.export(_KEY, records=subset)
        assert len(ex.records) == 2
        assert ex.record_count == 2

    def test_export_to_json_round_trip(self):
        exp = self._filled_explainer(2)
        ex = exp.export(_KEY)
        parsed = json.loads(ex.to_json())
        assert isinstance(parsed, dict)
        assert "export_id" in parsed
        assert len(parsed["records"]) == 2

    def test_different_keys_different_bundle_hmac(self):
        exp = self._filled_explainer()
        ex1 = exp.export(_KEY)
        ex2 = exp.export(_ALT_KEY)
        assert ex1.bundle_hmac != ex2.bundle_hmac

    def test_export_now_parameter(self):
        exp = self._filled_explainer()
        ex = exp.export(_KEY, now=5_000_000.0)
        assert ex.generated_at == 5_000_000.0
