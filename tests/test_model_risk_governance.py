# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for SR 11-7 / SOX ICFR model risk governance
(aegis.core.model_risk_governance)."""

from __future__ import annotations

import json
import time
import uuid

import pytest

from aegis.core.model_risk_governance import (
    ModelGovernanceRegistry,
    ModelRecord,
    ModelTier,
    SOXControlPoint,
    SOXControlReport,
    SR117ValidationStatus,
    ValidationRecord,
)

_KEY = b"test-aegis-signing-key-32-padded"
_ALT_KEY = b"other-key-32-bytes-padded0000000"


# ── Enumerations ──────────────────────────────────────────────────────────────


class TestEnums:
    def test_status_values(self):
        assert SR117ValidationStatus.PENDING == "pending"
        assert SR117ValidationStatus.APPROVED == "approved"
        assert SR117ValidationStatus.REJECTED == "rejected"
        assert SR117ValidationStatus.DECOMMISSIONED == "decommissioned"

    def test_tier_values(self):
        assert ModelTier.HIGH == "high"
        assert ModelTier.MEDIUM == "medium"
        assert ModelTier.LOW == "low"

    def test_status_is_str(self):
        assert isinstance(SR117ValidationStatus.APPROVED, str)

    def test_tier_is_str(self):
        assert isinstance(ModelTier.HIGH, str)


# ── ModelGovernanceRegistry.register ─────────────────────────────────────────


class TestRegister:
    def test_register_returns_model_record(self):
        reg = ModelGovernanceRegistry()
        rec = reg.register("m1", owner="team-a", use_case="credit-scoring")
        assert isinstance(rec, ModelRecord)

    def test_register_stores_fields(self):
        reg = ModelGovernanceRegistry()
        rec = reg.register(
            "m1", owner="team-a", use_case="credit-scoring", material=True, tier=ModelTier.HIGH
        )
        assert rec.model_id == "m1"
        assert rec.owner == "team-a"
        assert rec.use_case == "credit-scoring"
        assert rec.material is True
        assert rec.tier == ModelTier.HIGH

    def test_register_default_status_is_pending(self):
        reg = ModelGovernanceRegistry()
        rec = reg.register("m1", owner="o", use_case="u")
        assert rec.validation_status == SR117ValidationStatus.PENDING

    def test_register_default_tier_is_medium(self):
        reg = ModelGovernanceRegistry()
        rec = reg.register("m1", owner="o", use_case="u")
        assert rec.tier == ModelTier.MEDIUM

    def test_register_duplicate_raises(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u")
        with pytest.raises(ValueError, match="already registered"):
            reg.register("m1", owner="o", use_case="u")

    def test_register_now_parameter(self):
        reg = ModelGovernanceRegistry()
        rec = reg.register("m1", owner="o", use_case="u", now=1_000_000.0)
        assert rec.registered_at == 1_000_000.0

    def test_register_is_active(self):
        reg = ModelGovernanceRegistry()
        rec = reg.register("m1", owner="o", use_case="u")
        assert rec.is_active is True

    def test_register_not_deployment_approved(self):
        reg = ModelGovernanceRegistry()
        rec = reg.register("m1", owner="o", use_case="u")
        assert rec.is_deployment_approved is False

    def test_register_adds_control_environment_point(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u")
        assert any(cp.coso_component == "control_environment" for cp in reg.control_points)

    def test_model_ids_sorted(self):
        reg = ModelGovernanceRegistry()
        reg.register("z-model", owner="o", use_case="u")
        reg.register("a-model", owner="o", use_case="u")
        assert reg.model_ids == ["a-model", "z-model"]


# ── ModelGovernanceRegistry.record_validation ─────────────────────────────────


class TestRecordValidation:
    def _reg_with_model(self) -> ModelGovernanceRegistry:
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="team-a", use_case="credit-scoring")
        return reg

    def test_record_validation_returns_validation_record(self):
        reg = self._reg_with_model()
        val = reg.record_validation(
            "m1", "val-team", SR117ValidationStatus.APPROVED, "sha256:abc", _KEY
        )
        assert isinstance(val, ValidationRecord)

    def test_record_validation_id_is_uuid(self):
        reg = self._reg_with_model()
        val = reg.record_validation(
            "m1", "val-team", SR117ValidationStatus.APPROVED, "sha256:abc", _KEY
        )
        uuid.UUID(val.validation_id)

    def test_record_validation_updates_status(self):
        reg = self._reg_with_model()
        reg.record_validation("m1", "val-team", SR117ValidationStatus.APPROVED, "sha256:abc", _KEY)
        assert reg.get_model("m1").validation_status == SR117ValidationStatus.APPROVED

    def test_record_validation_appended_to_history(self):
        reg = self._reg_with_model()
        reg.record_validation("m1", "val-team", SR117ValidationStatus.APPROVED, "sha256:abc", _KEY)
        assert len(reg.get_model("m1").validation_history) == 1

    def test_multiple_validations_accumulate(self):
        reg = self._reg_with_model()
        reg.record_validation("m1", "v1", SR117ValidationStatus.APPROVED, "h1", _KEY)
        reg.record_validation(
            "m1", "v2", SR117ValidationStatus.APPROVED_WITH_CONDITIONS, "h2", _KEY
        )
        assert len(reg.get_model("m1").validation_history) == 2

    def test_record_validation_hmac_set(self):
        reg = self._reg_with_model()
        val = reg.record_validation("m1", "v", SR117ValidationStatus.APPROVED, "h", _KEY)
        assert len(val.record_hmac) == 64

    def test_verify_hmac_valid_key(self):
        reg = self._reg_with_model()
        val = reg.record_validation("m1", "v", SR117ValidationStatus.APPROVED, "h", _KEY)
        assert val.verify_hmac(_KEY) is True

    def test_verify_hmac_wrong_key(self):
        reg = self._reg_with_model()
        val = reg.record_validation("m1", "v", SR117ValidationStatus.APPROVED, "h", _KEY)
        assert val.verify_hmac(_ALT_KEY) is False

    def test_challenger_sets_info_comm_coso(self):
        reg = self._reg_with_model()
        reg.record_validation(
            "m1", "v", SR117ValidationStatus.APPROVED, "h", _KEY, challenger_model_id="challenger-1"
        )
        last_cp = reg.control_points[-1]
        assert last_cp.coso_component == "information_communication"

    def test_no_challenger_sets_risk_assessment_coso(self):
        reg = self._reg_with_model()
        reg.record_validation("m1", "v", SR117ValidationStatus.APPROVED, "h", _KEY)
        last_cp = reg.control_points[-1]
        assert last_cp.coso_component == "risk_assessment"

    def test_rejected_validation_marks_cp_failed(self):
        reg = self._reg_with_model()
        reg.record_validation("m1", "v", SR117ValidationStatus.REJECTED, "h", _KEY)
        last_cp = reg.control_points[-1]
        assert last_cp.passed is False

    def test_notes_truncated_to_500(self):
        reg = self._reg_with_model()
        long_note = "x" * 1000
        val = reg.record_validation(
            "m1", "v", SR117ValidationStatus.APPROVED, "h", _KEY, notes=long_note
        )
        assert len(val.notes) == 500

    def test_unregistered_model_raises(self):
        reg = ModelGovernanceRegistry()
        with pytest.raises(KeyError):
            reg.record_validation("nonexistent", "v", SR117ValidationStatus.APPROVED, "h", _KEY)


# ── ModelGovernanceRegistry.approve_deployment ────────────────────────────────


class TestApproveDeployment:
    def _reg_approved(self) -> ModelGovernanceRegistry:
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="team-a", use_case="credit-scoring")
        reg.record_validation("m1", "v", SR117ValidationStatus.APPROVED, "h", _KEY)
        return reg

    def test_approve_deployment_sets_approved_at(self):
        reg = self._reg_approved()
        reg.approve_deployment("m1", approver="cro")
        assert reg.get_model("m1").deployment_approved_at is not None

    def test_approve_deployment_sets_approver(self):
        reg = self._reg_approved()
        reg.approve_deployment("m1", approver="cro")
        assert reg.get_model("m1").deployment_approver == "cro"

    def test_approve_deployment_is_deployment_approved(self):
        reg = self._reg_approved()
        reg.approve_deployment("m1", approver="cro")
        assert reg.get_model("m1").is_deployment_approved is True

    def test_approve_deployment_now_parameter(self):
        reg = self._reg_approved()
        reg.approve_deployment("m1", approver="cro", now=2_000_000.0)
        assert reg.get_model("m1").deployment_approved_at == 2_000_000.0

    def test_approve_deployment_adds_control_activities_cp(self):
        reg = self._reg_approved()
        reg.approve_deployment("m1", approver="cro")
        assert any(cp.coso_component == "control_activities" for cp in reg.control_points)

    def test_approve_pending_model_raises(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u")
        with pytest.raises(ValueError, match="validated"):
            reg.approve_deployment("m1", approver="cro")

    def test_approve_decommissioned_model_raises(self):
        reg = self._reg_approved()
        reg.decommission("m1")
        with pytest.raises(ValueError, match="decommissioned"):
            reg.approve_deployment("m1", approver="cro")

    def test_approved_with_conditions_allows_deployment(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u")
        reg.record_validation("m1", "v", SR117ValidationStatus.APPROVED_WITH_CONDITIONS, "h", _KEY)
        reg.approve_deployment("m1", approver="cro")
        assert reg.get_model("m1").is_deployment_approved is True


# ── ModelGovernanceRegistry.decommission ──────────────────────────────────────


class TestDecommission:
    def test_decommission_sets_decommissioned_at(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u")
        reg.decommission("m1")
        assert reg.get_model("m1").decommissioned_at is not None

    def test_decommission_sets_status(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u")
        reg.decommission("m1")
        assert reg.get_model("m1").validation_status == SR117ValidationStatus.DECOMMISSIONED

    def test_decommission_is_active_false(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u")
        reg.decommission("m1")
        assert reg.get_model("m1").is_active is False

    def test_decommission_now_parameter(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u")
        reg.decommission("m1", now=3_000_000.0)
        assert reg.get_model("m1").decommissioned_at == 3_000_000.0

    def test_decommission_adds_monitoring_cp(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u")
        reg.decommission("m1", reason="end-of-life")
        assert any(cp.coso_component == "monitoring" for cp in reg.control_points)


# ── SOXControlReport ──────────────────────────────────────────────────────────


class TestSOXControlReport:
    def _full_registry(self) -> ModelGovernanceRegistry:
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="team-a", use_case="credit", material=True)
        reg.record_validation("m1", "v", SR117ValidationStatus.APPROVED, "h", _KEY)
        reg.approve_deployment("m1", approver="cro")
        return reg

    def test_sox_report_returns_sox_control_report(self):
        reg = self._full_registry()
        report = reg.sox_control_report(_KEY)
        assert isinstance(report, SOXControlReport)

    def test_sox_report_id_is_uuid(self):
        reg = self._full_registry()
        report = reg.sox_control_report(_KEY)
        uuid.UUID(report.report_id)

    def test_sox_report_generated_at_recent(self):
        before = time.time()
        reg = self._full_registry()
        report = reg.sox_control_report(_KEY)
        after = time.time()
        assert before <= report.generated_at <= after

    def test_sox_report_overall_effective_true(self):
        reg = self._full_registry()
        report = reg.sox_control_report(_KEY)
        assert report.overall_effective is True

    def test_sox_report_overall_effective_false_pending(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u", material=True)
        report = reg.sox_control_report(_KEY)
        assert report.overall_effective is False

    def test_sox_report_overall_effective_false_not_approved(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u", material=True)
        reg.record_validation("m1", "v", SR117ValidationStatus.APPROVED, "h", _KEY)
        report = reg.sox_control_report(_KEY)
        assert report.overall_effective is False

    def test_sox_report_only_material_models(self):
        reg = ModelGovernanceRegistry()
        reg.register("mat", owner="o", use_case="u", material=True)
        reg.register("nonmat", owner="o", use_case="u", material=False)
        reg.record_validation("mat", "v", SR117ValidationStatus.APPROVED, "h", _KEY)
        reg.approve_deployment("mat", approver="cro")
        report = reg.sox_control_report(_KEY)
        ids = [m["model_id"] for m in report.material_models]
        assert "mat" in ids
        assert "nonmat" not in ids

    def test_sox_report_bundle_hmac_64_char(self):
        reg = self._full_registry()
        report = reg.sox_control_report(_KEY)
        assert len(report.bundle_hmac) == 64

    def test_sox_report_verify_bundle_hmac_valid(self):
        reg = self._full_registry()
        report = reg.sox_control_report(_KEY)
        assert report.verify_bundle_hmac(_KEY) is True

    def test_sox_report_verify_bundle_hmac_wrong_key(self):
        reg = self._full_registry()
        report = reg.sox_control_report(_KEY)
        assert report.verify_bundle_hmac(_ALT_KEY) is False

    def test_sox_report_tampered_fails_hmac(self):
        reg = self._full_registry()
        report = reg.sox_control_report(_KEY)
        report.overall_effective = not report.overall_effective
        assert report.verify_bundle_hmac(_KEY) is False

    def test_sox_report_to_json_valid(self):
        reg = self._full_registry()
        report = reg.sox_control_report(_KEY)
        parsed = json.loads(report.to_json())
        assert isinstance(parsed, dict)
        assert "report_id" in parsed
        assert "control_points" in parsed

    def test_sox_report_control_points_present(self):
        reg = self._full_registry()
        report = reg.sox_control_report(_KEY)
        assert len(report.control_points) >= 3  # register + validate + approve

    def test_sox_report_no_material_models_effective_true(self):
        reg = ModelGovernanceRegistry()
        report = reg.sox_control_report(_KEY)
        assert report.overall_effective is True

    def test_sox_report_rejected_model_not_effective(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u", material=True)
        reg.record_validation("m1", "v", SR117ValidationStatus.REJECTED, "h", _KEY)
        report = reg.sox_control_report(_KEY)
        assert report.overall_effective is False


# ── ModelRecord ───────────────────────────────────────────────────────────────


class TestModelRecord:
    def test_to_dict_contains_all_fields(self):
        reg = ModelGovernanceRegistry()
        rec = reg.register("m1", owner="o", use_case="u")
        d = rec.to_dict()
        for f in [
            "model_id",
            "registered_at",
            "owner",
            "use_case",
            "material",
            "tier",
            "validation_status",
            "validation_history",
            "deployment_approved_at",
            "deployment_approver",
            "decommissioned_at",
            "is_active",
            "is_deployment_approved",
        ]:
            assert f in d

    def test_get_model_raises_for_missing(self):
        reg = ModelGovernanceRegistry()
        with pytest.raises(KeyError):
            reg.get_model("nonexistent")

    def test_control_points_property_returns_copy(self):
        reg = ModelGovernanceRegistry()
        reg.register("m1", owner="o", use_case="u")
        cp_copy = reg.control_points
        cp_copy.clear()
        assert len(reg.control_points) >= 1


# ── SOXControlPoint ───────────────────────────────────────────────────────────


class TestSOXControlPoint:
    def test_to_dict_fields(self):
        cp = SOXControlPoint(
            control_id="AIML-CE-001",
            coso_component="control_environment",
            description="test",
            model_id="m1",
            evidenced_at=1_000_000.0,
            evidence_summary="evidence",
            passed=True,
        )
        d = cp.to_dict()
        assert d["control_id"] == "AIML-CE-001"
        assert d["coso_component"] == "control_environment"
        assert d["passed"] is True
