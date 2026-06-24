# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for GxP computerised-system qualification hooks
(aegis.core.gxp_qualification)."""

from __future__ import annotations

import json

import pytest

from aegis.core.gxp_qualification import (
    AcceptanceCriterion,
    ChangeControlRegistry,
    ChangeRecord,
    ChangeRisk,
    ChangeStatus,
    DeploymentDecision,
    DeploymentGate,
    PerformanceQualification,
    QualificationStatus,
    RequirementTraceMatrix,
    RTMCoverage,
    TraceLink,
    VendorQualificationPackage,
    build_vendor_qualification_package,
    new_performance_qualification,
)

_KEY = b"test-aegis-signing-key-32-padded"
_ALT_KEY = b"other-key-32-bytes-padded0000000"


# ── Enumerations ──────────────────────────────────────────────────────────────


class TestEnums:
    def test_change_status_values(self):
        assert ChangeStatus.APPROVED == "approved"
        assert ChangeStatus.REJECTED == "rejected"
        assert ChangeStatus.SUBMITTED == "submitted"

    def test_change_risk_values(self):
        assert ChangeRisk.HIGH == "high"
        assert ChangeRisk.LOW == "low"

    def test_qualification_status_values(self):
        assert QualificationStatus.PASSED == "passed"
        assert QualificationStatus.FAILED == "failed"
        assert QualificationStatus.PENDING == "pending"

    def test_enums_are_str(self):
        assert isinstance(ChangeStatus.APPROVED, str)
        assert isinstance(QualificationStatus.PASSED, str)


# ── Change control ────────────────────────────────────────────────────────────


def _submit(cc: ChangeControlRegistry, **kwargs) -> ChangeRecord:
    defaults = dict(
        title="Upgrade WAF",
        description="Add new rules",
        target_version="2.5.0",
        requested_by="qa-lead",
    )
    defaults.update(kwargs)
    return cc.submit_change(**defaults)


class TestChangeControl:
    def test_submit_returns_change_record(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc)
        assert isinstance(rec, ChangeRecord)
        assert rec.status == ChangeStatus.SUBMITTED

    def test_submit_assigns_uuid(self):
        cc = ChangeControlRegistry()
        import uuid

        rec = _submit(cc)
        uuid.UUID(rec.change_id)

    def test_submit_stores_fields(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc, title="T", target_version="3.0.0", gxp_impact=True)
        assert rec.title == "T"
        assert rec.target_version == "3.0.0"
        assert rec.gxp_impact is True

    def test_description_truncated(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc, description="x" * 5000)
        assert len(rec.description) == 2000

    def test_approve_sets_approved_status(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc)
        cc.approve(rec.change_id, approver="qa-manager", signing_key=_KEY)
        assert rec.status == ChangeStatus.APPROVED
        assert rec.is_approved is True
        assert rec.approved_by == "qa-manager"
        assert rec.approved_at is not None

    def test_approve_signs_record(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc)
        cc.approve(rec.change_id, approver="qa-manager", signing_key=_KEY)
        assert len(rec.record_hmac) == 64
        assert rec.verify_hmac(_KEY) is True

    def test_approve_hmac_wrong_key(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc)
        cc.approve(rec.change_id, approver="qa-manager", signing_key=_KEY)
        assert rec.verify_hmac(_ALT_KEY) is False

    def test_unapproved_verify_hmac_false(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc)
        assert rec.verify_hmac(_KEY) is False

    def test_approve_segregation_of_duties(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc, requested_by="alice")
        with pytest.raises(ValueError, match="segregation of duties"):
            cc.approve(rec.change_id, approver="alice", signing_key=_KEY)

    def test_approve_rejected_change_fails(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc)
        cc.reject(rec.change_id, approver="qa-manager", reason="incomplete")
        with pytest.raises(ValueError, match="rejected"):
            cc.approve(rec.change_id, approver="qa-manager", signing_key=_KEY)

    def test_approve_unknown_change_raises(self):
        cc = ChangeControlRegistry()
        with pytest.raises(KeyError):
            cc.approve("nonexistent", approver="x", signing_key=_KEY)

    def test_reject_sets_rejected_status(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc)
        cc.reject(rec.change_id, approver="qa-manager", reason="bad")
        assert rec.status == ChangeStatus.REJECTED
        assert rec.rejected_reason == "bad"

    def test_reject_approved_change_fails(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc)
        cc.approve(rec.change_id, approver="qa-manager", signing_key=_KEY)
        with pytest.raises(ValueError, match="already-approved"):
            cc.reject(rec.change_id, approver="qa-manager", reason="late")

    def test_reject_reason_truncated(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc)
        cc.reject(rec.change_id, approver="m", reason="x" * 2000)
        assert len(rec.rejected_reason) == 1000

    def test_get_returns_record(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc)
        assert cc.get(rec.change_id) is rec

    def test_get_unknown_returns_none(self):
        cc = ChangeControlRegistry()
        assert cc.get("nope") is None

    def test_records_property(self):
        cc = ChangeControlRegistry()
        _submit(cc)
        _submit(cc)
        assert len(cc.records) == 2

    def test_approved_changes_for_version(self):
        cc = ChangeControlRegistry()
        r1 = _submit(cc, target_version="2.5.0")
        r2 = _submit(cc, target_version="2.5.0")
        _submit(cc, target_version="2.6.0")
        cc.approve(r1.change_id, approver="m", signing_key=_KEY)
        cc.approve(r2.change_id, approver="m", signing_key=_KEY)
        approved = cc.approved_changes_for("2.5.0")
        assert len(approved) == 2

    def test_approved_changes_excludes_unapproved(self):
        cc = ChangeControlRegistry()
        _submit(cc, target_version="2.5.0")  # submitted, not approved
        assert cc.approved_changes_for("2.5.0") == []


# ── Deployment gate ───────────────────────────────────────────────────────────


class TestDeploymentGate:
    def test_authorized_with_approved_change(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc, target_version="2.5.0")
        cc.approve(rec.change_id, approver="m", signing_key=_KEY)
        gate = DeploymentGate(cc)
        decision = gate.authorize_deploy("2.5.0")
        assert isinstance(decision, DeploymentDecision)
        assert decision.authorized is True
        assert rec.change_id in decision.approved_change_ids

    def test_denied_without_approved_change(self):
        cc = ChangeControlRegistry()
        _submit(cc, target_version="2.5.0")  # not approved
        gate = DeploymentGate(cc)
        decision = gate.authorize_deploy("2.5.0")
        assert decision.authorized is False
        assert "no approved change" in decision.reason

    def test_denied_for_unknown_version(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc, target_version="2.5.0")
        cc.approve(rec.change_id, approver="m", signing_key=_KEY)
        gate = DeploymentGate(cc)
        decision = gate.authorize_deploy("9.9.9")
        assert decision.authorized is False

    def test_fail_closed_on_no_changes_at_all(self):
        cc = ChangeControlRegistry()
        gate = DeploymentGate(cc)
        decision = gate.authorize_deploy("2.5.0")
        assert decision.authorized is False

    def test_signature_verification_passes(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc, target_version="2.5.0")
        cc.approve(rec.change_id, approver="m", signing_key=_KEY)
        gate = DeploymentGate(cc, require_signing_key=_KEY)
        decision = gate.authorize_deploy("2.5.0")
        assert decision.authorized is True

    def test_tampered_approval_denied(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc, target_version="2.5.0")
        cc.approve(rec.change_id, approver="m", signing_key=_KEY)
        rec.title = "tampered after approval"  # invalidates HMAC
        gate = DeploymentGate(cc, require_signing_key=_KEY)
        decision = gate.authorize_deploy("2.5.0")
        assert decision.authorized is False
        assert "signature invalid" in decision.reason

    def test_decision_to_dict(self):
        cc = ChangeControlRegistry()
        rec = _submit(cc, target_version="2.5.0")
        cc.approve(rec.change_id, approver="m", signing_key=_KEY)
        gate = DeploymentGate(cc)
        d = gate.authorize_deploy("2.5.0").to_dict()
        assert d["authorized"] is True
        assert d["version"] == "2.5.0"


# ── RTM ───────────────────────────────────────────────────────────────────────


class TestRTM:
    def test_add_requirement(self):
        rtm = RequirementTraceMatrix()
        link = rtm.add_requirement("URS-001", "Must redact PHI")
        assert isinstance(link, TraceLink)
        assert link.requirement_id == "URS-001"

    def test_add_requirement_idempotent(self):
        rtm = RequirementTraceMatrix()
        rtm.add_requirement("URS-001", "v1")
        rtm.add_requirement("URS-001", "v2")
        assert len(rtm.links) == 1
        assert rtm.links[0].requirement_text == "v2"

    def test_fully_traced_requirement(self):
        rtm = RequirementTraceMatrix()
        rtm.add_requirement("URS-001", "Redact PHI")
        rtm.link_design("URS-001", "DS-001")
        rtm.link_test("URS-001", "test_phi_redaction")
        rtm.link_evidence("URS-001", "run-2026-06-24")
        assert rtm.links[0].is_fully_traced is True
        assert rtm.links[0].missing_links == []

    def test_partial_trace_missing_links(self):
        rtm = RequirementTraceMatrix()
        rtm.add_requirement("URS-001", "Redact PHI")
        rtm.link_design("URS-001", "DS-001")
        link = rtm.links[0]
        assert link.is_fully_traced is False
        assert "test" in link.missing_links
        assert "evidence" in link.missing_links
        assert "design" not in link.missing_links

    def test_link_unknown_requirement_raises(self):
        rtm = RequirementTraceMatrix()
        with pytest.raises(KeyError):
            rtm.link_design("URS-999", "DS-001")

    def test_coverage_complete(self):
        rtm = RequirementTraceMatrix()
        rtm.add_requirement("URS-001", "r1")
        rtm.link_design("URS-001", "d")
        rtm.link_test("URS-001", "t")
        rtm.link_evidence("URS-001", "e")
        cov = rtm.coverage()
        assert isinstance(cov, RTMCoverage)
        assert cov.total == 1
        assert cov.fully_traced == 1
        assert cov.is_complete is True
        assert cov.coverage_ratio == 1.0
        assert cov.gaps == {}

    def test_coverage_with_gaps(self):
        rtm = RequirementTraceMatrix()
        rtm.add_requirement("URS-001", "r1")
        rtm.link_design("URS-001", "d")
        rtm.link_test("URS-001", "t")
        rtm.link_evidence("URS-001", "e")
        rtm.add_requirement("URS-002", "r2")  # untraced
        cov = rtm.coverage()
        assert cov.total == 2
        assert cov.fully_traced == 1
        assert cov.is_complete is False
        assert cov.coverage_ratio == 0.5
        assert "URS-002" in cov.gaps

    def test_coverage_empty_not_complete(self):
        rtm = RequirementTraceMatrix()
        cov = rtm.coverage()
        assert cov.total == 0
        assert cov.is_complete is False
        assert cov.coverage_ratio == 0.0

    def test_multiple_test_refs(self):
        rtm = RequirementTraceMatrix()
        rtm.add_requirement("URS-001", "r1")
        rtm.link_test("URS-001", "t1")
        rtm.link_test("URS-001", "t2")
        assert rtm.links[0].test_refs == ["t1", "t2"]

    def test_to_dict(self):
        rtm = RequirementTraceMatrix()
        rtm.add_requirement("URS-001", "r1")
        rtm.link_design("URS-001", "d")
        d = rtm.to_dict()
        assert "links" in d
        assert "coverage" in d
        assert d["coverage"]["total"] == 1


# ── Acceptance criteria ───────────────────────────────────────────────────────


class TestAcceptanceCriterion:
    def test_le_pass(self):
        c = AcceptanceCriterion("p99_latency_ms", "<=", 50.0)
        assert c.evaluate(45.0) is True
        assert c.evaluate(50.0) is True
        assert c.evaluate(55.0) is False

    def test_lt(self):
        c = AcceptanceCriterion("m", "<", 10.0)
        assert c.evaluate(9.0) is True
        assert c.evaluate(10.0) is False

    def test_ge_pass(self):
        c = AcceptanceCriterion("throughput", ">=", 900.0)
        assert c.evaluate(950.0) is True
        assert c.evaluate(900.0) is True
        assert c.evaluate(800.0) is False

    def test_gt(self):
        c = AcceptanceCriterion("m", ">", 5.0)
        assert c.evaluate(6.0) is True
        assert c.evaluate(5.0) is False

    def test_eq(self):
        c = AcceptanceCriterion("errors", "==", 0.0)
        assert c.evaluate(0.0) is True
        assert c.evaluate(1.0) is False

    def test_unknown_comparator_raises(self):
        c = AcceptanceCriterion("m", "!=", 0.0)
        with pytest.raises(ValueError, match="unknown comparator"):
            c.evaluate(1.0)

    def test_to_dict(self):
        c = AcceptanceCriterion("p99", "<=", 50.0)
        d = c.to_dict()
        assert d == {"metric": "p99", "comparator": "<=", "threshold": 50.0}


# ── Performance Qualification ─────────────────────────────────────────────────


def _criteria() -> list[AcceptanceCriterion]:
    return [
        AcceptanceCriterion("p99_latency_ms", "<=", 50.0),
        AcceptanceCriterion("throughput_rps", ">=", 900.0),
        AcceptanceCriterion("error_rate", "==", 0.0),
    ]


class TestPerformanceQualification:
    def test_new_pq_evaluates_passed(self):
        pq = new_performance_qualification(
            scenario="prod load",
            target_version="2.5.0",
            criteria=_criteria(),
            measurements={"p99_latency_ms": 42.0, "throughput_rps": 950.0, "error_rate": 0.0},
            executed_by="perf-eng",
        )
        assert pq.status == QualificationStatus.PASSED
        assert pq.failed_criteria == []

    def test_new_pq_evaluates_failed(self):
        pq = new_performance_qualification(
            scenario="prod load",
            target_version="2.5.0",
            criteria=_criteria(),
            measurements={"p99_latency_ms": 80.0, "throughput_rps": 950.0, "error_rate": 0.0},
        )
        assert pq.status == QualificationStatus.FAILED
        assert "p99_latency_ms" in pq.failed_criteria

    def test_missing_measurement_fails(self):
        pq = new_performance_qualification(
            scenario="s",
            target_version="2.5.0",
            criteria=_criteria(),
            measurements={"p99_latency_ms": 42.0},  # missing throughput + error_rate
        )
        assert pq.status == QualificationStatus.FAILED
        assert "throughput_rps" in pq.failed_criteria

    def test_pq_id_is_uuid(self):
        import uuid

        pq = new_performance_qualification(
            scenario="s", target_version="2.5.0", criteria=[], measurements={}
        )
        uuid.UUID(pq.pq_id)

    def test_empty_criteria_passes(self):
        pq = new_performance_qualification(
            scenario="s", target_version="2.5.0", criteria=[], measurements={}
        )
        assert pq.status == QualificationStatus.PASSED

    def test_sign_off_passed_pq(self):
        pq = new_performance_qualification(
            scenario="s",
            target_version="2.5.0",
            criteria=_criteria(),
            measurements={"p99_latency_ms": 42.0, "throughput_rps": 950.0, "error_rate": 0.0},
        )
        pq.sign_off(approver="qa-director", signing_key=_KEY)
        assert pq.is_signed_off is True
        assert pq.approved_by == "qa-director"
        assert len(pq.record_hmac) == 64
        assert pq.verify_hmac(_KEY) is True

    def test_sign_off_failed_pq_raises(self):
        pq = new_performance_qualification(
            scenario="s",
            target_version="2.5.0",
            criteria=_criteria(),
            measurements={"p99_latency_ms": 80.0, "throughput_rps": 950.0, "error_rate": 0.0},
        )
        with pytest.raises(ValueError, match="has not passed"):
            pq.sign_off(approver="qa-director", signing_key=_KEY)

    def test_verify_hmac_wrong_key(self):
        pq = new_performance_qualification(
            scenario="s",
            target_version="2.5.0",
            criteria=[],
            measurements={},
        )
        pq.sign_off(approver="d", signing_key=_KEY)
        assert pq.verify_hmac(_ALT_KEY) is False

    def test_unsigned_verify_hmac_false(self):
        pq = new_performance_qualification(
            scenario="s", target_version="2.5.0", criteria=[], measurements={}
        )
        assert pq.verify_hmac(_KEY) is False
        assert pq.is_signed_off is False

    def test_tampered_pq_fails_verify(self):
        pq = new_performance_qualification(
            scenario="s",
            target_version="2.5.0",
            criteria=[],
            measurements={},
        )
        pq.sign_off(approver="d", signing_key=_KEY)
        pq.scenario = "tampered"
        assert pq.verify_hmac(_KEY) is False

    def test_to_dict_contains_fields(self):
        pq = new_performance_qualification(
            scenario="s",
            target_version="2.5.0",
            criteria=_criteria(),
            measurements={"p99_latency_ms": 42.0, "throughput_rps": 950.0, "error_rate": 0.0},
        )
        d = pq.to_dict()
        for f in ["pq_id", "scenario", "criteria", "measurements", "status"]:
            assert f in d

    def test_construct_directly_pending(self):
        pq = PerformanceQualification(
            pq_id="x",
            executed_at=0.0,
            scenario="s",
            target_version="2.5.0",
            criteria=[],
            measurements={},
        )
        assert pq.status == QualificationStatus.PENDING


# ── Vendor Qualification Package ──────────────────────────────────────────────


def _qualified_setup():
    cc = ChangeControlRegistry()
    rec = _submit(cc, target_version="2.5.0")
    cc.approve(rec.change_id, approver="m", signing_key=_KEY)

    rtm = RequirementTraceMatrix()
    rtm.add_requirement("URS-001", "Redact PHI")
    rtm.link_design("URS-001", "DS-001")
    rtm.link_test("URS-001", "test_phi")
    rtm.link_evidence("URS-001", "run-1")

    pq = new_performance_qualification(
        scenario="prod load",
        target_version="2.5.0",
        criteria=_criteria(),
        measurements={"p99_latency_ms": 42.0, "throughput_rps": 950.0, "error_rate": 0.0},
    )
    pq.sign_off(approver="qa-director", signing_key=_KEY)
    return cc, rtm, pq


class TestVendorQualificationPackage:
    def test_build_returns_package(self):
        cc, rtm, pq = _qualified_setup()
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[pq],
            signing_key=_KEY,
        )
        assert isinstance(pkg, VendorQualificationPackage)

    def test_package_id_is_uuid(self):
        import uuid

        cc, rtm, pq = _qualified_setup()
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[pq],
            signing_key=_KEY,
        )
        uuid.UUID(pkg.package_id)

    def test_qualified_when_complete(self):
        cc, rtm, pq = _qualified_setup()
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[pq],
            signing_key=_KEY,
        )
        assert pkg.is_qualified is True

    def test_not_qualified_with_rtm_gap(self):
        cc, rtm, pq = _qualified_setup()
        rtm.add_requirement("URS-002", "untraced")
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[pq],
            signing_key=_KEY,
        )
        assert pkg.is_qualified is False

    def test_not_qualified_with_no_pq(self):
        cc, rtm, _pq = _qualified_setup()
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[],
            signing_key=_KEY,
        )
        assert pkg.is_qualified is False

    def test_not_qualified_with_unsigned_pq(self):
        cc, rtm, _pq = _qualified_setup()
        unsigned_pq = new_performance_qualification(
            scenario="s",
            target_version="2.5.0",
            criteria=_criteria(),
            measurements={"p99_latency_ms": 42.0, "throughput_rps": 950.0, "error_rate": 0.0},
        )
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[unsigned_pq],
            signing_key=_KEY,
        )
        assert pkg.is_qualified is False

    def test_only_approved_changes_for_version_included(self):
        cc, rtm, pq = _qualified_setup()
        # add an approved change for a different version
        other = _submit(cc, target_version="9.9.9")
        cc.approve(other.change_id, approver="m", signing_key=_KEY)
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[pq],
            signing_key=_KEY,
        )
        versions = {c.target_version for c in pkg.change_records}
        assert versions == {"2.5.0"}

    def test_bundle_hmac_64_char(self):
        cc, rtm, pq = _qualified_setup()
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[pq],
            signing_key=_KEY,
        )
        assert len(pkg.bundle_hmac) == 64

    def test_verify_bundle_hmac_valid(self):
        cc, rtm, pq = _qualified_setup()
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[pq],
            signing_key=_KEY,
        )
        assert pkg.verify_bundle_hmac(_KEY) is True

    def test_verify_bundle_hmac_wrong_key(self):
        cc, rtm, pq = _qualified_setup()
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[pq],
            signing_key=_KEY,
        )
        assert pkg.verify_bundle_hmac(_ALT_KEY) is False

    def test_tampered_package_fails_verify(self):
        cc, rtm, pq = _qualified_setup()
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[pq],
            signing_key=_KEY,
        )
        pkg.vendor = "Imposter"
        assert pkg.verify_bundle_hmac(_KEY) is False

    def test_to_json_round_trip(self):
        cc, rtm, pq = _qualified_setup()
        pkg = build_vendor_qualification_package(
            vendor="Aegis",
            product_version="2.5.0",
            registry=cc,
            rtm=rtm,
            pq_records=[pq],
            signing_key=_KEY,
        )
        parsed = json.loads(pkg.to_json())
        assert parsed["vendor"] == "Aegis"
        assert parsed["is_qualified"] is True
        assert "bundle_hmac" in parsed

    def test_unsigned_package_verify_false(self):
        cc, rtm, pq = _qualified_setup()
        pkg = VendorQualificationPackage(
            package_id="x",
            generated_at=0.0,
            vendor="Aegis",
            product_version="2.5.0",
            change_records=[],
            rtm_coverage=rtm.coverage(),
            pq_records=[pq],
        )
        assert pkg.verify_bundle_hmac(_KEY) is False
