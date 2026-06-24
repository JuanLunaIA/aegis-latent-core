# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.gxp_qualification — GxP computerised-system qualification hooks.

Implements the code-tractable parts of a GxP (GMP/GLP/GCP) Performance
Qualification programme for an AI control plane operating in a regulated
life-sciences environment (pharma manufacturing, clinical, laboratory):

- **Change control** (:class:`ChangeControlRegistry` + :class:`DeploymentGate`):
  a version-gated deployment gate that refuses to authorise a deploy unless an
  **approved** change record exists for the exact target software version.
  Mirrors EU GMP Annex 11 §10 ("Change and Configuration Management") and
  21 CFR Part 11 change-control expectations.
- **Requirement → Design → Test → Evidence traceability matrix**
  (:class:`RequirementTraceMatrix`): the RTM that GAMP 5 requires to demonstrate
  that every user/functional requirement is designed, tested, and evidenced.
- **Performance Qualification sign-off** (:class:`PerformanceQualification`):
  a production-representative load-test result evaluated against documented
  acceptance criteria and HMAC-signed by an approver (GAMP 5 PQ phase).
- **Vendor Qualification Package** (:class:`VendorQualificationPackage`): a
  single signed bundle of the above artefacts for an auditor / sponsor's
  supplier-qualification dossier.

All sign-offs and bundles are signed with **HMAC-SHA256** keyed by
``AEGIS_SIGNING_KEY`` (kept separate from API keys), so an auditor can verify
that an approval record or qualification report has not been altered after
sign-off.  No plaintext signatures are used.

Regulatory basis
----------------
- **EU GMP Annex 11** (Computerised Systems): §4 Validation, §7 Data, §10
  Change & Configuration Management, §11 Periodic Evaluation.
- **GAMP 5 (2nd ed.)**: V-model — URS/FS/DS → IQ/OQ/PQ; RTM; supplier
  assessment.
- **21 CFR Part 11**: electronic records / electronic signatures; audit-ready,
  tamper-evident records.
- **21 CFR Part 211** (cGMP): validated state of manufacturing systems.

Usage::

    import os
    from aegis.core.gxp_qualification import (
        ChangeControlRegistry,
        DeploymentGate,
        RequirementTraceMatrix,
        PerformanceQualification,
    )

    key = os.environb[b"AEGIS_SIGNING_KEY"]
    cc = ChangeControlRegistry()
    chg = cc.submit_change(
        title="Upgrade WAF ruleset",
        description="Add MAR market-abuse rules",
        target_version="2.5.0",
        requested_by="qa-lead",
        gxp_impact=True,
    )
    cc.approve(chg.change_id, approver="qa-manager", signing_key=key)

    gate = DeploymentGate(cc)
    decision = gate.authorize_deploy("2.5.0")
    assert decision.authorized
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum

# ── Enumerations ──────────────────────────────────────────────────────────────


class ChangeStatus(StrEnum):
    """Lifecycle states of a GxP change record (Annex 11 §10)."""

    DRAFT = "draft"
    SUBMITTED = "submitted"
    APPROVED = "approved"
    REJECTED = "rejected"
    IMPLEMENTED = "implemented"
    CLOSED = "closed"


class ChangeRisk(StrEnum):
    """Change risk classification driving review depth."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class QualificationStatus(StrEnum):
    """Outcome of a qualification (PQ) execution."""

    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"


# ── HMAC helpers ──────────────────────────────────────────────────────────────


def _hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _compute_record_hmac(d: dict[str, object], key: bytes) -> str:
    payload = {k: v for k, v in d.items() if k != "record_hmac"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return _hmac_hex(key, canonical)


# ── Change control ────────────────────────────────────────────────────────────


@dataclass
class ChangeRecord:
    """A GxP change-control record (EU GMP Annex 11 §10).

    A deploy of ``target_version`` is only authorised once this record reaches
    :attr:`ChangeStatus.APPROVED` (and is not subsequently rejected).

    Attributes
    ----------
    change_id:
        Unique UUID for this change.
    created_at:
        Unix timestamp (UTC) of submission.
    title / description:
        Human-readable change summary and detail.
    target_version:
        The software version this change authorises for deployment.
    risk:
        Risk classification (:class:`ChangeRisk`).
    status:
        Current lifecycle state.
    requested_by:
        Identity that submitted the change.
    approved_by / approved_at:
        Identity and timestamp of the approver, or None until approved.
    rejected_reason:
        Free-form reason when status is REJECTED.
    gxp_impact:
        Whether this change touches GxP-validated functionality (drives the
        need for re-qualification).
    record_hmac:
        HMAC-SHA256 (hex) over the canonical record, set at approval time.
    """

    change_id: str
    created_at: float
    title: str
    description: str
    target_version: str
    requested_by: str
    risk: ChangeRisk = ChangeRisk.MEDIUM
    status: ChangeStatus = ChangeStatus.SUBMITTED
    approved_by: str | None = None
    approved_at: float | None = None
    rejected_reason: str = ""
    gxp_impact: bool = False
    record_hmac: str = ""

    @property
    def is_approved(self) -> bool:
        return self.status == ChangeStatus.APPROVED

    def to_dict(self) -> dict[str, object]:
        return {
            "change_id": self.change_id,
            "created_at": self.created_at,
            "title": self.title,
            "description": self.description,
            "target_version": self.target_version,
            "requested_by": self.requested_by,
            "risk": self.risk.value,
            "status": self.status.value,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "rejected_reason": self.rejected_reason,
            "gxp_impact": self.gxp_impact,
            "record_hmac": self.record_hmac,
        }

    def verify_hmac(self, signing_key: bytes) -> bool:
        if not self.record_hmac:
            return False
        return hmac.compare_digest(
            _compute_record_hmac(self.to_dict(), signing_key), self.record_hmac
        )


class ChangeControlRegistry:
    """In-memory registry of GxP change records with an approval workflow."""

    def __init__(self) -> None:
        self._changes: dict[str, ChangeRecord] = {}

    def submit_change(
        self,
        *,
        title: str,
        description: str,
        target_version: str,
        requested_by: str,
        risk: ChangeRisk = ChangeRisk.MEDIUM,
        gxp_impact: bool = False,
        now: float | None = None,
    ) -> ChangeRecord:
        """Register a new change in SUBMITTED state and return it."""
        ts = now if now is not None else time.time()
        rec = ChangeRecord(
            change_id=str(uuid.uuid4()),
            created_at=ts,
            title=title,
            description=description[:2000],
            target_version=target_version,
            requested_by=requested_by,
            risk=risk,
            status=ChangeStatus.SUBMITTED,
            gxp_impact=gxp_impact,
        )
        self._changes[rec.change_id] = rec
        return rec

    def approve(
        self,
        change_id: str,
        *,
        approver: str,
        signing_key: bytes,
        now: float | None = None,
    ) -> ChangeRecord:
        """Approve a change; signs the record with HMAC-SHA256.

        Raises
        ------
        KeyError
            If ``change_id`` is unknown.
        ValueError
            If the change was already rejected, or the approver equals the
            requester (segregation of duties — Annex 11 §2 / Part 11).
        """
        rec = self._changes[change_id]
        if rec.status == ChangeStatus.REJECTED:
            raise ValueError("cannot approve a rejected change")
        if approver == rec.requested_by:
            raise ValueError("approver must differ from requester (segregation of duties)")
        rec.status = ChangeStatus.APPROVED
        rec.approved_by = approver
        rec.approved_at = now if now is not None else time.time()
        rec.record_hmac = _compute_record_hmac(rec.to_dict(), signing_key)
        return rec

    def reject(self, change_id: str, *, approver: str, reason: str) -> ChangeRecord:
        """Reject a change with a documented reason."""
        rec = self._changes[change_id]
        if rec.status == ChangeStatus.APPROVED:
            raise ValueError("cannot reject an already-approved change")
        rec.status = ChangeStatus.REJECTED
        rec.approved_by = approver
        rec.rejected_reason = reason[:1000]
        return rec

    def get(self, change_id: str) -> ChangeRecord | None:
        return self._changes.get(change_id)

    @property
    def records(self) -> list[ChangeRecord]:
        return list(self._changes.values())

    def approved_changes_for(self, version: str) -> list[ChangeRecord]:
        """All APPROVED change records targeting *version*."""
        return [
            r
            for r in self._changes.values()
            if r.target_version == version and r.status == ChangeStatus.APPROVED
        ]


# ── Deployment gate ───────────────────────────────────────────────────────────


@dataclass
class DeploymentDecision:
    """Result of a version-gated deployment authorisation check."""

    version: str
    authorized: bool
    reason: str
    approved_change_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "authorized": self.authorized,
            "reason": self.reason,
            "approved_change_ids": self.approved_change_ids,
        }


class DeploymentGate:
    """Version-gated deploy authoriser backed by a :class:`ChangeControlRegistry`.

    A deploy of a given software version is authorised **only** when at least
    one approved change record targets that exact version.  This enforces the
    Annex 11 §10 requirement that production changes follow an approved change
    request, and fails closed when no such record exists.
    """

    def __init__(
        self, registry: ChangeControlRegistry, *, require_signing_key: bytes | None = None
    ) -> None:
        self._registry = registry
        self._require_signing_key = require_signing_key

    def authorize_deploy(self, version: str) -> DeploymentDecision:
        """Return a :class:`DeploymentDecision` for deploying *version*."""
        approved = self._registry.approved_changes_for(version)
        if not approved:
            return DeploymentDecision(
                version=version,
                authorized=False,
                reason=f"no approved change record targets version {version!r}",
            )
        # When a verification key is configured, every approving record's HMAC
        # must verify — a tampered approval invalidates the gate (fail closed).
        if self._require_signing_key is not None:
            for rec in approved:
                if not rec.verify_hmac(self._require_signing_key):
                    return DeploymentDecision(
                        version=version,
                        authorized=False,
                        reason=f"approval signature invalid for change {rec.change_id}",
                    )
        return DeploymentDecision(
            version=version,
            authorized=True,
            reason=f"{len(approved)} approved change record(s) for version {version!r}",
            approved_change_ids=[r.change_id for r in approved],
        )


# ── Requirement traceability matrix (RTM) ─────────────────────────────────────


@dataclass
class TraceLink:
    """One row of the RTM: a requirement and its design/test/evidence links.

    A requirement is *fully traced* iff it has a design reference, at least one
    test reference, and at least one evidence reference (GAMP 5 V-model).
    """

    requirement_id: str
    requirement_text: str
    design_refs: list[str] = field(default_factory=list)
    test_refs: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)

    @property
    def is_fully_traced(self) -> bool:
        return bool(self.design_refs) and bool(self.test_refs) and bool(self.evidence_refs)

    @property
    def missing_links(self) -> list[str]:
        missing = []
        if not self.design_refs:
            missing.append("design")
        if not self.test_refs:
            missing.append("test")
        if not self.evidence_refs:
            missing.append("evidence")
        return missing

    def to_dict(self) -> dict[str, object]:
        return {
            "requirement_id": self.requirement_id,
            "requirement_text": self.requirement_text,
            "design_refs": list(self.design_refs),
            "test_refs": list(self.test_refs),
            "evidence_refs": list(self.evidence_refs),
            "is_fully_traced": self.is_fully_traced,
            "missing_links": self.missing_links,
        }


@dataclass
class RTMCoverage:
    """Summary of RTM completeness."""

    total: int
    fully_traced: int
    gaps: dict[str, list[str]]  # requirement_id → missing link kinds

    @property
    def coverage_ratio(self) -> float:
        if self.total == 0:
            return 0.0
        return self.fully_traced / self.total

    @property
    def is_complete(self) -> bool:
        return self.total > 0 and self.fully_traced == self.total

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "fully_traced": self.fully_traced,
            "gaps": self.gaps,
            "coverage_ratio": self.coverage_ratio,
            "is_complete": self.is_complete,
        }


class RequirementTraceMatrix:
    """GAMP 5 Requirement → Design → Test → Evidence traceability matrix."""

    def __init__(self) -> None:
        self._links: dict[str, TraceLink] = {}

    def add_requirement(self, requirement_id: str, requirement_text: str) -> TraceLink:
        """Register a requirement (idempotent on requirement_id)."""
        link = self._links.get(requirement_id)
        if link is None:
            link = TraceLink(requirement_id=requirement_id, requirement_text=requirement_text)
            self._links[requirement_id] = link
        else:
            link.requirement_text = requirement_text
        return link

    def link_design(self, requirement_id: str, design_ref: str) -> None:
        self._require(requirement_id).design_refs.append(design_ref)

    def link_test(self, requirement_id: str, test_ref: str) -> None:
        self._require(requirement_id).test_refs.append(test_ref)

    def link_evidence(self, requirement_id: str, evidence_ref: str) -> None:
        self._require(requirement_id).evidence_refs.append(evidence_ref)

    def _require(self, requirement_id: str) -> TraceLink:
        if requirement_id not in self._links:
            raise KeyError(f"unknown requirement {requirement_id!r}; add_requirement first")
        return self._links[requirement_id]

    @property
    def links(self) -> list[TraceLink]:
        return list(self._links.values())

    def coverage(self) -> RTMCoverage:
        """Compute RTM completeness across all registered requirements."""
        total = len(self._links)
        fully = sum(1 for link in self._links.values() if link.is_fully_traced)
        gaps = {
            link.requirement_id: link.missing_links
            for link in self._links.values()
            if not link.is_fully_traced
        }
        return RTMCoverage(total=total, fully_traced=fully, gaps=gaps)

    def to_dict(self) -> dict[str, object]:
        return {
            "links": [link.to_dict() for link in self._links.values()],
            "coverage": self.coverage().to_dict(),
        }


# ── Performance Qualification (PQ) ────────────────────────────────────────────


@dataclass
class AcceptanceCriterion:
    """One PQ acceptance criterion: ``metric`` compared to ``threshold``.

    ``comparator`` is one of ``"<="``, ``"<"``, ``">="``, ``">"``, ``"=="``.
    """

    metric: str
    comparator: str
    threshold: float

    def evaluate(self, measured: float) -> bool:
        if self.comparator == "<=":
            return measured <= self.threshold
        if self.comparator == "<":
            return measured < self.threshold
        if self.comparator == ">=":
            return measured >= self.threshold
        if self.comparator == ">":
            return measured > self.threshold
        if self.comparator == "==":
            return measured == self.threshold
        raise ValueError(f"unknown comparator {self.comparator!r}")

    def to_dict(self) -> dict[str, object]:
        return {
            "metric": self.metric,
            "comparator": self.comparator,
            "threshold": self.threshold,
        }


@dataclass
class PerformanceQualification:
    """A GAMP 5 Performance Qualification execution + sign-off record.

    Captures a production-representative load test: the scenario, the acceptance
    criteria, the measured values, the pass/fail outcome, and an HMAC-signed
    approver sign-off.

    Attributes
    ----------
    pq_id:
        Unique UUID for this PQ execution.
    executed_at:
        Unix timestamp of the test execution.
    scenario:
        Description of the production-representative load scenario.
    target_version:
        Software version under qualification.
    criteria:
        List of :class:`AcceptanceCriterion`.
    measurements:
        Mapping of metric name → measured value.
    status:
        PASSED / FAILED / PENDING.
    executed_by:
        Identity that ran the test.
    approved_by / approved_at:
        Sign-off identity and timestamp (None until signed off).
    record_hmac:
        HMAC-SHA256 (hex) of the canonical record, set at sign-off time.
    """

    pq_id: str
    executed_at: float
    scenario: str
    target_version: str
    criteria: list[AcceptanceCriterion]
    measurements: dict[str, float]
    status: QualificationStatus = QualificationStatus.PENDING
    executed_by: str = ""
    approved_by: str | None = None
    approved_at: float | None = None
    record_hmac: str = ""

    def evaluate(self) -> QualificationStatus:
        """Evaluate all criteria against measurements; set and return status.

        A missing measurement for any criterion fails the PQ (you cannot pass a
        criterion you did not measure).
        """
        for crit in self.criteria:
            if crit.metric not in self.measurements:
                self.status = QualificationStatus.FAILED
                return self.status
            if not crit.evaluate(self.measurements[crit.metric]):
                self.status = QualificationStatus.FAILED
                return self.status
        self.status = QualificationStatus.PASSED
        return self.status

    @property
    def failed_criteria(self) -> list[str]:
        """Metric names whose criterion did not pass (or was not measured)."""
        out: list[str] = []
        for crit in self.criteria:
            if crit.metric not in self.measurements or not crit.evaluate(
                self.measurements[crit.metric]
            ):
                out.append(crit.metric)
        return out

    def sign_off(self, *, approver: str, signing_key: bytes, now: float | None = None) -> None:
        """Record an approver sign-off and HMAC-sign the PQ record.

        Raises
        ------
        ValueError
            If the PQ has not been evaluated to PASSED (you cannot sign off a
            failing or un-run qualification).
        """
        if self.status != QualificationStatus.PASSED:
            raise ValueError("cannot sign off a PQ that has not passed")
        self.approved_by = approver
        self.approved_at = now if now is not None else time.time()
        self.record_hmac = _compute_record_hmac(self.to_dict(), signing_key)

    @property
    def is_signed_off(self) -> bool:
        return self.approved_by is not None and bool(self.record_hmac)

    def to_dict(self) -> dict[str, object]:
        return {
            "pq_id": self.pq_id,
            "executed_at": self.executed_at,
            "scenario": self.scenario,
            "target_version": self.target_version,
            "criteria": [c.to_dict() for c in self.criteria],
            "measurements": dict(sorted(self.measurements.items())),
            "status": self.status.value,
            "executed_by": self.executed_by,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "record_hmac": self.record_hmac,
        }

    def verify_hmac(self, signing_key: bytes) -> bool:
        if not self.record_hmac:
            return False
        return hmac.compare_digest(
            _compute_record_hmac(self.to_dict(), signing_key), self.record_hmac
        )


def new_performance_qualification(
    *,
    scenario: str,
    target_version: str,
    criteria: list[AcceptanceCriterion],
    measurements: dict[str, float],
    executed_by: str = "",
    now: float | None = None,
) -> PerformanceQualification:
    """Construct and immediately evaluate a :class:`PerformanceQualification`."""
    pq = PerformanceQualification(
        pq_id=str(uuid.uuid4()),
        executed_at=now if now is not None else time.time(),
        scenario=scenario,
        target_version=target_version,
        criteria=criteria,
        measurements=measurements,
        executed_by=executed_by,
    )
    pq.evaluate()
    return pq


# ── Vendor Qualification Package (VQP) ────────────────────────────────────────


@dataclass
class VendorQualificationPackage:
    """A signed bundle of GxP qualification artefacts for an auditor dossier.

    Combines the approved change records, the RTM coverage, and the PQ sign-off
    records into a single tamper-evident package with a bundle-level
    HMAC-SHA256 signature.

    ``is_qualified`` is True only when the RTM is complete *and* every included
    PQ record passed and was signed off.
    """

    package_id: str
    generated_at: float
    vendor: str
    product_version: str
    change_records: list[ChangeRecord]
    rtm_coverage: RTMCoverage
    pq_records: list[PerformanceQualification]
    bundle_hmac: str = ""

    @property
    def is_qualified(self) -> bool:
        if not self.rtm_coverage.is_complete:
            return False
        if not self.pq_records:
            return False
        return all(
            pq.status == QualificationStatus.PASSED and pq.is_signed_off for pq in self.pq_records
        )

    def _canonical(self) -> bytes:
        payload = {
            "package_id": self.package_id,
            "generated_at": self.generated_at,
            "vendor": self.vendor,
            "product_version": self.product_version,
            "change_records": [c.to_dict() for c in self.change_records],
            "rtm_coverage": self.rtm_coverage.to_dict(),
            "pq_records": [p.to_dict() for p in self.pq_records],
            "is_qualified": self.is_qualified,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def to_dict(self) -> dict[str, object]:
        return {
            "package_id": self.package_id,
            "generated_at": self.generated_at,
            "vendor": self.vendor,
            "product_version": self.product_version,
            "change_records": [c.to_dict() for c in self.change_records],
            "rtm_coverage": self.rtm_coverage.to_dict(),
            "pq_records": [p.to_dict() for p in self.pq_records],
            "is_qualified": self.is_qualified,
            "bundle_hmac": self.bundle_hmac,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def verify_bundle_hmac(self, signing_key: bytes) -> bool:
        if not self.bundle_hmac:
            return False
        return hmac.compare_digest(_hmac_hex(signing_key, self._canonical()), self.bundle_hmac)


def build_vendor_qualification_package(
    *,
    vendor: str,
    product_version: str,
    registry: ChangeControlRegistry,
    rtm: RequirementTraceMatrix,
    pq_records: list[PerformanceQualification],
    signing_key: bytes,
    now: float | None = None,
) -> VendorQualificationPackage:
    """Assemble and HMAC-sign a :class:`VendorQualificationPackage`.

    Includes only the APPROVED change records targeting ``product_version``.
    """
    pkg = VendorQualificationPackage(
        package_id=str(uuid.uuid4()),
        generated_at=now if now is not None else time.time(),
        vendor=vendor,
        product_version=product_version,
        change_records=registry.approved_changes_for(product_version),
        rtm_coverage=rtm.coverage(),
        pq_records=list(pq_records),
    )
    pkg.bundle_hmac = _hmac_hex(signing_key, pkg._canonical())
    return pkg
