# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.model_risk_governance — SOX ICFR + SR 11-7 model risk governance.

Implements governance hooks for regulated financial services, satisfying:

- **SR 11-7 (Federal Reserve / OCC)**: model inventory, validation evidence,
  challenger logging, and ongoing monitoring requirements.  Every model used in
  a material business process must have a documented model ID, owner,
  validation status, and challenger comparison record.
- **SOX Section 302/404 (ICFR)**: Internal Controls over Financial Reporting —
  AI/ML models used in financial forecasting, credit scoring, or trade
  recommendation must be included in the ICFR control environment.  This module
  provides audit-attestable control points.

SR 11-7 mandates
-----------------
- Model inventory: all models in use, with conceptual soundness and outcome
  analysis documentation.
- Validation independence: model-validation team must independently test
  challenger vs. champion outputs.
- Ongoing monitoring: performance metrics reported at a defined cadence;
  material deterioration triggers re-validation.
- Model lifecycle: pre-deployment review, deployment gate (approval record),
  post-deployment monitoring, decommission attestation.

SOX ICFR linkage
-----------------
Each control point in the model lifecycle maps to a COSO framework component:
- **Control Environment**: model policy + owner accountability.
- **Risk Assessment**: conceptual soundness review.
- **Control Activities**: deployment gate approval.
- **Information & Communication**: monitoring reports + challenger logs.
- **Monitoring**: ongoing performance tracking.

Usage::

    from aegis.core.model_risk_governance import (
        ModelRecord,
        ModelGovernanceRegistry,
        SR117ValidationStatus,
    )
    import os

    registry = ModelGovernanceRegistry()
    rec = registry.register(
        model_id="aegis-proxy/claude-3-sonnet",
        owner="ai-risk-team",
        use_case="credit-advice-generation",
        material=True,
    )
    registry.record_validation(
        model_id="aegis-proxy/claude-3-sonnet",
        validator="quant-validation-unit",
        status=SR117ValidationStatus.APPROVED,
        evidence_hash="sha256:abcdef...",
        signing_key=os.environb[b"AEGIS_SIGNING_KEY"],
    )
    report = registry.sox_control_report(signing_key=os.environb[b"AEGIS_SIGNING_KEY"])
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

# ── Enumerations ──────────────────────────────────────────────────────────────


class SR117ValidationStatus(StrEnum):
    """SR 11-7 model validation outcomes."""

    PENDING = "pending"
    APPROVED = "approved"
    APPROVED_WITH_CONDITIONS = "approved_with_conditions"
    REJECTED = "rejected"
    UNDER_REVIEW = "under_review"
    DECOMMISSIONED = "decommissioned"


class ModelTier(StrEnum):
    """SR 11-7 materiality tiers."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


COSOComponent = Literal[
    "control_environment",
    "risk_assessment",
    "control_activities",
    "information_communication",
    "monitoring",
]

# ── Validation record ─────────────────────────────────────────────────────────


@dataclass
class ValidationRecord:
    """SR 11-7 model validation evidence record.

    Attributes
    ----------
    validation_id:
        Unique UUID for this validation event.
    model_id:
        Identifier of the model validated.
    validated_at:
        Unix timestamp (UTC) of validation completion.
    validator:
        Identity of the independent validation unit.
    status:
        Validation outcome (SR 11-7 §4.3).
    evidence_hash:
        SHA-256 or other hash of the validation report document.  Allows
        regulators to verify the report referenced here has not been altered.
    challenger_model_id:
        If a challenger comparison was performed, the challenger model ID.
    notes:
        Free-form notes (max 500 chars; not for sensitive data).
    record_hmac:
        HMAC-SHA256 (hex) of the canonical JSON of this record (excluding
        ``record_hmac``), keyed by ``AEGIS_SIGNING_KEY``.
    """

    validation_id: str
    model_id: str
    validated_at: float
    validator: str
    status: SR117ValidationStatus
    evidence_hash: str
    challenger_model_id: str | None = None
    notes: str = ""
    record_hmac: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "validation_id": self.validation_id,
            "model_id": self.model_id,
            "validated_at": self.validated_at,
            "validator": self.validator,
            "status": self.status.value,
            "evidence_hash": self.evidence_hash,
            "challenger_model_id": self.challenger_model_id,
            "notes": self.notes,
            "record_hmac": self.record_hmac,
        }

    def verify_hmac(self, signing_key: bytes) -> bool:
        return hmac.compare_digest(
            _compute_record_hmac(self.to_dict(), signing_key), self.record_hmac
        )


# ── ModelRecord ───────────────────────────────────────────────────────────────


@dataclass
class ModelRecord:
    """SR 11-7 model inventory entry.

    Attributes
    ----------
    model_id:
        Unique model identifier (e.g. ``"aegis-proxy/claude-3-sonnet:v1"``).
    registered_at:
        Unix timestamp of initial registration.
    owner:
        Team or individual accountable for this model (SR 11-7 §4.1).
    use_case:
        Business use-case description.
    material:
        Whether this model is material to financial reporting (SOX ICFR scope).
    tier:
        SR 11-7 materiality tier.
    validation_status:
        Current validation status.
    validation_history:
        Chronological list of :class:`ValidationRecord` instances.
    deployment_approved_at:
        Unix timestamp of deployment gate approval, or None if not yet approved.
    deployment_approver:
        Identity of the approver at the deployment gate.
    decommissioned_at:
        Unix timestamp of decommission, or None if still active.
    """

    model_id: str
    registered_at: float = field(default_factory=time.time)
    owner: str = ""
    use_case: str = ""
    material: bool = False
    tier: ModelTier = ModelTier.MEDIUM
    validation_status: SR117ValidationStatus = SR117ValidationStatus.PENDING
    validation_history: list[ValidationRecord] = field(default_factory=list)
    deployment_approved_at: float | None = None
    deployment_approver: str | None = None
    decommissioned_at: float | None = None

    @property
    def is_active(self) -> bool:
        return self.decommissioned_at is None

    @property
    def is_deployment_approved(self) -> bool:
        return self.deployment_approved_at is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "model_id": self.model_id,
            "registered_at": self.registered_at,
            "owner": self.owner,
            "use_case": self.use_case,
            "material": self.material,
            "tier": self.tier.value,
            "validation_status": self.validation_status.value,
            "validation_history": [v.to_dict() for v in self.validation_history],
            "deployment_approved_at": self.deployment_approved_at,
            "deployment_approver": self.deployment_approver,
            "decommissioned_at": self.decommissioned_at,
            "is_active": self.is_active,
            "is_deployment_approved": self.is_deployment_approved,
        }


# ── SOXControlPoint ───────────────────────────────────────────────────────────


@dataclass
class SOXControlPoint:
    """One COSO-mapped control point in the model lifecycle.

    Attributes
    ----------
    control_id:
        Unique identifier (e.g. ``"AIML-CC-001"`` for AI/ML Control #1).
    coso_component:
        Which of the five COSO components this control satisfies.
    description:
        Short description of the control activity.
    model_id:
        Model this control point applies to.
    evidenced_at:
        Unix timestamp when evidence was captured.
    evidence_summary:
        Brief description of the evidence (not the evidence itself).
    passed:
        Whether the control is operating effectively.
    """

    control_id: str
    coso_component: COSOComponent
    description: str
    model_id: str
    evidenced_at: float
    evidence_summary: str
    passed: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "control_id": self.control_id,
            "coso_component": self.coso_component,
            "description": self.description,
            "model_id": self.model_id,
            "evidenced_at": self.evidenced_at,
            "evidence_summary": self.evidence_summary,
            "passed": self.passed,
        }


# ── SOXControlReport ──────────────────────────────────────────────────────────


@dataclass
class SOXControlReport:
    """SOX ICFR attestation report covering all material models.

    Attributes
    ----------
    report_id:
        Unique UUID for this report.
    generated_at:
        Unix timestamp when the report was produced.
    material_models:
        Dicts of material :class:`ModelRecord` instances.
    control_points:
        All :class:`SOXControlPoint` instances assessed.
    overall_effective:
        True if all material models are deployment-approved and have no
        rejected validations.
    bundle_hmac:
        HMAC-SHA256 (hex) of the canonical JSON representation.
    """

    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: float = field(default_factory=time.time)
    material_models: list[dict[str, object]] = field(default_factory=list)
    control_points: list[dict[str, object]] = field(default_factory=list)
    overall_effective: bool = False
    bundle_hmac: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "material_models": self.material_models,
            "control_points": self.control_points,
            "overall_effective": self.overall_effective,
            "bundle_hmac": self.bundle_hmac,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def verify_bundle_hmac(self, signing_key: bytes) -> bool:
        canonical = json.dumps(
            {
                "report_id": self.report_id,
                "generated_at": self.generated_at,
                "material_models": self.material_models,
                "control_points": self.control_points,
                "overall_effective": self.overall_effective,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        expected = _hmac_hex(signing_key, canonical)
        return hmac.compare_digest(expected, self.bundle_hmac)


# ── HMAC helpers ──────────────────────────────────────────────────────────────


def _hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _compute_record_hmac(d: dict[str, object], key: bytes) -> str:
    payload = {k: v for k, v in d.items() if k != "record_hmac"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return _hmac_hex(key, canonical)


# ── ModelGovernanceRegistry ───────────────────────────────────────────────────


class ModelGovernanceRegistry:
    """SR 11-7 model inventory + SOX ICFR control-point registry.

    Maintains in-memory model records and validation history.  Suitable for
    embedding in the proxy's startup lifecycle; persist via ``to_json()``
    and reload on restart for long-lived registries.
    """

    def __init__(self) -> None:
        self._models: dict[str, ModelRecord] = {}
        self._control_points: list[SOXControlPoint] = []

    # ── Model lifecycle ───────────────────────────────────────────────────────

    def register(
        self,
        model_id: str,
        owner: str,
        use_case: str,
        material: bool = False,
        tier: ModelTier = ModelTier.MEDIUM,
        now: float | None = None,
    ) -> ModelRecord:
        """Register a model in the SR 11-7 inventory.

        Raises :class:`ValueError` if *model_id* is already registered.
        """
        if model_id in self._models:
            raise ValueError(f"Model already registered: {model_id!r}")
        rec = ModelRecord(
            model_id=model_id,
            registered_at=now if now is not None else time.time(),
            owner=owner,
            use_case=use_case,
            material=material,
            tier=tier,
        )
        self._models[model_id] = rec
        self._add_control_point(
            control_id=f"AIML-CE-{model_id[:16]}",
            coso_component="control_environment",
            description="Model registered in SR 11-7 inventory with owner accountability",
            model_id=model_id,
            evidence_summary=f"owner={owner}, use_case={use_case}, material={material}",
            passed=True,
            now=rec.registered_at,
        )
        return rec

    def record_validation(
        self,
        model_id: str,
        validator: str,
        status: SR117ValidationStatus,
        evidence_hash: str,
        signing_key: bytes,
        challenger_model_id: str | None = None,
        notes: str = "",
        now: float | None = None,
    ) -> ValidationRecord:
        """Record a validation event and update the model's validation status.

        Raises :class:`KeyError` if *model_id* is not registered.
        """
        rec = self._models[model_id]
        ts = now if now is not None else time.time()
        val = ValidationRecord(
            validation_id=str(uuid.uuid4()),
            model_id=model_id,
            validated_at=ts,
            validator=validator,
            status=status,
            evidence_hash=evidence_hash,
            challenger_model_id=challenger_model_id,
            notes=notes[:500],
        )
        val.record_hmac = _compute_record_hmac(val.to_dict(), signing_key)
        rec.validation_history.append(val)
        rec.validation_status = status

        coso: COSOComponent = (
            "information_communication" if challenger_model_id else "risk_assessment"
        )
        self._add_control_point(
            control_id=f"AIML-RA-{val.validation_id[:8]}",
            coso_component=coso,
            description="Independent model validation performed per SR 11-7 §4.3",
            model_id=model_id,
            evidence_summary=f"validator={validator}, status={status.value}, "
            f"evidence_hash={evidence_hash[:16]}...",
            passed=status
            in (SR117ValidationStatus.APPROVED, SR117ValidationStatus.APPROVED_WITH_CONDITIONS),
            now=ts,
        )
        return val

    def approve_deployment(
        self,
        model_id: str,
        approver: str,
        now: float | None = None,
    ) -> ModelRecord:
        """Record deployment-gate approval.

        Raises :class:`KeyError` if not registered.
        Raises :class:`ValueError` if the model has not been validated (APPROVED
        or APPROVED_WITH_CONDITIONS) or is already decommissioned.
        """
        rec = self._models[model_id]
        if rec.decommissioned_at is not None:
            raise ValueError(f"Cannot approve decommissioned model: {model_id!r}")
        if rec.validation_status not in (
            SR117ValidationStatus.APPROVED,
            SR117ValidationStatus.APPROVED_WITH_CONDITIONS,
        ):
            raise ValueError(
                f"Model {model_id!r} must be validated before deployment approval. "
                f"Current status: {rec.validation_status.value}"
            )
        ts = now if now is not None else time.time()
        rec.deployment_approved_at = ts
        rec.deployment_approver = approver
        self._add_control_point(
            control_id=f"AIML-CA-{model_id[:16]}",
            coso_component="control_activities",
            description="Deployment gate approval — model cleared for production use",
            model_id=model_id,
            evidence_summary=f"approver={approver}",
            passed=True,
            now=ts,
        )
        return rec

    def decommission(
        self,
        model_id: str,
        reason: str = "",
        now: float | None = None,
    ) -> ModelRecord:
        """Record model decommission.

        Raises :class:`KeyError` if not registered.
        """
        rec = self._models[model_id]
        ts = now if now is not None else time.time()
        rec.decommissioned_at = ts
        rec.validation_status = SR117ValidationStatus.DECOMMISSIONED
        self._add_control_point(
            control_id=f"AIML-MON-{model_id[:16]}",
            coso_component="monitoring",
            description="Model decommissioned and removed from active inventory",
            model_id=model_id,
            evidence_summary=f"reason={reason[:200]}",
            passed=True,
            now=ts,
        )
        return rec

    # ── Reporting ─────────────────────────────────────────────────────────────

    def sox_control_report(self, signing_key: bytes, now: float | None = None) -> SOXControlReport:
        """Generate a SOX ICFR attestation report for all material models.

        Returns
        -------
        SOXControlReport
            Signed report with ``overall_effective`` True iff all material
            models are deployment-approved and have no REJECTED validations.
        """
        ts = now if now is not None else time.time()
        report_id = str(uuid.uuid4())
        material = [r for r in self._models.values() if r.material]
        overall = all(
            r.is_deployment_approved
            and r.validation_status
            not in (SR117ValidationStatus.REJECTED, SR117ValidationStatus.PENDING)
            for r in material
        )
        material_dicts = [m.to_dict() for m in material]
        cp_dicts = [cp.to_dict() for cp in self._control_points]

        canonical = json.dumps(
            {
                "report_id": report_id,
                "generated_at": ts,
                "material_models": material_dicts,
                "control_points": cp_dicts,
                "overall_effective": overall,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        bundle_hmac = _hmac_hex(signing_key, canonical)

        return SOXControlReport(
            report_id=report_id,
            generated_at=ts,
            material_models=material_dicts,
            control_points=cp_dicts,
            overall_effective=overall,
            bundle_hmac=bundle_hmac,
        )

    def get_model(self, model_id: str) -> ModelRecord:
        """Return the :class:`ModelRecord` for *model_id*.

        Raises :class:`KeyError` if not found.
        """
        return self._models[model_id]

    @property
    def model_ids(self) -> list[str]:
        """Sorted list of all registered model IDs."""
        return sorted(self._models)

    @property
    def control_points(self) -> list[SOXControlPoint]:
        """All accumulated control points (in insertion order)."""
        return list(self._control_points)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _add_control_point(
        self,
        control_id: str,
        coso_component: COSOComponent,
        description: str,
        model_id: str,
        evidence_summary: str,
        passed: bool,
        now: float | None = None,
    ) -> None:
        self._control_points.append(
            SOXControlPoint(
                control_id=control_id,
                coso_component=coso_component,
                description=description,
                model_id=model_id,
                evidenced_at=now if now is not None else time.time(),
                evidence_summary=evidence_summary,
                passed=passed,
            )
        )
