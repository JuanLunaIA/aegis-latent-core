# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.model_decision_explainer — Basel-aligned model-decision explainability.

Records a structured explanation for each model inference involving a
regulated credit, insurance, or investment decision, satisfying:

- **Basel III / CRR2 Art. 144(b)**: banks must document the inputs and
  outputs of internal rating models; explanations must be auditable.
- **EU AI Act Art. 13 (Transparency)** and **Art. 14 (Human Oversight)**:
  high-risk AI systems (credit scoring, insurance pricing) must provide
  explanations sufficient for meaningful human oversight.
- **ECOA / Regulation B (US, 15 USC § 1691)**: adverse-action notices must
  state the principal reasons for credit denial — directly traceable to the
  model's stated rationale.
- **SR 11-7 (Federal Reserve)**: model documentation must include conceptual
  soundness evidence; per-inference explanations form part of ongoing
  monitoring evidence.

Each :class:`DecisionRecord` captures:

- **Input features** (hashed — no raw PII retained).
- **Decision**: approve / deny / refer / not_applicable.
- **Confidence score** (0.0–1.0).
- **Principal reasons**: ordered list of factors that drove the decision,
  required for adverse-action notices.
- **Counterfactual hint**: the single change most likely to flip a denial to
  an approval, supporting EU AI Act Art. 14 human-oversight obligations.
- **Model version** and **policy version** for audit traceability.
- **HMAC-SHA256 signature** (keyed by ``AEGIS_SIGNING_KEY``).

Usage::

    from aegis.core.model_decision_explainer import (
        DecisionOutcome,
        ModelDecisionExplainer,
    )
    import os

    explainer = ModelDecisionExplainer(
        model_id="aegis-credit-llm/v2",
        policy_version="2026-Q2",
        signing_key=os.environb[b"AEGIS_SIGNING_KEY"],
    )
    record = explainer.record(
        session_id=session_id,
        client_id=client_id,
        input_features={"income_band": "40k-60k", "dti_ratio": "0.38"},
        outcome=DecisionOutcome.DENY,
        confidence=0.87,
        principal_reasons=["debt_to_income_ratio_exceeds_threshold"],
        counterfactual_hint="Reducing monthly obligations by 15% may qualify.",
    )
    if not record.verify_hmac(os.environb[b"AEGIS_SIGNING_KEY"]):
        raise RuntimeError("Decision record integrity check failed")
"""

from __future__ import annotations

import hashlib
import hmac as _hmac_mod
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum

# ── Enumerations ──────────────────────────────────────────────────────────────


class DecisionOutcome(StrEnum):
    """Regulated credit/insurance decision outcomes."""

    APPROVE = "approve"
    DENY = "deny"
    REFER = "refer"
    NOT_APPLICABLE = "not_applicable"


class DecisionDomain(StrEnum):
    """Regulatory domain the decision falls under."""

    CREDIT = "credit"
    INSURANCE = "insurance"
    INVESTMENT = "investment"
    GENERAL = "general"


# ── DecisionRecord ────────────────────────────────────────────────────────────


@dataclass
class DecisionRecord:
    """Per-inference model-decision explainability record.

    Attributes
    ----------
    record_id:
        Unique UUID for this record.
    recorded_at:
        Unix timestamp (UTC) of the decision.
    session_id:
        Session identifier linking to the conversation log.
    client_id:
        Pseudonymous client identifier (no raw PII).
    model_id:
        Model that made the decision.
    policy_version:
        Version of the decision policy applied.
    domain:
        Regulatory domain (credit, insurance, investment, general).
    outcome:
        The decision: approve / deny / refer / not_applicable.
    confidence:
        Model confidence in the outcome (0.0–1.0).
    principal_reasons:
        Ordered list of the top factors driving the decision (max 5,
        required for ECOA adverse-action notices on DENY outcomes).
    counterfactual_hint:
        Human-readable description of the single change most likely to
        produce a more favourable outcome; empty string if none or APPROVE.
    input_feature_hashes:
        SHA-256 hashes of ``"key=value"`` pairs (no raw values stored),
        preserving audit traceability without PII retention.
    record_hmac:
        HMAC-SHA256 (hex) of the canonical JSON of this record (excluding
        ``record_hmac``), keyed by ``AEGIS_SIGNING_KEY``.
    """

    record_id: str
    recorded_at: float
    session_id: str
    client_id: str
    model_id: str
    policy_version: str
    domain: DecisionDomain
    outcome: DecisionOutcome
    confidence: float
    principal_reasons: list[str]
    counterfactual_hint: str
    input_feature_hashes: list[str]
    record_hmac: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "recorded_at": self.recorded_at,
            "session_id": self.session_id,
            "client_id": self.client_id,
            "model_id": self.model_id,
            "policy_version": self.policy_version,
            "domain": self.domain,
            "outcome": self.outcome,
            "confidence": self.confidence,
            "principal_reasons": self.principal_reasons,
            "counterfactual_hint": self.counterfactual_hint,
            "input_feature_hashes": self.input_feature_hashes,
            "record_hmac": self.record_hmac,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def verify_hmac(self, signing_key: bytes) -> bool:
        """Return ``True`` if the HMAC is valid for *signing_key*."""
        if not self.record_hmac:
            return False
        return _hmac_mod.compare_digest(
            _compute_record_hmac(self.to_dict(), signing_key), self.record_hmac
        )

    @property
    def requires_adverse_action_notice(self) -> bool:
        """True when ECOA / Reg B adverse-action reasons must be provided."""
        return self.outcome == DecisionOutcome.DENY and self.domain == DecisionDomain.CREDIT


# ── ExplainabilityExport ──────────────────────────────────────────────────────


@dataclass
class ExplainabilityExport:
    """Bundle of decision records for regulatory submission.

    Attributes
    ----------
    export_id:
        Unique UUID for this export.
    generated_at:
        Unix timestamp of export generation.
    model_id:
        Model that produced all records in this export.
    policy_version:
        Policy version applied across the records.
    records:
        The :class:`DecisionRecord` instances.
    record_count:
        Total number of records (convenience field).
    bundle_hmac:
        HMAC-SHA256 (hex) of the canonical export JSON.
    """

    export_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: float = field(default_factory=time.time)
    model_id: str = ""
    policy_version: str = ""
    records: list[DecisionRecord] = field(default_factory=list)
    record_count: int = 0
    bundle_hmac: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "export_id": self.export_id,
            "generated_at": self.generated_at,
            "model_id": self.model_id,
            "policy_version": self.policy_version,
            "records": [r.to_dict() for r in self.records],
            "record_count": self.record_count,
            "bundle_hmac": self.bundle_hmac,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def verify_bundle_hmac(self, signing_key: bytes) -> bool:
        """Return ``True`` if the bundle HMAC is intact."""
        payload = {
            "export_id": self.export_id,
            "generated_at": self.generated_at,
            "model_id": self.model_id,
            "policy_version": self.policy_version,
            "records": [r.to_dict() for r in self.records],
            "record_count": self.record_count,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        expected = _hmac_hex(signing_key, canonical)
        return _hmac_mod.compare_digest(expected, self.bundle_hmac)


# ── HMAC helpers ──────────────────────────────────────────────────────────────


def _hmac_hex(key: bytes, data: bytes) -> str:
    return _hmac_mod.new(key, data, hashlib.sha256).hexdigest()


def _hash_feature(key: str, value: str) -> str:
    return hashlib.sha256(f"{key}={value}".encode()).hexdigest()


def _compute_record_hmac(d: dict[str, object], signing_key: bytes) -> str:
    payload = {k: v for k, v in d.items() if k != "record_hmac"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return _hmac_hex(signing_key, canonical)


# ── ModelDecisionExplainer ────────────────────────────────────────────────────

_MAX_REASONS = 5
_MAX_HINT_LEN = 500


class ModelDecisionExplainer:
    """Create and sign per-inference model-decision explainability records.

    Parameters
    ----------
    model_id:
        Identifier of the model whose decisions are being recorded.
    policy_version:
        Version string for the decision policy applied (e.g. ``"2026-Q2"``).
    signing_key:
        Bytes key for HMAC-SHA256 signing (``AEGIS_SIGNING_KEY``).  If
        ``None``, records are created unsigned (``record_hmac == ""``).
    domain:
        Default regulatory domain for all records from this explainer.
    """

    def __init__(
        self,
        model_id: str,
        policy_version: str = "",
        signing_key: bytes | None = None,
        domain: DecisionDomain = DecisionDomain.GENERAL,
    ) -> None:
        self._model_id = model_id
        self._policy_version = policy_version
        self._signing_key = signing_key
        self._domain = domain
        self._records: list[DecisionRecord] = []

    def record(
        self,
        session_id: str,
        client_id: str,
        input_features: dict[str, str],
        outcome: DecisionOutcome,
        confidence: float,
        principal_reasons: list[str],
        counterfactual_hint: str = "",
        domain: DecisionDomain | None = None,
        signing_key: bytes | None = None,
        now: float | None = None,
    ) -> DecisionRecord:
        """Create, sign, and store a decision record.

        Parameters
        ----------
        session_id:
            Session identifier from the proxy.
        client_id:
            Pseudonymous client identifier.
        input_features:
            Dict of feature name → value.  Values are SHA-256 hashed before
            storage; raw values are never retained.
        outcome:
            The decision outcome.
        confidence:
            Model confidence (clamped to [0.0, 1.0]).
        principal_reasons:
            Ordered list of top factors (max 5 kept; required for DENY).
        counterfactual_hint:
            Narrative of the minimal change to flip an adverse decision.
            Truncated to 500 characters.
        domain:
            Override the explainer-level default domain.
        signing_key:
            Override the explainer-level signing key for this record.
        now:
            Unix timestamp override for testing.
        """
        ts = now if now is not None else time.time()
        key = signing_key if signing_key is not None else self._signing_key
        effective_domain = domain if domain is not None else self._domain
        feature_hashes = [_hash_feature(k, v) for k, v in input_features.items()]
        rec = DecisionRecord(
            record_id=str(uuid.uuid4()),
            recorded_at=ts,
            session_id=session_id,
            client_id=client_id,
            model_id=self._model_id,
            policy_version=self._policy_version,
            domain=effective_domain,
            outcome=outcome,
            confidence=max(0.0, min(1.0, confidence)),
            principal_reasons=principal_reasons[:_MAX_REASONS],
            counterfactual_hint=counterfactual_hint[:_MAX_HINT_LEN],
            input_feature_hashes=feature_hashes,
        )
        if key is not None:
            rec.record_hmac = _compute_record_hmac(rec.to_dict(), key)
        self._records.append(rec)
        return rec

    def export(
        self,
        signing_key: bytes | None = None,
        records: list[DecisionRecord] | None = None,
        now: float | None = None,
    ) -> ExplainabilityExport:
        """Bundle all (or selected) records into a signed export.

        Parameters
        ----------
        signing_key:
            Key for bundle HMAC; falls back to the explainer-level key.
        records:
            Subset of records to export; defaults to all.
        now:
            Unix timestamp override for testing.
        """
        ts = now if now is not None else time.time()
        key = signing_key if signing_key is not None else self._signing_key
        export_id = str(uuid.uuid4())
        recs = records if records is not None else list(self._records)

        payload = {
            "export_id": export_id,
            "generated_at": ts,
            "model_id": self._model_id,
            "policy_version": self._policy_version,
            "records": [r.to_dict() for r in recs],
            "record_count": len(recs),
        }
        bundle_hmac = ""
        if key is not None:
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            bundle_hmac = _hmac_hex(key, canonical)

        return ExplainabilityExport(
            export_id=export_id,
            generated_at=ts,
            model_id=self._model_id,
            policy_version=self._policy_version,
            records=recs,
            record_count=len(recs),
            bundle_hmac=bundle_hmac,
        )

    @property
    def records(self) -> list[DecisionRecord]:
        """All accumulated records (copy)."""
        return list(self._records)
