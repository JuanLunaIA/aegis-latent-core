# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.pii_confidence — PII confidence scoring per response with block/flag/log actions.

Wraps the best-effort PHI identifier regex engine in
:mod:`aegis.core.phi_deidentifier` with a configurable action-threshold layer:

* **BLOCK** — highest-confidence PII entity ≥ ``block_threshold``; response
  must not be released.
* **FLAG**  — highest confidence ≥ ``flag_threshold`` (but below ``block``);
  response passes but is annotated with a warning and recorded in audit.
* **LOG**   — all entities below ``flag_threshold`` or none detected; response
  passes and the evaluation is recorded in the normal audit trail.

This module is transport-agnostic: the FastAPI response path calls
:meth:`PIIConfidenceFilter.evaluate` and inspects the returned
:class:`PIIConfidenceResult` to decide whether to return an error, add a
warning header, or allow the response unmodified.

Privacy risk rationale
----------------------
Even a redacted response may
contain residual PII with non-zero detection confidence.  A fixed action (always
scrub or always pass) is too coarse for regulated pipelines.  The
threshold-based model lets each deployment tune the boundary between
productivity and safety. It does not establish HIPAA de-identification or Part 11 compliance.

Usage::

    filter_ = PIIConfidenceFilter()
    result = filter_.evaluate("The patient SSN is 123-45-6789")
    if result.action is PIIAction.BLOCK:
        raise HTTPException(403, detail=result.reason)
    elif result.action is PIIAction.FLAG:
        response.headers["X-Aegis-PII-Warning"] = result.reason
    # else: LOG — record to audit and continue normally

    # From environment variables:
    filter_ = PIIConfidenceFilter.from_config()  # reads AEGIS_PII_BLOCK_THRESHOLD etc.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum

from aegis.core.phi_deidentifier import PHIDeidentifier


class PIIAction(StrEnum):
    """Action selected by the confidence gate for a response."""

    BLOCK = "block"
    FLAG = "flag"
    LOG = "log"


@dataclass(frozen=True)
class PIIConfidenceThreshold:
    """Per-action confidence thresholds (0.0–1.0).

    Parameters
    ----------
    block:
        Confidence at or above this value causes a BLOCK decision.
    flag:
        Confidence at or above this value (but below *block*) causes FLAG.
    """

    block: float = 0.95
    flag: float = 0.80

    def __post_init__(self) -> None:
        for name, val in (("block", self.block), ("flag", self.flag)):
            if not 0.0 <= val <= 1.0:
                raise ValueError(f"PIIConfidenceThreshold.{name} must be in [0, 1], got {val!r}")
        if self.flag > self.block:
            raise ValueError(
                f"flag threshold ({self.flag}) must not exceed block threshold ({self.block})"
            )


@dataclass
class PIIConfidenceResult:
    """Outcome of a PII confidence evaluation.

    Attributes
    ----------
    text:
        The original (un-scrubbed) response text.  No PHI is stored here —
        the text reference is passed through for caller convenience only.
    action:
        The selected :class:`PIIAction` (BLOCK / FLAG / LOG).
    max_confidence:
        The highest entity-level confidence score that influenced the decision.
        0.0 when no PII was detected.
    entity_scores:
        Map of ``{category_label: confidence}`` for every detected entity.
    entity_hits:
        Map of ``{category_label: count}`` (number of matches per category).
    triggered_label:
        The category label whose confidence drove the action decision.
        Empty string when no PII was detected.
    reason:
        Human-readable explanation for audit logging.
    """

    text: str
    action: PIIAction
    max_confidence: float
    entity_scores: dict[str, float] = field(default_factory=dict)
    entity_hits: dict[str, int] = field(default_factory=dict)
    triggered_label: str = ""
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.action is PIIAction.BLOCK

    @property
    def flagged(self) -> bool:
        return self.action is PIIAction.FLAG

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action.value,
            "max_confidence": self.max_confidence,
            "triggered_label": self.triggered_label,
            "entity_scores": self.entity_scores,
            "entity_hits": self.entity_hits,
            "reason": self.reason,
        }


class PIIConfidenceFilter:
    """Response-level PII confidence scorer with configurable action thresholds.

    Detects PII entities in response text, computes per-entity confidence
    scores, selects the highest, and maps it to a BLOCK / FLAG / LOG action
    based on configurable thresholds.

    Unlike :class:`~aegis.core.phi_deidentifier.PHIDeidentifier`, this class
    does **not** modify the text — it evaluates and classifies, leaving the
    caller to decide how to handle each action.

    Parameters
    ----------
    threshold:
        The :class:`PIIConfidenceThreshold` governing when to block/flag/log.
    deidentifier:
        Optional pre-built :class:`~aegis.core.phi_deidentifier.PHIDeidentifier`
        instance.  A default instance is constructed when omitted.
    """

    def __init__(
        self,
        threshold: PIIConfidenceThreshold | None = None,
        deidentifier: PHIDeidentifier | None = None,
    ) -> None:
        self._threshold = threshold or PIIConfidenceThreshold()
        self._deidentifier = deidentifier or PHIDeidentifier()

    # ── Evaluation ───────────────────────────────────────────────────────────

    def evaluate(self, text: str) -> PIIConfidenceResult:
        """Evaluate a single response text for PII confidence.

        Parameters
        ----------
        text:
            Raw response text (not yet scrubbed).

        Returns
        -------
        PIIConfidenceResult
            Contains the action decision and all entity-level metadata.
        """
        if not text:
            return PIIConfidenceResult(
                text=text,
                action=PIIAction.LOG,
                max_confidence=0.0,
                reason="empty text; no PII evaluation performed",
            )

        _result, audit = self._deidentifier.scrub_with_audit(text)

        if not audit.entity_hits:
            return PIIConfidenceResult(
                text=text,
                action=PIIAction.LOG,
                max_confidence=0.0,
                reason="no PII entities detected",
            )

        entity_scores = audit.confidence_scores
        triggered_label = max(entity_scores, key=lambda k: entity_scores[k])
        max_conf = entity_scores[triggered_label]

        action, reason = self._select_action(triggered_label, max_conf)
        return PIIConfidenceResult(
            text=text,
            action=action,
            max_confidence=max_conf,
            entity_scores=dict(entity_scores),
            entity_hits=dict(audit.entity_hits),
            triggered_label=triggered_label,
            reason=reason,
        )

    def evaluate_messages(self, messages: list[dict[str, object]]) -> list[PIIConfidenceResult]:
        """Evaluate a list of chat message dicts.

        Each dict is expected to have a ``"content"`` string key.  Messages
        without string content are returned with a LOG / no-PII result.

        Returns one :class:`PIIConfidenceResult` per message, in order.
        """
        results: list[PIIConfidenceResult] = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                results.append(self.evaluate(content))
            else:
                results.append(
                    PIIConfidenceResult(
                        text="",
                        action=PIIAction.LOG,
                        max_confidence=0.0,
                        reason="non-string content; no PII evaluation performed",
                    )
                )
        return results

    def worst_case(self, results: list[PIIConfidenceResult]) -> PIIConfidenceResult:
        """Return the highest-severity result from a list of evaluations.

        Useful when evaluating a multi-message response and needing a single
        action for the whole batch: returns the BLOCK result if any message
        was blocked, then FLAG, then LOG.
        """
        priority = {PIIAction.BLOCK: 2, PIIAction.FLAG: 1, PIIAction.LOG: 0}
        return max(results, key=lambda r: priority[r.action])

    # ── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls) -> PIIConfidenceFilter:
        """Construct from environment variables.

        Variables
        ---------
        ``AEGIS_PII_BLOCK_THRESHOLD``
            Float in [0, 1]; default ``0.95``.
        ``AEGIS_PII_FLAG_THRESHOLD``
            Float in [0, 1]; default ``0.80``.
        """
        block = float(os.environ.get("AEGIS_PII_BLOCK_THRESHOLD", "0.95"))
        flag = float(os.environ.get("AEGIS_PII_FLAG_THRESHOLD", "0.80"))
        return cls(threshold=PIIConfidenceThreshold(block=block, flag=flag))

    # ── Internal ─────────────────────────────────────────────────────────────

    def _select_action(self, label: str, confidence: float) -> tuple[PIIAction, str]:
        t = self._threshold
        if confidence >= t.block:
            return (
                PIIAction.BLOCK,
                f"{label} confidence {confidence:.2f} ≥ block threshold {t.block:.2f}",
            )
        if confidence >= t.flag:
            return (
                PIIAction.FLAG,
                f"{label} confidence {confidence:.2f} ≥ flag threshold {t.flag:.2f}",
            )
        return (
            PIIAction.LOG,
            f"{label} confidence {confidence:.2f} below flag threshold {t.flag:.2f}",
        )
