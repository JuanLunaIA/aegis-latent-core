# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Closed-schema, content-free telemetry events."""

from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SAFE_CORRELATION = re.compile(
    r"^(?:[0-9a-f]{32}|[0-9a-f]{64}|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)


class EventKind(StrEnum):
    POLICY_DECISION = "policy_decision"
    PROOF_VERIFICATION = "proof_verification"
    REQUEST_COMPLETED = "request_completed"
    EXPORT_HEALTH = "export_health"


class EventOutcome(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ProofState(StrEnum):
    VERIFIED = "verified"
    INVALID = "invalid"
    NOT_PROVIDED = "not_provided"


class Severity(IntEnum):
    DEBUG = 2
    INFO = 5
    WARNING = 7
    ERROR = 9
    CRITICAL = 10


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """A strictly typed projection containing no free-form sensitive fields."""

    kind: EventKind
    outcome: EventOutcome
    correlation_id: str
    severity: Severity = Severity.INFO
    proof_state: ProofState = ProofState.NOT_PROVIDED
    item_count: int = 0
    duration_ms: float = 0.0
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if _SAFE_IDENTIFIER.fullmatch(self.event_id) is None:
            raise ValueError("event_id must contain 1-128 safe characters")
        if _SAFE_CORRELATION.fullmatch(self.correlation_id) is None:
            raise ValueError("correlation_id must be a lowercase UUID, trace ID, or digest")
        if self.item_count < 0:
            raise ValueError("item_count cannot be negative")
        if self.duration_ms < 0 or not math.isfinite(self.duration_ms):
            raise ValueError("duration_ms must be a finite non-negative value")
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")


__all__ = ["EventKind", "EventOutcome", "ProofState", "SecurityEvent", "Severity"]
