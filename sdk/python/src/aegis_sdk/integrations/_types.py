# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Privacy-preserving types shared by optional framework integrations."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from aegis_sdk.proof import AegisProofError, verify_proof_headers


class ProofStatus(StrEnum):
    """Result of portable Aegis proof verification."""

    NOT_PROVIDED = "not_provided"
    VERIFIED = "verified"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class IntegrationMetric:
    """Content-free framework callback metric.

    The deliberately closed schema makes it impossible to attach prompts,
    responses, tokens, embeddings, nodes, metadata, or exception messages.
    """

    framework: str
    operation: str
    correlation_id: str
    parent_correlation_id: str | None
    duration_ms: float
    input_count: int
    output_count: int
    failed: bool
    proof_status: ProofStatus


class MetricSink(Protocol):
    """Destination for content-free callback metrics."""

    def emit(self, metric: IntegrationMetric) -> None: ...


class MemoryMetricSink:
    """Thread-safe bounded metric sink suitable for local aggregation."""

    def __init__(self, capacity: int = 1024) -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self._metrics: deque[IntegrationMetric] = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def emit(self, metric: IntegrationMetric) -> None:
        if not isinstance(metric, IntegrationMetric):
            raise TypeError("metric must be an IntegrationMetric")
        with self._lock:
            self._metrics.append(metric)

    def snapshot(self) -> tuple[IntegrationMetric, ...]:
        with self._lock:
            return tuple(self._metrics)


@dataclass(slots=True)
class _PendingMetric:
    started_ns: int
    operation: str
    parent_id: str | None
    input_count: int


class PrivacyCallbackCore:
    """Framework-neutral timing and proof-verification state machine."""

    _OPERATIONS = frozenset(
        {"llm", "chat", "chain", "tool", "retriever", "embedding", "query", "agent", "other"}
    )

    def __init__(
        self,
        framework: str,
        sink: MetricSink | None = None,
        *,
        trusted_root: str | None = None,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        max_pending: int = 4096,
        pending_ttl_seconds: float = 600.0,
    ) -> None:
        if max_pending < 1 or pending_ttl_seconds <= 0:
            raise ValueError("pending callback bounds must be positive")
        self._framework = framework
        self._sink = sink if sink is not None else MemoryMetricSink()
        self._trusted_root = trusted_root
        self._clock_ns = clock_ns
        self._pending: dict[str, _PendingMetric] = {}
        self._lock = threading.Lock()
        self._max_pending = max_pending
        self._pending_ttl_ns = int(pending_ttl_seconds * 1_000_000_000)
        self._sink_failures = 0

    @property
    def sink(self) -> MetricSink:
        return self._sink

    @property
    def sink_failures(self) -> int:
        with self._lock:
            return self._sink_failures

    def begin(
        self, correlation_id: object, operation: str, input_count: int, parent_id: object = None
    ) -> str:
        identifier = _correlation_id(correlation_id)
        parent = None if parent_id is None else _correlation_id(parent_id)
        normalized = operation if operation in self._OPERATIONS else "other"
        now = self._clock_ns()
        pending = _PendingMetric(now, normalized, parent, max(0, input_count))
        with self._lock:
            expired = [
                key
                for key, value in self._pending.items()
                if now - value.started_ns >= self._pending_ttl_ns
            ]
            for key in expired:
                del self._pending[key]
            if identifier not in self._pending and len(self._pending) >= self._max_pending:
                del self._pending[next(iter(self._pending))]
            self._pending[identifier] = pending
        return identifier

    def finish(
        self,
        correlation_id: object,
        *,
        output_count: int = 0,
        failed: bool = False,
        proof_headers: Mapping[str, str] | None = None,
    ) -> IntegrationMetric:
        identifier = _correlation_id(correlation_id)
        ended_ns = self._clock_ns()
        with self._lock:
            pending = self._pending.pop(identifier, None)
        if pending is None:
            pending = _PendingMetric(ended_ns, "other", None, 0)
        metric = IntegrationMetric(
            framework=self._framework,
            operation=pending.operation,
            correlation_id=identifier,
            parent_correlation_id=pending.parent_id,
            duration_ms=max(0.0, (ended_ns - pending.started_ns) / 1_000_000),
            input_count=pending.input_count,
            output_count=max(0, output_count),
            failed=failed,
            proof_status=self._verify(proof_headers),
        )
        try:
            self._sink.emit(metric)
        except Exception:
            with self._lock:
                self._sink_failures += 1
        return metric

    def _verify(self, headers: Mapping[str, str] | None) -> ProofStatus:
        if headers is None or self._trusted_root is None:
            return ProofStatus.NOT_PROVIDED
        try:
            verify_proof_headers(headers, self._trusted_root)
        except (AegisProofError, KeyError, TypeError, ValueError):
            return ProofStatus.INVALID
        return ProofStatus.VERIFIED


def item_count(value: object) -> int:
    """Count top-level items without reading or retaining their contents."""

    if value is None:
        return 0
    if isinstance(value, (str, bytes, bytearray)):
        return 1
    if isinstance(value, Mapping):
        return len(value)
    if isinstance(value, Sequence):
        return len(value)
    return 1


def proof_headers(value: object) -> Mapping[str, str] | None:
    """Accept only an explicitly supplied string-to-string proof header map."""

    if not isinstance(value, Mapping):
        return None
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        return None
    return value


def _correlation_id(value: object) -> str:
    """Return a bounded opaque identifier, never a representation of content."""

    if value is None:
        return "unassigned"
    text = str(value)
    if 1 <= len(text) <= 128 and all(
        character.isalnum() or character in "-_.:" for character in text
    ):
        return text
    raise ValueError("correlation identifiers must be 1-128 safe characters")


__all__ = [
    "IntegrationMetric",
    "MemoryMetricSink",
    "MetricSink",
    "PrivacyCallbackCore",
    "ProofStatus",
    "item_count",
    "proof_headers",
]
