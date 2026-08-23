# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Small typed tracing facade with strict W3C propagation and no content capture."""

from __future__ import annotations

import math
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-(0[01])$")
_TRACESTATE_MEMBER = re.compile(
    r"^[a-z0-9][a-z0-9_*/-]{0,255}(?:@[a-z0-9][a-z0-9_*/-]{0,13})?=[\x21-\x2b\x2d-\x3c\x3e-\x7e]{1,256}$"
)


class SpanName(StrEnum):
    GATEWAY_REQUEST = "aegis.gateway.request"
    POLICY_EVALUATION = "aegis.policy.evaluate"
    PROOF_VERIFICATION = "aegis.proof.verify"
    SIEM_EXPORT = "aegis.siem.export"


class SpanStatus(StrEnum):
    OK = "ok"
    ERROR = "error"


_ALLOWED_ATTRIBUTES = frozenset(
    {
        "aegis.operation",
        "aegis.outcome",
        "aegis.proof_status",
        "aegis.item_count",
        "aegis.duration_ms",
        "aegis.retry_count",
    }
)
_ALLOWED_TEXT = frozenset(
    {
        "gateway",
        "policy",
        "proof",
        "siem",
        "allowed",
        "denied",
        "succeeded",
        "failed",
        "verified",
        "invalid",
        "not_provided",
    }
)
AttributeValue = str | int | float | bool


@dataclass(frozen=True, slots=True)
class TraceContext:
    trace_id: str
    span_id: str
    sampled: bool = True
    tracestate: str | None = None

    def __post_init__(self) -> None:
        if not _valid_hex(self.trace_id, 32) or int(self.trace_id, 16) == 0:
            raise ValueError("trace_id must be a non-zero 32-character lowercase hex value")
        if not _valid_hex(self.span_id, 16) or int(self.span_id, 16) == 0:
            raise ValueError("span_id must be a non-zero 16-character lowercase hex value")
        if self.tracestate is not None and not _valid_tracestate(self.tracestate):
            raise ValueError("tracestate is not valid W3C tracestate")

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{'01' if self.sampled else '00'}"


@dataclass(frozen=True, slots=True)
class ExportedSpan:
    name: SpanName
    context: TraceContext
    parent_span_id: str | None
    started_ns: int
    ended_ns: int
    status: SpanStatus
    attributes: tuple[tuple[str, AttributeValue], ...] = field(default_factory=tuple)


class SpanExporter(Protocol):
    """Injected exporter; return true only after durable acknowledgement."""

    def export(self, spans: tuple[ExportedSpan, ...]) -> bool: ...

    def shutdown(self) -> None: ...


class TraceExportError(RuntimeError):
    """The exporter did not durably acknowledge a completed span."""


class TraceProvider:
    """Explicitly started provider that exports closed-schema spans."""

    def __init__(
        self, exporter: SpanExporter, *, clock_ns: Callable[[], int] = time.time_ns
    ) -> None:
        self._exporter = exporter
        self._clock_ns = clock_ns
        self._running = False
        self._lock = threading.Lock()
        self._export_failures = 0

    @property
    def export_failures(self) -> int:
        with self._lock:
            return self._export_failures

    def start(self) -> None:
        with self._lock:
            if self._running:
                raise RuntimeError("trace provider is already started")
            self._running = True

    def shutdown(self) -> None:
        with self._lock:
            was_running = self._running
            self._running = False
        if was_running:
            self._exporter.shutdown()

    @contextmanager
    def span(
        self,
        name: SpanName,
        *,
        parent: TraceContext | None = None,
        attributes: Mapping[str, AttributeValue] | None = None,
    ) -> Iterator[TraceContext]:
        with self._lock:
            if not self._running:
                raise RuntimeError("trace provider is not started")
        checked = _validate_attributes(attributes or {})
        context = TraceContext(
            trace_id=parent.trace_id if parent else secrets.token_hex(16),
            span_id=secrets.token_hex(8),
            sampled=parent.sampled if parent else True,
            tracestate=None,
        )
        started = self._clock_ns()
        status = SpanStatus.OK
        active_error = False
        try:
            yield context
        except BaseException:
            status = SpanStatus.ERROR
            active_error = True
            raise
        finally:
            ended = self._clock_ns()
            span = ExportedSpan(
                name=name,
                context=context,
                parent_span_id=parent.span_id if parent else None,
                started_ns=started,
                ended_ns=max(started, ended),
                status=status,
                attributes=checked,
            )
            try:
                acknowledged = self._exporter.export((span,))
            except Exception as exc:
                with self._lock:
                    self._export_failures += 1
                if not active_error:
                    raise TraceExportError("span exporter raised before acknowledgement") from exc
            else:
                if not acknowledged:
                    with self._lock:
                        self._export_failures += 1
                    if not active_error:
                        raise TraceExportError("span exporter did not acknowledge the span")


def parse_trace_context(carrier: Mapping[str, str]) -> TraceContext | None:
    """Parse strict W3C ``traceparent``/``tracestate`` headers."""

    headers = {key.lower(): value for key, value in carrier.items()}
    value = headers.get("traceparent")
    if value is None:
        return None
    match = _TRACEPARENT.fullmatch(value)
    if match is None:
        raise ValueError("invalid W3C traceparent")
    trace_id, span_id, flags = match.groups()
    try:
        return TraceContext(trace_id, span_id, flags == "01", headers.get("tracestate"))
    except ValueError as exc:
        raise ValueError("invalid W3C traceparent or tracestate") from exc


def inject_trace_context(context: TraceContext, carrier: MutableMapping[str, str]) -> None:
    """Inject validated W3C headers into a mutable text carrier."""

    if not isinstance(context, TraceContext):
        raise TypeError("context must be a TraceContext")
    carrier["traceparent"] = context.traceparent
    if context.tracestate is not None:
        carrier["tracestate"] = context.tracestate
    else:
        carrier.pop("tracestate", None)


def _validate_attributes(
    values: Mapping[str, AttributeValue],
) -> tuple[tuple[str, AttributeValue], ...]:
    result: list[tuple[str, AttributeValue]] = []
    for key, value in values.items():
        if key not in _ALLOWED_ATTRIBUTES:
            raise ValueError(f"attribute is not allowlisted: {key}")
        if isinstance(value, str):
            if value not in _ALLOWED_TEXT:
                raise ValueError(f"attribute value is not low-cardinality: {key}")
        elif isinstance(value, bool):
            result.append((key, value))
            continue
        elif isinstance(value, int):
            if value < 0:
                raise ValueError(f"attribute value cannot be negative: {key}")
        elif isinstance(value, float):
            if value < 0 or not math.isfinite(value):
                raise ValueError(f"attribute value must be finite and non-negative: {key}")
        else:
            raise TypeError(f"unsupported attribute type: {key}")
        result.append((key, value))
    return tuple(sorted(result))


def _valid_tracestate(value: str) -> bool:
    if len(value) > 512:
        return False
    members = [member.strip() for member in value.split(",")]
    return (
        1 <= len(members) <= 32
        and len(set(members)) == len(members)
        and all(_TRACESTATE_MEMBER.fullmatch(member) is not None for member in members)
    )


def _valid_hex(value: str, length: int) -> bool:
    return len(value) == length and all(character in "0123456789abcdef" for character in value)


__all__ = [
    "AttributeValue",
    "ExportedSpan",
    "SpanExporter",
    "SpanName",
    "SpanStatus",
    "TraceContext",
    "TraceExportError",
    "TraceProvider",
    "inject_trace_context",
    "parse_trace_context",
]
