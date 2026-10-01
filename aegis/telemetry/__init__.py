# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""Privacy-preserving telemetry and SIEM export primitives."""

from aegis.telemetry.events import EventKind, EventOutcome, ProofState, SecurityEvent, Severity
from aegis.telemetry.otel import (
    ExportedSpan,
    SpanExporter,
    SpanName,
    SpanStatus,
    TraceContext,
    TraceExportError,
    TraceProvider,
    inject_trace_context,
    parse_trace_context,
)
from aegis.telemetry.siem import (
    HTTPSIEMSink,
    SIEMExporter,
    SIEMFormat,
    SIEMMessage,
    SIEMSink,
    serialize_event,
)

__all__ = [
    "EventKind",
    "EventOutcome",
    "ExportedSpan",
    "HTTPSIEMSink",
    "ProofState",
    "SIEMExporter",
    "SIEMFormat",
    "SIEMMessage",
    "SIEMSink",
    "SecurityEvent",
    "Severity",
    "SpanExporter",
    "SpanName",
    "SpanStatus",
    "TraceContext",
    "TraceExportError",
    "TraceProvider",
    "inject_trace_context",
    "parse_trace_context",
    "serialize_event",
]
