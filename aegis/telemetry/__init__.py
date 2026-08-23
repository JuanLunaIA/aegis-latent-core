# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
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
