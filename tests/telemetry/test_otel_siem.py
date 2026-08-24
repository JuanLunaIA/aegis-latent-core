# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
import stat
import threading
import time
from dataclasses import FrozenInstanceError, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.telemetry.events import EventKind, EventOutcome, ProofState, SecurityEvent, Severity
from aegis.telemetry.otel import (
    ExportedSpan,
    SpanName,
    TraceContext,
    TraceExportError,
    TraceProvider,
    inject_trace_context,
    parse_trace_context,
)
from aegis.telemetry.siem import SIEMExporter, SIEMFormat, SIEMMetricsSnapshot, serialize_event

SENTINEL = "PROMPT_RESPONSE_EXCEPTION_SECRET_7f3d"


@dataclass
class SpanCollector:
    spans: list[ExportedSpan] = field(default_factory=list)
    closed: bool = False

    def export(self, spans: tuple[ExportedSpan, ...]) -> bool:
        self.spans.extend(spans)
        return True

    def shutdown(self) -> None:
        self.closed = True


@dataclass
class Sink:
    statuses: list[int | Exception]
    payloads: list[bytes] = field(default_factory=list)

    def send(self, payload: bytes, content_type: str) -> int:
        self.payloads.append(payload)
        status = self.statuses.pop(0) if self.statuses else 204
        if isinstance(status, Exception):
            raise status
        return status


def event(index: int = 1) -> SecurityEvent:
    return SecurityEvent(
        EventKind.PROOF_VERIFICATION,
        EventOutcome.SUCCEEDED,
        f"{index:032x}",
        Severity.INFO,
        ProofState.VERIFIED,
        item_count=index,
        duration_ms=1.25,
        event_id=f"event-{index}",
        occurred_at=datetime(2026, 8, 23, tzinfo=UTC),
    )


def test_w3c_round_trip_and_validation() -> None:
    context = TraceContext("1" * 32, "2" * 16, True, "vendor=value")
    carrier: dict[str, str] = {}
    inject_trace_context(context, carrier)
    assert parse_trace_context(carrier) == context
    with pytest.raises(ValueError, match="traceparent"):
        parse_trace_context({"traceparent": "00-" + "0" * 32 + "-" + "2" * 16 + "-01"})
    with pytest.raises(ValueError, match="traceparent"):
        parse_trace_context({"traceparent": SENTINEL})


def test_provider_lifecycle_allowlist_and_no_exception_text() -> None:
    collector = SpanCollector()
    provider = TraceProvider(collector)
    with pytest.raises(RuntimeError, match="not started"):
        with provider.span(SpanName.GATEWAY_REQUEST):
            pass
    provider.start()
    with pytest.raises(ValueError, match="allowlisted"):
        with provider.span(SpanName.GATEWAY_REQUEST, attributes={"prompt": SENTINEL}):
            pass
    try:
        with pytest.raises(RuntimeError, match=SENTINEL):
            with provider.span(
                SpanName.GATEWAY_REQUEST,
                attributes={"aegis.outcome": "failed", "aegis.item_count": 2},
            ):
                raise RuntimeError(SENTINEL)
    finally:
        provider.shutdown()
    assert collector.closed
    assert collector.spans[0].status.value == "error"
    assert SENTINEL not in repr(collector.spans)


def test_inbound_tracestate_is_not_exported() -> None:
    collector = SpanCollector()
    provider = TraceProvider(collector)
    provider.start()
    parent = TraceContext("1" * 32, "2" * 16, True, "vendor=opaque-identifier")
    with provider.span(SpanName.GATEWAY_REQUEST, parent=parent):
        pass
    provider.shutdown()
    assert collector.spans[0].context.tracestate is None
    assert "opaque-identifier" not in repr(collector.spans)


def test_all_siem_serializers_are_content_free_and_well_formed() -> None:
    for output_format in SIEMFormat:
        message = serialize_event(event(), output_format)
        assert SENTINEL.encode() not in message.payload
        assert b"00000000000000000000000000000001" in message.payload
    cef = serialize_event(event(), SIEMFormat.CEF).payload.decode()
    assert cef.startswith("CEF:0|Aegis|Aegis Gateway|")
    rfc = serialize_event(event(), SIEMFormat.RFC5424).payload.decode()
    assert rfc.startswith("<")
    assert "[aegis@32473 " in rfc
    splunk = json.loads(serialize_event(event(), SIEMFormat.SPLUNK).payload)
    assert splunk["source"] == "aegis:security"
    with pytest.raises(TypeError, match="SecurityEvent"):
        serialize_event({"prompt": SENTINEL}, SIEMFormat.CEF)  # type: ignore[arg-type]


def test_rejects_arbitrary_correlation_text() -> None:
    with pytest.raises(ValueError, match="UUID, trace ID, or digest"):
        SecurityEvent(
            EventKind.POLICY_DECISION,
            EventOutcome.DENIED,
            r"corr|=]\value",
            event_id="event-escape",
            occurred_at=datetime(2026, 8, 23, tzinfo=UTC),
        )


def test_siem_metrics_snapshot_is_immutable_content_free_and_observes_quota(
    tmp_path: Path,
) -> None:
    exporter = SIEMExporter(
        Sink([]),
        tmp_path / "quota.sqlite3",
        queue_capacity=1,
        max_spool_rows=1,
    )

    assert exporter.submit(event(1)) is True
    assert exporter.submit(event(2)) is False

    snapshot = exporter.metrics_snapshot()
    assert snapshot == SIEMMetricsSnapshot(
        accepted=1,
        rejected=1,
        delivered=0,
        retried=0,
        pending=1,
    )
    assert SENTINEL not in repr(snapshot)
    assert event(1).correlation_id not in repr(snapshot)
    assert event(1).event_id not in repr(snapshot)
    with pytest.raises(FrozenInstanceError):
        snapshot.accepted = 2  # type: ignore[misc]


def test_siem_metrics_discard_exception_text_and_observe_acknowledgement(tmp_path: Path) -> None:
    exporter = SIEMExporter(
        Sink([RuntimeError(SENTINEL), 204]),
        tmp_path / "retry.sqlite3",
        retry_base_seconds=0.01,
        retry_max_seconds=0.01,
    )

    assert exporter.submit(event()) is True
    exporter.start()
    assert exporter.flush(2)
    exporter.shutdown()

    snapshot = exporter.metrics_snapshot()
    assert snapshot == SIEMMetricsSnapshot(
        accepted=1,
        rejected=0,
        delivered=1,
        retried=1,
        pending=0,
    )
    assert SENTINEL not in repr(snapshot)


def test_concurrent_start_creates_exactly_one_worker(tmp_path: Path) -> None:
    exporter = SIEMExporter(Sink([204]), tmp_path / "concurrent-start.sqlite3")
    barrier = threading.Barrier(3)
    outcomes: list[str] = []
    outcomes_lock = threading.Lock()

    def start_exporter() -> None:
        barrier.wait()
        try:
            exporter.start()
            outcome = "started"
        except RuntimeError:
            outcome = "rejected"
        with outcomes_lock:
            outcomes.append(outcome)

    workers = [threading.Thread(target=start_exporter) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join(2)

    assert sorted(outcomes) == ["rejected", "started"]
    exporter.shutdown(drain=False)


def test_spool_mode_queue_bound_retry_ack_and_restart_replay(tmp_path: Path) -> None:
    spool = tmp_path / "events.sqlite3"
    failing = Sink([500] * 100)
    first = SIEMExporter(
        failing,
        spool,
        queue_capacity=1,
        retry_base_seconds=0.01,
        retry_max_seconds=0.02,
    )
    assert first.submit(event(1)) is True
    assert first.submit(event(2)) is True
    assert first.queue_size <= first.queue_capacity
    assert first.pending_count() == 2
    assert first.metrics_snapshot() == SIEMMetricsSnapshot(
        accepted=2,
        rejected=0,
        delivered=0,
        retried=0,
        pending=2,
    )
    assert stat.S_IMODE(spool.stat().st_mode) == 0o600
    first.start()
    deadline = time.monotonic() + 1
    while not failing.payloads and time.monotonic() < deadline:
        time.sleep(0.01)
    first.shutdown(drain=False)
    assert first.pending_count() == 2

    successful = Sink([204, 200])
    second = SIEMExporter(
        successful,
        spool,
        queue_capacity=1,
        retry_base_seconds=0.01,
        retry_max_seconds=0.02,
    )
    second.start()
    assert second.flush(2)
    second.shutdown()
    assert second.pending_count() == 0
    assert second.metrics_snapshot() == SIEMMetricsSnapshot(
        accepted=0,
        rejected=0,
        delivered=2,
        retried=0,
        pending=0,
    )
    assert len(successful.payloads) == 2
    assert all(SENTINEL.encode() not in payload for payload in successful.payloads)


def test_negative_span_ack_is_visible() -> None:
    collector = SpanCollector()
    collector.export = lambda spans: False  # type: ignore[method-assign]
    provider = TraceProvider(collector)
    provider.start()
    with pytest.raises(TraceExportError, match="did not acknowledge"):
        with provider.span(SpanName.SIEM_EXPORT):
            pass
    assert provider.export_failures == 1
    provider.shutdown()
