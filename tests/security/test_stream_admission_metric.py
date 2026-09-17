# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""StreamAdmissionGate's concurrency ceiling must be observable on /metrics.

REG-050: the gate (``aegis/proxy/streaming.py``) already caps concurrent
streams and therefore the FD/memory a slow-drip client can hold open, but an
operator had no runtime signal for how close the process sits to that
ceiling, or how often it has been refused. ``guarded_stream`` releases a slot
from its own ``finally`` and deliberately does not import ``observability``
(the module boundary that owns every other metric write lives in
``aegis/proxy/app.py``), so the gauges are wired with ``set_function`` at gate
construction rather than pushed on every acquire/release — reading the
gate's own counters lazily at scrape time.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from aegis.config import AegisSettings
from aegis.core import observability
from aegis.proxy.app import create_app
from aegis.proxy.streaming import StreamAdmissionFullError, StreamAdmissionGate

_ACTIVE_METRIC = "aegis_stream_admission_active"
_REJECTED_METRIC = "aegis_stream_admission_rejected_total"


class _Recorder:
    """Stand-in for a Gauge that records the function bound via set_function."""

    def __init__(self) -> None:
        self.fn: Callable[[], float] | None = None

    def set_function(self, fn: Callable[[], float]) -> None:
        self.fn = fn


def _settings(tmp_path, name: str) -> AegisSettings:
    return AegisSettings(
        security_enforcement_mode="development",
        wal_path=str(tmp_path / name),
        backend_api_key="k",
    )


def _close(app) -> None:
    try:
        app.state.aegis.ledger.close()
    except Exception:  # pragma: no cover - best-effort teardown
        pass


def test_gate_gauges_wired_via_set_function(tmp_path, monkeypatch):
    """create_app must bind both gauges to callables that read the live gate."""
    active_recorder = _Recorder()
    rejected_recorder = _Recorder()
    monkeypatch.setattr(observability, "STREAM_ADMISSION_ACTIVE", active_recorder)
    monkeypatch.setattr(observability, "STREAM_ADMISSION_REJECTED", rejected_recorder)

    app = create_app(_settings(tmp_path, "gate.wal.jsonl"))
    try:
        assert active_recorder.fn is not None
        assert rejected_recorder.fn is not None
        assert active_recorder.fn() == 0
        assert rejected_recorder.fn() == 0

        app.state.aegis.stream_gate.acquire()
        assert active_recorder.fn() == 1

        app.state.aegis.stream_gate.release()
        assert active_recorder.fn() == 0
    finally:
        _close(app)


def test_gate_gauges_reflect_rejections(tmp_path, monkeypatch):
    """A refusal must be visible without any push call from the reject site."""
    active_recorder = _Recorder()
    rejected_recorder = _Recorder()
    monkeypatch.setattr(observability, "STREAM_ADMISSION_ACTIVE", active_recorder)
    monkeypatch.setattr(observability, "STREAM_ADMISSION_REJECTED", rejected_recorder)

    app = create_app(_settings(tmp_path, "gate-reject.wal.jsonl"))
    try:
        app.state.aegis.stream_gate = StreamAdmissionGate(limit=1)
        app.state.aegis.stream_gate.acquire()
        with pytest.raises(StreamAdmissionFullError):
            app.state.aegis.stream_gate.acquire()

        # The recorder's captured function still closes over the original
        # `app.state.aegis` object, whose `.stream_gate` attribute was
        # reassigned above -- proving the gauge reads live state, not a
        # snapshot taken at construction time.
        assert rejected_recorder.fn() == 1
    finally:
        _close(app)


def test_gauges_accept_writes_without_prometheus():
    """The no-op stub must satisfy the same call, so imports stay optional."""
    observability.STREAM_ADMISSION_ACTIVE.set_function(lambda: 0)
    observability.STREAM_ADMISSION_REJECTED.set_function(lambda: 0)


@pytest.mark.skipif(
    not observability.prometheus_available(), reason="prometheus_client is not installed"
)
def test_registry_reflects_live_gate_state(tmp_path):
    """End-to-end: the real gauges, not stand-ins, track the real gate."""
    from prometheus_client import REGISTRY

    app = create_app(_settings(tmp_path, "gate-e2e.wal.jsonl"))
    try:

        def _read(metric_name: str) -> float:
            for metric in REGISTRY.collect():
                if metric.name != metric_name:
                    continue
                assert len(metric.samples) == 1
                return metric.samples[0].value
            raise AssertionError(f"{metric_name} is not registered")

        assert _read(_ACTIVE_METRIC) == 0
        assert _read(_REJECTED_METRIC) == 0

        app.state.aegis.stream_gate.acquire()
        try:
            assert _read(_ACTIVE_METRIC) == 1
        finally:
            app.state.aegis.stream_gate.release()

        assert _read(_ACTIVE_METRIC) == 0

        app.state.aegis.stream_gate = StreamAdmissionGate(limit=1)
        app.state.aegis.stream_gate.acquire()
        with pytest.raises(StreamAdmissionFullError):
            app.state.aegis.stream_gate.acquire()
        assert _read(_REJECTED_METRIC) == 1
    finally:
        _close(app)
