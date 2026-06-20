# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.observability — prometheus and OTel paths."""

from __future__ import annotations

import importlib
import sys
from contextlib import asynccontextmanager
from unittest.mock import MagicMock, patch

import pytest


# ── Prometheus paths (lines 46, 52-109) ───────────────────────────────────────


def test_observability_prometheus_paths_via_reload():
    """Reload the module with prometheus_client mocked to hit the _PROM=True branch."""
    mock_counter = MagicMock()
    mock_gauge = MagicMock()
    mock_histogram = MagicMock()

    mock_prom = MagicMock()
    mock_prom.Counter = mock_counter
    mock_prom.Gauge = mock_gauge
    mock_prom.Histogram = mock_histogram

    old_prom = sys.modules.get("prometheus_client")

    sys.modules["prometheus_client"] = mock_prom

    try:
        import aegis.core.observability as obs_mod
        importlib.reload(obs_mod)
        assert obs_mod._PROM is True
        assert obs_mod.prometheus_available() is True
    finally:
        if old_prom is None:
            sys.modules.pop("prometheus_client", None)
        else:
            sys.modules["prometheus_client"] = old_prom
        # Restore module to _PROM=False state
        importlib.reload(obs_mod)


# ── OTel paths (lines 151-153, 170-183, 200-203, 210-213) ────────────────────


def test_observability_otel_paths_via_reload():
    """Reload with opentelemetry mocked to cover _OTEL=True branch (lines 151-153)."""
    mock_otel_trace = MagicMock()
    mock_tracer_provider = MagicMock()

    mock_otel_mod = MagicMock()
    mock_otel_mod.trace = mock_otel_trace

    mock_sdk_trace = MagicMock()
    mock_sdk_trace.TracerProvider = mock_tracer_provider

    old_otel = sys.modules.get("opentelemetry")
    old_otel_trace = sys.modules.get("opentelemetry.trace")
    old_sdk = sys.modules.get("opentelemetry.sdk")
    old_sdk_trace = sys.modules.get("opentelemetry.sdk.trace")

    sys.modules["opentelemetry"] = mock_otel_mod
    sys.modules["opentelemetry.trace"] = mock_otel_trace
    sys.modules["opentelemetry.sdk"] = MagicMock()
    sys.modules["opentelemetry.sdk.trace"] = mock_sdk_trace

    try:
        import aegis.core.observability as obs_mod
        importlib.reload(obs_mod)
        assert obs_mod._OTEL is True
    finally:
        for key, val in [
            ("opentelemetry", old_otel),
            ("opentelemetry.trace", old_otel_trace),
            ("opentelemetry.sdk", old_sdk),
            ("opentelemetry.sdk.trace", old_sdk_trace),
        ]:
            if val is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = val
        importlib.reload(obs_mod)


def test_setup_otel_when_otel_enabled(monkeypatch):
    """setup_otel() body executes when _OTEL=True (lines 170-183)."""
    import aegis.core.observability as obs

    mock_provider = MagicMock()
    mock_provider_instance = MagicMock()
    mock_provider.return_value = mock_provider_instance

    mock_trace = MagicMock()

    monkeypatch.setattr(obs, "_OTEL", True)
    monkeypatch.setattr(obs, "_TracerProvider", mock_provider)
    monkeypatch.setattr(obs, "_otel_trace", mock_trace)

    obs.setup_otel("test-service")

    mock_trace.set_tracer_provider.assert_called_once_with(mock_provider_instance)
    mock_trace.get_tracer.assert_called_once_with("test-service")


def test_setup_otel_with_endpoint(monkeypatch):
    """setup_otel() with OTEL endpoint env var set exercises BatchSpanProcessor path."""
    import aegis.core.observability as obs
    import os

    mock_provider = MagicMock()
    mock_provider_instance = MagicMock()
    mock_provider.return_value = mock_provider_instance

    mock_trace = MagicMock()
    mock_exporter = MagicMock()
    mock_processor = MagicMock()
    mock_batch_cls = MagicMock(return_value=mock_processor)
    mock_exporter_cls = MagicMock(return_value=mock_exporter)

    monkeypatch.setattr(obs, "_OTEL", True)
    monkeypatch.setattr(obs, "_TracerProvider", mock_provider)
    monkeypatch.setattr(obs, "_otel_trace", mock_trace)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")

    mock_otlp_mod = MagicMock()
    mock_otlp_mod.OTLPSpanExporter = mock_exporter_cls
    mock_sdk_export = MagicMock()
    mock_sdk_export.BatchSpanProcessor = mock_batch_cls

    with patch.dict(sys.modules, {
        "opentelemetry.exporter.otlp.proto.grpc.trace_exporter": mock_otlp_mod,
        "opentelemetry.sdk.trace.export": mock_sdk_export,
    }):
        obs.setup_otel("test-service")

    mock_provider_instance.add_span_processor.assert_called_once()


def test_record_span_with_tracer_yields_span(monkeypatch):
    """record_span() with _tracer set follows the OTel path (lines 200-203)."""
    import aegis.core.observability as obs

    mock_span = MagicMock()
    mock_span.set_attribute = MagicMock()

    class _FakeCtx:
        def __enter__(self_):
            return mock_span
        def __exit__(self_, *a):
            pass

    mock_tracer = MagicMock()
    mock_tracer.start_as_current_span.return_value = _FakeCtx()
    monkeypatch.setattr(obs, "_tracer", mock_tracer)

    with obs.record_span("test.span", key="val") as sp:
        assert sp is mock_span

    mock_tracer.start_as_current_span.assert_called_once_with("test.span")
    mock_span.set_attribute.assert_called_once_with("key", "val")


def test_current_trace_id_when_otel_enabled(monkeypatch):
    """current_trace_id() executes OTel path when _OTEL=True (lines 210-213)."""
    import aegis.core.observability as obs

    mock_ctx = MagicMock()
    mock_ctx.is_valid = True
    mock_ctx.trace_id = 0x1234567890ABCDEF1234567890ABCDEF

    mock_span = MagicMock()
    mock_span.get_span_context.return_value = mock_ctx

    mock_trace = MagicMock()
    mock_trace.get_current_span.return_value = mock_span

    monkeypatch.setattr(obs, "_OTEL", True)
    monkeypatch.setattr(obs, "_otel_trace", mock_trace)

    result = obs.current_trace_id()
    assert result is not None
    assert isinstance(result, str)
    assert len(result) == 32
