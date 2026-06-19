# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.observability — Prometheus metrics and OpenTelemetry span helpers.

Both backends are optional extras. The proxy starts and serves traffic whether
or not a collector is reachable — operators add the extras when deploying to
an observable environment.

Prometheus
----------
pip install prometheus-client           # or aegis-latent-core[metrics]
Metrics are registered at module import. Expose them via /metrics by calling
attach_prometheus_endpoint(app) in create_app().

OpenTelemetry
-------------
pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-grpc
                                        # or aegis-latent-core[otel]
Set OTEL_EXPORTER_OTLP_ENDPOINT before starting. Call setup_otel() once during
the lifespan to configure the trace provider.

Zero-forensic-latency claim
----------------------------
AUDIT_COMMIT_DURATION measures only WAL fsync time (background task, NOT on
the request path). REQUEST_DURATION.labels(stage="forward") measures only the
upstream HTTP call. The two series are independent: comparing their p99 values
proves (or refutes) the "zero forensic latency" isolation claim.

AUDIT_COMMIT_LAG adds queue-wait time, giving the full end-to-end delay
between a request arriving and its record being durably committed.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Generator
from typing import Any

# ── Prometheus ─────────────────────────────────────────────────────────────────

try:
    from prometheus_client import Counter, Gauge, Histogram

    _PROM = True
except ImportError:
    _PROM = False


if _PROM:
    REQUEST_TOTAL: Any = Counter(
        "aegis_requests_total",
        "Proxy requests by HTTP method, endpoint slug, and HTTP status class (2xx/4xx/5xx)",
        ["method", "endpoint", "status_class"],
    )
    REQUEST_DURATION: Any = Histogram(
        "aegis_request_duration_seconds",
        "Pipeline stage latency. stage=total is end-to-end (client-visible); "
        "stage=forward is upstream HTTP only; stage=waf and stage=ratelimit are "
        "sub-stages that do not include upstream I/O.",
        ["stage"],
        buckets=(0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0),
    )
    FORWARD_ERRORS: Any = Counter(
        "aegis_forward_errors_total",
        "Errors returned or raised during upstream forwarding, by failure stage",
        ["stage"],
    )
    WAF_BLOCKS: Any = Counter(
        "aegis_waf_blocks_total",
        "Requests blocked by WAF, labelled by WAF layer (layer1 or layer2)",
        ["layer"],
    )
    RATELIMIT_REJECTIONS: Any = Counter(
        "aegis_ratelimit_rejections_total",
        "Requests rejected by the rate limiter",
    )
    AUDIT_COMMIT_DURATION: Any = Histogram(
        "aegis_audit_commit_duration_seconds",
        "Wall-clock time for one WAL fsync (background task, NOT on the request path). "
        "Compare p99 here with REQUEST_DURATION{stage='forward'} to validate "
        "the zero-forensic-latency isolation claim.",
        buckets=(0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 5.0),
    )
    AUDIT_COMMIT_LAG: Any = Histogram(
        "aegis_audit_commit_lag_seconds",
        "Wall-clock lag from request arrival to audit node committed "
        "(queue wait + WAL fsync). Includes background-task scheduling overhead.",
        buckets=(0.010, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0, 30.0),
    )
    AUDIT_CHAIN_NODES: Any = Gauge(
        "aegis_audit_chain_nodes_total",
        "Total nodes in the in-memory audit chain (grows monotonically until eviction)",
    )
    AUDIT_PENDING_COMMITS: Any = Gauge(
        "aegis_audit_pending_commits",
        "Background commit tasks currently in flight",
    )
    AUDIT_COMMIT_ERRORS: Any = Counter(
        "aegis_audit_commit_errors_total",
        "Failures to commit an audit node to the WAL (proxy continues — fail-open policy)",
    )
    CIRCUIT_BREAKER_OPENS: Any = Counter(
        "aegis_circuit_breaker_opens_total",
        "Number of times the upstream circuit breaker transitioned to OPEN",
        ["provider"],
    )
    CIRCUIT_BREAKER_STATE: Any = Gauge(
        "aegis_circuit_breaker_state",
        "Current circuit breaker state: 0=CLOSED (healthy), 1=HALF_OPEN (probing), 2=OPEN (blocking)",
        ["provider"],
    )
else:
    # No-op stubs — identical API surface so callers never branch on _PROM.
    # All methods are silent no-ops; the proxy runs identically when
    # prometheus_client is not installed.
    class _NoopMetric:  # noqa: F811
        def labels(self, **_kw: Any) -> _NoopMetric:
            return self

        def inc(self, _amount: float = 1.0) -> None: ...

        def observe(self, _amount: float) -> None: ...

        def set(self, _value: float) -> None: ...

    REQUEST_TOTAL = _NoopMetric()
    REQUEST_DURATION = _NoopMetric()
    FORWARD_ERRORS = _NoopMetric()
    WAF_BLOCKS = _NoopMetric()
    RATELIMIT_REJECTIONS = _NoopMetric()
    AUDIT_COMMIT_DURATION = _NoopMetric()
    AUDIT_COMMIT_LAG = _NoopMetric()
    AUDIT_CHAIN_NODES = _NoopMetric()
    AUDIT_PENDING_COMMITS = _NoopMetric()
    AUDIT_COMMIT_ERRORS = _NoopMetric()
    CIRCUIT_BREAKER_OPENS = _NoopMetric()
    CIRCUIT_BREAKER_STATE = _NoopMetric()


def prometheus_available() -> bool:
    """True when prometheus_client is installed and metrics are active."""
    return _PROM


# ── OpenTelemetry ──────────────────────────────────────────────────────────────

try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.sdk.trace import TracerProvider as _TracerProvider

    _OTEL = True
except ImportError:
    _OTEL = False

_tracer: Any = None


def setup_otel(service_name: str = "aegis-proxy") -> None:
    """Configure the OTel trace provider. No-op when opentelemetry-sdk is absent.

    Reads OTEL_EXPORTER_OTLP_ENDPOINT from the environment. When unset, a
    no-export provider is registered — spans are created (trace_id is valid)
    but not shipped to a collector.
    """
    global _tracer
    if not _OTEL:
        return
    import os

    provider = _TracerProvider()
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        except ImportError:
            pass  # OTLP exporter not installed — spans created but not exported
    _otel_trace.set_tracer_provider(provider)
    _tracer = _otel_trace.get_tracer(service_name)


@contextlib.contextmanager
def record_span(name: str, **attributes: str) -> Generator[Any, None, None]:
    """Context manager that starts an OTel span. Yields None when OTel is absent.

    Callers should guard per-span attribute writes::

        with record_span("waf.check", session_id=sid) as sp:
            result = waf.inspect(payload)
            if sp:
                sp.set_attribute("waf.allowed", str(result.allowed))
    """
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as sp:
        for k, v in attributes.items():
            sp.set_attribute(k, v)
        yield sp


def current_trace_id() -> str | None:
    """Return the W3C hex trace-id of the currently active span, or None."""
    if not _OTEL:
        return None
    ctx = _otel_trace.get_current_span().get_span_context()
    if ctx is None or not ctx.is_valid:
        return None
    return format(ctx.trace_id, "032x")


# ── Stage timer ────────────────────────────────────────────────────────────────


class StageTimer:
    """Lightweight wall-clock timer for per-stage latency recording.

    Usage::

        timer = StageTimer()           # starts at construction
        # ... call upstream ...
        timer.record("forward")        # observes duration, resets clock
        # ... analyze response ...
        timer.record("analyze")        # records analysis stage

    ``record()`` returns elapsed seconds and resets the internal clock.
    ``elapsed()`` reads elapsed time without resetting or recording.
    """

    __slots__ = ("_start",)

    def __init__(self) -> None:
        self._start = time.perf_counter()

    def elapsed(self) -> float:
        return time.perf_counter() - self._start

    def record(self, stage: str) -> float:
        elapsed = self.elapsed()
        REQUEST_DURATION.labels(stage=stage).observe(elapsed)
        self.reset()
        return elapsed

    def reset(self) -> None:
        self._start = time.perf_counter()
