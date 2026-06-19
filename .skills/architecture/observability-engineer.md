---
name: observability-engineer
tier: HIGH
domains: [metrics, logs, traces, OpenTelemetry, RED, USE, SLI, dashboards, alerting]
---
## Activation
Load on: observability setup, instrumentation, OpenTelemetry, metrics/logs/traces design,
dashboard creation, alerting strategy, debugging production via telemetry.

## Three Pillars (all required, correlated)
```
Metrics:  aggregatable numbers over time. Cheap. "What is broken?"
          RED (services): Rate, Errors, Duration
          USE (resources): Utilization, Saturation, Errors
Logs:     discrete events with context. Expensive at volume. "Why is it broken?"
          Structured JSON; sampled on success; 100% on error
Traces:   request lifecycle across services. "Where is it broken?"
          OpenTelemetry; trace_id propagated; span per operation

Correlation: trace_id in every log line; exemplars linking metrics → traces
```

## Instrumentation Standards (OpenTelemetry)
```python
# Every service boundary = a span
from opentelemetry import trace, metrics
tracer = trace.get_tracer(__name__)
meter = metrics.get_meter(__name__)

# RED metrics — emit on every request
request_counter = meter.create_counter("http.server.requests")
request_duration = meter.create_histogram("http.server.duration", unit="ms")
error_counter = meter.create_counter("http.server.errors")

# Span with attributes (not in span name — high cardinality kills metrics)
with tracer.start_as_current_span("process_order") as span:
    span.set_attribute("order.id", order_id)        # attribute (searchable)
    span.set_attribute("order.value_cents", value)
    # span name stays low-cardinality: "process_order" not f"process_order_{id}"
```

## Metric Design Rules
```
Cardinality:   labels = bounded sets (status_code, region, endpoint_template)
               NEVER: user_id, order_id, timestamp as labels (cardinality explosion)
Naming:        namespace.subsystem.metric_unit (http.server.duration.ms)
Types:         counter (monotonic), gauge (point-in-time), histogram (distribution)
Histograms:    for latency (need percentiles); buckets tuned to SLO boundaries
```

## Dashboard Hierarchy
```
Level 1 — Service health (per service):
  RED: request rate, error rate %, p50/p95/p99 latency
  SLO: error budget remaining, burn rate

Level 2 — Resource health (per resource):
  USE: CPU/memory utilization, connection pool saturation, queue depth, disk I/O

Level 3 — Business metrics:
  Conversion rate, checkout success, signups, revenue — correlated with deploys

Level 4 — Dependency health:
  External API latency/errors, DB query time, cache hit rate
```

## Alerting Strategy (symptom-based, not cause-based)
```
Alert on symptoms (user-facing):
  "checkout error rate > 1% for 5 min" (symptom) ✓
  "CPU > 80%" (cause — may not affect users) ✗ (dashboard, not page)

Severity:
  Page (wake someone):  user-facing SLO breach, revenue impact, data loss risk
  Ticket (business hrs): degradation trending toward SLO breach, capacity warning
  Dashboard (no alert):  resource metrics, informational trends

Multi-window burn rate (avoid alert fatigue):
  fast (1h, burn > 14.4) → page    | slow (6h, burn > 6) → ticket

Anti-patterns:
  Alerting on every metric → fatigue → ignored alerts → missed real incidents
  No runbook link in alert → responder doesn't know what to do
```

## Log Hygiene
```
DO:    structured JSON, trace_id, level, service, duration_ms, user_id (if not PII-sensitive)
DON'T: PII in logs, secrets in logs, full request bodies, log-and-throw (double logging)
Levels: ERROR (action needed), WARN (anomaly), INFO (state change), DEBUG (off in prod)
Sampling: 100% errors, sample INFO at high volume (head or tail sampling)
Retention: hot 7-30d (searchable), cold/archive per compliance, cost-managed
```
