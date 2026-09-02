# Monitoring and Alerting

**Audience:** SRE, platform engineers, security operations.
**Scope:** the metrics the gateway exposes, what to alert on, and the logging policy.
**Boundary:** metric names below are read from `aegis/core/observability.py` in the checked-out source. Metrics require the optional `metrics` extra; without `prometheus-client` no `/metrics` endpoint is registered and every metric is a no-op stub. Alert thresholds here are starting points, not tuned values — no target-environment measurement exists to tune them against.

---

## 1. Enabling metrics

```bash
pip install 'aegis-latent-core[metrics]'
```

`/metrics` is registered only when `prometheus_client` is importable. Verify:

```bash
curl -s localhost:8080/metrics | head -5
```

`/health` deliberately carries no configuration values, so posture is on `/metrics` and not on `/health`.

## 2. Metrics reference

Names as implemented. Do not alert on a metric not in this table; it does not exist.

### Posture

| Metric | Type | Meaning |
| --- | --- | --- |
| `aegis_security_enforcement_mode` | Gauge | `1` strict, `0` development. No labels, no config values. |

### Requests

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `aegis_requests_total` | Counter | `method`, `endpoint`, `status_class` | Proxy requests by HTTP status class |
| `aegis_request_duration_seconds` | Histogram | `stage` | `total` is end-to-end; `forward` is upstream only; `waf` and `ratelimit` are sub-stages excluding upstream I/O |
| `aegis_forward_errors_total` | Counter | `stage` | Upstream forwarding failures |

### Evidence

| Metric | Type | Meaning |
| --- | --- | --- |
| `aegis_audit_commit_duration_seconds` | Histogram | Time to commit one node |
| `aegis_audit_commit_lag_seconds` | Histogram | Request arrival to durable evidence completion |
| `aegis_audit_commit_errors_total` | Counter | Failed commits |
| `aegis_audit_chain_nodes_total` | Gauge | Nodes in the retained chain |
| `aegis_audit_pending_commits` | Gauge | Background commit tasks in flight |
| `aegis_native_stream_wal_errors_total` | Counter | Auxiliary Rust WAL append failures. JSONL remains authoritative, so this is degradation, not evidence loss |
| `aegis_wal_replication_lag_bytes` | Gauge | Replication lag where configured |

### Security

| Metric | Type | Meaning |
| --- | --- | --- |
| `aegis_waf_blocks_total` | Counter | Requests blocked by the WAF |
| `aegis_ratelimit_rejections_total` | Counter | Requests rejected by rate limiting |
| `aegis_ratelimit_backend_errors_total` | Counter | Rate-limit backend failures |

### Streaming and analysis

| Metric | Type | Meaning |
| --- | --- | --- |
| `aegis_stream_duration_seconds` | Histogram | Admitted stream lifetime |
| `aegis_stream_tokens_total` | Counter | Tokens emitted |
| `aegis_stream_redactions_total` | Counter | Redactions applied in stream |
| `aegis_analysis_queue_rejections_total` | Counter | Enrichment rejected by the bounded queue |
| `aegis_analysis_errors_total` | Counter | Analysis worker errors |
| `aegis_background_scheduling_jitter_seconds` | Histogram | Delay between enqueue and execution |

### Resilience

| Metric | Type | Meaning |
| --- | --- | --- |
| `aegis_circuit_breaker_state` | Gauge | Breaker state |
| `aegis_circuit_breaker_opens_total` | Counter | Breaker open transitions |

## 3. Alerts

Ordered by what they mean for evidence, not by conventional severity.

### Evidence integrity — page immediately

```yaml
- alert: AegisDevelopmentModeInGovernedEnvironment
  expr: aegis_security_enforcement_mode == 0
  for: 1m
  labels: {severity: critical}
  annotations:
    summary: "Gateway is running in development mode"
    description: >
      Required authentication, durable evidence, distributed limiting and
      kernel controls are relaxed. Traffic served in this window is not
      governed. Runbook: docs/security/INCIDENT_RESPONSE.md

- alert: AegisAuditCommitErrors
  expr: rate(aegis_audit_commit_errors_total[5m]) > 0
  for: 2m
  labels: {severity: critical}
  annotations:
    summary: "Evidence commits are failing"
    description: >
      Governed responses may be refused. Check WAL storage capacity, mount
      state, and whether a second writer took the path.
```

An evidence-commit failure is more urgent than a latency regression. A slow gateway is a degraded service; a gateway that cannot commit is either refusing traffic or, worse, serving it unevidenced.

### Evidence health — page during hours

```yaml
- alert: AegisAuditCommitLagHigh
  expr: histogram_quantile(0.99, rate(aegis_audit_commit_lag_seconds_bucket[10m])) > 1
  for: 10m
  labels: {severity: warning}
  annotations:
    summary: "p99 evidence commit lag above 1s"
    description: >
      Starting threshold, not a tuned value. Establish your own baseline.
      Investigate storage and fsync latency before adding replicas.
      Runbook: docs/operations/BACKPRESSURE_RUNBOOK.md

- alert: AegisPendingCommitsGrowing
  expr: aegis_audit_pending_commits > 100
  for: 5m
  labels: {severity: warning}

- alert: AegisNativeStreamWalErrors
  expr: rate(aegis_native_stream_wal_errors_total[15m]) > 0
  for: 15m
  labels: {severity: info}
  annotations:
    summary: "Auxiliary native WAL failing; JSONL remains authoritative"
```

### Security

```yaml
- alert: AegisWafBlockSpike
  expr: rate(aegis_waf_blocks_total[5m]) > 3 * rate(aegis_waf_blocks_total[1h] offset 1h)
  for: 10m
  labels: {severity: warning}
  annotations:
    summary: "WAF block rate well above its own recent baseline"

- alert: AegisRateLimitBackendErrors
  expr: rate(aegis_ratelimit_backend_errors_total[5m]) > 0
  for: 5m
  labels: {severity: warning}
  annotations:
    summary: "Rate-limit backend failing; requests fail closed at 503"
```

### Availability

```yaml
- alert: AegisCircuitBreakerOpen
  expr: aegis_circuit_breaker_state > 0
  for: 5m
  labels: {severity: warning}

- alert: AegisAnalysisQueueSaturated
  expr: rate(aegis_analysis_queue_rejections_total[5m]) > 0
  for: 10m
  labels: {severity: info}
  annotations:
    summary: "Enrichment rejected; governed calls unaffected"
```

The chart can render burn-rate SLO rules; see `deploy/helm/templates/prometheusrule.yaml`, disabled by default. Those require the Prometheus Operator and an approved SLO definition, and an SLO you have not agreed is not an SLO.

## 4. Logging policy

**Payloads are not logged by default, and must not be enabled in a governed deployment.** The WAL is the evidence store; application logs are for operations. Duplicating payloads into logs creates an uncontrolled second copy of sensitive data with none of the WAL's integrity properties and none of its retention controls.

| Never log | Instead |
| --- | --- |
| Prompt or response content | The evidence record ID |
| API keys, signing keys, backend credentials | The principal pseudonym |
| Raw tenant identifiers where pseudonyms exist | The pseudonym |
| Full WAL records | The node hash |
| Personal data of any kind | A reference |

**Log level.** `AEGIS_LOG_LEVEL=INFO` for governed deployments. `DEBUG` may surface configuration and request detail and is not appropriate outside local development.

**What to log:** request IDs, principal pseudonyms, status codes, stage durations, control decisions (WAF block, rate-limit rejection, admission refusal), evidence outcomes by ID, and startup posture.

**SIEM.** `aegis/telemetry/siem.py` exports a closed schema that excludes content fields and raw identity values. Downstream delivery, retention, access control and response remain your responsibility.

## 5. Dashboards

A useful dashboard answers, in this order:

1. **Is evidence being committed?** Commit rate, error rate, p99 lag, pending commits.
2. **What posture is running?** `aegis_security_enforcement_mode` per replica. A mixed fleet is a finding.
3. **Is traffic being governed or rejected?** Requests by status class, WAF blocks, rate-limit rejections.
4. **Is the upstream healthy?** Forward errors, breaker state, forward-stage latency.
5. **Are bounds being hit?** Queue rejections, stream duration, scheduling jitter.

The forensic dashboard under `dashboard/` reads the audit API for ledger, proof and integrity views. It parses an allowlist from the current `/metrics` scrape and shows current values only — it has no historical query contract and does not represent a snapshot as history. See [dashboard/README.md](../../dashboard/README.md).

## 6. What monitoring does not establish

- Metric absence is not evidence of correctness. A metric that never increments may mean the code path is unreachable.
- Alerts firing is not incident detection. Detection needs someone reading them.
- These metrics say nothing about whether the WAL is intact on disk. That needs `verify_integrity()`; see [Incident Response](../security/INCIDENT_RESPONSE.md).
- No threshold here is validated against a target deployment, because no such measurement exists.

---

**Related:** [Deployment Profiles](DEPLOYMENT_PROFILES.md) · [Backpressure Runbook](BACKPRESSURE_RUNBOOK.md) · [Incident Response](../security/INCIDENT_RESPONSE.md) · [Storage Requirements](STORAGE_REQUIREMENTS.md) · [Data Retention](../privacy/DATA_RETENTION.md)
