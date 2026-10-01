<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
-->

# Observability Assets

**Audience:** the operator wiring Aegis into Prometheus and Grafana.
**Scope:** alert rules and a dashboard built only from metrics the gateway exports. They serve the "pilot dashboards and alert runbook exercised" gap in the TRL matrix.
**Boundary:** not exercised against a live deployment. Every metric name is checked against `aegis/core/observability.py` by a test; nothing has shown that the thresholds suit any workload, and the dashboard has never been loaded into Grafana in this repository.

| File | What it is |
| --- | --- |
| [`prometheus-alerts.yml`](prometheus-alerts.yml) | Fourteen alert rules in four groups. Eleven are the rules written out in [Monitoring and Alerting](../../docs/operations/MONITORING_ALERTING.md) §3; three are marked `EXTRA` |
| [`grafana-aegis-dashboard.json`](grafana-aegis-dashboard.json) | Twelve panels: traffic, latency, commit duration and lag, errors, outbox, WAF, rate limiting, streams, breaker and enforcement mode |

Load the rules with `rule_files:` in Prometheus and import the dashboard from the Grafana UI. Start with the critical alerts under evidence integrity: an evidence-commit failure is more urgent than a latency regression.

To check the assets against the code: `python -m pytest tests/test_observability_assets.py -q`.
