<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# SLO and error budget

**Audience:** operator, on-call engineer, and any customer asking what
availability means.
**Scope:** internal service-level objectives for the hosted evaluation console
and the self-hosted gateway reference deployment. This is **not** a customer
SLA.
**Boundary:** the numbers below are proposals with a named measurement and a
current baseline. No SLO has been agreed with a customer, and the live account
has no alarm or paging path yet.

> **[COUNSEL-REVIEW-REQUIRED]** Any customer-facing SLA must be a separate,
> signed document. Do not quote this page as a contractual commitment.

## 1. What is measured

| Service | SLI | Definition | Source |
| --- | --- | --- | --- |
| Hosted console API | availability | `2xx` and `3xx` responses ÷ all responses, excluding client `4xx` | Lambda access logs / CloudWatch |
| Hosted console API | latency | p95 of `GET /v1/plans` and authenticated `GET /v1/me` | CloudWatch `Duration`; synthetic probe |
| Hosted console | error rate | `5xx` ÷ all responses | CloudWatch `Errors` |
| Hosted console | saturation | `DatabaseConnections` ÷ ceiling; `Throttles` | CloudWatch RDS/Lambda |
| Self-hosted gateway | commit durability | governed response returned only after WAL commit | gateway contract tests; operator evidence |
| Self-hosted gateway | integrity | `/v1/audit/integrity` returns `valid: true` | gateway endpoint |

The self-hosted gateway's availability is the operator's responsibility. The
project can publish code and a reference configuration; it cannot promise a
customer's uptime.

## 2. Proposed internal objectives

These are **proposals**, not commitments:

| Objective | Target | Window | Consequence of miss |
| --- | --- | --- | --- |
| Console availability | 99.5% | 30 days | review, no automatic credit |
| Console p95 latency | < 2,500 ms | 30 days | investigate; scale or optimize |
| Console 5xx rate | < 0.5% | 30 days | freeze non-essential deploys |
| RDS connections | < 90 | continuous | alarm at 90; act before 112 |
| Backup restore drill | one successful restore per quarter | quarter | operations gate stays open |

99.5% allows about 3 h 39 m of unavailability in a 30-day month. It is chosen
because the current deployment is a single Lambda function plus a single-AZ
`db.t4g.micro`; a higher target would be a claim without redundancy.

## 3. Current baseline (measured, with boundary)

| Measurement | Value | Environment | Date | What it does not prove |
| --- | --- | --- | --- | --- |
| `/health` p50 | 2.16 ms at 50 req/s | loopback, local | 2026-10 | not network latency |
| `/v1/plans` p50 | 3.77 ms | loopback, local | 2026-10 | not cold start |
| `POST /v1/usage` p50 | 9.19 ms at 20 req/s | loopback, local | 2026-10 | not RDS production |
| Function URL p50 | 190.5 ms | AWS `us-east-1` | 2026-10 | one shape, not a percentile over a month |

The live console has **no** long-window availability measurement, no synthetic
probe, and no alarm delivery. The 99.5% objective is therefore unmeasured until
the observability stack is deployed and a 30-day window exists.

## 4. Error budget policy

- Budget = 100% − objective. At 99.5%, the monthly budget is 0.5%.
- If 50% of the budget is consumed in a week, the next non-essential deploy
  waits for a written cause and a fix.
- If 100% is consumed, feature work stops until the cause is fixed and a
  retrospective is recorded.
- A budget exclusion requires a named incident and an owner signature; do not
  silently exclude planned maintenance.

## 5. Alerts

The alarms in `aegis-cloud/deploy/aws/observability.yaml` cover errors,
throttles, p95 duration, RDS CPU/connections/storage/memory and budget. They do
not cover external availability or synthetic login. Until a synthetic check and
a paging rotation exist, an alarm is a dashboard signal, not an on-call
guarantee.

## 6. Open items

| Item | Owner | Blocks |
| --- | --- | --- |
| Deploy the alarm stack and confirm email delivery | operations | any SLO claim |
| Add synthetic `GET /health` and login probe from outside AWS | operations | availability SLI |
| Measure 30 days before quoting a target | operations | customer SLA discussion |
| Decide whether the console is single-AZ or multi-AZ | owner | 99.5% target |
| Record on-call rotation and escalation | owner | paging promise |
