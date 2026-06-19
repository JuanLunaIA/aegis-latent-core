---
name: sre-reliability
tier: HIGH
domains: [SLO, SLI, error-budget, chaos, capacity, postmortem, oncall, GameDay]
---

## Activation
Load on: SLO definition, error budget policy, chaos engineering, capacity planning,
postmortem writing, on-call setup, GameDay planning, reliability review.

## SLO Definition Framework
```
Step 1: User journey → NOT system metrics
  Wrong: "CPU < 80%"
  Right: "checkout flow completes in < 2s at p99 for 99.9% of requests"

Step 2: SLI formula (what to measure)
  Availability:  good_requests / total_requests (exclude expected 4xx)
  Latency:       requests_under_threshold / total_requests (p99 < 500ms)
  Freshness:     data_updated_within_SLA / total_data_points

Step 3: SLO target + window
  99.9% over 28-day rolling window
  Error budget: 0.1% × 28d × 24h × 60min = 40.3 minutes/month

Step 4: Error budget policy
  > 50% consumed: no new features; focus on reliability
  > 75% consumed: feature freeze; incident review
  100% consumed: post-incident review required before new deploys
```

## Multi-Burn-Rate Alerting
```
Fast burn (1h window):   burn rate > 14.4 → page immediately (consumes 2% budget in 1h)
Slow burn (6h window):   burn rate > 6 → ticket + investigation (consumes 5% budget in 6h)
Trend (3d window):       burn rate > 1 → watch (on track to exhaust budget)
```

## Chaos Engineering Protocol
```
1. Hypothesis: "Service X remains below SLO when Y fails"
2. Steady state: define measurable baseline (p99 latency, error rate)
3. Blast radius control: % traffic, single AZ, single pod, synthetic traffic only
4. Rollback verified BEFORE experiment starts
5. GameDay runbook: who, what, when, how to abort
6. Result: hypothesis confirmed / refuted + system improvement identified
```

## Postmortem Template (blameless)
```markdown
## Incident: [title]
Severity: P0/P1/P2 | Duration: Xh Ym | Impact: [users/revenue affected]

### Timeline (UTC, minute-by-minute)
HH:MM — [what happened / who did what]

### Root Cause
[Mechanism: X→Y because Z — not "Bob deployed bad code"]

### Contributing Factors (multi-causal)
- [System factor]: [how it contributed]
- [Process factor]: [how it contributed]

### What Went Well
- [Detection was fast because...]
- [Rollback worked because...]

### Action Items
| Item | Owner | Due | Priority |
|---|---|---|---|
| Add circuit breaker for DB pool | @eng | 2025-Q2 | HIGH |

### Lessons (distributable to other teams)
- [Pattern to adopt/avoid]
```

## Capacity Planning
```
Forecast method:  Holt-Winters (seasonal) or Prophet (trend + seasonality)
Headroom alert:   70% utilization → plan capacity increase
Lead time buffer: provision at 50% → alert at 70% → hard limit at 90%
Peak event prep:  load test at 3× expected peak; have pre-scaled fleet ready
Autoscaling:      SLO-aware (don't scale down during error budget burn)
```
