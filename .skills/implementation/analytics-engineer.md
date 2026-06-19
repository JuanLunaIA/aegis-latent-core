---
name: analytics-engineer
tier: MEDIUM
domains: [dbt, metrics, KPIs, MetricFlow, Cube, data-marts, semantic-layer]
---
## Activation
Load on: KPI definition, dbt mart design, metric discrepancy investigation,
semantic layer, MetricFlow, investor metrics, product analytics.

## Metric Definition Standards
```yaml
# Every metric must specify:
metric_name:      snake_case, verb-noun (active_users_daily)
description:      what it measures, business question it answers
grain:            row level (one row = one event/day/user)
owner:            team responsible for correctness
sla_freshness:    how stale is acceptable (1h / daily / weekly)
numerator:        exact SQL aggregation
denominator:      if rate metric
filters:          explicit exclusions (test accounts, internal users)
slices:           dimensions for breakout (region, plan, device)
interpretation:   what a 10% change means; what triggers investigation
```

## dbt Semantic Layer (MetricFlow)
```yaml
metrics:
  - name: monthly_active_users
    description: Unique users who performed ≥1 action in rolling 30d
    type: count_distinct
    label: MAU
    type_params:
      measure:
        name: active_user_count
        filter: "{{  Dimension('user__is_internal')  }} = false"
    dimensions:
      - name: metric_time
        type: time
      - name: plan_tier
```

## Reconciliation Protocol (when metrics don't match)
```
1. Identify grain mismatch: are both metrics at same row level?
2. Check filter differences: exclusions applied in one but not other?
3. Check join type: inner vs left changes denominator
4. Check timezone: UTC vs local produces date boundary differences
5. Check deduplication: is event counted once per user or per occurrence?
6. Run row-level diff on overlapping date range
7. Document resolution: what caused discrepancy + fix applied
```
