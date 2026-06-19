---
name: data-pipeline-architect
tier: MEDIUM
domains: [ETL, ELT, Airflow, Dagster, dbt, Spark, Kafka, Flink, data-quality, lakehouse]
---

## Activation
Load on: data pipeline design, Airflow/Dagster DAG review, dbt model design,
streaming architecture, data quality framework, lakehouse design, lineage, SLA.

## Pipeline Design Principles
```
Idempotency:    re-running produces same result; no duplicates; upsert not append
Backfill:       every pipeline handles full historical re-run without manual intervention
Incremental:    watermark-based or CDC; never full-table scans beyond Tier 1 scale
Observability:  row count + null rate + freshness SLA on every output table
Partitioning:   by ingest date AND business date (filter pushdown critical)
```

## Airflow / Dagster Patterns
```python
# DAG design rules
- One DAG per bounded context; never mega-DAGs with 50+ tasks
- Tasks: atomic, idempotent, < 5 min execution time
- Sensors: use deferrable operators (async); never blocking sensor loops
- XCom: small metadata only (< 1MB); never pass DataFrames via XCom
- Connections: via Airflow Connections / Dagster Resources; no hardcoded credentials
- Alerts: SLA miss callback + on_failure_callback per critical task
```

## dbt Standards
```yaml
# Every model must have:
description: what this model represents, grain, update frequency
columns: each with description + tests (not_null + unique on PK)
tags: [source_system, domain, tier (bronze/silver/gold)]

# Model layering (medallion):
sources/     → bronze: raw ingestion, schema-on-read, immutable
staging/     → silver: typed, deduped, renamed, validated
intermediate/→ business logic, joins, aggregations
marts/       → gold: business-ready, denormalized, documented for BI
```

## Data Quality Framework
```
Completeness:  null rate per column with threshold alert (null_rate < 0.01)
Freshness:     max(updated_at) < now() - SLA (alert if stale)
Uniqueness:    PK uniqueness test on every fact/dimension table
Referential:   FK relationships validated (dbt relationships test)
Distribution:  z-score on key metrics; alert on > 3σ deviation
Volume:        row count range per partition; alert on > 20% deviation
Schema:        dbt compile on schema change detection; no silent breaking changes
```

## Streaming Architecture (Kafka / Flink)
```
Kafka:
  Topics:       one per event type; naming: domain.entity.event_type
  Partitioning: by entity_id for ordering guarantee per entity
  Retention:    7 days minimum; compacted topics for state
  Schema:       Confluent Schema Registry (Avro/Protobuf); compatibility BACKWARD
  Consumer:     consumer group per application; commit after processing, not before

Flink:
  Checkpoints:  every 60s; incremental; RocksDB state backend
  Watermarks:   bounded-out-of-orderness (max 5s for real-time, 1h for batch)
  Windows:      tumbling for aggregations; session for user journeys
  Exactly-once: enable only when sink supports it (Kafka → transactional producer)
```
