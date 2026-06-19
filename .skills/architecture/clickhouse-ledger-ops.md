---
name: clickhouse-ledger-ops
tier: MEDIUM
domains: [ClickHouse, columnar, audit-analytics, MergeTree, partitioning, compliance-query]
---
## Activation
Load on: ClickHouse schema for audit, columnar audit streaming, compliance analytical queries,
MergeTree partitioning, audit log aggregation at scale, time-series audit storage.

## Why ClickHouse for the Analytical Tier (mechanism)
```
[ESTABLISHED] Audit analytics = scan large time ranges, aggregate (count by model, entropy
distribution, compliance windows). Columnar storage reads only queried columns.
X→Y because Z: columnar + sparse primary index → fast range scans because only the columns
in the query are read from disk and partition pruning skips irrelevant time ranges, vs a
row store that reads full rows.
```

## Schema (real, with engine choice rationale)
```sql
-- ReplacingMergeTree: idempotent ingestion (at-least-once replication safe)
-- X→Y because Z: ReplacingMergeTree on node_id → duplicate replays deduped because
--   the engine collapses rows with the same sorting key on background merge.
CREATE TABLE audit_nodes (
    node_id           String,                    -- sha256(root || signature)
    prev_hash         String,
    merkle_root       String,
    signature         String,                    -- ML-DSA-65 sig (or HMAC) — base64
    sig_algo          LowCardinality(String),    -- 'ml-dsa-65' | 'hmac-sha256'
    key_epoch         UInt32,                    -- for key rotation segments
    entropy_bits      Float32,
    entropy_method    LowCardinality(String),    -- 'logprobs' | 'char' | 'onnx-surprise'
    model             LowCardinality(String),
    provider          LowCardinality(String),
    prompt_tokens     UInt32,
    completion_tokens UInt32,
    ts                DateTime64(3, 'UTC'),       -- millisecond precision
    ingested_at       DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(ts)                          -- monthly partitions: prune by compliance window
ORDER BY (ts, node_id)                             -- sorting key: time-range queries + dedup key
TTL toDateTime(ts) + INTERVAL 7 YEAR;             -- retention per compliance (adjust)

-- LowCardinality: model/provider/algo are small enumerable sets → dictionary-encoded,
-- X→Y because Z: LowCardinality → smaller storage + faster filter because repeated string
--   values are stored once and referenced by integer id.
```

## Compliance Query Patterns
```sql
-- Compliance export window (SOC2/HIPAA audit period)
SELECT node_id, merkle_root, signature, sig_algo, model, ts
FROM audit_nodes
WHERE ts BETWEEN '2026-01-01 00:00:00' AND '2026-12-31 23:59:59'
ORDER BY ts;   -- partition pruning skips non-2026 partitions automatically

-- Entropy anomaly detection (potential hallucination spikes)
SELECT toStartOfHour(ts) AS hr, model,
       quantile(0.5)(entropy_bits) AS p50, quantile(0.99)(entropy_bits) AS p99,
       countIf(entropy_bits > 4.0) AS high_entropy_count
FROM audit_nodes
WHERE ts >= now() - INTERVAL 24 HOUR
GROUP BY hr, model ORDER BY hr;

-- Chain continuity check (gaps in prev_hash linkage)
SELECT node_id, prev_hash, ts
FROM audit_nodes
WHERE prev_hash NOT IN (SELECT node_id FROM audit_nodes) AND key_epoch > 0
ORDER BY ts;   -- non-empty result (excluding genesis) = chain break to investigate
```

## Ingestion (async batch from LSM tier)
```
Pattern:  buffer N nodes (or T seconds) in the replicator → single async INSERT batch.
X→Y because Z: batched INSERT → high ingest throughput because ClickHouse is optimized for
  bulk inserts (1000s of rows), and per-row inserts create excessive small parts (merge storm).
Use async_insert=1 for high-frequency small batches, or buffer client-side (preferred).
Settings: max_insert_block_size tuned; wait_for_async_insert=0 for fire-and-forget with
  at-least-once semantics (the LSM tier remains the durable source of truth).
```

## Edge-Case Matrix & Recovery
| Scenario | Detection Signature | Recovery Protocol |
|---|---|---|
| Ingestion pool exhaustion | INSERT errors; "too many parts"; merge backlog | Increase batch size (fewer larger inserts); enable async_insert; check merge settings; LSM tier buffers meanwhile |
| Duplicate rows from replay | Same node_id, multiple rows pre-merge | ReplacingMergeTree dedups on merge; use FINAL in critical queries or OPTIMIZE; idempotent by design |
| Partition explosion | 1000s of tiny partitions; slow queries | Verify PARTITION BY granularity (monthly, not daily/hourly); merge small parts |
| Clock skew (ts out of order) | Nodes with ts earlier than predecessor | ClickHouse tolerates out-of-order; flag at analytics layer; rely on node_id/prev_hash for chain order, ts for analytics only |
| ClickHouse total outage | All INSERTs failing | LSM tier (source of truth) keeps serving; replicator queues to disk; backfill on recovery; analytics degraded, audit intact |
