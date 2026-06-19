---
name: lsm-storage-ops
tier: HIGH
domains: [RocksDB, LSM-tree, append-only, WAL, audit-storage, durability, backpressure]
---
## Activation
Load on: LSM storage design, RocksDB tuning, append-only audit log, WAL durability,
local-tier persistence, write amplification, audit node storage at scale.

## Why LSM for Audit Logs (mechanism)
```
[ESTABLISHED] Audit logs are append-heavy, read-rarely (until audit/export). LSM-trees
(RocksDB) optimize exactly this: sequential writes to memtable → flush to immutable SSTables.
X→Y because Z: append-only audit workload → LSM is optimal because writes are sequential
(no in-place update, no B-tree page splits), matching the access pattern's write dominance.

"Lock-free" correction: RocksDB writes are NOT lock-free — they use a write batch + WAL.
What you get is HIGH write throughput via group commit, not lock-freedom. Claim "high
sequential write throughput", not "lock-free".
```

## RocksDB Configuration for Audit Nodes
```python
# Python: rocksdict or python-rocksdb
import rocksdict
opts = rocksdict.Options()
opts.create_if_missing(True)
# Audit-log tuning:
opts.set_write_buffer_size(64 * 1024 * 1024)        # 64MB memtable before flush
opts.set_max_write_buffer_number(4)                  # allow 4 memtables (absorb write bursts)
opts.set_compression_type(rocksdict.DBCompressionType.zstd())  # zstd: good ratio, fast
opts.set_level_compaction_dynamic_level_bytes(True)  # reduce write amplification
# Durability: WAL is on by default. For audit, NEVER disable WAL.
# X→Y because Z: WAL on → crash-recoverable because every write is logged before memtable ack.
write_opts = rocksdict.WriteOptions()
write_opts.set_sync(False)  # async WAL: fast; fsync batched by OS
# For compliance requiring durability guarantee per-node: set_sync(True) (slower, fsync per write)
```

## WAL Corruption Recovery (the F-07 class fix)
```
[INFERENCE] A corrupt WAL line halting startup is a recovery-policy gap. RocksDB offers
wal_recovery_mode — choose explicitly:

  kTolerateCorruptedTailRecords (default): truncate at first corruption in tail (last record
    may be lost on crash — acceptable; that write wasn't acked). RECOMMENDED for audit.
  kAbsoluteConsistency: any corruption = refuse to open (too strict — one bad byte = outage).
  kPointInTimeRecovery: recover up to last consistent point.
  kSkipAnyCorruptedRecords: skip all corrupt records (data loss risk — avoid for audit).

X→Y because Z: kTolerateCorruptedTailRecords → no startup halt on crash because only the
unacked tail record is dropped, and that record's write never returned success to the caller.

Recovery test: inject a truncated/garbled byte into the WAL, restart, assert the DB opens
and all ACKED nodes are present.
```

## Dual-Tier Architecture (local LSM + async replication)
```
[ANALYSIS] Tier design that is real (not magic):

  Tier 1 (hot, local):  RocksDB on local NVMe. Every audit node written here FIRST.
                        Provides: instant durable local persistence, single-node source of truth.
  Tier 2 (analytical):  ClickHouse, fed by async batch replication FROM the LSM log.
                        Provides: SQL analytics, compliance queries, cross-node aggregation.

Replication is ASYNC with at-least-once delivery + idempotent upsert (node_id is the key).
X→Y because Z: async replication → local writes don't block on ClickHouse because the LSM
ack is independent of downstream ingestion; backpressure handled by the replication queue.

Failure policy (MUST be explicit):
  ClickHouse down → LSM keeps accepting writes; replication queue buffers; alert on lag.
  LSM disk full   → fail CLOSED on audit writes (audit completeness > availability for
                    a compliance product) OR fail open with loud alert — this is a PRODUCT
                    decision; document it. Do not leave it implicit.
```

## Edge-Case Matrix & Recovery
| Scenario | Detection Signature | Recovery Protocol |
|---|---|---|
| WAL corrupt tail on restart | RocksDB open error / corruption log | wal_recovery_mode=kTolerateCorruptedTailRecords; unacked tail dropped; ACKED nodes intact |
| LSM disk full | write returns IOError; disk usage metric > 95% | Per policy: fail-closed (reject audit writes, 503) or fail-open+alert; never silent loss; compaction to reclaim; expand volume |
| Compaction stall (write stall) | RocksDB write stall metric; p99 write latency spike | Increase max_write_buffer_number; check L0 file count trigger; throttle ingestion via backpressure |
| Replication lag to ClickHouse | replication queue depth rising; CH ingest errors | Buffer in queue; batch larger; if CH down, persist queue to disk; alert; never drop (at-least-once) |
| Duplicate node on replay (at-least-once) | Same node_id ingested twice | Idempotent: ClickHouse ReplacingMergeTree on node_id, or dedup on insert; at-least-once + idempotent = effectively-once |
