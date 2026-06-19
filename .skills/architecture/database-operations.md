---
name: database-operations
tier: HIGH
domains: [migrations, zero-downtime, schema-change, replication, backup, sharding, DBA]
---
## Activation
Load on: schema migration, zero-downtime deploy, large table alteration, replication setup,
backup/restore strategy, sharding, connection pooling, database operations at scale.

## Zero-Downtime Migration: Expand-Contract Pattern
```
Goal: schema changes without breaking running application (old + new code coexist)

EXPAND phase (backward-compatible additions):
  - Add new column as NULLABLE (never NOT NULL with default on large table — locks)
  - Add new table
  - Add index CONCURRENTLY (Postgres — no table lock)
  - Backfill data in batches (1000-10000 rows; throttled; off-peak)

MIGRATE phase (dual-write):
  - Deploy code that writes to BOTH old and new schema
  - Backfill historical data while dual-writing
  - Verify data consistency between old and new

CONTRACT phase (remove old):
  - Deploy code that reads/writes ONLY new schema
  - Verify no code references old schema
  - Drop old column/table (separate deploy, after confidence window)

Each phase = separate deploy. Never combine expand + contract in one release.
```

## Dangerous Operations (lock the table — avoid on large tables)
```
DANGER (full table lock or rewrite):
  ALTER TABLE ... ADD COLUMN ... NOT NULL DEFAULT (rewrites table pre-PG11)
  ALTER TABLE ... ALTER COLUMN TYPE (rewrites table)
  CREATE INDEX (without CONCURRENTLY — locks writes)
  ADD CONSTRAINT (validates all rows — locks)

SAFE alternatives:
  ADD COLUMN nullable → backfill batched → add NOT NULL via NOT VALID + VALIDATE
  CREATE INDEX CONCURRENTLY (no write lock; slower; can't be in transaction)
  ADD CONSTRAINT ... NOT VALID → VALIDATE CONSTRAINT (separate, non-blocking)
  Type change: add new column → dual-write → backfill → swap → drop old
```

## Migration Safety Checklist
```
[ ] Reversible: down migration tested in staging (or documented why irreversible)
[ ] Lock analysis: no ACCESS EXCLUSIVE lock on tables > 1M rows during business hours
[ ] Batch size: backfills in chunks with sleep; monitor replication lag
[ ] Timeout: statement_timeout set; lock_timeout set (fail fast vs block forever)
[ ] Replication: lag monitored during migration; pause if lag > threshold
[ ] Rollback plan: documented; tested; < 5 min to execute
[ ] Backup: verified recent backup before destructive migration
```

## Backup & Recovery Standards
```
RPO (Recovery Point Objective): max acceptable data loss → backup frequency
RTO (Recovery Time Objective):  max acceptable downtime → restore speed needed

Strategy:
  Continuous archiving:  WAL archiving (Postgres) / binlog (MySQL) → point-in-time recovery
  Full backup:           daily; tested restore monthly (untested backup = no backup)
  Snapshot:              cloud volume snapshots (fast restore, same-region risk)
  Cross-region:          replicate backups to second region (DR)
  Retention:             daily 7d, weekly 4w, monthly 12m (adjust per compliance)

CRITICAL: restore tested regularly. "We have backups" ≠ "we can restore in RTO".
```

## Connection Pooling (prevent connection exhaustion)
```
Problem:   each app instance × pool size can exceed DB max_connections
Solution:  PgBouncer (transaction mode) between app and Postgres
Sizing:    pool_size = (core_count × 2) + effective_spindle_count (start point, tune)
Monitor:   active connections, wait time, pool saturation
At scale:  read replicas for read traffic; primary for writes only
```

## Sharding (Tier 3+ only — last resort)
```
When:      single primary can't handle write throughput AND vertical scaling exhausted
Shard key: high cardinality, even distribution, in most queries (user_id common)
Challenges: cross-shard joins (avoid), cross-shard transactions (avoid), rebalancing
Avoid until: read replicas + partitioning + caching exhausted (sharding adds huge complexity)
```
