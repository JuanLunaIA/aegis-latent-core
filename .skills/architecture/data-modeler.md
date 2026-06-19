---
name: data-modeler
tier: MEDIUM
domains: [OLTP, OLAP, star-schema, lakehouse, partitioning, indexes, retention, pgvector]
---
## Activation
Load on: schema design, Postgres schema, data warehouse layout, choosing between
Postgres and DynamoDB, lakehouse design, vector DB, partitioning strategy.

## OLTP Schema Requirements
```sql
-- Every table must have:
id          UUID PRIMARY KEY DEFAULT gen_random_uuid()  -- not serial int (global uniqueness)
created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()          -- trigger to auto-update
deleted_at  TIMESTAMPTZ                                  -- soft delete; NULL = active

-- Naming: snake_case; foreign keys: {table}_id
-- No nullable columns without explicit reason in comment
-- Enum types: Postgres ENUM or check constraint; not magic strings
-- Indexes: every FK column; every frequently-filtered column; partial indexes for soft-delete
-- Constraints: NOT NULL, UNIQUE, FK, CHECK at DB level (not just application)
```

## Index Strategy
```sql
-- Partial index (most selective first)
CREATE INDEX idx_orders_user_active ON orders(user_id, created_at DESC)
WHERE deleted_at IS NULL;

-- Covering index (avoid heap fetch for common query)
CREATE INDEX idx_users_email_covering ON users(email) INCLUDE (id, name, plan);

-- JSONB: GIN index for @>, ?, jsonb_path_ops for path queries
CREATE INDEX idx_meta_gin ON events USING GIN(metadata jsonb_path_ops);

-- Vector search (pgvector)
CREATE INDEX idx_embeddings_hnsw ON documents
USING hnsw(embedding vector_cosine_ops) WITH (m=16, ef_construction=64);
-- HNSW: fast query, slow build, high memory
-- IVFFlat: faster build, slower query, lower memory — for > 1M vectors
```

## OLAP / Star Schema
```
Fact tables:       immutable events; append-only; partition by date
Dimension tables:  slowly changing (SCD Type 2 for history); surrogate keys
Grain:             ONE ROW = ONE EVENT (never pre-aggregated in fact)
Partitioning:      by created_date (filter pushdown) + by tenant_id if multi-tenant
Clustering:        on most common filter columns (Snowflake/BigQuery)
```

## Database Selection
```
PostgreSQL:    OLTP default; ACID; pgvector; PostGIS; mature ecosystem
CockroachDB:  PostgreSQL-compatible + horizontal scale + multi-region
DynamoDB:     single-digit ms at any scale; key-value/document; no joins
Cassandra:    write-heavy; time-series; multi-region; no transactions
ClickHouse:   OLAP; columnar; 100× faster than Postgres for analytics
Redis:        cache + pub/sub + leaderboard; not primary store
Qdrant:       purpose-built vector DB; HNSW; payload filtering
```
