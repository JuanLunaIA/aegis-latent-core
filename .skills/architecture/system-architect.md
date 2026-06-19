---
name: system-architect
tier: HIGH
domains: [distributed-systems, microservices, event-driven, CQRS, CAP, scalability]
---

## Activation
Load on: system design, architecture review, scalability analysis, service decomposition,
database selection, event-driven design, CQRS, saga pattern, microservices decomposition.

## CAP Theorem — State Position Explicitly
```
CP (Consistency + Partition Tolerance): Zookeeper, HBase, etcd
  → Use for: coordination, leader election, config, financial transactions
AP (Availability + Partition Tolerance): Cassandra, DynamoDB, CouchDB
  → Use for: user activity, shopping carts, social feeds, metrics
CA (impossible in distributed systems — only in single-node)

PACELC extension: even without partition, tradeoff Latency vs Consistency
  → DynamoDB: EL (low latency with eventual consistency)
  → CockroachDB: EC (high consistency, higher latency)
```

## Service Decomposition Criteria
```
Correct boundaries → Domain-Driven Design: bounded context per service
Wrong boundaries   → chatty interfaces (sync calls > 3 hops), shared DB, coordinated deploys

Team Topologies alignment:
  Stream-aligned team   → owns 1-2 bounded contexts end-to-end
  Platform team         → provides self-service capabilities (IDP)
  Enabling team         → temporary knowledge transfer
  Complicated-subsystem → only for genuinely complex tech (ML, crypto)
```

## Scalability Patterns (tier-appropriate)
```
Tier 1: Vertical scale + connection pooling + read replicas + CDN
Tier 2: Horizontal app scale + sharding by user_id + async queues (SQS/RabbitMQ)
Tier 3: CQRS + event sourcing + fan-out writes + eventual consistency
Tier 4: Custom storage engines + edge compute + dedicated hardware + multi-region active-active
```

## Resilience Patterns (apply by failure mode)
```
Retry             → idempotent ops; exponential backoff with jitter (full jitter formula)
Circuit breaker   → Hystrix/Resilience4j; open after N failures; half-open probe
Bulkhead          → separate thread pools per external dependency
Timeout           → every external call has timeout (connect_timeout ≠ read_timeout)
Fallback          → graceful degradation; cached response > empty response > error
Shed load         → 503 with Retry-After > cascading failure
Backpressure      → bounded queues; upstream notified when buffer full
```

## Data Architecture Decision Matrix
```
Read-heavy (<1% writes):  read replicas + CDN + materialized views
Write-heavy (>50% writes): partitioning + write-ahead log + async indexing
Mixed OLTP:               PostgreSQL with connection pooler (PgBouncer)
Mixed OLAP + OLTP:        HTAP (TiDB / YugabyteDB) or separate OLAP (ClickHouse/BQ)
Event-driven:             Kafka (retention + replay) > SQS (fire-and-forget)
Real-time stream:         Flink / Spark Streaming / Materialize
```

## ADR Output Template
```markdown
## [ADR-NNN] [Decision Title]
Date: YYYY-MM-DD | Status: Proposed/Accepted/Superseded
Context: [forces in tension, constraints, scale targets]
Options:
  A. [name] — pros / cons / operational cost / failure mode
  B. [name] — pros / cons / operational cost / failure mode
Decision: [chosen] because [mechanism, not preference]
CAP position: [CP/AP + what consistency guarantee]
Consequences: positive / negative / revisit trigger (metric)
Rejected: [why each non-chosen option fails under stated constraints]
```
