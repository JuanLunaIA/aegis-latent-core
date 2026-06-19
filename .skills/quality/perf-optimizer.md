---
name: perf-optimizer
tier: HIGH
domains: [profiling, flame-graphs, latency, throughput, memory, CPU, DB-queries, async]
---
## Activation
Load on: "optimize this", "p99 high", "this is slow", "reduce inference cost",
profiling attached, flame graph, latency regression.

## Protocol: Measure First, Optimize Second
```
1. BASELINE    Reproduce problem with measurement. No optimization without baseline.
2. PROFILE     Find the actual bottleneck (not the assumed one).
3. HYPOTHESIZE X is bottleneck because [mechanism]. Tag [INFERENCE] until confirmed.
4. OPTIMIZE    Change ONE thing at a time.
5. MEASURE     Compare against baseline. Reject if no measurable improvement.
6. REPEAT      Until SLO met or further improvement < 5%.
```

## Profiling Tools
```bash
# Python — CPU
python -m cProfile -o profile.out script.py && snakeviz profile.out
py-spy record -o flamegraph.svg --pid <PID>  # production-safe, low overhead

# Python — Memory
memray run -o output.bin script.py && memray flamegraph output.bin
tracemalloc (stdlib) — for targeted allocation tracing

# Async Python — event loop blocking
aiomonitor  # attach to running asyncio app; inspect event loop lag

# Go
go tool pprof http://localhost:6060/debug/pprof/profile  # 30s CPU profile
go tool pprof http://localhost:6060/debug/pprof/heap     # heap snapshot

# Rust
cargo flamegraph -- --args  # perf + inferno

# DB queries
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) <query>  # never EXPLAIN without ANALYZE
pg_stat_statements — top queries by total_time, calls, mean_time
```

## Common Bottlenecks and Mechanisms
```
N+1 queries       Model.objects.all() in loop; fix: prefetch_related/select_related/DataLoader
Missing index      Seq scan on large table; fix: index on filter/join columns
Lock contention    High wait events in pg_locks; fix: reduce transaction scope, optimistic locking
Serialization      JSON encode/decode in hot path; fix: binary protocol (msgpack/protobuf) or cache
GIL contention     CPU-bound Python with threads; fix: multiprocessing or move to async or Rust
Memory allocation  Objects created in tight loop; fix: object pool or pre-allocate
Cache miss         Cold start on expensive computation; fix: warm-up or lazy-load with TTL
Blocking in async  time.sleep() or sync I/O in event loop; fix: run_in_executor or async alternative
```

## Database Query Optimization
```sql
-- Before optimizing: capture baseline
EXPLAIN (ANALYZE, BUFFERS) SELECT ...;
-- Look for: Seq Scan on large tables, high rows_removed, nested loops on large sets

-- Common fixes:
-- 1. Add missing index on filter column
CREATE INDEX CONCURRENTLY idx_orders_status ON orders(status) WHERE deleted_at IS NULL;

-- 2. Rewrite correlated subquery as JOIN
-- Slow:  SELECT * FROM a WHERE id IN (SELECT a_id FROM b WHERE ...)
-- Fast:  SELECT a.* FROM a JOIN b ON a.id = b.a_id WHERE ...

-- 3. Use partial index to skip dead rows
-- 4. Batch inserts: INSERT ... VALUES (...), (...) not individual INSERTs
-- 5. COPY for bulk load (100× faster than INSERT)
```
