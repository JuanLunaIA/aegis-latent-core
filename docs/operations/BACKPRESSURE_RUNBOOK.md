# Backpressure and I/O Stall Runbook

**Scope:** Aegis local WAL and governed-request evidence path  
**Audience:** platform engineering, SRE, security operations, release reviewers

## Runtime contract

A governed request must not return a successful response before its authoritative evidence record has been durably committed. The durable path is intentionally synchronous with respect to the request lifecycle: request admission, policy evaluation, response capture, signing, WAL write, flush, and `fsync` occur before the terminal governed response. This preserves evidence integrity at the cost of blocking throughput when storage stalls.

The optional enrichment path may be bounded and rejected when saturated. It must never be used as a substitute for the authoritative evidence record. A response that cannot obtain durable evidence must fail closed according to the configured error contract and emit durable error evidence when the storage boundary is still available.

## Observable signals

| Signal | Meaning | Operator action |
|---|---|---|
| `aegis_wal_backpressure_active=1` | WAL entry or byte threshold is active. | Stop increasing offered load; inspect storage latency and age of oldest evidence. |
| WAL `fsync` latency p95/p99 rising | Durable commit is the bottleneck. | Check filesystem, volume, encryption layer, and host I/O queue. |
| Queue depth or inflight commits rising | Offered load exceeds durable commit rate. | Apply upstream rate limiting or shed before the evidence boundary. |
| Durable evidence count below accepted governed count | Evidence invariant violation. | Block release/traffic, preserve WAL, and start incident response. |
| WAL integrity failure or duplicate/missing request IDs | Chain or correlation failure. | Freeze writes if possible, preserve artifacts read-only, and execute rollback. |

## Fault-injection procedure

The repository includes a deterministic `fsync_fn` injection seam in `CryptographicAuditLedger`. The default remains `os.fsync`; production code does not sleep or simulate storage. The local harness is:

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_backpressure_stall.py \
  --duration-s 0.25 \
  --offered-rps 10000 \
  --fsync-delay-ms 2 \
  --max-workers 64 \
  --output evidence/backpressure_stall_report.json
```

The artifact must record offered load, delay, worker count, accepted-and-durable count, failure count, missing IDs, duplicate IDs, chain integrity, commit latency percentiles, WAL hash, and the explicit statement that offered load is not accepted capacity.

The retained candidate run offered 10,000 requests at 10,000 RPS with a 2 ms injected `fsync` delay and 64 workers. It recorded 10,000 durable commits, zero failures, zero missing IDs, zero duplicate IDs, and valid chain integrity. Observed total runtime was 32.36878035601694 s, with commit latency p50 `202.13615702232346 ms`, p95 `614.082946034614 ms`, p99 `1189.8909930023365 ms`, and max `3208.868669986259 ms`. This proves the no-silent-drop behavior within the local harness boundary; it also demonstrates that the offered load caused severe queueing and does not establish accepted capacity or a production SLO.

A privileged storage test using `dm-delay` is a separate lab operation. It MUST run only on a disposable loop-backed block device or disposable namespace with explicit root/capability checks. It MUST NOT attach to host, production, or user data volumes. When the environment cannot prove that boundary, the result is `NOT_EXECUTED`, not pass.

## Gate

The scenario passes only when every request that crossed the governed evidence boundary maps to exactly one durable record or one durable fail-closed terminal record, there are no silent drops, no duplicate evidence IDs, the chain verifies, and the system recovers after the delay is removed. The 10k value is an offered-load input for this corpus; it is not an accepted-throughput claim.

## Recovery

First stop or reduce upstream admission. Preserve the active WAL and rotated segments without truncation. Confirm that the filesystem reports the expected owner-only permissions and that the ledger can replay all segments. Remove the injected or infrastructure delay, wait for inflight commits to drain, and rerun the integrity check. If any request ID is missing or duplicated, stop release and retain the raw report, WAL, environment manifest, and hashes for investigation.

## Rollback and kill criteria

Rollback uses the previous signed/image-digest release and keeps the evidence artifacts read-only. Kill criteria are any accepted governed response without durable evidence, a failed chain verification, an unrecoverable WAL write error, an unbounded queue, an unexpected 5xx/503 surge without a bounded rejection signal, or evidence correlation that cannot distinguish rejection before the boundary from failure after admission.

## Residual risk

The injected seam validates the application’s lifecycle and correlation behavior. It does not prove that every filesystem, CSI driver, kernel, storage controller, cloud volume, encryption layer, or failure mode has the same ordering and durability semantics. Production acceptance requires the target deployment’s own storage and recovery evidence.
