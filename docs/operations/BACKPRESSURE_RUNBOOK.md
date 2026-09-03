# Backpressure and I/O Stall Runbook — Aegis Latent Core

This runbook is for platform engineering, SRE, security operations and release reviewers who must diagnose storage or `fsync` stall without losing authoritative evidence. It describes the local injected seam, operator actions, recovery and residual risk. A `dm-delay` test remains a separate privileged lab operation.

**Last verified:** 2026-08-27 UTC
**Release baseline:** four-layer truth model
**Source baseline/release target:** `v4.1.0` with 14 synchronized anchors; source metadata does not establish external lifecycle state; verify the tag, GitHub Release, PyPI, npm, OCI digest, signature, and attestation through independent readback
**Immutable comparison source:** `fdace8844568eb788216740b2cb5daf187d99d3b` with `4.0.0` anchors
**Previous public GitHub Release:** `v4.0.1` lightweight tag targeting `6469904380218584ae0b5221334bc9a46500f5ba`
**Observed registries:** PyPI/npm `4.0.0`, without workflow provenance attribution
**Historical evidence baseline:** `v3.1.0`; retained measurements are historical evidence for that release only
**Scope:** Aegis local WAL and governed-request evidence path
**Audience:** Platform engineering, SRE, security operations and release reviewers

The retained numeric results below belong to the published `v3.1.0` evidence baseline. The checked-out `v4.1.0` source baseline/release target and immutable comparison source identify implementations under documentation review, not a rerun of those measurements. Do not promote the v3.1.0 results to v4 capacity, latency, availability, or SLO claims without a v4 rerun and target-environment acceptance evidence.

## Runtime contract

A non-streaming governed request must not return its response before authoritative evidence has been durably committed. SSE is incremental: sanitized non-terminal events can be emitted while evidence is `pending-terminal`, but `[DONE]` or Anthropic `message_stop` is withheld until the one terminal summary commit completes. This preserves terminal evidence integrity at the cost of terminal latency when storage stalls; it does not claim that already-emitted events can be recalled.

The optional enrichment path may be bounded and rejected when saturated. It must never be used as a substitute for the authoritative evidence record. A response that cannot obtain durable evidence must fail closed according to the configured error contract and emit durable error evidence when the storage boundary is still available.

## Observable signals

| Signal | Meaning | Operator action |
|---|---|---|
| `aegis_wal_backpressure_active=1` | WAL entry or byte threshold is active. | Stop increasing offered load; inspect storage latency and age of oldest evidence. |
| WAL `fsync` latency p95/p99 rising | Durable commit is the bottleneck. | Check filesystem, volume, encryption layer, and host I/O queue. |
| Queue depth or inflight commits rising | Offered load exceeds durable commit rate. | Apply upstream rate limiting or shed before the evidence boundary. |
| `aegis_stream_duration_seconds{provider,outcome}` shifts toward limit outcomes | Streams are reaching duration or size bounds. | Inspect provider behavior and declared limits; do not raise bounds without memory and privacy review. |
| `aegis_stream_redactions_total{provider,entity}` changes unexpectedly | Incremental de-identification behavior or traffic mix changed. | Correlate with deployment changes without logging raw stream content. |
| `aegis_native_stream_wal_errors_total` increases | The auxiliary CRC-framed stream copy failed after an authoritative JSONL commit. | Preserve JSONL, inspect capacity/I/O, rotate or repair the auxiliary segment and restart under change control. Do not treat the auxiliary gap as loss of the JSONL record. |
| Durable evidence count below accepted governed count | Evidence invariant violation. | Block release/traffic, preserve WAL, and start incident response. |
| WAL integrity failure or duplicate/missing request IDs | Chain or correlation failure. | Freeze writes if possible, preserve artifacts read-only, and execute rollback. |

`AEGIS_STREAM_QUEUE_MAX_ITEMS` and `AEGIS_STREAM_QUEUE_MAX_BYTES` jointly bound each active stream queue. `AEGIS_MAX_STREAM_EVENT_BYTES` bounds both upstream and canonical events and must not exceed the queue byte budget. `AEGIS_STREAM_DEIDENTIFIER_WINDOW_CHARS` bounds logical-text holdback. `BoundedStreamProxy` computes response SHA-256 incrementally; it does not buffer the complete response. A byte, event or duration limit closes upstream immediately, commits one terminal failure outcome and omits the success terminal marker.

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

The retained `v3.1.0` candidate run offered 10,000 requests at 10,000 RPS with a 2 ms injected `fsync` delay and 64 workers. It recorded 10,000 durable commits, zero failures, zero missing IDs, zero duplicate IDs, and valid chain integrity. Observed total runtime was 32.36878035601694 s, with commit latency p50 `202.13615702232346 ms`, p95 `614.082946034614 ms`, p99 `1189.8909930023365 ms`, and max `3208.868669986259 ms`. This proves the no-silent-drop behavior within that historical local harness boundary; it also demonstrates that the offered load caused severe queueing and does not establish accepted capacity or a production SLO for v3.1.0 or v4.

A privileged storage test using `dm-delay` is a separate lab operation. It MUST run only on a disposable loop-backed block device or disposable namespace with explicit root/capability checks. It MUST NOT attach to host, production, or user data volumes. When the environment cannot prove that boundary, the result is `NOT_EXECUTED`, not pass.

## Gate

The scenario passes only when every request that crossed the governed evidence boundary maps to exactly one durable record or one durable fail-closed terminal record, there are no silent drops, no duplicate evidence IDs, the chain verifies, and the system recovers after the delay is removed. The 10k value is an offered-load input for this corpus; it is not an accepted-throughput claim.

## Recovery

First stop or reduce upstream admission. Preserve the active WAL and rotated segments without truncation. Confirm that the filesystem reports the expected owner-only permissions and that the ledger can replay all segments. Remove the injected or infrastructure delay, wait for inflight commits to drain, and rerun the integrity check. If any request ID is missing or duplicated, stop release and retain the raw report, WAL, environment manifest, and hashes for investigation.

## Rollback and kill criteria

Rollback uses the previous signed/image-digest release and keeps the evidence artifacts read-only. Kill criteria are any accepted governed response without durable evidence, a failed chain verification, an unrecoverable WAL write error, an unbounded queue, an unexpected 5xx/503 surge without a bounded rejection signal, or evidence correlation that cannot distinguish rejection before the boundary from failure after admission.

## Residual risk

The injected seam validates the application’s lifecycle and correlation behavior. It does not prove that every filesystem, CSI driver, kernel, storage controller, cloud volume, encryption layer, or failure mode has the same ordering and durability semantics. Production acceptance requires the target deployment’s own storage and recovery evidence.

## Related documents

- [`../benchmarks/BENCHMARK_RESULTS.md`](../benchmarks/BENCHMARK_RESULTS.md)
- [`../performance/SCALING_GUIDE.md`](../performance/SCALING_GUIDE.md)
- [`ROLLBACK_RUNBOOK.md`](ROLLBACK_RUNBOOK.md)
- [`../../DEPLOYMENT_GUIDE.md`](../../DEPLOYMENT_GUIDE.md)
- [`../../README.md`](../../README.md)
