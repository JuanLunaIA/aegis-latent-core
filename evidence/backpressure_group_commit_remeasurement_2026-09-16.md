# Backpressure Re-measurement After Group Commit — 2026-09-16

> **Nature of this document.** A record of one benchmark harness, re-executed three times in one
> ephemeral Linux container on 2026-09-16 against the source commit named below, at the *same
> parameters* as the retained 2026-08-20 run. It is not a capacity claim, a service level, an
> end-to-end API latency figure, or a statement about any target deployment. It follows the
> citation rules in [`docs/benchmarks/BENCHMARK_METHOD.md`](../docs/benchmarks/BENCHMARK_METHOD.md):
> artifact, environment, date, boundary.

## [EPISTEMIC_HEADER]

| Field | Value |
|---|---|
| Measurement type | Ledger commit latency under an **injected** `fsync` delay at deliberately oversubscribed offered load |
| Source baseline | `88e01f0234a58d5720d5b8faad4e8b51ee2dd7ae` |
| Environment | Ephemeral container; `Linux-6.18.44-fc-v33-x86_64-with-glibc2.39`; CPython 3.11.15; **4 logical CPUs**, shared and unpinned |
| Harness | `tools/benchmarks/run_backpressure_stall.py`, default parameters (0.25 s offered window, 10,000 offered RPS, 2.0 ms injected `fsync` delay, 64 worker threads) |
| Raw artifacts | [`execution_2026-09-16/backpressure_stall_report_run1.json`](execution_2026-09-16/backpressure_stall_report_run1.json), [`run2`](execution_2026-09-16/backpressure_stall_report_run2.json), [`run3`](execution_2026-09-16/backpressure_stall_report_run3.json) |
| Confidence | High for the order-of-magnitude change and for the `fsync`-call count, which is structural; low for absolute milliseconds, which are a property of this container |
| Falsification | Re-run [§ Reproduction](#reproduction) on this commit and observe a different `fsync` count or a p99 outside the recorded range |

## 1. Why this run exists

The 2026-08-20 report was produced at commit `20fa011f64bff3582f6be8a6b12735ac2430ec7e`. The
coalesced group-commit engine (`aegis/core/group_commit.py`, `CLM-082`) first entered the tree on
2026-09-10 in `b791638`. **The retained figure therefore measures a ledger that fsynced once per
committed node**, and it was still being cited across the corpus as the in-tree baseline for a
tree that no longer behaves that way. This record does not correct the old number — it was
correct for what it measured — it supplies the current one beside it.

## 2. Observed

Three consecutive runs, identical parameters:

| Run | p50 | p95 | p99 | max | `fsync` calls | Drain time |
|---|---|---|---|---|---|---|
| 1 | 36.209 ms | 46.815 ms | 52.317 ms | 68.891 ms | 207 | 1.694 s |
| 2 | 33.545 ms | 41.176 ms | 51.875 ms | 59.726 ms | 200 | 1.573 s |
| 3 | 32.301 ms | 39.207 ms | 47.531 ms | 52.382 ms | 198 | 1.491 s |

Every run: 2,500 offered, **2,500 durable**, 0 failures, 0 missing identifiers, 0 duplicates,
chain integrity valid. Maximum in-flight 2,071–2,194.

### Against the 2026-08-20 run, same parameters

| Metric | 2026-08-20 (`20fa011`) | 2026-09-16 (`88e01f0`, run 2) | Change |
|---|---|---|---|
| p50 | 167.290 ms | 33.545 ms | −80.0% |
| p95 | 504.704 ms | 41.176 ms | −91.8% |
| p99 | 836.351 ms | 51.875 ms | −93.8% |
| max | 2,290.622 ms | 59.726 ms | −97.4% |
| `fsync` calls | 2,501 | 200 | 12.5 records per `fsync` |
| Drain time | 6.630 s | 1.573 s | −76.3% |

**The two runs are on different hosts**, so the millisecond deltas are not a controlled
comparison and must not be quoted as a speedup factor for any deployment. The `fsync`-call count
is the part that is host-independent: 2,501 calls for 2,500 records is one sync per commit;
200 calls for 2,500 records is the coalescing engine doing what `CLM-082` says it does.

## 3. What these numbers are not

- **Not per-request overhead.** This workload offers 2,500 commits inside a 0.25 s window against
  64 worker threads and takes ~1.5 s to drain. The latency is dominated by queueing at an offered
  rate the harness never claims is accepted capacity — the report's own `success_rate_claim` field
  reads `NOT_CLAIMED; offered load is not accepted capacity`. Re-running with
  `--fsync-delay-ms 0` on this host gives p50 32.426 ms / p99 48.247 ms, within the noise of the
  2 ms-delay run: at this offered rate the injected disk delay is not the dominant term.
- **Not an end-to-end API latency.** It measures `commit_state` in-process. Ingress, auth, WAF,
  rate limiting, upstream dispatch and response redaction are all outside it.
- **Not real storage.** The delay is injected into a Python `fsync` seam. `fsync` returning
  establishes nothing about stable media on container-backed storage.
- **Not a capacity figure**, a storage SLO, or `dm-delay` equivalence.

For the single-threaded, uncontended per-commit cost, cite
[`evidence_path_measurements_2026-09-03.md`](evidence_path_measurements_2026-09-03.md) §2 instead:
`commit_forensic` with a real `fsync` per node measured 808.565 µs/op.

## Reproduction

```bash
python tools/benchmarks/run_backpressure_stall.py \
  --duration-s 0.25 --offered-rps 10000 --fsync-delay-ms 2.0 --max-workers 64 \
  --output evidence/execution_2026-09-16/backpressure_stall_report_run1.json
```

The harness writes a `.wal.jsonl` beside its report. That file holds raw WAL records and is
**not** committed; only the report JSON is, and it carries the WAL's SHA-256 for attribution.

---

**Related:** [Benchmark Method](../docs/benchmarks/BENCHMARK_METHOD.md) · [Benchmark Results](../docs/benchmarks/BENCHMARK_RESULTS.md) · [Claims Matrix](../docs/CLAIMS_MATRIX.md) (`CLM-034`, `CLM-082`) · [Evidence Index](INDEX.md)
