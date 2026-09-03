# Commit-Cost Scaling Measurement — 2026-09-03

> **Nature of this document.** This records one in-process microbenchmark taken in a
> single ephemeral Linux container on 2026-09-03. It is not a capacity claim, a service
> level, an end-to-end latency figure, or a statement about any target deployment. It
> follows the citation rules in [`docs/benchmarks/BENCHMARK_METHOD.md`](../docs/benchmarks/BENCHMARK_METHOD.md):
> artifact, environment, date, boundary.

## [EPISTEMIC_HEADER]

| Field | Value |
|---|---|
| Measurement type | In-process microbenchmark of `CryptographicAuditLedger.commit_forensic` |
| Question | Does per-commit cost depend on the number of leaves already committed? |
| Baseline measured ("before") | `ef71920a431c5d1950274f8946264a41e97b24f4` |
| Change measured ("after") | Same commit with the MMR rollback change in the working tree |
| Environment | Ephemeral container; `Linux-6.18.44-fc-v24-x86_64-with-glibc2.39`; CPython 3.11.15 (GCC 13.3.0); 4 logical CPUs |
| Harness | `benchmarks/bench_commit_scaling.py` |
| Confidence | High for the shape of the curve; none asserted for any deployment |
| Falsification | Re-run the commands below on the same commit and observe a different curve |

## What was measured

`commit_forensic` appends a leaf to the MMR before it knows whether signing and WAL
persistence will succeed, and reverts the MMR if either fails. The revert was a
`copy.deepcopy` of the entire accumulator, taken on **every** commit — including the
successful ones, which are the overwhelming majority. The copy is O(number of leaves),
so per-commit cost grew with the length of the chain.

The change replaces the copy with `MerkleMountainRange.checkpoint()` /
`rollback_to()`: a token holding the append-only lengths plus the live peak node
objects, which is O(log n) to take and O(log n) to apply.

## Result

200 measured commits at each chain length, best of 2 trials, no-op `fsync` seam:

| Prior leaves | Before (µs/commit) | After (µs/commit) | Ratio |
|---|---|---|---|
| 0 | 1,708.2 | 378.7 | 4.5× |
| 500 | 7,827.1 | 328.9 | 23.8× |
| 1,000 | 14,618.7 | 394.7 | 37.0× |
| 2,000 | 30,153.9 | 361.7 | 83.4× |

Normalised to each run's own shortest chain, the "before" curve rises `1.00× → 4.58× →
8.56× → 17.65×` while the "after" curve stays within measurement noise of flat
(`1.00× → 0.87× → 1.04× → 0.95×`).

A separate run of the same harness on the changed code over a wider range
(`0, 500, 1000, 2000, 4000, 8000` prior leaves, 300 commits, best of 3) reported
`1.00× → 1.09× → 1.05× → 1.00× → 1.07× → 1.12×`. The residual rise at 8,000 tracks the
growing WAL file, not the accumulator.

**Interpretation.** Per-commit cost is now independent of chain length over the range
measured. The absolute microsecond figures are properties of this container and this
harness only.

## Correctness evidence accompanying the change

The optimisation is only sound if the rollback is exact. `tests/test_mmr_rollback.py`
compares `rollback_to` against a `copy.deepcopy` restore across leaf counts straddling
every power of two up to 64, checks peak/node object aliasing and cleared parent
pointers, and asserts that a ledger whose commit failed at signing or at WAL persistence
produces the same MMR — node for node — as a ledger that never attempted the failed
commit.

## Boundary

- In-process commit path only. **Excludes** network, upstream provider, request parsing,
  admission control, WAF evaluation, rate limiting, and response handling.
- The default harness installs a no-op `fsync_fn`, so **durable-write cost is excluded**.
  Pass `--fsync` to include it; real `fsync` dominates and hides the CPU-bound shape,
  which is why it is off by default here.
- Best-of-k reporting strips scheduler noise; it does not model tail latency.
- One container, one CPU model, one Python build, one date. Nothing here establishes
  throughput capacity, a service level, multi-replica behaviour, behaviour on network
  storage, or sustained load.
- No production-scale measurement exists for this repository.

## Reproduction

```bash
# "after" — current source
python -m benchmarks.bench_commit_scaling --lengths 0,500,1000,2000 --batch 200 --k 2 --json

# "before" — the same harness against the pre-change rollback strategy
git stash push aegis/core/mmr.py aegis/core/crypto_audit.py
python -m benchmarks.bench_commit_scaling --lengths 0,500,1000,2000 --batch 200 --k 2 --json
git stash pop
```

Once the change is merged, reproduce "before" by checking the two files out at the
parent commit instead of stashing.

Preserve the raw JSON, the environment manifest, the source commit and the UTC
timestamp with every rerun.
