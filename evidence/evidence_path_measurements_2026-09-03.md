# Evidence-Path Measurements — 2026-09-03

> **Nature of this document.** A record of benchmark harnesses executed in one ephemeral
> Linux container on 2026-09-03, against the source at the commit named below. It is not a
> capacity claim, a service level, an end-to-end latency figure, or a statement about any
> target deployment. It follows the citation rules in
> [`docs/benchmarks/BENCHMARK_METHOD.md`](../docs/benchmarks/BENCHMARK_METHOD.md): artifact,
> environment, date, boundary.

## [EPISTEMIC_HEADER]

| Field | Value |
|---|---|
| Measurement type | In-process microbenchmarks of the evidence path plus one native-crypto latency sample |
| Source baseline | `f77420a` (merge of PR #132 into `main`) |
| Environment | Ephemeral container; `Linux-6.18.44-fc-v24-x86_64-with-glibc2.39`; CPython 3.11.15 (GCC 13.3.0); cargo/rustc 1.94.1; Kani 0.67.0; **4 logical CPUs**, shared and unpinned |
| Harnesses | `benchmarks/bench_mmr.py`, `benchmarks/bench_crypto_audit.py`, `benchmarks/bench_dispatch_overhead.py`, `benchmarks/bench_commit_scaling.py` |
| Confidence | High for relative shape and ordering; low for absolute values, which are properties of this container |
| Falsification | Re-run the commands in [§ Reproduction](#reproduction) on the same commit and observe a different result |

**Read the CPU count before reading anything else.** Four shared, unpinned logical CPUs is a
noisy measurement host. Tail statistics here reflect the container's scheduler as much as the
code, which is why the tails are reported rather than smoothed away.

## 1. MMR append throughput — Rust versus Python

`benchmarks/bench_mmr.py`, best of k = 5, 32-byte leaf payloads.

| N (leaves) | Python leaves/s | Python µs/leaf | Rust leaves/s | Rust µs/leaf | Speedup |
|---|---|---|---|---|---|
| 100 | 202.99k | 4.926 | 979.57k | 1.021 | 4.83× |
| 1,000 | 187.91k | 5.322 | 840.29k | 1.190 | 4.47× |
| 10,000 | 166.61k | 6.002 | 804.79k | 1.243 | 4.83× |
| 100,000 | 156.90k | 6.373 | 775.76k | 1.289 | 4.94× |

Average speedup 4.77×, maximum 4.94× at N = 100,000.

**Both implementations use SHA-256 over ASCII-hex concatenation**, not BLAKE3. The wire literal
is `sha256-asciihex` and `verify_portable_inclusion_hash` rejects any other value. The Rust
accumulator stores peaks in a `Vec<usize>` indexing a `Vec<MmrNode>`; there is no hash-map peak
index. The measured advantage is native execution of the same algorithm, not a different data
structure or a different digest.

**Boundary.** Append only. Excludes proof generation, which is served from the Python replica in
`RustBackedMMR` and is not measured here.

## 2. Audit-chain commit and verification

`benchmarks/bench_crypto_audit.py`, N = 2,000 per phase, best of k = 5, **real `fsync` per node**.

| Phase | ops/s | µs/op |
|---|---|---|
| HMAC-SHA256 sign (crypto only, no I/O) | 456.78k | 2.189 |
| `commit_forensic` (HMAC + MMR + WAL fsync) | 1.24k | 808.565 |
| `verify_integrity` (chain sweep) | 23.38k | 42.770 |

A durable commit costs roughly 369× the bare signature. The per-node budget is dominated by MMR
insertion and WAL `fsync`, not by signing.

**Boundary.** `fsync` returning does not establish that bytes reached stable media; that depends
on the filesystem, the device, and its write cache. Container-backed storage is not a durability
model for any target deployment.

## 3. Commit cost versus chain length

`benchmarks/bench_commit_scaling.py`, 200 commits per point, best of k = 2, no-op `fsync` seam.
Recorded in full in
[`commit_scaling_measurement_2026-09-03.md`](commit_scaling_measurement_2026-09-03.md).

Per-commit cost is flat in chain length after the `checkpoint()` / `rollback_to()` change
(`1.00× → 0.87× → 1.04× → 0.95×` at 0/500/1,000/2,000 prior leaves), against `1.00× → 17.65×`
before it.

## 4. Background dispatch overhead

`benchmarks/bench_dispatch_overhead.py`, n = 5,000 invocations of
`aegis.proxy.app._spawn_background`.

| Statistic | Value |
|---|---|
| min | 1.702 µs |
| p25 | 2.127 µs |
| p50 | 2.490 µs |
| mean | 13.322 µs |
| p75 | 3.999 µs |
| p90 | 6.143 µs |
| p95 | 9.426 µs |
| p99 | 31.869 µs |
| max | 42,597.965 µs |
| σ | 602.830 µs |

**The mean is not the typical case.** It sits above p90 because a single 42.6 ms outlier —
scheduler preemption or a collection pause on a shared 4-CPU container — dominates it. The
median of 2.49 µs describes the common path; the p99 of 31.9 µs and the max describe what this
host does under contention. Quote the median and the tail together or neither.

**Boundary.** This measures task creation, set insertion, gauge update and callback registration
— the work charged to the caller. It is **not** end-to-end request latency and must never be
presented as such. No comparison to network round-trip time is made here: the ratio would be a
statement about someone else's network, which this measurement cannot support.

## 5. Steady-state memory

Same harness: 30 samples × 200 commits = 6,000 commits on one long-lived ledger with a 512-node
window.

| Interval | ΔRSS | Over |
|---|---|---|
| First to last sample | +3.81 MiB | 6,000 commits |
| After round 1 (warm-up excluded) | +1.75 MiB | 5,800 commits |

**RSS is not flat, and this measurement does not establish "zero memory leaks."** What it does
establish is narrower and checkable: repeating the run at 500, 1,000 and 2,000 total commits
produced deltas of 6.36, 6.48 and 6.15 MiB — essentially constant rather than proportional to
commit count. A per-commit leak would grow with the commit count and does not. The residual is
consistent with allocator arena growth and one-time warm-up.

**Boundary.** A bounded run in one process. It says nothing about fragmentation over days,
behaviour under memory pressure, or any other allocator. Absence of growth over 6,000 commits is
evidence against a leak in the sampled path, not proof of absence.

## 6. ML-DSA-65 signing latency

Direct measurement of `aegis_rust.generate_pqc_keypair().sign()` over a 256-byte message,
n = 2,000 after 200 warm-up iterations.

| Statistic | Value |
|---|---|
| min | 52.95 µs |
| p50 | 103.11 µs |
| p95 | 278.69 µs |
| p99 | 405.07 µs |
| max | 660.68 µs |
| mean | 125.47 µs |
| σ | 75.97 µs |

The distribution is right-skewed: mean exceeds median by 1.22×. FIPS 204 signing uses rejection
sampling, so the iteration count varies per signature and a long right tail is the expected
shape rather than an anomaly. **The average iteration count was not measured here**, so no
figure for it is recorded.

**Boundary.** This is a **latency** sample, not a timing-leakage experiment. It establishes
nothing about constant-time behaviour. The repository's leakage harness,
`tools/benchmarks/run_pqc_timing.py`, deliberately refuses sample counts below 1,000,000 and is
the only instrument here whose output may be cited on that question; its retained result is in
[`docs/benchmarks/BENCHMARK_RESULTS.md`](../docs/benchmarks/BENCHMARK_RESULTS.md).

## 7. Gates executed on this commit

| Gate | Result | Status |
|---|---|---|
| `cargo kani` (5 `#[kani::proof]` harnesses) | 5 verified, 0 failures | VERIFIED-LOCAL |
| `cargo test --lib` | 31 passed, 0 failed | VERIFIED-LOCAL |
| Z3 SMT checks | — | **NOT-EXECUTED**: `z3` is absent from this container |
| Lean 4 theorem check | — | **NOT-EXECUTED**: `lean`/`lake` are absent from this container |
| TLA+/TLC models | — | **NOT-EXECUTED**: the TLA+ tools JAR is not built here |

The three not-executed rows are neither confirmed nor refuted by this session. Their retained
results in [`docs/formal/FORMAL_VERIFICATION.md`](../docs/formal/FORMAL_VERIFICATION.md) remain
the record, and CI runs them on every pull request.

## 8. What is not measured

- **Throughput under concurrency.** No proxy load sweep was run. No requests-per-second figure
  at any concurrency level is recorded here, and none should be inferred from § 2.
- **End-to-end governed-call latency.** Not measured; the upstream round-trip dominates and is
  absent from every figure above.
- **Any target deployment.** One container, one CPU model, one Python build, one date.

## Reproduction

```bash
python -m benchmarks.bench_mmr
python -m benchmarks.bench_crypto_audit --n 2000 --k 5
python -m benchmarks.bench_dispatch_overhead --dispatch-samples 5000 \
  --memory-rounds 30 --commits-per-round 200 --json
python -m benchmarks.bench_commit_scaling --lengths 0,500,1000,2000 --batch 200 --k 2 --json
cd aegis_rust_v2 && cargo kani && cargo test --lib
```

Preserve the raw output, the environment manifest, the source commit and the UTC timestamp with
every rerun. A number without those is not a measurement.
