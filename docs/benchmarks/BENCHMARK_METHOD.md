# Benchmark Method

**Audience:** performance engineers, security reviewers, anyone about to quote a number.
**Scope:** how measurements in this repository are taken, what they exclude, and the rules for citing them.
**Boundary:** **every measurement here is a local observation in a named environment. None is a capacity claim, a service level, or a statement about any target deployment.** No production-scale measurement exists.

---

## 1. Rules for every measurement

A number without these four things is not a measurement:

| Required | Why |
| --- | --- |
| **The artifact** | A file a reader can open |
| **The environment** | Hardware, OS, Python version, configuration |
| **The date** | Numbers move as code changes |
| **The boundary** | What the number excludes |

"93.91% coverage" is not a measurement. "93.9096% statement coverage (`coverage.json`, 2026-08-18, 11,765 of 12,528 statements)" is.

## 2. What is measured

| Class | Method | Excludes |
| --- | --- | --- |
| Statement coverage | `coverage.py` over the suite | Branch coverage; whether tests assert anything meaningful |
| Test suite outcome | `pytest -q` | Environments where optional backends are absent produce skips |
| Background dispatch | Microbenchmark of the dispatch path | Everything else: upstream, network, storage, serialization |
| Commit-cost scaling | `benchmarks/bench_commit_scaling.py` — per-commit latency at increasing chain lengths | Network, provider, request handling, and (by default) durable-write cost; reports the shape of the curve, not a throughput figure |
| Background dispatch overhead | `benchmarks/bench_dispatch_overhead.py` — distribution over `_spawn_background` | Everything the caller does not pay for inline; it is not request latency |
| Steady-state memory | Same harness — RSS sampled across repeated commit batches | Fragmentation over days, behaviour under memory pressure, every other allocator |
| ML-DSA signing latency | Direct sample of the native signer | Constant-time behaviour, which a latency sample cannot address at all |
| Native MMR operations | Rust criterion benchmarks | Python interop overhead |
| Backpressure under injected `fsync` delay | Local harness with a seam | Real storage behaviour, real network, real provider |
| WAF corpus | Pinned corpus replay | Traffic outside the corpus |
| PQC signing timing | Sample-based timing | Constant-time behaviour, which is not established |
| Commit latency distribution, concurrent-thread commit throughput, in-process streaming RSS, Ed25519/ML-DSA-65 sign+verify | `scripts/run_benchmarks_5.0.1.py` — see §8 | Network, provider, request handling, multi-process/multi-replica scaling, constant-time behaviour |

## 8. The v5.0.1 documentation-pass benchmark (`run_benchmarks_5.0.1.py`)

Written to answer four specific questions with real numbers rather than invented
ones, for the v5.0.1 README and CLAIMS_MATRIX pass. Retained artifact:
[`evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json`](../../evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json)
(host `vm`, 4 CPUs, Linux x86_64, Python 3.11.15, git `ce58c58723e15…`, 2026-09-24).
Reproduce with `python scripts/run_benchmarks_5.0.1.py --json`.

| Measurement | Method | This run |
| --- | --- | --- |
| `commit_forensic` latency (n=1000) | `perf_counter()` around each commit against a real temp-dir WAL with real `fsync` | P50 0.62 ms · P95 1.00 ms · P99 1.22 ms · max 4.18 ms |
| Concurrent commit throughput | `ThreadPoolExecutor` at 10/50/100 threads sharing one ledger's single-writer WAL lock, 200 ops/thread | 10 threads: 1,727/s · 50 threads: 1,630/s · 100 threads: 1,482/s |
| Streaming ingestion memory | `resource.getrusage().ru_maxrss` delta around 1,000 concurrent in-process `BoundedStreamProxy` streams (20 events each) after an 8-stream warmup | +20.1 MB (52,648 KB → 73,256 KB) |
| Ed25519 sign / verify | Best-of-5 over 500 ops, `cryptography` (RFC 8032) | sign 40.5 µs/op · verify 128.6 µs/op |
| ML-DSA-65 sign / verify | Best-of-5 over 500 ops, `aegis_rust` (pqcrypto-mldsa, FIPS 204) | sign 173.0 µs/op · verify 62.4 µs/op |

Read the throughput row carefully: **it does not scale with thread count, and that
is the correct result, not noise.** All three columns measure one process writing
to one WAL file through one lock (`AD-16`: this source tree does not implement a
distributed WAL); more threads add contention on that lock, not more writers.
Confusing this row for a multi-replica capacity figure would misstate the
architecture, not just round the number wrong.

Also read the memory row's ordering dependency: `ru_maxrss` is a whole-process
high-water mark that Linux never lowers within a process's lifetime, so the
harness runs the streaming-memory phase **before** the thread-heavy commit
phases in the same process — reversing that order silently zeroes the delta
by letting an unrelated, larger phase set the mark first. The script's own
comments state this; a caller extending it must preserve the ordering or
measure streaming memory in a fresh process.

None of these five numbers is a capacity claim, an SLO, or a statement about a
target deployment — see the boundary text atop this document and inside the
script's own module docstring.

## 3. What is not measured, at all

Naming these matters more than the list above, because their absence is what a reader should take away:

- **End-to-end latency in a target deployment.** None exists.
- **Throughput capacity.** No RPS figure is claimed for any environment.
- **Concurrent stream limits at scale.**
- **Behaviour on real network storage.**
- **Multi-replica performance.**
- **Sustained load over hours or days.**
- **Cost per governed call.**

A buyer needing any of these must measure them. See [Pilot Playbook §6](../enterprise/PILOT_PLAYBOOK.md#6-measurements-to-record).

## 4. The two coverage figures

The repository contains two statement-coverage numbers from different runs:

| Value | Artifact | Date |
| --- | --- | --- |
| 93.9096% (11,765 / 12,528) | `coverage.json` | 2026-08-18 |
| 89.7169% | `evidence/v4_0_0_release_candidate_gate_2026-08-24.md` | 2026-08-24 |

Both are real. They differ because they were taken at different commits under different conditions.

**Cite whichever you are relying on, with its artifact and date. Do not select one and present it as "the" coverage figure.** Choosing the higher number without disclosing the other would be a misrepresentation by omission, and the discrepancy is itself informative: coverage moves.

## 5. Suite counts move

Recorded suite outcomes:

| Result | Source | Date |
| --- | --- | --- |
| 5,707 passed, 37 skipped | Candidate gate record | 2026-08-24 |
| 5,661 passed, 81 skipped, 0 failed | `evidence/cold_start_reproduction_audit_2026-09-01.md` | 2026-09-01 |

The 2026-09-01 run was in a clean container; its higher skip count is attributed to uninstalled optional backends, not to failures.

**The current count is whatever `pytest -q` reports on the commit you are evaluating.** Test counts change with every commit that adds a test. Do not quote a historical count as a current property — run it.

## 6. The microbenchmark caveat

A background-dispatch microbenchmark measures the dispatch path in isolation. It is a useful regression signal and it is **not** proxy overhead.

An end-to-end governed call includes request parsing, admission checks, WAF evaluation, rate limiting, upstream network round-trip, response parsing, redaction, node construction, signing, serialization, write, flush, and `fsync`. The upstream round-trip alone typically dominates by orders of magnitude.

**Never present a microbenchmark as end-to-end overhead or provider-visible latency.** That specific misuse is why this section exists.

## 7. The injected-`fsync` harness

The backpressure measurement uses a local seam that injects a delay into `fsync`. Current
recorded result, at source `88e01f0` on 2026-09-16: under a 2 ms injected delay and 10k RPS
offered load for 0.25 seconds, 2,500 offered requests produced 2,500 durable records with zero
failures, zero missing or duplicate IDs, and valid chain integrity. Observed p99 commit latency
was 51.87478800007739 ms across 200 `fsync` calls.

Read carefully:

- **Offered load is not accepted capacity.** 10k RPS was offered for a quarter second. That is 2,500 requests, not sustained throughput.
- **An injected delay is not real storage.** It models one failure mode.
- **The latency is queueing, not per-request overhead.** 2,500 commits are offered inside a 0.25 s window against 64 worker threads and take ~1.5 s to drain. Re-running the same harness with `--fsync-delay-ms 0` moves p50 by about a millisecond, which is what tells you the injected disk delay is not the dominant term at this offered rate.

The useful conclusion is that the system fails correctly under storage pressure, not that it handles 10k RPS.

### Three backpressure runs, and which one you can reproduce

There are three distinct injected-`fsync` runs in this repository's history. They are
different measurements taken at different source commits, and each remains correct for what
it measured:

| Run | Workload | p99 commit latency | Raw artifact |
|---|---|---|---|
| Retracted `v3.1.0` historical | 10,000 offered requests over 32.4 s, 2 ms injected `fsync` (as previously published) | **Not citable — retracted (`UC-018`)** | **No committed artifact produces this run or its p99.** Kept here only to record the retraction; cite the two in-tree rows instead |
| Pre-group-commit baseline (2026-08-20, `20fa011`) | 2,500 offered requests over 0.25 s at 10k RPS offered, 2 ms injected `fsync` | 836.35 ms | [`evidence/execution_2026-08-20/backpressure_stall_report.json`](../../evidence/execution_2026-08-20/backpressure_stall_report.json) |
| **Current in-tree baseline (2026-09-16, `88e01f0`)** | Identical parameters | **51.87 ms** (three runs: 52.317 / 51.875 / 47.531 ms) | [`evidence/execution_2026-09-16/`](../../evidence/execution_2026-09-16/), recorded in [`backpressure_group_commit_remeasurement_2026-09-16.md`](../../evidence/backpressure_group_commit_remeasurement_2026-09-16.md) |

**Cite the 2026-09-16 run for current source behaviour.** The 2026-08-20 figure predates the
coalesced group-commit engine (`aegis/core/group_commit.py`, `CLM-082`, first in tree
2026-09-10), so it measures a ledger that fsynced once per committed node: 2,501 `fsync` calls
for 2,500 records, against 200 now. That structural difference — not the millisecond delta, which
was measured on a different host — is what makes the older number the wrong one to quote for the
current tree. It is not withdrawn; it is superseded for current-state citation only.

Quoting one run's latency beside another's request count produces a number that was never
measured. The 10,000-request run is a historical observation whose raw JSON is not here to check,
which is a limitation of that figure and is stated wherever it appears.

All three used a 2 ms *injected* delay. None is a measurement of real storage, and none is
accepted capacity — see the boundaries below.

The full percentile set for the current in-tree run (run 2 of three), so it can be cited without
opening the file: p50 33.545 ms, p95 41.176 ms, p99 51.875 ms, max 59.726 ms, over a 0.25 s
offered window that took 1.573 s to drain, with 200 `fsync` calls and a maximum in-flight of
2,071. Integrity valid, zero failures, zero missing identifiers, zero duplicates.

The corresponding set for the superseded 2026-08-20 run, retained because it is still cited as a
historical observation: p50 167.290 ms, p95 504.704 ms, p99 836.351 ms, max 2,290.622 ms, over
the same offered window, taking 6.630 s to drain, with 2,501 `fsync` calls and a maximum
in-flight of 2,407.

For the single-threaded, uncontended per-commit cost — the figure to reach for when someone asks
"how much latency does Aegis add?" — cite
[`evidence/evidence_path_measurements_2026-09-03.md`](../../evidence/evidence_path_measurements_2026-09-03.md)
§2 instead: `commit_forensic` with a real `fsync` per node measured 808.565 µs/op. None of the
backpressure runs is that number.

### The same split applies to key rotation

The key-rotation harness has the same shape, and the two figures circulate in the corpus
for the same reason:

| Run | Records | Raw artifact |
|---|---|---|
| Retained `v3.1.0` historical | 2,239 across three local signer instances | **Not committed to this tree** |
| In-tree reproducible baseline (2026-08-20) | 2,033 over 0.5 s; `key-old` 701, `key-new` 1,332 | [`evidence/execution_2026-08-20/key_rotation_report.json`](../../evidence/execution_2026-08-20/key_rotation_report.json) |

Both observed zero failed commits, zero unverifiable records, both key IDs, and keyring
mode `0o600`. Neither establishes secret-manager propagation or orchestrator acceptance.

The ML-DSA timing artifact has **no** in-tree counterpart: the retained `p=0.852` / `p=0.0`
figures are `v3.1.0`-era, and rerunning the harness produces a new measurement rather than
reproducing that one. Say so whenever those numbers are quoted.

## 8. Reproducing

```bash
# Suite and coverage
pytest -q
pytest --cov=aegis --cov-report=json

# Backpressure harness
python tools/benchmarks/run_backpressure_stall.py

# WAF corpus
python tools/security/run_waf_corpus.py

# Rust-side cost measurement. There is no Criterion bench target in the crate:
# `cargo bench` compiles nothing to run (AUD-24). This harness prints numbers
# that are attributable to the host that printed them and to nothing else.
cd aegis_rust_v2 && cargo test --release --features zk-spartan --test zk_mmr_cost -- --ignored --nocapture

# Commit-cost scaling
python -m benchmarks.bench_commit_scaling --json

# Dispatch overhead and steady-state memory
python -m benchmarks.bench_dispatch_overhead --json

# MMR append throughput, Rust versus Python
python -m benchmarks.bench_mmr
```

Record your environment alongside any result. A number without its environment is not reproducible, and an irreproducible number is not evidence.

## 9. Prohibited phrasing

| Never | Instead |
| --- | --- |
| "Handles 10k RPS" | "2,500 requests were offered over 0.25s in a local harness" |
| "Zero overhead" | State the measured microbenchmark and its scope |
| "Sub-millisecond latency" | Name the stage measured |
| "93.91% coverage" alone | Add artifact and date |
| "5,707 tests pass" | Run it on the commit you are evaluating |
| "Benchmarked at scale" | No scale measurement exists |
| "Overhead is negligible versus network round-trip" | State the measured stage. A ratio against an unmeasured provider RTT is a claim about someone else's network, and this repository has measured none |
| "Zero memory leaks" | Say what was sampled and over how many operations. Flat RSS over a bounded run is evidence against a leak, never proof of absence |
| Quoting a mean alone | Give the median with the tail. A single outlier on a shared runner can pull a mean above its own p90, which happened in the 2026-09-03 dispatch sample |

### The mean is the easiest number to misuse

The 2026-09-03 dispatch measurement recorded a median of 2.490 µs and a mean of 13.322 µs over
the same 5,000 samples. Both are correct. The mean is larger than the p90 because one 42.6 ms
outlier is in the sample. Reporting either alone misleads in opposite directions, so the record
carries the full distribution and the rule here is to quote the median with the tail.

---

**Related:** [Benchmark Results](BENCHMARK_RESULTS.md) · [Benchmarks](../BENCHMARKS.md) · [Scaling Guide](../performance/SCALING_GUIDE.md) · [Pilot Playbook](../enterprise/PILOT_PLAYBOOK.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md)
