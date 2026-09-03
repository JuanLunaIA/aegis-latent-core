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
| Native MMR operations | Rust criterion benchmarks | Python interop overhead |
| Backpressure under injected `fsync` delay | Local harness with a seam | Real storage behaviour, real network, real provider |
| WAF corpus | Pinned corpus replay | Traffic outside the corpus |
| PQC signing timing | Sample-based timing | Constant-time behaviour, which is not established |

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

The backpressure measurement uses a local seam that injects a delay into `fsync`. Recorded result: under a 2 ms injected delay and 10k RPS offered load for 0.25 seconds, 2,500 offered requests produced 2,500 durable records with zero failures, zero missing or duplicate IDs, and valid chain integrity. Observed p99 commit latency was 836.3514210795984 ms.

Read carefully:

- **Offered load is not accepted capacity.** 10k RPS was offered for a quarter second. That is 2,500 requests, not sustained throughput.
- **An injected delay is not real storage.** It models one failure mode.
- **The p99 is the point.** Under storage pressure, commit latency rose to hundreds of milliseconds while remaining correct. Correctness held; latency did not.

The useful conclusion is that the system fails correctly under storage pressure, not that it handles 10k RPS.

## 8. Reproducing

```bash
# Suite and coverage
pytest -q
pytest --cov=aegis --cov-report=json

# Backpressure harness
python tools/benchmarks/run_backpressure_stall.py

# WAF corpus
python tools/security/run_waf_corpus.py

# Rust benchmarks
cd aegis_rust_v2 && cargo bench

# Commit-cost scaling
python -m benchmarks.bench_commit_scaling --json
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

---

**Related:** [Benchmark Results](BENCHMARK_RESULTS.md) · [Benchmarks](../BENCHMARKS.md) · [Scaling Guide](../performance/SCALING_GUIDE.md) · [Pilot Playbook](../enterprise/PILOT_PLAYBOOK.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md)
