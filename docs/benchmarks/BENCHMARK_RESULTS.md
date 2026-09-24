# Benchmark Results — Aegis Latent Core

This document records the retained `v3.1.0` market-hardening measurements and the measurements taken on the `v5.0.1` source baseline (2026-09-24). It is for engineers, security reviewers, and procurement evaluators who need reproducible numbers and explicit boundaries. These measurements are evidence for named workloads; they are not production capacity, availability SLOs, universal detection rates, or cryptographic proofs.

**Last verified:** 2026-09-24 UTC
**Release baseline:** checked-out source baseline `v5.0.1` with fourteen synchronized anchors — **published nowhere**, read back 2026-09-21 (`docs/RELEASE_STATUS.md` §1.0a); the most recent published release is `v5.0.0` (2026-09-16, every surface except PyPI `aegis-latent-core`).
**Historical evidence baseline:** retained `v3.1.0` artifacts and measurements remain historical and are not `v5.0.1` results.
**Canonical methodology:** [`docs/benchmarks/README.md`](README.md)
**Artifact locations:** retained release evidence plus repository-scoped artifacts under [`evidence/`](../../evidence/)

## Result summary

| Scenario | Workload | Result | Interpretation | Status |
|---|---|---|---|---|
| Backpressure under injected I/O stall — **retracted `v3.1.0` figures**, raw JSON never in this tree | 10,000 offered requests at 10,000 RPS; 2 ms injected `fsync` delay (as previously published) | **Not citable:** the 10,000-commit count and the p99 1,189.891 ms figure are retracted (`UC-018`) — no artifact in this tree produces them | The retraction is the record; the two in-tree rows below are the citable runs | `RETRACTED` |
| Backpressure latency (2026-08-20, `20fa011`) | 2,500 offered requests over 0.25 s at 10,000 RPS offered; 2 ms injected `fsync` delay | p50 167.290 ms; p95 504.704 ms; p99 836.351 ms; max 2,290.622 ms — `evidence/execution_2026-08-20/backpressure_stall_report.json` | The queue is not low latency under this stall | Measured, not an SLO |
| Backpressure under injected I/O stall — **current in-tree baseline** (2026-09-16, `88e01f0`) | 2,500 offered requests over a 0.25 s window at 10,000 RPS offered; 2 ms injected `fsync` delay; 1.573 s to drain | 2,500 durable commits; 0 failures; 0 missing IDs; 0 duplicates; valid chain; p50 33.545 ms, p95 41.176 ms, p99 51.875 ms, max 59.726 ms; 200 `fsync` calls | The figure to cite for current source. Three runs gave p99 52.317 / 51.875 / 47.531 ms | `PASS` for bounded gate |
| Backpressure under injected I/O stall — superseded pre-group-commit baseline (2026-08-20, `20fa011`) | Identical parameters; 6.630 s to drain | 2,500 durable commits; 0 failures; 0 missing IDs; 0 duplicates; valid chain; p50 167.290 ms, p95 504.704 ms, p99 836.351 ms, max 2,290.622 ms; 2,501 `fsync` calls | Correct for the tree it measured, which fsynced once per node. Superseded for current-state citation by the row above; not withdrawn | `PASS` for bounded gate |
| WAF corpus | 15 malicious and 8 benign pinned local cases | 0 observed bypasses; 0 false positives; Wilson 95% upper bound approximately 20.39% for bypass rate | Regression signal for the pinned application-layer corpus | `PASS` for declared corpus |
| Key rotation — retained `v3.1.0`, raw JSON **not in this tree** | 2,239 records across 3 independent local signer instances | 0 failed commits; 0 unverifiable records; both key IDs observed; keyring mode `0o600` | Local atomic replacement and overlap path behaved as intended | `PASS` for local harness |
| Key rotation — **in-tree reproducible baseline** | 2,033 records across 3 independent local signer instances over 0.5 s | 0 failed commits; 0 unverifiable records; `key-old` 701 and `key-new` 1,332 observed; keyring mode `0o600` | A different run of the same harness, not a correction of the row above | `PASS` for local harness |
| ML-DSA `sign` timing — retained `v3.1.0`-era, raw JSON **not in this tree** | 1,000,000 interleaved samples | `p=0.8521504207157158` | No statistically significant difference detected under the named experiment | Measured; not a proof |
| ML-DSA `verify` timing — same retained artifact | 1,000,000 interleaved samples | `p=0.0`; mean class difference approximately 540.526 ns | The experiment detected a class-dependent timing difference at this boundary | `FAIL`; claim blocked |
| Bounded SSE transformation | 7 rounds × 1,000 deterministic events on the recorded sandbox host | first-byte p50 2.030 ms, p95 2.295 ms; duration p50 316.892 ms; 3,155.654 events/s p50; queue high-water 664 bytes / 8 items; `tracemalloc` peak 141,338 bytes | In-process transform only; excludes network, provider and durable-WAL latency | Measured, not an SLO |
| v5.0.1 documentation-pass — `commit_forensic` latency (n = 1,000) | One process, real WAL `fsync` per commit (MMR append + HMAC sign) | p50 0.62 ms; p95 1.00 ms; p99 1.22 ms; max 4.18 ms — `evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json` | Per-commit latency on the recorded host | Accepted capacity, other storage, queueing behaviour | `MEASURED` |
| v5.0.1 documentation-pass — concurrent commit throughput | 10 / 50 / 100 threads against one WAL | 1,727 / 1,630 / 1,482 commits per second | The single-writer design does not scale with threads (`AD-16`) | Multi-process / replica behaviour | `MEASURED` |
| v5.0.1 documentation-pass — streaming ingestion memory | 1,000 concurrent in-process SSE streams × 20 events | +20.1 MB RSS | Bounded in-process memory for the named workload | Network, durable WAL, providers | `MEASURED` |
| v5.0.1 documentation-pass — Ed25519 sign / verify | `cryptography`, RFC 8032 | 40.5 / 128.6 µs per op | Order of magnitude on the recorded host | HSM paths, other machines | `MEASURED` |
| v5.0.1 documentation-pass — ML-DSA-65 sign / verify | `aegis_rust`, FIPS 204 | 173.0 / 62.4 µs per op | A latency sample only | Constant-time behaviour remains blocked (`REG-041`) | `MEASURED` |

## Reproduction commands

```bash
# WAF corpus
PYTHONPATH=. .venv/bin/python tools/security/run_waf_corpus.py \
  --corpus tests/data/waf_corpus_v1.json \
  --output evidence/waf_corpus_report.json

# Backpressure and injected fsync delay
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_backpressure_stall.py \
  --duration-s 0.25 --offered-rps 10000 --fsync-delay-ms 2 --max-workers 64 \
  --output evidence/backpressure_stall_report.json

# Local key rotation
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_key_rotation.py \
  --output evidence/key_rotation_report.json

# Native ML-DSA timing; retained candidate uses 1,000,000 samples per operation
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_pqc_timing.py \
  --samples 1000000 --output evidence/pqc_timing_report.json

# Bounded in-process SSE transform
PYTHONPATH=. .venv/bin/python benchmarks/bench_streaming_sse.py \
  --events 1000 --rounds 7 \
  > evidence/commercial_phase2_streaming_benchmark.json

# v5.0.1 documentation-pass suite (commit latency percentiles, throughput, RSS, device-key timing)
PYTHONPATH=. .venv/bin/python scripts/run_benchmarks_5.0.1.py --json \
  > evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json
```

The commands require the corresponding local environment and may produce different timings. Preserve the raw report, environment manifest, tool version, CPU information, source commit and UTC timestamp with every rerun.

## Bounded SSE method

The harness drives `BoundedStreamProxy` from a deterministic in-process async iterator, consumes the transformed output without accumulating it, and records the first yielded byte, total duration, queue high-water marks, terminal outcome, and Python allocation peak. The 2026-08-22 artifact reports exactly one `complete` terminal commit in every round. The benchmark does not open a socket, call a provider, execute a durable ledger commit, or model concurrent clients. Consequently, its throughput and latency values cannot be used as gateway capacity, provider latency, production SLO, or “zero overhead” evidence.

## Backpressure method

The harness injects an `fsync_fn` delay at the WAL boundary. It offers requests at a configured rate and checks durable record count, request-ID uniqueness, missing IDs, duplicate IDs and chain integrity. The test observes application-level queueing and record preservation.

The retracted 10,000-record result is not equivalent to a block-device `dm-delay` experiment, and the in-tree 2,500-record runs are not either. Neither establishes power-loss behavior, cloud-volume semantics, storage replication, accepted capacity, throughput under an upstream provider, or recovery after a real disk fault.

**The raw JSON for the 10,000-request run was never committed to this tree, and the claims
register retracts it (`UC-018`).** A reader cannot re-derive the 10,000-commit count or the
p99 1,189.89 ms figure from the repository, so neither is citable — restating them with
another run's numbers would be the same defect in the other direction: the figures above are
now labelled retracted, and the citable figures are the two in-tree runs below.

A second, smaller injected-`fsync` run *is* committed and reproducible:
[`evidence/execution_2026-08-20/backpressure_stall_report.json`](../../evidence/execution_2026-08-20/backpressure_stall_report.json)
records 2,500 offered requests over 0.25 s under the same 2 ms injected delay, with p99
commit latency 836.35 ms. It is a different workload, not a correction of this one — see
[Benchmark Method §7](BENCHMARK_METHOD.md) for both side by side and the rule against
mixing their figures.

## WAF method

The pinned corpus contains 15 malicious and 8 benign cases. The harness records observed bypasses and false positives and calculates the Wilson interval. With zero observed bypasses in 15 malicious cases, the point estimate is zero, but the upper confidence bound remains wide. The corpus does not exercise HTTP/2 fragmentation, pseudo-header ordering, continuation boundaries, compressed-body parser differences, proxy translation or an authorized `nuclei-templates/waf-bypass` run.

## Key-rotation method

The local harness uses three independent signer instances, atomic keyring replacement, key ID metadata and verification overlap. It checks failed commits and record verification across the local rotation window. It does not simulate or prove a Kubernetes controller, real secret-manager delivery, pod restart ordering, clock skew, cross-region replication, or secret destruction.

## ML-DSA timing method

The timing harness interleaves classes and retains raw samples. It tests the Python-to-Rust boundary used by the current binding, including decode work exposed by that boundary. The null hypothesis is that the declared timing distributions have no class-dependent difference at the chosen boundary.

A p-value above 0.05 means that the experiment did not detect a statistically significant difference at its declared sensitivity. It does not prove constant-time execution, absence of compiler or microarchitectural leakage, absence of key-dependent behavior outside the measured path, FIPS 140 validation, or security against all timing observers.

The `verify` result returned `p=0.0`. The release therefore blocks the phrase “constant-time ML-DSA verification.” The next technical experiment must isolate decoding from the native verification operation, pin CPU and compiler behavior, retain raw data, report effect size and repeat across supported targets.

## Benchmark interpretation rules

| Term | Meaning in this repository |
|---|---|
| Microbenchmark | Isolated function or scheduling measurement; not client-visible latency |
| Integration benchmark | Multiple Aegis components without a complete external network path |
| End-to-end benchmark | Full lifecycle including network, upstream, storage and deployment topology |
| Offered load | Requests presented to the system; not necessarily accepted capacity |
| Durable commit | The declared local WAL flush and `fsync` path completed |
| Production SLO | A customer-owned service objective with workload, error budget, telemetry and operating commitment; none is created by these local artifacts |

## Related documents

- [`docs/benchmarks/README.md`](README.md)
- [`docs/BENCHMARKS.md`](../BENCHMARKS.md)
- [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
- [`docs/security/PQC_CONSTANT_TIME.md`](../security/PQC_CONSTANT_TIME.md)
- [`docs/security/WAF_TESTING.md`](../security/WAF_TESTING.md)
- [`docs/operations/BACKPRESSURE_RUNBOOK.md`](../operations/BACKPRESSURE_RUNBOOK.md)
