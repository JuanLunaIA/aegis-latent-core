# Benchmark Results — Aegis Latent Core v3.1.0

This document records the retained v3.1.0 market-hardening measurements. It is for engineers, security reviewers, and procurement evaluators who need reproducible numbers and explicit boundaries. These measurements are evidence for named workloads; they are not production capacity, availability SLOs, universal detection rates, or cryptographic proofs.

**Last verified:** 2026-08-22 UTC
**Release baseline:** `v3.1.0`
**Canonical methodology:** [`docs/benchmarks/README.md`](README.md)
**Artifact locations:** retained release evidence plus repository-scoped artifacts under [`evidence/`](../../evidence/)

## Result summary

| Scenario | Workload | Result | Interpretation | Status |
|---|---|---|---|---|
| Backpressure under injected I/O stall | 10,000 offered requests at 10,000 RPS; 2 ms injected `fsync` delay | 10,000 durable commits; 0 failures; 0 missing IDs; 0 duplicates; valid chain | Evidence integrity survived the injected seam while queueing increased latency | `PASS` for bounded gate |
| Backpressure latency | Same run | p50 202.136 ms; p95 614.083 ms; p99 1,189.891 ms; max 3,208.869 ms | The queue is not low latency under this stall | Measured, not an SLO |
| WAF corpus | 15 malicious and 8 benign pinned local cases | 0 observed bypasses; 0 false positives; Wilson 95% upper bound approximately 20.39% for bypass rate | Regression signal for the pinned application-layer corpus | `PASS` for declared corpus |
| Key rotation | 2,239 records across 3 independent local signer instances | 0 failed commits; 0 unverifiable records; both key IDs observed; keyring mode `0o600` | Local atomic replacement and overlap path behaved as intended | `PASS` for local harness |
| ML-DSA `sign` timing | 1,000,000 interleaved samples | `p=0.8521504207157158` | No statistically significant difference detected under the named experiment | Measured; not a proof |
| ML-DSA `verify` timing | 1,000,000 interleaved samples | `p=0.0`; mean class difference approximately 540.526 ns | The experiment detected a class-dependent timing difference at this boundary | `FAIL`; claim blocked |
| Bounded SSE transformation | 7 rounds × 1,000 deterministic events on the recorded sandbox host | first-byte p50 2.030 ms, p95 2.295 ms; duration p50 316.892 ms; 3,155.654 events/s p50; queue high-water 664 bytes / 8 items; `tracemalloc` peak 141,338 bytes | In-process transform only; excludes network, provider and durable-WAL latency | Measured, not an SLO |

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
```

The commands require the corresponding local environment and may produce different timings. Preserve the raw report, environment manifest, tool version, CPU information, source commit and UTC timestamp with every rerun.

## Bounded SSE method

The harness drives `BoundedStreamProxy` from a deterministic in-process async iterator, consumes the transformed output without accumulating it, and records the first yielded byte, total duration, queue high-water marks, terminal outcome, and Python allocation peak. The 2026-08-22 artifact reports exactly one `complete` terminal commit in every round. The benchmark does not open a socket, call a provider, execute a durable ledger commit, or model concurrent clients. Consequently, its throughput and latency values cannot be used as gateway capacity, provider latency, production SLO, or “zero overhead” evidence.

## Backpressure method

The harness injects an `fsync_fn` delay at the WAL boundary. It offers requests at a configured rate and checks durable record count, request-ID uniqueness, missing IDs, duplicate IDs and chain integrity. The test observes application-level queueing and record preservation.

The 10,000-record result is not equivalent to a block-device `dm-delay` experiment. It does not establish power-loss behavior, cloud-volume semantics, storage replication, accepted capacity, throughput under an upstream provider, or recovery after a real disk fault.

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
