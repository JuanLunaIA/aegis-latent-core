# Benchmark Methodology and Index — Aegis Latent Core v3.1.0

This document defines how Aegis benchmark results must be interpreted and routes readers to the retained v3.1.0 results. It is for engineers, security reviewers, release owners and procurement evaluators. A benchmark is evidence only for its declared workload, environment, code boundary, sample method and artifact.

**Last verified:** 2026-08-22 UTC
**Release baseline:** `v3.1.0`
**Detailed results:** [`BENCHMARK_RESULTS.md`](BENCHMARK_RESULTS.md)
**Historical interpretation:** [`../BENCHMARKS.md`](../BENCHMARKS.md)

## Measurement contract

Every published number must identify the source commit, date, hardware, operating system, language/runtime versions, dependency versions, workload, warmup, sample count, percentile or statistical method, raw artifact, output path, and failure boundary. If any item is missing, label the result `UNVERIFIED` or `INCOMPLETE`.

| Field | Required value |
|---|---|
| Workload | Request shape, payload size, provider behavior, concurrency and duration |
| Environment | CPU/microarchitecture, kernel, Python/Rust/compiler/library versions, storage, container/runtime |
| Warmup | Explicit warmup duration and cache state |
| Samples | Count, seeds, rejected/failed samples and independence assumptions |
| Statistics | p50/p95/p99, max, confidence interval where applicable and outlier policy |
| Boundary | Dispatch-only, proxy client-visible, upstream-inclusive, WAL durability, WAF corpus or native crypto function |
| Artifact | Raw data, summary, command, exit status, timestamp and SHA-256 |

## Current benchmark classes

| Class | What it can establish | What it cannot establish |
|---|---|---|
| Dispatch microbenchmark | Cost of the named local scheduling operation under the named interpreter and machine | End-to-end proxy latency or provider latency |
| Proxy lifecycle benchmark | Client-visible behavior for the declared local upstream and evidence path | Capacity against real model providers or another kernel/storage topology |
| WAL durability benchmark | Commit rate and latency under a named filesystem/storage and `fsync` policy | Durability semantics of every CSI driver or cloud volume |
| WAF corpus | Corpus-scoped bypass and false-positive metrics at the application boundary | Universal prompt-injection detection or ingress HTTP/2 parser coverage |
| Backpressure fault injection | Evidence correlation and fail-closed behavior under an injected `fsync` stall | Production storage failure equivalence |
| Native ML-DSA timing | Timing non-detection under a declared experiment, if executed and passed | Proof of constant-time execution or certification |
| Bounded SSE transformation | First-byte timing, local event throughput and memory high-water marks for the named deterministic in-process stream | Provider/network latency, durable-WAL latency or production capacity |

## Current result index

| Result | Harness | Retained artifact | Boundary |
|---|---|---|---|
| WAF corpus | `tools/security/run_waf_corpus.py` | `waf_corpus_report_v1_candidate.json` | 15 malicious and 8 benign application-layer cases; HTTP/2 and Nuclei not executed |
| Backpressure | `tools/benchmarks/run_backpressure_stall.py` | `backpressure_stall_10k_report.json` | 10k offered requests and 2 ms injected `fsync`; p99 1,189.89 ms; no production capacity claim |
| Key rotation | `tools/benchmarks/run_key_rotation.py` | `key_rotation_report_v2.json` | Three independent local signer instances; no real orchestrator/secret-manager acceptance |
| ML-DSA timing | `tools/benchmarks/run_pqc_timing.py` | `pqc_timing_report_v2.json` | 1M samples per operation; `sign` non-detection, `verify` failure; no constant-time claim |
| Bounded SSE transformation | `benchmarks/bench_streaming_sse.py` | `evidence/commercial_phase2_streaming_benchmark.json` | Seven local rounds of 1,000 events; excludes network and WAL durability latency |

## Reproduction commands

```bash
PYTHONPATH=. .venv/bin/python tools/security/run_waf_corpus.py \
  --corpus tests/data/waf_corpus_v1.json \
  --output evidence/waf_corpus_report.json

PYTHONPATH=. .venv/bin/python tools/benchmarks/run_backpressure_stall.py \
  --duration-s 0.25 --offered-rps 10000 --fsync-delay-ms 2 --max-workers 64 \
  --output evidence/backpressure_stall_report.json

PYTHONPATH=. .venv/bin/python tools/benchmarks/run_key_rotation.py \
  --output evidence/key_rotation_report.json

PYTHONPATH=. .venv/bin/python tools/benchmarks/run_pqc_timing.py \
  --operation both --samples 1000000 --warmup 10000 \
  --output evidence/pqc_timing_report.json \
  --raw-output evidence/pqc_timing_raw.jsonl

PYTHONPATH=. .venv/bin/python benchmarks/bench_streaming_sse.py \
  --events 1000 --rounds 7 \
  > evidence/commercial_phase2_streaming_benchmark.json
```

The commands require the corresponding local environment and may produce different timings. Preserve command output and environment metadata with every rerun. Do not overwrite a prior evidence artifact without preserving its hash and provenance.

## Interpretation rules

Use “offered load” rather than “capacity” unless a target deployment has a complete acceptance artifact. Use “no statistically significant difference detected under the named experiment” rather than “constant-time.” Use “observed zero bypasses in the pinned corpus” rather than “zero bypasses.” Use “durable commit under the declared WAL path” rather than “immutable storage.”

The 2.70 microsecond result documented in historical material is a background-dispatch scheduling microbenchmark. It is not end-to-end gateway latency, provider-visible latency or a production SLO.

A change to source, compiler, dependency, storage, runtime flags, corpus or measurement method invalidates the affected claim until the benchmark is rerun. A failed gate blocks the related public statement; it does not permit substitution with a more favorable measurement.

## Related documents

- [`BENCHMARK_RESULTS.md`](BENCHMARK_RESULTS.md)
- [`../BENCHMARKS.md`](../BENCHMARKS.md)
- [`../CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
- [`../security/WAF_TESTING.md`](../security/WAF_TESTING.md)
- [`../security/PQC_CONSTANT_TIME.md`](../security/PQC_CONSTANT_TIME.md)
- [`../operations/BACKPRESSURE_RUNBOOK.md`](../operations/BACKPRESSURE_RUNBOOK.md)
- [`../../DEPLOYMENT_GUIDE.md`](../../DEPLOYMENT_GUIDE.md)
