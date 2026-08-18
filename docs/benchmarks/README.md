# Aegis Benchmarks and Evidence Interpretation

Benchmarks in this repository are evidence artifacts with a declared workload and boundary. They are not universal capacity claims, production SLOs, or independent assurance.

## Measurement contract

| Field | Required value |
|---|---|
| Workload | Request shape, payload size, provider behavior, concurrency, and duration. |
| Environment | CPU/microarchitecture, kernel, Python/Rust/compiler/library versions, storage, container/runtime. |
| Warmup | Explicit warmup duration and cache state. |
| Samples | Count, seeds, rejected/failed samples, and whether samples are independent. |
| Statistics | p50/p95/p99, max, confidence interval where applicable, outlier policy. |
| Boundary | Dispatch-only, proxy client-visible, upstream-inclusive, WAL durability, WAF corpus, or native crypto function. |
| Artifact | Raw data, summary, command, exit status, timestamp, and SHA-256. |

## Current benchmark classes

| Class | What it can establish | What it cannot establish |
|---|---|---|
| Dispatch microbenchmark | Cost of the named local scheduling operation under the named interpreter and machine. | End-to-end proxy latency or provider latency. |
| Proxy lifecycle benchmark | Client-visible behavior for the declared local upstream and evidence path. | Capacity against real model providers or another kernel/storage topology. |
| WAL durability benchmark | Commit rate and latency under a named filesystem/storage and fsync policy. | Durability semantics of every CSI driver or cloud volume. |
| WAF corpus | Corpus-scoped bypass and false-positive metrics at the application boundary. | Universal prompt-injection detection or ingress HTTP/2 parser coverage. |
| Backpressure fault injection | Evidence correlation and fail-closed behavior under an injected fsync stall. | Production storage failure equivalence. |
| Native ML-DSA timing | Timing leakage non-detection under a declared experiment, if executed and passed. | Proof of constant-time execution or certification. |

## Backpressure command

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_backpressure_stall.py \
  --duration-s 0.25 --offered-rps 10000 --fsync-delay-ms 2 --max-workers 64 \
  --output evidence/backpressure_stall_report.json
```

The retained candidate artifact offered 10,000 requests at 10,000 RPS with a 2 ms injected `fsync` delay and recorded 10,000 durable commits, zero missing IDs, zero duplicate IDs, and valid chain integrity. The result demonstrates the tested hot-path blocking semantics; it does not claim that Aegis accepts 10k requests per second in production. The observed p50/p95/p99 commit latencies were `202.13615702232346/614.082946034614/1189.8909930023365 ms`, respectively.

## Key rotation command

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_key_rotation.py \
  --duration-s 0.5 --output evidence/key_rotation_report.json
```

This local multi-instance exercise uses three independent signer instances, atomic replacement, overlap verification, and owner-only keyring permissions. It does not establish secret-manager propagation, orchestrator restart behavior, clock-skew tolerance, or distributed storage semantics.

## Native ML-DSA timing command

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_pqc_timing.py \
  --operation both --samples 1000000 --warmup 10000 \
  --output evidence/pqc_timing_report.json \
  --raw-output evidence/pqc_timing_raw.jsonl
```

A result with `p > 0.05` is only timing non-detection under the declared experiment. The retained candidate artifact met the threshold for `sign` but not `verify`; the constant-time claim remains blocked.

## Release wording

Use **measured under `<workload>`** and include p-values/intervals where relevant. Do not use “zero latency,” “zero overhead,” “10k RPS capacity,” “1B RPM,” or “production SLO” unless the exact claim has a matching artifact, environment, boundary, and owner-approved release gate.

## Reproducibility and rollback

Every benchmark artifact must be hashed and linked from the release provenance. A change to the source, compiler, dependency, storage, runtime flags, corpus, or measurement method invalidates prior claims until the affected benchmark is rerun. A failed gate blocks the related marketing statement but does not permit silent substitution with a more favorable measurement.
