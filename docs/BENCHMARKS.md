<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Benchmark and Measurement Record

This document is the public benchmark and measurement record for the `v5.0.1` source baseline and for the retained `v3.1.0` release measurements. It routes readers to detailed methods and retained artifacts while preserving workload, environment and interpretation boundaries. The numbers below are named measurements, not production capacity, availability SLOs, universal WAF rates or cryptographic proofs.

**Last verified:** 2026-09-24 UTC
**Release baseline:** checked-out source baseline `v5.0.1` with fourteen synchronized anchors — **published nowhere**, read back 2026-09-21 (`docs/RELEASE_STATUS.md` §1.0a); the most recent published release is `v5.0.0` (2026-09-16, every surface except PyPI `aegis-latent-core`).
**Historical evidence baseline:** retained `v3.1.0` artifacts and measurements remain historical and are not `v5.0.1` results.
**Detailed methods and results:** [`docs/benchmarks/BENCHMARK_RESULTS.md`](benchmarks/BENCHMARK_RESULTS.md)

## Measurement contract

Every performance or security measurement must record the workload, environment, warmup, sample count, statistic, code boundary, command, raw or derived artifact, exit status, timestamp and SHA-256. Changes to source, compiler, dependency, storage, corpus, runtime flags or measurement method invalidate prior claims until the affected experiment is rerun.

| Field | Required content |
|---|---|
| Workload | Request shape, payload size, provider behavior, concurrency, offered load and duration. |
| Environment | CPU model and affinity, kernel, Python/Rust/compiler/library versions, storage, container/runtime and relevant security controls. |
| Warmup | Explicit warmup duration and cache state. |
| Samples | Count, class balance, seed or deterministic generator, rejected samples and failures. |
| Statistics | p50/p95/p99/max, confidence interval or p-value where applicable, outlier policy and effect size. |
| Boundary | Dispatch-only, proxy client-visible, upstream-inclusive, WAL durability, WAF application boundary, keyring lifecycle or native crypto function. |
| Artifact | Raw data, summary report, command, exit status, timestamp and SHA-256. |

## Result summary

| Experiment | Observed result | What it establishes | What remains unproven |
|---|---|---|---|
| Full Python regression | Historical release run: 5,442 passed, 37 skipped, 47 warnings in 68.08 s; 93.91% line coverage. Post-reconstruction checkout: 5,438 passed, 41 skipped, 47 warnings in 31.78 s. | The named test suites passed in their respective environments. | Other Python versions, kernels, providers and deployment topologies. |
| Rust unit tests | 26 passed, 0 failed; doc-tests 0 passed. | The Rust unit suite passed with the committed lockfile and named toolchain. | Cross-compilation, every released wheel target and production runtime behavior. |
| WAF corpus | 15 malicious and 8 benign cases; 0 bypasses; 0 false positives; Wilson 95% upper bound approximately 20.39% for bypass rate. | The pinned corpus passed the application-layer regression gate. | Universal prompt-injection detection, HTTP/2 parser differentials, ingress normalization and Nuclei coverage. |
| Backpressure | 2,500 requests offered at 10,000 RPS with 2 ms injected `fsync` delay; 2,500 durable commits; 0 failures; 0 missing IDs; 0 duplicates; valid chain (`evidence/execution_2026-08-20/backpressure_stall_report.json`). | No-silent-drop and chain-correlation behavior under the injected application seam. | Accepted capacity, production SLO, `dm-delay` block-device equivalence, cloud-volume semantics and every failure mode. The previously published 10,000-request / p99 1,189.89 ms `v3.1.0` pair is retracted (`UC-018`): no artifact in this tree produces it. |
| Backpressure latency (2026-08-20, `20fa011`) | Total runtime 6.630050110979937 s; p50 167.29020897764713 ms; p95 504.7037289477885 ms; p99 836.3514210795984 ms; max 2290.622486965731 ms. | The offered load produces substantial queueing while preserving evidence integrity. | Any claim that the gateway is low-latency or accepts 10k RPS in production. The previously published `v3.1.0` distribution (p99 1189.8909930023365 ms; max 3208.868669986259 ms) is retracted (`UC-018`): no committed artifact produces it. |
| Key rotation | 2,239 records across three independent local signer instances; 0 failed commits; 0 unverifiable records; old and new key IDs observed; keyring mode `0o600`. | Atomic local snapshot replacement, overlap verification, key ID metadata and no-restart signer behavior within the local harness. | Kubernetes/secret-manager propagation, independent process restart, clock skew, distributed storage and rollback under orchestration. |
| ML-DSA sign timing | 1,000,000 interleaved samples; `p=0.8521504207157158`; validity control passed. | No statistically significant timing difference was detected for `sign` under the named experiment. | Constant-time proof, compiler/microarchitecture leakage, FIPS 140 validation and independent review. |
| ML-DSA verify timing | 1,000,000 interleaved samples; `p=0.0`; measured mean delta 540.5259299977988 ns. | The declared verify experiment detected a class-dependent timing difference at this boundary. | Root cause, exploitability, secret-leakage relevance and whether an alternative verifier boundary removes the effect. The constant-time claim is blocked. |
| WAF gate implementation | Script gate requires zero critical bypasses, observed bypass below 5% and zero false positives. | The executable gate matches the stricter regression test and public claim. | Corpus completeness and actual ingress parser behavior. |

## Reproducible commands

### Python and static gates

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. .venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/bandit -r aegis aegis_server -lll
pip-audit --progress-spinner off
/home/ubuntu/aegis-rebuild/helm-bin/helm lint deploy/helm
cargo test --manifest-path aegis_rust_v2/Cargo.toml --locked
```

### WAF corpus

```bash
PYTHONPATH=. .venv/bin/python tools/security/run_waf_corpus.py \
  --output evidence/waf_corpus_report.json
```

The harness loads the pinned `tests/data/waf_corpus_v1.json`, reports per-case verdicts and a Wilson interval, and exits non-zero when the executable gate fails. HTTP/2 fragmentation and `nuclei-templates/waf-bypass` are deliberately separate authorized-ingress exercises.

### Backpressure and WAL stall

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_backpressure_stall.py \
  --duration-s 1.0 --offered-rps 10000 --fsync-delay-ms 2 --max-workers 64 \
  --output evidence/backpressure_stall_10k_report.json
```

The harness injects delay through `fsync_fn`; production defaults remain `os.fsync`. The gate means **hot-path blocking on the durable commit with no silent evidence drop**. It explicitly does not mean accepted throughput.

A `dm-delay` experiment is a separate privileged lab operation. It must use a disposable loop-backed block device or namespace, explicit capability checks and a retained chain-of-custody record. It must never attach to host, production or user data volumes. If those constraints cannot be proven, the result is `NOT_EXECUTED`.

### Key rotation

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_key_rotation.py \
  --duration-s 0.5 --output evidence/key_rotation_report.json
```

The local exercise uses three independent signer instances, atomic replacement, overlap verification, key IDs and owner-only file permissions. A production acceptance must additionally exercise the actual secret manager, three process lifecycles, restart/replay, delayed propagation, independent storage, clock behavior and rollback.

### Native ML-DSA timing

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_pqc_timing.py \
  --operation both --samples 1000000 --warmup 10000 \
  --output evidence/pqc_timing_report.json \
  --raw-output evidence/pqc_timing_raw.jsonl
```

The harness measures the current Python-to-Rust boundary, including public-key/signature decoding performed by the binding. It returns `2` and writes `UNAVAILABLE` when the real backend is absent. A p-value above 0.05 is **non-detection under the experiment**, not proof of constant-time execution. The retained release measurement passed the `sign` experiment and failed the `verify` experiment.

## Where a second, in-tree run exists for the same harness

The whole table above is the retained `v3.1.0` record, and its raw JSON is **not committed
to this tree**. For two of those harnesses a *different* run **is** committed here, and a
reader who compares the two sets will otherwise conclude one of them is wrong. Neither is:
they are different workloads, and neither supersedes the other.

| Harness | Retracted `v3.1.0` (no committed artifact; `UC-018`) | In-tree, reproducible from this repository |
|---|---|---|
| Backpressure under injected `fsync` | Retracted: 10,000 offered requests over 32.4 s; p99 1,189.89 ms — no committed artifact (`UC-018`) | **Current (2026-09-16, `88e01f0`):** 2,500 offered requests over a 0.25 s window; p99 51.87 ms — [`execution_2026-09-16/`](../evidence/execution_2026-09-16/). **Superseded (2026-08-20, `20fa011`, before group commit):** same parameters; p99 836.35 ms — [`backpressure_stall_report.json`](../evidence/execution_2026-08-20/backpressure_stall_report.json) |
| Key rotation | 2,239 records across three local signer instances | 2,033 records across three local signer instances over 0.5 s; `key-old` 701, `key-new` 1,332 — [`key_rotation_report.json`](../evidence/execution_2026-08-20/key_rotation_report.json) |

Both backpressure runs used the same 2 ms *injected* delay; both rotation runs used the
same three-instance local harness. **Do not quote one run's statistic beside another run's
count** — that produces a figure that was never measured. Cite the run you rely on together
with its workload and whether its artifact is in this tree. Set out in full at
[Benchmark Method §7](benchmarks/BENCHMARK_METHOD.md).

The ML-DSA timing rows have no in-tree counterpart: that artifact is retained `v3.1.0`-era
only, and rerunning `tools/benchmarks/run_pqc_timing.py` produces a new measurement rather
than reproducing that one.

## Evidence-path measurements on the current source baseline

The table above is the retained **v3.1.0** record and is not restated here. The measurements
below were taken on **2026-09-03** against commit `f77420a` in one ephemeral container —
`Linux-6.18.44-fc-v24-x86_64`, CPython 3.11.15, cargo 1.94.1, **4 shared unpinned logical
CPUs**. The full record, including every boundary, is
[`evidence/evidence_path_measurements_2026-09-03.md`](../evidence/evidence_path_measurements_2026-09-03.md).

| Experiment | Observed result | What it establishes | What remains unproven |
|---|---|---|---|
| MMR append, Rust versus Python | Rust 979.57k→775.76k leaves/s; Python 202.99k→156.90k leaves/s across N ∈ {100; 1,000; 10,000; 100,000}; average 4.77×, maximum 4.94× at N = 100,000 | The native accumulator executes the same SHA-256 ASCII-hex algorithm faster on this host | Proof generation, which is served from the Python replica and is not measured; any other host |
| Audit-chain commit | HMAC-SHA256 sign 456.78k ops/s (2.189 µs); `commit_forensic` with real `fsync` 1.24k commits/s (808.565 µs); `verify_integrity` 23.38k nodes/s (42.770 µs) | The per-node budget is dominated by MMR insertion and WAL `fsync`, not by signing | That `fsync` returning means bytes reached stable media; accepted capacity at any concurrency |
| Commit cost versus chain length | Flat within noise after the checkpoint change (`1.00× → 0.87× → 1.04× → 0.95×` at 0/500/1,000/2,000 prior leaves) against `1.00× → 17.65×` before it | Per-commit cost no longer grows with the length of the chain | Absolute throughput; the figures exclude durable-write cost by default |
| Background dispatch overhead | n = 5,000: p50 2.490 µs, p95 9.426 µs, p99 31.869 µs, max 42,597.965 µs, mean 13.322 µs, σ 602.830 µs | The common path costs a few microseconds; the tail on a shared 4-CPU host reaches tens of milliseconds | End-to-end request latency, which this does not measure and must not be presented as |
| Steady-state memory | ΔRSS +3.81 MiB across 6,000 commits; +1.75 MiB after warm-up. Repeats at 500/1,000/2,000 commits gave 6.36/6.48/6.15 MiB — constant, not proportional | No per-commit growth: a leak would scale with commit count and does not | Absence of a leak. Fragmentation over days, behaviour under memory pressure, other allocators |
| ML-DSA-65 signing latency | n = 2,000: p50 103.11 µs, p95 278.69 µs, p99 405.07 µs, max 660.68 µs, mean 125.47 µs, σ 75.97 µs; mean exceeds median by 1.22× | Signing latency is right-skewed, the expected shape for FIPS 204 rejection sampling | Constant-time behaviour — a latency sample cannot address it. The average rejection-iteration count was not measured |

**The mean dispatch figure exceeds the p90.** One 42.6 ms outlier on a shared runner is
responsible. Quote the median with the tail, never the mean alone. No ratio against provider
round-trip time appears here: this repository has measured no provider RTT, so any such ratio
would be a claim about someone else's network.

## Documentation-pass benchmarks on the `v5.0.1` source baseline (2026-09-24)

Executed by [`scripts/run_benchmarks_5.0.1.py`](../scripts/run_benchmarks_5.0.1.py) on one shared,
unpinned four-CPU `x86_64` container (`Linux`, CPython 3.11.15), against real backends — a real
WAL `fsync` per commit. Full record:
[`evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json`](../evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json);
method in [Benchmark Method §8](benchmarks/BENCHMARK_METHOD.md).

| Experiment | Observed result | What it establishes | What remains unproven |
|---|---|---|---|
| `commit_forensic` latency (n = 1,000) | p50 0.62 ms, p95 1.00 ms, p99 1.22 ms, max 4.18 ms — MMR append + HMAC sign + one real WAL `fsync` per commit | Per-commit latency on this host for a real ledger write | Accepted capacity; other storage devices; behaviour under queueing |
| Concurrent commit throughput | 10 threads 1,727/s · 50 threads 1,630/s · 100 threads 1,482/s | One process, one WAL, one writer: throughput **does not scale with thread count, by design** (`AD-16`) | Multi-process or multi-replica behaviour |
| Streaming ingestion memory | +20.1 MB RSS for 1,000 concurrent in-process SSE streams (20 events each) | Bounded in-process memory for the named workload | Network sockets, durable-WAL cost, provider behaviour |
| Ed25519 sign / verify | 40.5 µs/op / 128.6 µs/op (`cryptography`, RFC 8032; 64-byte signature) | Order of magnitude on this host | HSM-backed paths; other machines |
| ML-DSA-65 sign / verify | 173.0 µs/op / 62.4 µs/op (`aegis_rust`, FIPS 204; 3,309-byte signature) | A latency sample on this host | Constant-time behaviour — the claim remains blocked (`REG-041`, `UC-012`) |

None of these rows is a capacity, SLO or production-readiness figure. The artifact's own
provenance note applies: cite the retained artifact, not this summary.

## Release language controls

Use **“measured under the named workload,” “no statistically significant difference detected under the named experiment,”** and **“offered load.”** Do not use “zero latency,” “zero overhead,” “10k RPS capacity,” “1B RPM,” “constant-time,” “universal WAF” or “production SLO” without a matching artifact, boundary, environment, owner-approved gate and qualified review.

Historical benchmark material from releases before v3.1.0 is not a current capability statement. The immutable v3.1.0 release artifacts remain available at the [GitHub release](https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v3.1.0).

## Artifact and rollback requirements

Every benchmark artifact must be written outside the source tree or attached to the release, hashed with SHA-256 and linked from the provenance envelope. Preserve the raw report and environment metadata read-only. A failed gate blocks the related claim; it must not be hidden by substituting a shorter workload, a different boundary or a more favorable run.

## Related documents

- [`docs/benchmarks/README.md`](benchmarks/README.md)
- [`docs/benchmarks/BENCHMARK_RESULTS.md`](benchmarks/BENCHMARK_RESULTS.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/security/WAF_TESTING.md`](security/WAF_TESTING.md)
- [`docs/security/PQC_CONSTANT_TIME.md`](security/PQC_CONSTANT_TIME.md)
- [`docs/operations/BACKPRESSURE_RUNBOOK.md`](operations/BACKPRESSURE_RUNBOOK.md)
- [`README.md`](../README.md)
