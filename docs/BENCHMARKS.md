<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Benchmark and Measurement Record

**Status:** v3.1.0 market-hardening candidate

This document is the canonical interpretation guide for repository benchmarks. A benchmark is evidence only for its declared workload, environment, code boundary, sample method, and artifact. It is not a production SLO, capacity guarantee, certification, or universal security result.

## Measurement contract

Every performance or security measurement must record the workload, environment, warmup, sample count, statistic, code boundary, command, raw or derived artifact, exit status, timestamp, and SHA-256. Changes to source, compiler, dependency, storage, corpus, runtime flags, or measurement method invalidate prior claims until the affected experiment is rerun.

| Field | Required content |
|---|---|
| Workload | Request shape, payload size, provider behavior, concurrency, offered load, and duration. |
| Environment | CPU model and affinity, kernel, Python/Rust/compiler/library versions, storage, container/runtime, and relevant security controls. |
| Warmup | Explicit warmup duration and cache state. |
| Samples | Count, class balance, seed or deterministic generator, rejected samples, and failures. |
| Statistics | p50/p95/p99/max, confidence interval or p-value where applicable, outlier policy, and effect size. |
| Boundary | Dispatch-only, proxy client-visible, upstream-inclusive, WAL durability, WAF application boundary, keyring lifecycle, or native crypto function. |
| Artifact | Raw data, summary report, command, exit status, timestamp, and SHA-256. |

## Candidate results

The following results were executed in the current sandbox against the v3.1.0 candidate checkout. They are bounded measurements, not production claims.

| Experiment | Observed result | What it establishes | What remains unproven |
|---|---|---|---|
| Full Python regression | 5,442 passed, 37 skipped, 47 warnings in 68.08 s; 93.91% line coverage | The current Python test suite passed in the named environment. | Other Python versions, kernels, providers, and deployment topologies. |
| Rust unit tests | 26 passed, 0 failed; doc-tests 0 passed | The Rust unit suite passed with Cargo 1.97.1 and the committed lockfile. | Cross-compilation, released wheels on every target, and production runtime behavior. |
| WAF corpus | 15 malicious and 8 benign cases; 0 bypasses; 0 false positives; Wilson 95% upper bound approximately 20.39% for bypass rate | The pinned corpus passed the application-layer regression gate. | Universal prompt-injection detection, HTTP/2 parser differentials, ingress normalization, and Nuclei coverage. |
| Backpressure | 10,000 requests offered at 10,000 RPS with 2 ms injected `fsync` delay; 10,000 durable commits; 0 failures; 0 missing IDs; 0 duplicates; valid chain | No-silent-drop and chain-correlation behavior under the injected application seam. | Accepted capacity, production SLO, `dm-delay` block-device equivalence, cloud volume semantics, and recovery of every failure mode. |
| Backpressure latency | Total runtime 32.36878035601694 s; p50 202.13615702232346 ms; p95 614.082946034614 ms; p99 1189.8909930023365 ms; max 3208.868669986259 ms | The offered load produces substantial queueing while preserving evidence integrity. | Any claim that the gateway is low-latency or accepts 10k RPS in production. |
| Key rotation | 2,239 records across three independent local signer instances; 0 failed commits; 0 unverifiable records; old and new key IDs observed; keyring mode `0o600` | Atomic local snapshot replacement, overlap verification, key ID metadata, and no-restart signer behavior within the local harness. | Kubernetes/secret-manager propagation, independent process restart, clock skew, distributed storage, and rollback under orchestration. |
| ML-DSA sign timing | 1,000,000 interleaved samples; `p=0.8521504207157158`; validity control passed | No statistically significant timing difference was detected for `sign` under the named experiment. | Constant-time proof, compiler/microarchitecture leakage, FIPS 140 validation, and independent review. |
| ML-DSA verify timing | 1,000,000 interleaved samples; `p=0.0`; measured mean delta 540.5259299977988 ns | The declared verify experiment detected a class-dependent timing difference at this boundary. | Root cause, exploitability, secret leakage relevance, and whether an alternative verifier boundary removes the effect. The constant-time claim is blocked. |
| WAF gate implementation | Script gate requires zero critical bypasses, observed bypass below 5%, and zero false positives | The executable gate matches the stricter regression test and public claim. | Corpus completeness and actual ingress parser behavior. |

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

A `dm-delay` experiment is a separate privileged lab operation. It must use a disposable loop-backed block device or namespace, explicit capability checks, and a retained chain-of-custody record. It must never attach to host, production, or user data volumes. If those constraints cannot be proven, the result is `NOT_EXECUTED`.

### Key rotation

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_key_rotation.py \
  --duration-s 0.5 --output evidence/key_rotation_report.json
```

The local exercise uses three independent signer instances, atomic replacement, overlap verification, key IDs, and owner-only file permissions. A production acceptance must additionally exercise the actual secret manager, three process lifecycles, restart/replay, delayed propagation, independent storage, clock behavior, and rollback.

### Native ML-DSA timing

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_pqc_timing.py \
  --operation both --samples 1000000 --warmup 10000 \
  --output evidence/pqc_timing_report.json \
  --raw-output evidence/pqc_timing_raw.jsonl
```

The harness measures the current Python-to-Rust boundary, including public-key/signature decoding performed by the binding. It returns `2` and writes `UNAVAILABLE` when the real backend is absent. A p-value above 0.05 is **non-detection under the experiment**, not proof of constant-time execution. The retained candidate passed the `sign` experiment and failed the `verify` experiment.

## Release language controls

Use **“measured under the named workload”**, **“no statistically significant difference detected under the named experiment”**, and **“offered load”**. Do not use “zero latency,” “zero overhead,” “10k RPS capacity,” “1B RPM,” “constant-time,” “universal WAF,” or “production SLO” without a matching artifact, boundary, environment, owner-approved gate, and qualified review.

Historical benchmark material from releases before v3.0.1 is not a current capability statement. The immutable v3.0.1 release artifacts remain available at the [GitHub release](https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v3.0.1); the v3.1.0 line is a candidate until source, tests, supply-chain scans, GitHub checks, human review, and provenance pass together.

## Artifact and rollback requirements

Every benchmark artifact must be written outside the source tree or attached to the release, hashed with SHA-256, and linked from the provenance envelope. Preserve the raw report and environment metadata read-only. A failed gate blocks the related claim; it must not be hidden by substituting a shorter workload, a different boundary, or a more favorable run.
