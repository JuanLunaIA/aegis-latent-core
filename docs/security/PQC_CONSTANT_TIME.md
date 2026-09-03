# ML-DSA-65 Timing Assessment — Aegis Latent Core v4.1.1 Source Baseline

This document is for cryptography reviewers and security architects evaluating the native ML-DSA-65 timing boundary. It defines the experiment, statistical interpretation, retained result and blocked claims. It does not prove constant-time execution, side-channel absence, FIPS 140 validation or legal admissibility.

**Last verified:** 2026-08-27 UTC
**Release baseline:** four-layer truth model
**Source baseline/release target:** `v4.1.1` with 14 synchronized anchors; source metadata does not establish external lifecycle state; verify the tag, GitHub Release, PyPI, npm, OCI digest, signature, and attestation through independent readback
**Immutable comparison source:** `fdace8844568eb788216740b2cb5daf187d99d3b` with `4.0.0` anchors
**Previous public GitHub Release:** `v4.0.1` lightweight tag targeting `6469904380218584ae0b5221334bc9a46500f5ba`
**Observed registries:** PyPI/npm `4.0.0`, without workflow provenance attribution
**Historical evidence baseline:** retained `v3.1.0` timing evidence remains historical and is not a `v4.1.1` result
**Scope:** Native ML-DSA-65 `sign` and `verify` boundary
**Current assurance status:** No constant-time claim is approved

## Terminology correction

A timing assessment must distinguish **signing** from **verification**. The expected p-value statement applies to one experiment and cannot be transferred between operations. If the native implementation exposes both operations, run and report separate results.

## Required experiment

The benchmark must run the release-optimized native implementation, not a Python request-path benchmark. The repository harness is `tools/benchmarks/run_pqc_timing.py`; it measures the exposed Python-to-native boundary, including the current Rust binding’s key/signature decode work. Record CPU model and microarchitecture, kernel, compiler, Rust toolchain, crate version, build flags, CPU affinity, frequency/turbo controls, process isolation, sample generator, random seeds, and environmental noise. Run at least 1,000,000 samples for each declared experiment, use multiple seeds/runs, balance fixed and variable classes, retain raw timing samples, and publish the harness version and artifact hash.

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_pqc_timing.py \
  --operation both --samples 1000000 --warmup 10000 \
  --output evidence/pqc_timing_report.json \
  --raw-output evidence/pqc_timing_raw.jsonl
```

The harness exits with `2` and writes `UNAVAILABLE` when the real native backend cannot be loaded. That is a blocked timing claim, not a pass or a simulated measurement.

The null hypothesis is that the timing distributions do not contain detectable class-dependent leakage under the chosen experiment. A result with `p > 0.05` means **no statistically significant leakage detected under this experiment**. It does not prove constant-time execution, compiler-level constant-time preservation, absence of microarchitectural leakage, or FIPS 204 validation.

Report p-value, effect size, sample balance, confidence bounds, outliers, run-to-run divergence, environmental noise, and the exact implementation boundary. A failed result blocks any constant-time marketing wording and triggers triage; it must not be hidden behind an average or discarded run.

## Release language

Allowed before independent review:

> ML-DSA-65 signing and verification use the native Rust backend when available. Timing leakage has not been independently ruled out; a dudect-style assessment is a release prerequisite for any stronger side-channel statement.

Allowed only after the named experiment passes:

> No statistically significant timing leakage was detected for ML-DSA-65 `<operation>` under harness `<version>`, `<sample count>`, `<CPU>`, `<kernel>`, and `<build>`.

Blocked without implementation review, dependency review, build reproducibility, and qualified external assurance:

> Aegis is constant-time, side-channel proof, FIPS 204 certified, or FIPS 140 validated.

## Historical v3.1.0 timing status

The source-level signer correctly refuses to fabricate ML-DSA signatures when the Rust backend is unavailable. A release build was loaded and measured with 1,000,000 interleaved samples per operation. In the retained historical `v3.1.0`-era v2 artifact, `sign` produced `p = 0.8521504207157158` and met the experiment’s non-detection threshold; `verify` produced `p = 0.0` with a measured mean delta of `540.5259299977988 ns`, so the verify experiment did not meet the threshold. This result is not a constant-time proof or a diagnosis of secret leakage: the current verifier decodes public key and signature bytes on every call, and the experiment varied valid signatures over a fixed message. The release gate for any constant-time claim remains closed until the verifier boundary is reviewed and rerun under the declared protocol.

## Falsification

The claim is falsified within the declared envelope by a statistically significant class-dependent timing difference, a failed signature-class control, unexplained run divergence, sample imbalance, noisy or unisolated execution, missing raw samples, changed compiler/crate/build flags, or a reviewer finding that the measured function is not the deployed function.

## Related documents

- [`../benchmarks/BENCHMARK_RESULTS.md`](../benchmarks/BENCHMARK_RESULTS.md)
- [`../CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
- [`../FAQ_SECURITY.md`](../FAQ_SECURITY.md)
- [`../../README.md`](../../README.md)
