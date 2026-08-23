# WAF Testing and Evasion Boundaries

This document defines the application-layer WAF corpus, metrics, reproduction method and ingress boundary for security reviewers. It does not provide universal prompt-injection detection, HTTP/2 parser coverage, or a production WAF certification.

**Last verified:** 2026-08-22 UTC
**Release baseline:** `v3.1.0`
**Scope:** Aegis application-layer payload inspection
**Current artifact:** `evidence/market_hardening_v3_1/waf_corpus_report_v1_candidate.json` outside the source tree

## What is tested

Aegis normalizes user-visible text with NFKC and removes selected zero-width characters before the critical-pattern layer. The critical layer runs before weighted local analysis. The local corpus covers benign prompts, direct instruction override, prompt exfiltration, persona override, template syntax, case and spacing variants, Unicode normalization, nested messages, and a structural-depth guard.

Run the pinned local corpus with:

```bash
PYTHONPATH=. .venv/bin/python tools/security/run_waf_corpus.py \
  --corpus tests/data/waf_corpus_v1.json \
  --output evidence/waf_corpus_report_v1.json
```

The harness records the repository commit, corpus SHA-256, environment, per-case expected and observed verdict, bypass count, false positives, and a Wilson 95% interval for the observed malicious-case bypass rate.

## Metric definition

For this corpus:

```text
observed_bypass_rate = missed_malicious_cases / executable_malicious_cases
false_positive_rate  = benign_cases_blocked / executable_benign_cases
```

The `<5%` threshold is a release threshold for the named corpus and configuration only. It is not a universal WAF guarantee. A critical-severity bypass blocks the gate regardless of the aggregate rate. The denominator must exclude invalid or ambiguous cases and must be preserved with the artifact.

## Current result

The v3.1.0 candidate corpus contains 15 executable malicious cases and 8 benign cases. The current local run recorded **0 bypasses and 0 false positives**, with the observed bypass rate below the corpus threshold. The Wilson interval remains wide because the corpus is small; the result is a regression signal, not statistical proof of universal detection coverage.

## HTTP/2 and ingress boundary

The application-layer harness does not execute HTTP/2 fragmentation, pseudo-header ordering, continuation boundaries, duplicate-header normalization, content-length/transfer-encoding conflicts, compressed-body behavior, or ingress-specific parser differentials. Those tests MUST run against an authorized local target at the actual TLS/HTTP/2 termination boundary. If HTTP/2 terminates at an ingress controller, Aegis cannot claim to control parser behavior that occurs before the application receives the normalized request.

A future privileged or integration suite must pin the ingress image, HTTP/2 library, corpus revision, request capture format, and target topology. It must minimize every bypass into a safe regression fixture and preserve the normalization trace without publishing live-target instructions.

## Nuclei templates

`nuclei-templates/waf-bypass` is **NOT EXECUTED** in the current release artifact. Running it requires a pinned repository revision, license/provenance record, a disposable local target owned by the project, and a review that excludes live or third-party targets. Do not convert the absence of that run into a pass.

## Residual risk

A WAF is one control at one protocol boundary. It does not replace authentication, authorization, output handling, model-specific safety, network egress policy, secrets management, tenant isolation, or incident response. False negatives remain possible outside the named corpus, especially for semantic, multilingual, encoded, multimodal, and provider-specific attack classes.

## Related documents

- [`../CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
- [`../benchmarks/BENCHMARK_RESULTS.md`](../benchmarks/BENCHMARK_RESULTS.md)
- [`../FAQ_SECURITY.md`](../FAQ_SECURITY.md)
- [`../../README.md`](../../README.md)
