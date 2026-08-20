# Aegis Latent Core — Public Claims Matrix

**Status:** v3.1.0 market-hardening release evidence baseline
**Canonical language:** US English
**Last verified:** 2026-08-20 UTC
**Release baseline:** `v3.1.0`
**Owner:** Release owner + qualified security reviewer
**Machine-readable ledger:** `evidence/market_hardening_v3_1/claims_ledger_v3_1_0.json` (generated outside the source tree)

This matrix separates what the repository implements, what has been measured in a named environment, what depends on deployment configuration, what remains roadmap work, and what requires legal or independent review. It is a claim-control document, not a certification.

## Product category

Aegis is an **OpenAI-compatible AI Governance and Evidence Gateway**. It sits between an application and an upstream model provider, applies request policy and security controls, and commits governed request/response evidence to a durable signed ledger before returning a governed successful response. It is not an LLM, a universal WAF, a universal compliance product, a legal-admissibility decision, or a substitute for organizational security controls.

## Claim status vocabulary

| Status | Meaning |
|---|---|
| `IMPLEMENTED` | Source code and regression tests implement the behavior under declared conditions. |
| `MEASURED` | A reproducible artifact exists for a named workload, environment, sample method, and boundary. |
| `CONFIGURATION-DEPENDENT` | Behavior requires deployment controls such as Redis, durable storage, HSM/Vault, Seccomp, LSM, TLS, ingress, or a specific topology. |
| `ROADMAP` | Capability is incomplete, unmeasured, a stub, or future work. |
| `LEGAL-REVIEW-REQUIRED` | Statement could be interpreted as legal, regulatory, certification, procurement, or contractual claim. |

## Buyer-facing claims

| Claim | Status | Evidence path | Boundary / falsification |
|---|---|---|---|
| Aegis exposes an OpenAI-compatible gateway surface. | `IMPLEMENTED` | `aegis/proxy/`, provider contract tests, README integration path | Falsified by a failed contract test or incompatible endpoint behavior. |
| Strict mode rejects startup or requests when required authentication, durable evidence, strong signing, body bounds, distributed limiting, or kernel controls are unavailable. | `CONFIGURATION-DEPENDENT` | `DEPLOYMENT_GUIDE.md`, `tests/test_p0_release_gates.py`, startup and failure-path tests | Target kernel, filesystem, Redis, signer, secrets path, and ingress must be validated at deployment. |
| Governed successful and terminal error responses expose durable evidence status. | `IMPLEMENTED` | `tests/test_enterprise_durable_evidence.py`, proxy failure-path tests, and v3.1.0 release evidence | Falsified by any accepted governed response without a durable evidence record in the declared test scope. |
| Streaming responses are buffered under the configured bound and are not emitted before the evidence gate. | `IMPLEMENTED` | Proxy streaming tests and deployment lifecycle | Large responses beyond the bound must follow the documented rejection/failure path. |
| The ledger detects tampering or chain-link changes through canonical hashes and signatures. | `IMPLEMENTED` | `aegis/core/crypto_audit.py`, `verify_integrity()`, crypto tests | Integrity detection is not proof that an external storage system is immutable. |
| The declared finite-state abstractions preserve commit-before-emission, append-only ledger prefixes, and session-to-ledger binding. | `MEASURED` | `scripts/verify_formal_artifacts.sh`, `specs/aegis_invariants.tla`, `specs/aegis_ledger_immutability.tla`, `specs/aegis_session_manager.tla`, `specs/AegisVerification.lean`, and `specs/aegis_invariants.smt2` | Falsified by a Z3 result other than `unsat`, a Lean type-check failure, or a TLC counterexample in the configured bounds. This is not a refinement proof of the Python/Rust implementation or target filesystem. |
| HMAC-SHA256, HSM/Vault, or a reviewed PQC signer can satisfy the configured signing policy. | `CONFIGURATION-DEPENDENT` | Signer configuration and tests | HMAC is symmetric and classical; it is not third-party non-repudiation or PQ resistance. |
| The enterprise HMAC signer can reload an atomic versioned keyring without restart. | `IMPLEMENTED` | `aegis_server/crypto/keyring.py`, `tests/test_keyring_rotation.py` | Three-replica propagation, secret-manager custody, clock behavior, and failure recovery require deployment evidence. |
| Compliance export bundles retain the non-secret signing key ID used for sealing. | `IMPLEMENTED` | `aegis_server/compliance/exporter.py`, exporter tests | Key ID metadata does not disclose key material or prove custody. |
| ML-DSA-65 is available through the native Rust dependency when the extension is present. | `CONFIGURATION-DEPENDENT` | `aegis/core/pqc_signer.py`, Rust tests, capability endpoint | Does not establish FIPS 140 validation, constant-time behavior, legal admissibility, or production availability on every platform. |
| The application-layer egress guard rejects malformed or unauthorized endpoint forms. | `IMPLEMENTED` | `aegis/proxy/egress_guard.py`, egress tests | Does not replace network namespaces, firewall policy, Kubernetes NetworkPolicy, or cloud egress controls. |
| The pinned WAF corpus recorded zero observed bypasses and zero false positives. | `MEASURED` | `tools/security/run_waf_corpus.py`, `tests/data/waf_corpus_v1.json`, `waf_corpus_report_v1_candidate.json` | 15 malicious and 8 benign local cases only; Wilson interval remains wide; observed rate is not universal detection coverage; HTTP/2 and Nuclei remain unexecuted. |
| The `<5%` WAF bypass threshold applies to any traffic or ingress. | `ROADMAP` | No universal artifact exists. | Threshold is meaningful only for a pinned corpus, ingress boundary, denominator, severity policy, and harness. |
| Under 2 ms injected fsync delay and 10k RPS offered load, 10,000 requests produced 10,000 durable records with zero failures, zero missing/duplicate IDs, and valid chain integrity. | `MEASURED` | `tools/benchmarks/run_backpressure_stall.py`, `backpressure_stall_10k_report.json` | Local injected seam only; observed p99 was 1,189.89 ms; offered load is not accepted capacity and does not prove target storage semantics. |
| Aegis accepts 10k requests/s in production. | `ROADMAP` | No target deployment capacity artifact exists. | Must include topology, upstream, storage, rejected traffic, latency distribution, and recovery. |
| The 2.70 µs result is a background-dispatch microbenchmark. | `MEASURED` | `docs/BENCHMARKS.md` | Must not be presented as end-to-end proxy overhead or provider-visible latency. |
| Cross-replica global audit ordering and multi-region HA are available today. | `ROADMAP` | `docs/performance/SCALING_GUIDE.md`, `docs/ROADMAP.md` | Current topology provides independently verifiable per-replica evidence unless a centralized writer is deployed. |
| Static Samples dashboards represent live runtime, customer activity, cryptographic proof, or production capacity. | `ROADMAP` | `Samples/` plus explicit demo banner and bootstrap metadata | Static dashboards are illustrative only; sample values must not be used as evidence. |
| Aegis implements technical controls that may contribute evidence to customer governance, privacy, security, retention, and policy workflows. | `LEGAL-REVIEW-REQUIRED` | `docs/compliance/COMPLIANCE_MAPPING.md`, `docs/privacy/DATA_RETENTION.md`, and the external source register | Not a SOC 2 opinion, HIPAA determination, FedRAMP authorization, EU AI Act conformity assessment, GDPR legal basis, or legal advice. |
| Aegis provides constant-time ML-DSA signing or verification. | `ROADMAP` | `docs/security/PQC_CONSTANT_TIME.md`, `pqc_timing_report_v2.json` | The retained v3.1.0 1M-sample measurement met non-detection for `sign` (`p=0.8521504207157158`) but failed the declared `verify` threshold (`p=0.0`); no constant-time claim is approved. |
| The open-source project has an enterprise support SLA, customer references, or independent assurance. | `ROADMAP` | No independent evidence in the repository. | Do not imply 24/7 support, SOC 2, pentest completion, or procurement readiness without artifacts and accountable operations. |
| Published pricing hypotheses are market-validated Aegis prices. | `ROADMAP` | `docs/COMMERCIAL_STRATEGY_US.md` | Ranges are illustrative hypotheses pending buyer interviews, cost-to-serve modeling, quotes, and paid pilots. |

## Required wording controls

Use **“implements controls aligned with”** instead of **“satisfies compliance.”** Use **“timing leakage was not detected under the named experiment”** instead of **“constant-time.”** Use **“offered load”** instead of **“capacity.”** Use **“independently verifiable per-replica evidence bundle”** instead of **“globally ordered multi-region audit trail.”** Use **“static demo telemetry”** instead of **“live telemetry”** for material under `Samples/`.

## External reference boundary

Framework references are contribution mappings and review lenses. Primary sources are registered in `evidence/market_hardening_v3_1/documentation_source_register_v3_1_0.md`. They do not certify Aegis, determine legal applicability, or replace a customer assessment.

## Falsification protocol

A public claim is blocked when its source path changes, the named regression or benchmark fails, the workload boundary changes without rerun, a deployment prerequisite is absent, an independent reviewer identifies a contradiction, or a customer-facing document uses stronger language than this matrix. Every future claim must add a locator, evidence artifact, boundary conditions, and a falsification test before publication.

## Machine-readable source

The original baseline scan contained 791 claim-bearing lines and 79 drift candidates. The generated v3.1.0 ledger contains 304 claim records and 27 drift candidates in `claims_ledger_v3_1_0.json`; it is retained as a release artifact outside the source tree. The scan is an inventory aid; human review remains required for context, reachability, legal interpretation, source quality, and the effect of this documentation reconstruction.

## Related documents

- [`README.md`](../README.md)
- [`docs/compliance/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md)
- [`docs/privacy/DATA_RETENTION.md`](privacy/DATA_RETENTION.md)
- [`docs/benchmarks/BENCHMARK_RESULTS.md`](benchmarks/BENCHMARK_RESULTS.md)
- [`docs/security/THREAT_MODEL.md`](security/THREAT_MODEL.md)
- [`docs/security/PQC_CONSTANT_TIME.md`](security/PQC_CONSTANT_TIME.md)
