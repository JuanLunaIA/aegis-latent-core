# Product and Evidence Boundaries

**Last verified:** 2026-09-01 UTC
**Release baseline:** checked-out source baseline/release target `4.1.1` with fourteen synchronized anchors

This document consolidates the boundary statements that apply across Aegis. It exists so that `README.md` and the developer guides can describe mechanisms plainly and link here once, instead of repeating a disclaimer beside every sentence.

Nothing here weakens a claim made elsewhere. Where this document and marketing copy disagree, this document and [`CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md) control.

## What Aegis is

An OpenAI-compatible governance and evidence gateway. It sits between an application and an upstream model provider, applies configured request policy, and commits a signed, hash-linked record of governed interactions before returning a response.

## What Aegis is not

It is not a model, a universal web application firewall, a compliance certification, a legal-admissibility determination, a service level objective, or a replacement for network, identity, privacy, retention, or incident-response controls in the deploying organization.

## Evidence boundaries

| Mechanism | What it establishes | What it leaves open |
|---|---|---|
| Durable commit before response | The evidence record was written, flushed, and synchronized through the configured path before the response returned | `fsync` returning means the process asked the kernel to flush. Survival of a power cut is a property of the device, controller, and filesystem. See [storage requirements](operations/STORAGE_REQUIREMENTS.md). |
| Hash chain and signature | Modification of a committed record is detectable without the signing key | The signer is symmetric HMAC by default. A holder of that key can rewrite history consistently. Third-party non-repudiation requires an asymmetric signer and external key custody. |
| Portable MMR inclusion proof | A disclosed leaf is included under a root the verifier already trusts | It does not establish authorship, time, custody, ordering across processes, external immutability, or that the trusted root is authentic. The root must be pinned through an independent channel. |
| Streaming terminal summary | Exactly one summary covering the exact emitted bytes was committed before the terminal marker | Initial stream headers are `pending-terminal` and carry no proof. Per-stream bounds are enforced; aggregate memory scales with concurrency and needs deployment-level admission control. |
| Formal artifacts | The stated formulas and bounded models hold under their declared assumptions | They are abstractions, not refinement proofs of the Python runtime, the Rust runtime, the FFI boundary, the filesystem, or any deployment. |
| Streaming de-identification | Supported bounded identifier grammars are settled before release, including across chunk boundaries | It is deterministic pattern matching. It does not detect every encoding, paraphrase, or semantic disclosure, and it is not the complete HIPAA Safe Harbor method or Expert Determination. |

## Regulatory boundaries

Aegis can contribute technical inputs to a customer's own governance programme. It does not determine regulatory applicability, perform a conformity assessment, issue a certification, establish a lawful basis, or decide admissibility. Scope, configuration, retention, custody, operating effectiveness, and jurisdiction-specific conclusions belong to the deploying organization and its qualified reviewers.

See [`compliance/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md) for the framework-by-framework mapping and [`institutional/DOC-05_REGULATORY_DOSSIER.md`](institutional/DOC-05_REGULATORY_DOSSIER.md) for the full dossier.

## Deployment boundaries

Topology determines evidence semantics. A single process with one worker and its own write-ahead log produces one process-local ordered sequence. Multiple workers sharing one log path do not, and that configuration is unsupported for a single ordered chain. Cross-process and cross-region total ordering is not implemented.

See [`institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md`](institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md) section 8 for the topology matrix.

## Threat-model non-goals

Physical attacks, hypervisor or firmware compromise, host-root adversaries, micro-architectural side channels, guaranteed prevention of prompt injection, upstream provider trustworthiness, and network-layer denial of service are outside the model by design.

See [`institutional/DOC-03_THREAT_MODEL.md`](institutional/DOC-03_THREAT_MODEL.md) section 5.3.

## Evidence-state vocabulary

| State | Meaning |
|---|---|
| **Implemented** | Source and regression tests establish the behavior under stated conditions. |
| **Measured** | A named workload, revision, environment, date, and retained artifact establish a bounded result. |
| **Configuration-dependent** | The control requires validation in the target deployment. |
| **Roadmap** | Incomplete or unmeasured; must not be described as available. |
| **Legal-review-required** | Regulatory, certification, procurement, contractual, and admissibility conclusions sit outside repository evidence. |

## Related documents

- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md) — controlling public claims register.
- [`docs/RELEASE_STATUS.md`](RELEASE_STATUS.md) — version, publication, and provenance record.
- [`docs/institutional/UNSUPPORTED_CLAIMS.md`](institutional/UNSUPPORTED_CLAIMS.md) — claims explicitly not supported.
- [`docs/security/THREAT_MODEL.md`](security/THREAT_MODEL.md) — security threat model.
