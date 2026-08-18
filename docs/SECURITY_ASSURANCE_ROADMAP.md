# Security Assurance Roadmap — Aegis Latent Core v3.1.0

This roadmap distinguishes **repository evidence** from **deployment acceptance** and **independent assurance**. Passing repository tests does not create a certification, attestation or customer-specific production SLO.

**Last verified:** 2026-08-18 UTC
**Release baseline:** `v3.1.0`

## Assurance layers

| Layer | Current status | Required artifact | Owner |
|---|---|---|---|
| Source and regression | Implemented and published for v3.1.0; post-release documentation hardening is tracked on `main` | Test output, lint, dependency scan, SBOM, source/tree hash | Release owner |
| Deployment controls | Configuration-dependent | Target kernel/LSM/Seccomp, ingress, storage, Redis, signer, TLS, backup, and recovery evidence | Customer platform/SRE |
| Adversarial application testing | Local WAF corpus passed; HTTP/2 ingress corpus not executed | Pinned corpus, minimized regressions, ingress boundary, raw results | Security reviewer |
| Key custody and rotation | File-backed keyring contract implemented; three-replica production run unverified | Secret-manager propagation, overlap, rollback, expiry, replica evidence | Security/platform owner |
| Native crypto timing | Sign experiment measured; verify experiment failed the declared threshold | Repeated native sign/verify timing experiments, raw samples, implementation review | Qualified crypto reviewer |
| Independent security review | Not completed by this repository | Scope, methodology, findings, retest, residual risk | Independent assessor |
| Production pilot | Not established in public evidence | Customer-owned workload, consented metrics, rollback, incident evidence | Customer + release owner |
| Certification / attestation | Not claimed | Applicable external assessment and formal report | Qualified external authority |

## Prioritized sequence

The first milestone is to keep all public claims tied to the source and release artifacts. The second is to run target-deployment acceptance against the customer’s actual ingress, storage, key manager, kernel controls, and recovery process. The third is an independent code and threat-model review. The fourth is a controlled pilot with a written acceptance report. Certification or attestation work is considered only after those layers exist and counsel identifies a concrete scope.

## Release blockers

A release remains blocked when any governed accepted response lacks durable evidence within the tested scope, when the signer or key ID cannot be verified, when a critical WAF corpus case bypasses, when public language exceeds its artifact, when a dependency gate has an unresolved critical finding, or when rollback and incident ownership are undefined.

## External review scope

A qualified reviewer should inspect request admission, canonicalization, WAF normalization, egress validation, rate-limit failure handling, WAL ordering and replay, signature coverage, key reload state transitions, stream buffering, error evidence, secret handling, container/runtime profiles, and documentation claims. The review should state exclusions, test environment, error rate, residual risk, and retest conditions.

## PQC and side-channel status

A native ML-DSA-65 dependency is a cryptographic implementation fact, not a certification. The project must separately track algorithm conformance, implementation review, key custody, compiler/build reproducibility, timing-leakage assessment and any FIPS 140 module boundary. The retained v3.1.0 experiment detected no significant difference for `sign` (`p=0.8521504207157158`) but detected a class-dependent difference for `verify` (`p=0.0`). Until the verifier boundary is reviewed and rerun, approved language is limited to backend availability and the measured experiment; no constant-time claim is permitted.

## Customer pilot evidence

A customer pilot must not expose customer payloads in the public repository. The public release may publish sanitized methodology, aggregate results, artifact hashes and explicit scope. Private raw evidence remains subject to the customer’s lawful basis, retention, access and disclosure policy.

## Related documents

- [`README.md`](../README.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/compliance/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md)
- [`docs/security/THREAT_MODEL.md`](security/THREAT_MODEL.md)
- [`docs/operations/ROLLBACK_RUNBOOK.md`](operations/ROLLBACK_RUNBOOK.md)
- [`docs/FAQ_SECURITY.md`](FAQ_SECURITY.md)
