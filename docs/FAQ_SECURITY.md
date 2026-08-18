# Security FAQ — Aegis Latent Core v3.1.0

This FAQ is for application-security reviewers, cryptography reviewers, CISOs and security procurement teams. It states the implemented mechanism, the evidence path and the residual risk for common security questions. It does not replace the threat model, security policy, independent assessment or customer controls.

**Last verified:** 2026-08-18 UTC
**Release baseline:** `v3.1.0`
**Audience:** AppSec, cryptography, security architecture and procurement
**Primary security document:** [`SECURITY.md`](../SECURITY.md)

## Is Aegis secure?

That word is too broad to be a useful claim. Aegis implements named controls such as request bounds, application-layer WAF checks, egress validation, signing, WAL integrity, fail-closed paths and strict startup prerequisites. Each control has a residual risk and deployment dependency. The claims matrix is the normative public boundary.

## Is Aegis FIPS validated?

No. ML-DSA-65 is specified by NIST FIPS 204, but the repository does not claim FIPS 140 validation for its module, cryptographic boundary, operational environment or key-management process. HMAC-SHA256 is a classical symmetric mechanism and requires its own deployment and module review.

## Is Aegis quantum-safe or quantum-resistant?

No universal claim is approved. The repository contains a native ML-DSA-65 path when the real Rust extension is available, but the retained verify timing experiment returned `p=0.0`. ML-DSA availability, algorithm standardization and implementation side-channel behavior are separate properties. Long-lived evidence requires a reviewed migration or hybrid design.

## What did the timing experiment show?

The experiment used 1,000,000 interleaved samples per declared operation at the current Python-to-Rust boundary. `sign` returned `p=0.8521504207157158`, which means the named experiment did not detect a statistically significant class difference. `verify` returned `p=0.0` and detected a class-dependent difference. No constant-time statement is authorized.

## Does a p-value prove constant-time behavior?

No. A p-value is conditional on the measured boundary, classes, sample method, CPU, compiler, noise model and statistical test. It cannot prove absence of leakage on other platforms, inputs, observers or implementation paths.

## Does HMAC provide non-repudiation?

No. HMAC is symmetric. A verifier that holds the key can also create a valid MAC. An asymmetric signature may support a non-repudiation argument, but custody, identity, algorithm implementation, verifier independence and legal process remain necessary.

## Does the WAF protect against prompt injection?

The application-layer WAF scans the declared input representation using normalization and pattern controls. The pinned corpus is a regression suite, not universal prompt-injection coverage. It does not include all model behaviors, tool-use attacks, provider-side transformations, HTTP/2 parser differentials or downstream business-logic abuse.

## Does the WAF cover HTTP/2 request smuggling or fragmentation?

No. The retained application harness does not exercise frame fragmentation, pseudo-header ordering, continuation-boundary behavior, H2C, protocol translation or parser disagreement between ingress and application. Those require an authorized, pinned ingress test with retained traffic and environment metadata.

## Does `nuclei-templates/waf-bypass` count as executed?

No. It counts only if a pinned template revision runs against an authorized disposable local target and produces a retained artifact with scope, result and hash. The v3.1.0 retained evidence does not contain that artifact.

## Can a root user bypass the evidence ledger?

The application and file-permission controls are defense in depth. A privileged host actor can potentially alter files, keys, runtime or backups. Immutable external storage, host hardening, access control, monitoring and independent custody are outside the local ledger alone.

## Does strict startup prove production security?

No. Strict startup checks required prerequisites at initialization. It does not prove the ongoing health of the filesystem, kernel, provider, Redis, signer, network, secret manager or backup system. Target acceptance is required.

## Does the egress guard replace a firewall?

No. It validates application-level endpoint forms and allowlists. Network namespaces, firewall policy, cloud egress controls, Kubernetes NetworkPolicy, DNS controls, TLS validation and provider policy remain separate defenses.

## What is the supply-chain posture?

The release process retains lockfile, SBOM, vulnerability/advisory, provenance, manifest, hashes and workflow artifacts. An artifact attestation binds a build artifact to declared workflow and source metadata, but it is not a guarantee that the artifact is secure. Customers should independently verify the release, base image, dependencies, licenses, signatures, vulnerability posture and deployment digest.

## What should a security reviewer request?

Request the source tag and commit, release assets and hashes, SBOM, dependency scan, workflow provenance, claims matrix, threat model, WAF artifact, backpressure artifact, key-rotation artifact, timing artifact, test output, configuration boundary, backup/restore result, secret-manager acceptance, ingress test and support/escalation model.

## Related documents

- [`SECURITY.md`](../SECURITY.md)
- [`docs/security/THREAT_MODEL.md`](security/THREAT_MODEL.md)
- [`docs/security/WAF_TESTING.md`](security/WAF_TESTING.md)
- [`docs/security/PQC_CONSTANT_TIME.md`](security/PQC_CONSTANT_TIME.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md)
- [`docs/FAQ_TECHNICAL.md`](FAQ_TECHNICAL.md)
