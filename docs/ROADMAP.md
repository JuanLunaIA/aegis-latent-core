<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Engineering and Market Roadmap

**Status:** Published v3.1.0 release line with open deployment and assurance work
**Last verified:** 2026-08-18 UTC
**Release baseline:** `v3.1.0`
**Purpose:** Single source of truth for work that is implemented, measured, deployment-dependent, or still open.

## Status rules

| Mark | Meaning |
|---|---|
| `[x]` | Implemented and covered by a named test or artifact under declared conditions. |
| `[m]` | Measured by a reproducible artifact; not a universal capacity or assurance claim. |
| `[d]` | Deployment-dependent; source support exists but target infrastructure evidence is required. |
| `[ ]` | Open work, incomplete, unmeasured, or intentionally not claimed. |
| `[l]` | Requires legal, regulatory, contractual, or independent-assurance review. |

A checkbox may not be changed to `[x]` because a stub, dashboard sample, docstring, vendor statement, or favorable benchmark exists. Every change requires a locator, test or artifact, boundary, and falsification condition in [`CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md).

## Current public baseline

The current immutable public release is [`v3.1.0`](https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v3.1.0). Its release pipeline completed with source, wheels, provenance, hashes and GitHub checks. The historical `v3.0.1` release remains available for provenance; it is not the current capability baseline. The open items below are deployment, assurance, independent-review or future-product work and must not be represented as shipped capabilities.

## Completed core controls

- [x] Strict runtime mode requires authentication, durable evidence, strong signing, request-size bounds, distributed rate limiting, and configured kernel controls.
- [x] Governed successful, streaming, and terminal-error paths expose durable evidence status and use the durable error-evidence path where storage is available.
- [x] The ledger canonicalizes hashes, binds chain links, signs records, persists WAL segments, synchronizes the WAL before the governed success path, and verifies integrity.
- [x] Redis rate-limit failure is observable and fail-closed at the HTTP boundary.
- [x] Egress endpoint validation rejects malformed, unsupported, userinfo-bearing, and non-approved endpoints.
- [x] Seccomp and LSM/AppArmor/SELinux guards distinguish required enforcement from explicit sandbox/development operation.
- [x] Response analysis uses bounded workers and per-session serialization; enrichment is not required for authoritative evidence.
- [x] Native ML-DSA and other hardware-dependent controls refuse to fabricate success when their real backend is unavailable.
- [x] Dependency, SBOM, release provenance, and security disclosure surfaces exist and are tied to release artifacts.

Historical implementation detail remains in [`CHANGELOG.md`](../CHANGELOG.md), git history, module docs, and release assets. This file tracks current decision status rather than repeating every historical patch.

## v3.1.0 market-hardening release

### Documentation and claim governance

- [x] Restore a complete US-English README as the primary product, architecture, operation, buyer, and repository index.
- [x] Add `docs/PRODUCT_BRIEF_US.md`, `docs/BUYER_GUIDE_US.md`, and `docs/COMMERCIAL_STRATEGY_US.md` with an explicit non-binding pricing hypothesis and no fabricated customer proof.
- [x] Replace stale security and commercial documents with current support, disclosure, license, procurement, and assurance boundaries.
- [x] Add `docs/REPOSITORY_MAP.md`, `docs/security/THREAT_MODEL.md`, `docs/security/WAF_TESTING.md`, `docs/security/PQC_CONSTANT_TIME.md`, and `docs/SECURITY_ASSURANCE_ROADMAP.md`.
- [x] Mark all `Samples/` dashboards as static demo-only and add explicit provenance metadata; sample numbers are not runtime evidence.
- [x] Update `CLAIMS_MATRIX.md` with evidence locators, falsification conditions, and prohibited wording.

### Backpressure and WAL

- [x] Add an injectable `fsync_fn` seam while keeping `os.fsync` as the production default.
- [x] Add a deterministic 10k RPS offered-load / injected-fsync-stall harness with missing/duplicate ID checks, chain verification, latency percentiles, and WAL hash.
- [m] Local result: 10,000 offered requests at 10k RPS, 10,000 durable commits, zero failures, zero missing IDs, zero duplicate IDs, and valid chain integrity under a 2 ms injected fsync delay; observed p99 commit latency was 1,189.89 ms.
- [ ] Run the equivalent test against a disposable, loop-backed `dm-delay` block device only when root/capability, device ownership, cleanup, and isolation are proven.
- [ ] Add customer-target storage acceptance for filesystem, CSI/cloud volume, backup, restore, crash recovery, and external immutable retention.
- [ ] Revisit group commit or a Rust WAL path only after preserving the per-request durability contract and proving ordering semantics.

### WAF and ingress

- [x] Add a critical persona-override rule and regression coverage.
- [x] Add a pinned application-layer corpus with benign, critical, Unicode, structural, and nested cases.
- [m] Local result: 0 observed bypasses and 0 false positives across 15 malicious and 8 benign cases; Wilson interval remains wide because the corpus is small.
- [ ] Pin and execute HTTP/2 fragmentation and parser-differential tests at the actual authorized ingress boundary.
- [ ] Pin a reviewed `nuclei-templates` revision and run only against a disposable, owned local target; retain raw artifacts and minimize every finding into a safe regression test.
- [ ] Expand corpus by language, encoding, multimodal boundary, provider parameter, and parser normalization class with measured false-positive review.

### Key rotation

- [x] Add a versioned HMAC keyring with one active key, verify-key overlap, expiry, atomic snapshot validation, reload failure counter, and no-secret logging.
- [x] Add signer metadata so compliance exports persist the non-secret key ID used for sealing.
- [x] Add unit tests for rotation, overlap, expiry, invalid snapshot, weak key, duplicate ID, and initial-load failure.
- [ ] Run the full three-replica deployment test with staggered reload, secret-manager propagation, one delayed replica, restart/replay, rollback, and per-record key ID correlation.
- [ ] Add HSM/Vault rotation evidence and compare behavior with file-backed keyring under network failure.

### ML-DSA timing and assurance

- [m] Run separate native `sign()` and `verify()` timing experiments with 1,000,000 balanced interleaved samples per operation, release build, raw sample retention, and a declared Python-to-Rust boundary. `sign` met the non-detection threshold (`p=0.8521504207157158`); `verify` did not (`p=0.0`).
- [ ] Repeat across isolated CPU runs/seeds and report effect size, outliers, noise, run divergence, and implementation-boundary review before any stronger claim.
- [ ] Use only “no statistically significant timing leakage detected under the named experiment” after a passing run; never use “constant-time” without qualified review and the required evidence.
- [ ] Track algorithm conformance, compiler/build reproducibility, key custody, module boundary, and any FIPS 140 review separately.

## P0/P1 open work

- [ ] Replace the honest `zk_proof` stub with a reviewed real proving system or remove the public feature surface; `require_real=True` must continue to fail closed until then.
- [ ] Add an external transparency-log or timestamp anchoring backend with verifiable third-party evidence; never fabricate transaction IDs or proofs.
- [ ] Complete actual ingress, storage, secret-manager, kernel, TLS, Redis, backup, restore, and crash-recovery acceptance for each supported deployment profile.
- [ ] Keep dependency and action exceptions bounded, owned, time-limited, and documented; no silent advisory ignore.
- [ ] Complete an independent threat-model and code review before any certification, court-admissibility, or high-assurance procurement language.

## P2 performance and operations

- [ ] Measure end-to-end proxy latency with a real or explicitly bounded upstream, including evidence durability, streaming, WAF, rate limiting, and provider failure paths.
- [ ] Measure multi-worker or multi-process topology with the actual container/seccomp policy; document worker count, GIL/event-loop boundary, storage, and rejected traffic.
- [ ] Bound and instrument every cache and queue with explicit eviction, age, saturation, and memory-pressure tests.
- [ ] Add memory-pressure, disk-exhaustion, WAL rotation, and recovery tests that preserve evidence correlation.
- [ ] Publish an SLO only after an owner, target, error budget, telemetry, and rollback path exist.

## Market and assurance work

- [x] Define one initial ICP: private-deployment B2B SaaS, fintech, and regulated-enterprise platform/security teams operating multiple model providers.
- [x] Define the sales sequence: local evaluation, evidence replay, controlled pilot, security review, procurement package, production rollout.
- [x] Define non-binding package hypotheses and support boundaries.
- [ ] Validate pricing with at least three buyer interviews, cost-to-serve modeling, comparable quotes, and a paid pilot.
- [ ] Build a support operation before promising contractual response targets, 24/7 coverage, or mission-critical SLA.
- [ ] Create a customer data/retention/deletion statement and have counsel review AGPL/commercial terms before external sale.
- [ ] Obtain independent security, cryptographic, and deployment assurance appropriate to the target buyer segment.

## Release gate

The v3.1.0 release passed its declared publication gate. Future market-facing releases remain blocked until the affected source and tests pass, version anchors are coherent, the claim matrix is updated, documentation has no stronger language than the artifacts, the SBOM and dependency gates are clean or explicitly excepted, release provenance is regenerated, rollback and kill criteria are documented, and a qualified reviewer accepts the residual risk.

## Related documents

- [`README.md`](../README.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/BENCHMARKS.md`](BENCHMARKS.md)
- [`docs/SECURITY_ASSURANCE_ROADMAP.md`](SECURITY_ASSURANCE_ROADMAP.md)
- [`docs/COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md)
- [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md)
