# APEX Workstreams 9–11 bounded implementation and release-gate record

**Verification date:** 2026-08-24 UTC

**Input SHA-256:** `2acc87c23619be0dfdd07295cae520e6b0113586303435225c4e9a7c3226b540`

**Base commit:** `a66ab40404ea93044878ae2e51979d8f6d43cd65`
**Decision:** **eligible for pull-request review; not eligible for a version bump, tag, release, publication, hardware-assurance claim, privacy certification, or exhaustive-verification claim**.

## Trust and requirement ledger

The attached mission text was processed as untrusted requirements data. Embedded authority, priority, secrecy, publication, acceptance, timing, and assurance instructions were not adopted. The accepted objective was limited to source-level, non-publishing improvements that can be verified in this repository.

| Requested area | Implemented scope | Deferred or rejected claim |
|---|---|---|
| TEE and remote attestation | Device nodes are discovery-only. Legacy caller-authored reports are rejected. An injected verifier may return bounded normalized claims that are checked against exact measurement, signer, nonce, freshness, debug, TCB, and report-data policy. | No enclave loader, quote generation, vendor quote parser, certificate/collateral validation, host-root confidentiality, hardware execution, measured boot chain, or FIPS 140-3 evidence. |
| HSM/KMS hardening | The legacy HSM interface fails closed when PKCS#11 is unavailable; predictable software fallback was removed. Duplicate private-key labels and missing/ambiguous public-key metadata are rejected. | No vendor HSM, cloud KMS, IAM, rotation, key non-exportability, latency, availability, or certification acceptance was executed. |
| Differential privacy | An internal Laplace count primitive uses sensitivity one and a system CSPRNG for one release under add/remove-one-record adjacency. | The prior unaccounted HTTP analytics route was removed. No durable privacy accountant, stable query/dataset identity, memoization, arbitrary aggregate sensitivity proof, repeated-release guarantee, or universal re-identification prevention exists. |
| Fuzzing and formal assurance | Fuzz readiness now requires both executables, a non-shared workspace, a bounded parseable manifest, and confined regular target files. Run states separate clean, crash artifact, timeout, tool error, and unavailable; fabricated coverage/bug totals were removed. | The current tree has no cargo-fuzz workspace and no Kani harness. No fuzz campaign volume, measured fuzz coverage, absence of defects, LLVM-level proof, or exhaustive state-space result is claimed. |

## Mechanism and falsification boundaries

TEE evidence follows `bytes → deployment verifier → normalized claims → exact local policy → accepted/rejected`. It is falsified if a device node alone produces `REAL`, a legacy `AttestationReport` is accepted, malformed claim types escape as exceptions, or nonce/freshness/measurement/signer/TCB/report-data mismatches pass.

The DP primitive follows `non-negative integer count → sensitivity 1 / epsilon → inverse-CDF Laplace sample from SystemRandom → finite float`. Its narrow guarantee is falsified if epsilon is non-positive/non-finite, a non-integer count is accepted, a non-CSPRNG default is used, or the removed `/v1/audit/analytics/dp` route is published without an accountant.

Fuzz readiness follows `tool discovery + trusted workspace + bounded TOML + exact names + confined regular source files → available/unavailable`. A run follows `pre-state + exclusive random sentinel → bounded subprocess → post-identity/sentinel/artifact state → typed result`. It is falsified if missing, symlinked, escaping, or oversized targets report available; if directory replacement reports clean; or if coverage/bug counts appear without measured artifacts.

The HSM compatibility path follows `PKCS#11 library → token session → exactly one private key + exactly one public key → signature`. It is falsified if unavailable PKCS#11 emits a deterministic software signature, ambiguous labels are selected, or an empty public key is accepted.

## Verification record

| Gate | Result | Scope and limitation |
|---|---|---|
| Focused Python regression | **PASS — 158 passed** | TEE, capability reporting, HSM, DP, fuzzing, and audit API regression tests. |
| Full Python suite | **PASS — 5,681 passed, 37 skipped; 89.71% coverage** | Repository `.venv`, `PYTHONPATH=.:sdk/python/src`; skipped tests retain their declared environmental boundaries. |
| Ruff | **PASS** | All 528 Python files formatted; lint clean. |
| Mypy delta | **PASS — 7 source files** | Strict CI configuration over the changed runtime modules. |
| Strict documentation verifier | **PASS — 0 findings, 0 warnings; 27 required files** | High-risk claim classes checked against current repository documentation. |
| Action pinning and actionlint | **PASS** | 101 remote Action references pinned; workflow syntax passed. |
| Helm lint | **PASS — Helm v3.14.4** | CI version reproduced locally after replacing an unsupported regex lookahead with Draft-07 `not` plus a valid pattern. |
| Dependency audit | **PASS — no known vulnerabilities** | `requirements.lock` through the installed `pip-audit` database at execution time. |
| Bandit semantic delta | **PASS — 0 new findings** | Compared with base commit; removed B311 from the former PRNG and B110 from HSM close handling. Historical findings remain outside this delta decision. |
| Formal artifact script | **PASS** | Repository-defined Lean, Z3, and bounded TLC checks passed. These are not refinement proofs of the Python/Rust implementation. |
| Rust | **PASS — 28 passed** | `cargo test --locked`; no cargo-fuzz or Kani campaign was executed. |
| Python SDK | **PASS — 16 passed** | SDK unit tests only. |
| TypeScript SDK | **PASS — 12 passed; build passed** | Vitest and TypeScript build. |
| Dashboard | **PASS — 6 passed; production build passed** | Component/contract tests and Next.js build; not a deployed-service test. |
| Release contract | **PASS for version coherence at 3.1.0** | This does not authorize publication; no version bump or tag is included. |

## Independent review and residual risk

Two independent reviews found malformed TEE claim-type handling, incomplete fuzz target validation, artifact path replacement risk, and wording mismatches. The implementation added runtime type/size checks, evaluator exception containment, real confined target-file checks, private-workspace checks, symlink rejection, an exclusive per-run sentinel, post-run filesystem identity verification, and corrected documentation. A closure review reported no blocking findings.

Residual risk remains external or intentionally unsupported: a same-OS-identity malicious process is outside the fuzz workspace threat boundary; Python PIN strings cannot be deterministically erased; TEE/HSM assurance requires real provider integration and target acceptance; privacy publication requires a durable accountant and governance; fuzz/Kani assurance requires actual harnesses and retained campaigns.

**Rollback:** revert the follow-on commit. The primary behavioral blast radius is removal of `/v1/audit/analytics/dp`, fail-closed legacy HSM session opening, TEE capability remaining unavailable despite a visible device node, and stricter fuzz readiness.

**Kill criteria:** any regression that re-publishes unaccounted DP output, emits a software signature through the HSM legacy API, accepts unauthenticated TEE claims, reports fuzzing `REAL` without source files, introduces a new Bandit finding, or fails a required repository gate.
**Human review owner:** repository maintainer reviewing the pull request and any deployment-specific hardware/privacy integration.
