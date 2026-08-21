# Final Verification Report — Aegis Latent Core

**Date:** 2026-08-21 UTC  
**Repository:** `JuanLunaIA/aegis-latent-core`  
**Final verified `main` commit:** `43677edca6d39a2b4078187d3676d5a286627846`  
**Prepared by:** Manus AI

## Executive decision

**Gate result: CONDITIONAL PASS.** `[ESTABLISHED]` The code, Python 3.11 remediation, bounded SSE behavior, formal gates, source SBOM, container build, GitHub Actions SHA pinning, selected-action allowlist, signed-commit requirement, and administrator branch-protection enforcement are merged to `main` and have passed actual GitHub Actions executions.[1] [2] [3] [4] [5] The final `main` commit is GitHub-verified with a valid signature.

The qualification is external authority, not a failing repository control. `[UNRESOLVED]` The active GitHub integration receives HTTP 403 from the Dependabot, code-scanning, and secret-scanning alert-list endpoints. Therefore, this report does **not** claim that the open-alert count is zero. The public Security page exposes the repository security policy but not the private alert inventories.[6]

## Scope and mechanism

The verification chain was `uploaded repository and instructions → local reproduction and remediation → pull-request CI → signed squash merge → post-merge CI → repository-policy hardening → active reruns under the hardened policy → evidence snapshots`. The acceptance boundary required Python 3.11 to complete rather than be cancelled, every remote workflow reference to be a full commit SHA, source and container supply-chain jobs to pass on `main`, and repository settings to be read back from the GitHub API.

| Front | Implemented mechanism | Failure observable | Final result |
|---|---|---|---|
| Python 3.11 | Bounded test job, faulthandler, deterministic runtime-manifest audit, one bounded retry only for operational audit failure | Timeout, failed pytest, vulnerability finding, or second audit failure | **PASS** |
| SSE buffering | Per-response byte and total-duration bounds; upstream generator closure; durable 502/504 evidence | Limit/deadline regression or unclosed generator | **PASS** |
| Actions supply chain | 76 source references pinned to 40-character SHAs; CI pin verifier; repository SHA enforcement | Mutable `uses:` reference or policy rejection | **PASS** |
| Action publisher scope | Selected allowlist of 31 direct and observed transitive action paths | Workflow setup rejection for an omitted action | **PASS after active closure test** |
| Source provenance | Deterministic source archive, SPDX 2.3 SBOM, OIDC/Sigstore attestation | Syft failure, digest mismatch, or attestation verification failure | **PASS** |
| Branch governance | 13 required CI contexts, strict updates, one code-owner review, admin enforcement, required signatures | API readback differs or a protected push bypasses controls | **PASS** |
| Security alert inventory | Authenticated REST enumeration | HTTP 200 with list payload | **BLOCKED: HTTP 403** |

## Merged change sets

PR #94 established the formal-verification gates, WAL concurrency hardening, institutional documentation corpus, claim corrections, and dependency updates.[7] PR #95 merged the Python 3.11 cancellation and audit fixes, SSE byte/deadline limits, workflow timeouts, deprecation cleanup, and SHA pinning as signed squash commit `8907a6db75cff2a3bd6a551ef7983f53bda17027`.[1] PR #96 corrected the `main`-only SBOM source-type failure and made SBOM generation execute on pull requests before merge; it merged as signed squash commit `43677edca6d39a2b4078187d3676d5a286627846`.[2]

The SBOM defect was mechanistic: `anchore/sbom-action` treated the `.tar.gz` passed through `path` as `dir:<archive>`, and Syft rejected it because it was not a directory. The fix extracts the deterministic `git archive` into `sbom-root/`, catalogs that directory, retains the archive as the attested subject, and restricts the OIDC attestation step to `main` pushes and releases.

## Actual CI evidence

### Final `main` execution

`CI` run `32448725497` completed successfully on the final commit.[3] The original post-merge attempt passed all 14 jobs after the SBOM source fix. A later active rerun under selected-action enforcement exposed omitted transitive composite actions; after restricting the allowlist to the observed closure, attempt 3 completed successfully.

| Job | Final conclusion |
|---|---|
| License Headers and action-pin verifier | Success |
| Formal Verification (Z3, Lean, TLC) | Success |
| Lint & Format | Success |
| Type Check | Success |
| Test (Python 3.11) | Success |
| Test (Python 3.12) | Success |
| Test (Python 3.13) | Success |
| Market Hardening Gates | Success |
| Rust Extension | Success |
| Security Scan | Success |
| Lock File Integrity | Success |
| Helm Lint | Success |
| Generate SBOM | Success |
| Docker Build & Push, provenance, SBOM, and keyless signing | Success |

The GitHub-hosted Python 3.11.16 job reported **5,392 passed, 83 skipped in 64.34 seconds**, **92% line coverage**, and `No known vulnerabilities found` for the locked runtime manifest. This directly falsifies the earlier symptom that Python 3.11 remained indefinitely near 5% progress. The local CPython 3.11 validation remained stronger in test count for that checkout: **5,447 passed, 37 skipped, zero warnings**, plus 25 repeated file iterations without timeout.

### Security and forensic reruns under hardening

`Security` run `32448725428`, attempt 4, completed successfully after the selected-action transitive closure was made explicit.[4] CodeQL, Bandit, dependency audit, Trivy, OSV Scanner, and Cargo Audit all passed. `Forensic CI` run `32448725435`, attempt 2, also passed under the hardened policy.[5]

The first hardened rerun was intentionally treated as a falsification test. It found four transitive actions used inside `actions/attest-sbom` and `aquasecurity/trivy-action`; a subsequent Trivy run exposed `actions/cache/restore` and inspection of the pinned `setup-trivy` composite also established `actions/cache/save`. The final policy contains 31 patterns: 25 direct workflow actions plus six observed transitive paths. GitHub's repository policy separately requires full-SHA references, so the wildcard allowlist limits identity/path while SHA enforcement limits revision mutability.

## SBOM and attestation

The final CI artifact contains the source archive and an SPDX JSON document. Independent local parsing validated the tar archive and `SPDX-2.3` document. Computed digests are:

| Artifact | SHA-256 |
|---|---|
| `aegis-source-43677edca6d39a2b4078187d3676d5a286627846.tar.gz` | `67a5ced5cebc1a525e407cc4cbfcc85f0d87aac1cb059317c0871e4c1d2f0562` |
| `sbom.spdx.json` | `dde2021093e2b4fae4cf8b9f5b7740843b5c8aab5acab8c60bcb48d70576b1cc` |

`gh attestation verify` succeeded when constrained to repository `JuanLunaIA/aegis-latent-core`, signer workflow `.github/workflows/ci.yml`, source digest `43677edca6d39a2b4078187d3676d5a286627846`, and predicate `https://spdx.dev/Document`. The verified statement binds the source-archive digest above to the SPDX 2.3 predicate and contains Rekor transparency-log timestamps for the original run and hardened rerun. This establishes GitHub/Sigstore workflow identity and subject integrity within that trust boundary; it is not by itself a claim of reproducible build equivalence or SLSA Level 3/4.

## Final repository security posture

| Control | API readback |
|---|---|
| Secret scanning | Enabled |
| Push protection | Enabled |
| Dependabot security updates | Enabled |
| Automated vulnerability alerts | Endpoint responded successfully with HTTP 204 |
| Selected Actions | Enabled; 31 patterns |
| Full-SHA enforcement | Enabled |
| Required checks | 13 CI contexts, including Python 3.11 and Generate SBOM |
| Strict branch updates | Enabled |
| Code-owner review | Enabled; one approval |
| Administrator enforcement | Enabled |
| Required signed commits | Enabled |
| Force pushes / branch deletion | Disabled by preserved branch-protection posture |

The repository exposes five Dependabot ecosystem labels: `dependencies`, `python`, `rust`, `ci`, and `docker`. The repository API still reports `secret_scanning_non_provider_patterns=disabled` and `secret_scanning_validity_checks=disabled`. A PATCH requesting both returned HTTP 200 but the follow-up GET remained unchanged. `[UNRESOLVED]` This is an API/feature-availability boundary requiring repository-owner inspection in GitHub's Security settings; the report does not infer that unsupported patterns are scanned.

## Security tab and alert enumeration

The requested public Security page was inspected directly. It displays the current `SECURITY.md`, private-vulnerability-reporting path, disclosure objectives, deployment baseline, supply-chain policy, and residual-risk language.[6] It does not expose private Dependabot, CodeQL, or secret-scanning alert counts to an unauthenticated viewer.

The authenticated collector successfully obtained repository metadata, Actions permissions/runs, branch protection, workflows, zero published repository security advisories, and final security configuration. The three alert-list calls each returned `Resource not accessible by integration (HTTP 403)`. The needed authority is repository-scoped read access for **Dependabot alerts**, **Code scanning alerts**, and **Secret scanning alerts**. Until a suitably authorized GitHub App or fine-grained token is provided, alert enumeration remains `MISSING_EVIDENCE`, not a zero-alert result.

## Falsification and CHOKE checks

| Test | Null hypothesis | Perturbation / threshold | Result |
|---|---|---|---|
| Python 3.11 progress | Job still hangs or is cancelled | Complete pytest plus audit within the 15-minute job bound | Rejected |
| Mutable workflow revisions | At least one remote action uses a mutable ref | 100% of 76 references must match a full 40-character SHA | Rejected |
| Selected-action incompleteness | Hardened policy blocks an actual workflow dependency | Rerun CI, Security, and Forensic after policy change | Rejected after bounded closure correction |
| SBOM source mismatch | Syft cannot catalog the declared source | PR run plus post-merge run must generate SPDX JSON | Rejected |
| Attestation mismatch | Subject digest or workflow identity does not verify | `gh attestation verify` with repo, workflow, source digest, and SPDX predicate | Rejected |
| Alert inventory completeness | Open-alert inventory is enumerable | Each list endpoint must return HTTP 200 | **Not rejected; blocked at 403** |

The three CHOKE perturbation classes were interpreter variation (Python 3.11/3.12/3.13), workflow-policy variation (pre- and post-allowlist), and source-representation variation (archive subject versus extracted catalog root). The behavioral conclusion remained invariant after correcting the one diagnosed source-type mismatch and the bounded transitive allowlist omissions. No quantitative content-delta score is claimed because this was an operational gate, not a model-output similarity experiment.

## Residual risk and next action

**Residual authority risk:** the alert inventories cannot be audited with the current integration token. **Owner:** repository administrator. **Acceptance threshold:** all three alert endpoints return HTTP 200 and every open alert is exported with identifier, severity, dependency/rule, state, and disposition. **Rollback:** branch-protection and Actions-permission snapshots are retained under `evidence/github_status_post_pr95/`; if the allowlist blocks a newly introduced reviewed action, add only its pinned direct or transitive path after code review and rerun the affected workflows. **Kill criterion:** any bypass of required checks, unsigned commit accepted on `main`, mutable action reference, failed attestation, or unreviewed critical/high vulnerability must block release.

## Evidence index

The canonical machine-readable snapshots are in `evidence/github_status_post_pr95/`. `SHA256SUMS` records hashes for the JSON evidence set. The repository additionally retains the implementation manifest, injection-containment log, supply-chain assessment, PR #95 diagnostic, and provenance envelope in `evidence/remediation_2026-08-21/`.

## References

[1]: https://github.com/JuanLunaIA/aegis-latent-core/pull/95 "PR #95 — Close Python 3.11 and supply-chain gaps"
[2]: https://github.com/JuanLunaIA/aegis-latent-core/pull/96 "PR #96 — Fix source SBOM generation on main"
[3]: https://github.com/JuanLunaIA/aegis-latent-core/actions/runs/32448725497 "Final CI run on main"
[4]: https://github.com/JuanLunaIA/aegis-latent-core/actions/runs/32448725428 "Final Security workflow run"
[5]: https://github.com/JuanLunaIA/aegis-latent-core/actions/runs/32448725435 "Final Forensic CI workflow run"
[6]: https://github.com/JuanLunaIA/aegis-latent-core/security "Repository Security page"
[7]: https://github.com/JuanLunaIA/aegis-latent-core/pull/94 "PR #94 — Formal verification, WAL hardening, and institutional documentation"
