# Supply-Chain Assessment — 2026-08-21

**Epistemic state:** `[ESTABLISHED_EMPIRICAL]` for repository source and API settings observed; `[UNRESOLVED]` for alert inventories denied by the integration token.

## Findings and disposition

| Control | Baseline | Remediation | Acceptance evidence |
|---|---|---|---|
| Remote Actions | 75 references; none pinned | 76 references, including SBOM attestation, pinned to full commit SHAs | `scripts/verify_github_action_pins.py` reports PASS |
| Dependabot security updates | Disabled | Enabled; five configured ecosystem labels created | Repository API plus label API records |
| Source SBOM | Release-only upload; no post-merge source attestation | Main/release source archive, SPDX JSON, GitHub OIDC SBOM attestation | Required post-merge workflow and `gh attestation verify` |
| Docker publication | Could run after tests/security without Market Hardening | Now also requires `Market Hardening Gates` | CI DAG and post-merge run |
| Actions policy | `allowed_actions=all`, SHA enforcement false | Deferred until the pinned PR passes; then selected allowlist and SHA enforcement | Repository API snapshot |
| Signed commits | Not required | Deferred until the remediation PR is merged and GitHub-generated merge signatures are verified | Branch protection API and commit verification |
| Admin enforcement | Disabled | Deferred until all required contexts are stable on the remediation commit | Branch protection API |
| Alert inventories | HTTP 403 | Requires new GitHub App/PAT authority; no repository patch can add token scope | Each alert GET must return HTTP 200 |

## Action identity

The pin set was resolved from the named upstream repositories on 2026-08-21 and retains the prior tag/branch as an inline comment. Mutable references such as `master`, `stable`, and `release/v1` no longer control execution bytes. The pin verifier rejects every remote `uses:` entry without a lowercase full SHA.

## Residual risks

SHA identity does not provide independent source review, reproducible-build proof, or publisher non-compromise. GitHub-hosted OIDC attestations prove workflow identity and subject digest under GitHub's trust boundary; they do not establish SLSA Level 3/4 by themselves. The selected-action allowlist can break workflows if a nested or newly added publisher is omitted, so it is applied after the PR passes and with a captured rollback snapshot.

The active integration token cannot enumerate Dependabot, code-scanning, or secret-scanning alerts. A repository administrator must reauthorize the GitHub App with `Dependabot alerts: read`, `Code scanning alerts: read`, and `Secret scanning alerts: read`, or provide a repository-scoped fine-grained token. Secret values must never be written to logs or evidence artifacts.

## Falsification

`H0`: the workflow corpus contains at least one mutable remote Action revision. `H1`: every remote revision is a full 40-character SHA. The acceptance threshold is 100%; 75/75 was the pre-SBOM count and 76/76 is the current count. A single non-matching reference rejects `H1`.

`H0`: the post-merge artifact is not bound to an SPDX SBOM attestation. `H1`: GitHub verifies the artifact subject against the repository and SPDX predicate. Only a successful post-merge attestation verification rejects `H0`.
