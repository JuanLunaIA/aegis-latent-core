# Supply-Chain Assessment — 2026-08-21

**Epistemic state:** `[ESTABLISHED]` for repository source, workflow executions, artifact hashes, Sigstore verification, and API settings observed; `[UNRESOLVED]` for private alert inventories denied by the active integration token.

## Findings and disposition

| Control | Baseline | Final remediation | Acceptance evidence |
|---|---|---|---|
| Remote Actions | 75 references; none pinned | 76 references, including source SBOM attestation, pinned to full commit SHAs | `scripts/verify_github_action_pins.py` reports PASS |
| Dependabot security updates | Disabled | Enabled; five ecosystem labels created | Repository and label API records |
| Source SBOM | Release-only upload; no verified post-merge subject binding | Deterministic source archive, extracted Syft catalog root, SPDX 2.3 JSON, GitHub OIDC/Sigstore attestation | CI run `32448725497`; `gh attestation verify` with SPDX predicate |
| Docker publication | Could run without Market Hardening | Requires `Market Hardening Gates`; final build, provenance, SBOM, and keyless signing job passed | CI job `96673666354` |
| Actions policy | `allowed_actions=all`, SHA enforcement false | `allowed_actions=selected`, 31 direct/transitive patterns, SHA enforcement true | Repository API readback and hardened reruns |
| Signed commits | Not required | Required on `main`; final squash commit signature is valid | Branch-protection and commit APIs |
| Admin enforcement | Disabled | Enabled on `main` | Branch-protection API |
| Required checks | Six contexts; Python 3.11 and source SBOM omitted | Thirteen contexts, including all Python versions, formal verification, lock integrity, and SBOM | Branch-protection API |
| Alert inventories | HTTP 403 | Still blocked by token authority; not represented as zero alerts | Each alert GET must return HTTP 200 |

## Action identity and transitive closure

The 76 workflow references are fixed to 40-character commit SHAs and retain human-readable release comments. The repository-level selected-action policy contains 31 paths: 25 directly declared workflow actions plus six observed transitive composite-action paths. Full-SHA enforcement remains enabled independently of the path patterns.

The first hardened reruns intentionally tested allowlist completeness. `actions/attest-sbom` required `actions/attest-sbom/predicate` and `actions/attest`; `aquasecurity/trivy-action` required `aquasecurity/setup-trivy`, `actions/cache`, `actions/cache/restore`, and `actions/cache/save`. The final CI, Security, and Forensic executions passed under the corrected policy. This bounded closure is empirical for the pinned action revisions; future action upgrades require reinspection and rerun.

## Artifact identity and provenance

The final source archive SHA-256 is `67a5ced5cebc1a525e407cc4cbfcc85f0d87aac1cb059317c0871e4c1d2f0562`. The downloaded SPDX JSON SHA-256 is `dde2021093e2b4fae4cf8b9f5b7740843b5c8aab5acab8c60bcb48d70576b1cc`. `gh attestation verify` validated the source digest against repository `JuanLunaIA/aegis-latent-core`, signer workflow `.github/workflows/ci.yml`, source commit `43677edca6d39a2b4078187d3676d5a286627846`, and predicate type `https://spdx.dev/Document/v2.3`. Rekor transparency-log timestamps were returned for the original post-merge attestation and hardened rerun.

These observations establish subject integrity and workflow identity within GitHub's OIDC and Sigstore trust boundary. They do not establish bit-for-bit reproducible builds, independent builder non-compromise, or SLSA Level 3/4.

## Residual risks

The active integration token cannot enumerate Dependabot, code-scanning, or secret-scanning alerts. A repository administrator must reauthorize the GitHub App or provide a repository-scoped fine-grained token with read access to all three alert families. Secret values must never be written to logs or evidence artifacts.

Secret scanning and push protection are enabled. The API still reports non-provider patterns and validity checks as disabled after a PATCH request returned HTTP 200 without changing the follow-up state. This remains a repository-setting or feature-availability review item and is not treated as active coverage.

## Falsification

`H0`: at least one remote workflow revision is mutable. `H1`: all 76 remote revisions are full 40-character SHAs. Acceptance is 76/76; one non-matching reference rejects `H1`.

`H0`: selected-action enforcement blocks the pinned workflow graph. `H1`: the direct and observed transitive action paths are sufficient. Actual reruns of CI, Security, and Forensic rejected `H0` after the bounded transitive closure was added.

`H0`: the source artifact is not bound to the SPDX predicate. `H1`: Sigstore verification binds the exact source SHA-256 to `https://spdx.dev/Document/v2.3` under the repository CI workflow identity. Successful constrained `gh attestation verify` rejected `H0`.
