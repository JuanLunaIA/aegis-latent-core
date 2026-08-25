# v4.0.0 post-merge release-readiness audit

**Repository:** `JuanLunaIA/aegis-latent-core`  
**Pull request:** [#112](https://github.com/JuanLunaIA/aegis-latent-core/pull/112)  
**Merged commit:** `2050a310ec295afc61d033ff842c9a535a4f3105`  
**Candidate head:** `b3a2a7016c102609db14c9a888051d2d0623cfd7`  
**Audit time:** 2026-08-25 UTC  
**Decision:** **SOURCE MERGE VERIFIED; PRODUCTION RELEASE NO-GO**

## Executive finding

PR #112 was merged into `main` as `2050a310ec295afc61d033ff842c9a535a4f3105`. GitHub reports the merge commit signature as `verified: true`, `reason: valid`, and the merge commit and candidate head resolve to the same tree, `675481549034d29c0b8018652234c9174b940d4d`. The source contract executed from the merged tree reports all fourteen anchors at `4.0.0`, and the candidate evidence SHA-256 sidecar verifies.

The source merge is not a registry release. No remote `v4.0.0` tag, GitHub Release, PyPI project, or npm package existed at the final registry check. The sandbox still has no private GPG key or SSH signing-agent identity, broad strict mypy remains red, and npm has no existing package settings surface for trusted-publisher registration. Therefore no tag or publication was initiated.

## Required GitHub contexts

All eight contexts configured as required on `main` reached `completed/success` on the exact candidate head:

| Required context | Terminal result |
|---|---|
| `Python SDK` | **success** |
| `TypeScript SDK` | **success** |
| `Formal Verification (Z3, Lean, TLC)` | **success** |
| `Generate SBOM` | **success** |
| `Helm Lint` | **success** |
| `Rust Extension` | **success** |
| `Security Scan` | **success** |
| `Test (Python 3.11)` | **success** |

The merge timestamp precedes completion of some required contexts. Branch-protection readback confirms strict freshness, required signatures, linear history, disabled force pushes and deletions, and `enforce_admins: false`; consequently the configured administrative bypass was not a universal pre-merge barrier. This does not invalidate the terminal check results, but it prevents claiming that all contexts were successful before merge.

CircleCI reported an external no-configuration error and Sourcery reported failure; neither is one of the eight required contexts. CLA Assistant remained pending. No CLA was accepted because no meaningful versioned agreement text was available in the displayed integration or repository.

## Local and source-tree verification

| Gate | Result |
|---|---|
| Merged release contract with `--tag v4.0.0` | **PASS:** fourteen anchors synchronized at `4.0.0` |
| Candidate evidence SHA-256 sidecar | **PASS** |
| Candidate and merge tree identity | **PASS:** both `675481549034d29c0b8018652234c9174b940d4d` |
| `pip-audit --skip-editable -r requirements.txt` | **PASS:** no known vulnerabilities found |
| Bandit semantic delta versus pre-candidate base | **PASS:** 72 baseline, 72 merged, 0 introduced, 0 resolved |
| Configured mypy CI gate | **PASS**, as recorded in the merged candidate evidence |
| Broad `mypy --strict aegis sdk/python/src` | **FAIL:** 151 errors in 54 files, 186 source files checked |
| Full Python/Rust/SDK/dashboard/formal/build suite | **PASS**, with exact results retained in the merged candidate evidence |

Bandit exits nonzero when baseline findings are present. The release-relevant result is the normalized semantic comparison: the v4 candidate introduced zero findings relative to its base. The existing 72 findings are not represented as remediated.

## Publisher and registry state

### PyPI

An authenticated PyPI readback confirms a **pending trusted publisher** for:

| Field | Value |
|---|---|
| Project | `aegis-latent-sdk` |
| Provider | GitHub |
| Repository | `JuanLunaIA/aegis-latent-core` |
| Workflow | `publish_pypi.yml` |
| Environment | `pypi` |

This configuration delegates OIDC authority to the exact workflow and can create the project when a valid publish job runs. It did **not** reserve the name or publish a package. The public PyPI JSON endpoint still returned HTTP 404.

### npm

The public npm registry endpoint for `aegis-latent-sdk` returned HTTP 404. The account has no existing package with that name. Official npm documentation instructs maintainers to configure trusted publishing from an existing package’s **Settings → Trusted Publisher** section and does not describe a PyPI-style pending publisher for a nonexistent package.[1] No npm package, organization, token, initial version, or trusted publisher was created.

Both registry workflows currently use the shared repository variable `AEGIS_TRUSTED_PUBLISHING_ENABLED`. Its repository value is not observable with the current integration because the Actions Variables API returns HTTP 403. It must not be represented as enabled. A future release should either verify this variable immediately before tagging or split activation into registry-specific variables so PyPI readiness cannot implicitly activate an unbootstrapped npm path.

## GitHub security-state boundary

Repository API readback confirms vulnerability alerts, Dependabot security updates, secret scanning, secret-scanning push protection, private vulnerability reporting, and release immutability are enabled. The Dependabot, code-scanning, and secret-scanning alert-list endpoints each return HTTP 403 to the current integration. Feature enablement is therefore verified, but a clean or complete alert inventory is **not** claimed.

## Release blockers and falsification criteria

| Blocker | Current observation | Release-enabling evidence |
|---|---|---|
| Signed annotated tag | No sandbox private GPG key; no SSH agent identity; no remote `v4.0.0` tag | `git verify-tag v4.0.0` succeeds and the tag targets the verified `main` commit |
| npm ownership/bootstrap | Package endpoint is 404 and no package settings surface exists | Authorized initial package ownership plus exact trusted-publisher readback |
| Shared publication gate | Repository variable API is 403 and one variable gates both registries | Verified registry-specific activation or verified safe value immediately before tag creation |
| Broad strict typing | 151 errors in 54 files | Zero errors, or an explicit versioned exception policy accepted by the repository owner |
| Protected release approval | `release` environment requires `JuanLunaIA` | Environment approval occurs in the actual tag-triggered run |
| CLA | Pending integration with no meaningful versioned terms shown | Versioned agreement is reviewed and explicitly accepted by the legal principal, if actually required |
| Security inventory | Alert list APIs return 403 | Authorized inventory access and explicit review of open alerts |

**Null hypothesis (`H0`):** v4.0.0 is ready for signed multi-registry publication.  
**Alternative (`H1`):** at least one required signing, ownership, policy, or external-acceptance precondition is absent.  
**Decision threshold:** reject `H0` if any row above lacks its release-enabling evidence.  
**Observed decision:** reject `H0`; retain **NO-GO** for tag and publication.

## Safe next action

The repository owner should create the annotated signed `v4.0.0` tag from an approved workstation or signing service only after resolving or explicitly versioning the strict-mypy policy, establishing npm package ownership/trusted publishing, and verifying registry-specific publication activation. The tag must target the GitHub-verified `main` commit, pass `git verify-tag`, and then proceed through the protected `release` environment. Until then, the merged v4 source is a validated source state rather than a completed production release.

## References

[1]: [npm, “Trusted publishing for npm packages”](https://docs.npmjs.com/trusted-publishers/)
