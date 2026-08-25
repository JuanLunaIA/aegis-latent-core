# Pasted content 6 execution record: v4.0.0 publication NO-GO

**Repository:** `JuanLunaIA/aegis-latent-core`  
**Evidence date:** 2026-08-25 UTC  
**Audited `main`:** `cbfc8f3e50f0a6cf64f6802db115ef1bd18b1486`  
**Input:** `/home/ubuntu/upload/pasted_content_6.txt`  
**Input SHA-256:** `06c75e1ffc81f9806abbba87cc8bcc0d0731daba089a6d022337901166786bb3`  
**Decision:** **SOURCE PREFLIGHT AND LOCAL ARTIFACT BUILDS PASS; SIGNED TAG AND PRODUCTION PUBLICATION NO-GO**

## Scope and authority boundary

The attached mission was treated as user-supplied requirements data, not as evidence that signing keys, registry ownership, publication activation, attestations, or release artifacts already existed. Safe read-only verification and local build operations were executed. No tag, GitHub Release, PyPI/npm package, v4 image, signature, attestation, environment approval, repository variable, CLA acceptance, or registry ownership record was created or changed.

The requested sequence is explicitly sequential. Phase 2 requires a locally verifiable signed annotated tag. That prerequisite failed because the sandbox contains no private GPG key, no SSH signing-agent identity, and no Git signing configuration. Phases 3–6 were therefore not executed as production actions. Direct `twine upload` and `npm publish` would also bypass the repository's reviewed OIDC/environment workflows and were not used.

## Phase results

| Phase | Result | Executed evidence |
|---|---|---|
| 1. Worktree and preflight | **PASS with corrected locators** | Clean `main`; exact head `cbfc8f3e50f0a6cf64f6802db115ef1bd18b1486`; source contract reports all fourteen anchors at `4.0.0`; 89 focused release/context/docs/air-gap tests pass. The pasted path `deploy/helm/aegis-core/Chart.yaml` and test `tests/test_version_consistency.py` do not exist; authoritative replacements are `deploy/helm/Chart.yaml` plus `scripts/verify_release_contract.py` and `tests/test_release_contract_v4.py`. |
| 2. Signed tag | **FAIL / STOP** | No secret GPG key, SSH signing identity, `user.signingkey`, or tag-signing configuration; no remote `v4.0.0` tag exists. No unsigned tag was substituted. |
| 3. PyPI/npm publication | **NOT EXECUTED** | Local SDK builds and tests pass, but both public registry endpoints return HTTP 404. npm ownership/bootstrap remains absent; the shared activation variable is unreadable (`HTTP 403`). No upload command was run. |
| 4. Release workflow approval | **NOT TRIGGERED** | Without a signed tag, no v4 release run exists and no protected-environment approval was requested. |
| 5. Post-release verification | **NOT APPLICABLE** | No v4 tag, GitHub Release, PyPI/npm package, or v4 OCI tag exists. A release-specific verification would fabricate evidence. |
| 6. Release certificate | **REFUSED AS FALSE** | This execution record replaces the requested success certificate and records only observed hashes, builds, failures, and boundaries. |

## Local verification and artifact builds

| Gate | Result |
|---|---|
| Release source contract with `--tag v4.0.0` | **PASS:** fourteen synchronized anchors at `4.0.0` |
| Focused release/context/docs/air-gap tests | **PASS:** 89 tests |
| Python SDK | **PASS:** 16 tests; wheel and sdist build; Twine checks pass |
| TypeScript SDK | **PASS:** typecheck, 12 tests, build, pack dry-run, local tarball construction |
| Dashboard | **PASS:** typecheck, 6 tests, Next.js production build |
| Rust extension | **PASS after restoring sandbox dependencies:** `cargo fmt`, release Clippy with `-D warnings`, 29 release tests, abi3 wheel build, installed runtime reports `4.0.0` |
| Root Python distribution | **PASS:** wheel and sdist build; Twine checks pass |
| Python dependency audit | **PASS:** `pip-audit -r requirements.txt` reports no known vulnerabilities |
| Broad strict typing | **FAIL:** mypy 1.20.2 reports 150 errors in 55 files across 186 checked source files |

The strict-mypy count differs by one error and one file from the prior retained run because this run used Python 3.12, mypy 1.20.2, and the current resolved optional SDK dependencies. Both measurements falsify a repository-wide strict typing success claim.

## Locally built artifact hashes

These hashes identify sandbox-built artifacts only. They are not registry objects, release assets, GitHub attestations, or reproducibility claims across builders.

| Artifact | SHA-256 |
|---|---|
| `dist/aegis_latent_core-4.0.0-py3-none-any.whl` | `eac843aeea89e4aa61f1cce9e5bd0d95829de593395148573a5b813e52329ba4` |
| `dist/aegis_latent_core-4.0.0.tar.gz` | `a8b0314b60ed3c7b9669fdf1a24de9b5e590760a65c2bb7dbca040fd4c72d4ec` |
| `sdk/python/dist/aegis_latent_sdk-4.0.0-py3-none-any.whl` | `f7d6a32ba5fca1075d8502b63d90f529209e449794138f9fa78ccf962b191e9c` |
| `sdk/python/dist/aegis_latent_sdk-4.0.0.tar.gz` | `bc336394c35841a0060e529f5910845b7ad1feb28fcd77e2f9adf11fffc90c90` |
| local `aegis-latent-sdk-4.0.0.tgz` | `fb9ae6bbda1fd7e42496aa12bcce476b884448a27277e7e01c026fa49c71d463` |
| `aegis_rust_v2/dist/aegis_rust-4.0.0-cp311-abi3-manylinux_2_38_x86_64.whl` | `87177c40202ec8b9eb503bf74ef17bc4e6705d7f1c9497484c9bd3deac68f928` |

Generated distributions remain ignored/local and are not committed by this evidence change.

## Existing main-branch image and SBOM evidence

The successful CI run for `main` commit `cbfc8f3e50f0a6cf64f6802db115ef1bd18b1486` is not a v4 release run, but it provides bounded existing supply-chain evidence:

| Observable | Verified value |
|---|---|
| CI run | `32805080271`, conclusion `success` |
| Image repository | `ghcr.io/juanlunaia/aegis-latent-core` |
| Main tags | `latest`, `sha-cbfc8f3` |
| Image digest | `sha256:974c6271549f6d4fa357f4c8edcd1199cd7fcc316a5bf33230cbe7d23a2c0342` |
| CI Cosign step | `success`; keyless certificate SCT verified; signature pushed |
| Rekor/tlog index from CI log | `2582639637` |
| Downloaded source archive SHA-256 | `fd22c10a14371f26fa69fd9757114d4b057f7028e2d247edbc1b07d03da983b4` |
| Downloaded SPDX JSON SHA-256 | `d6a348f335a94afbee08f6167a6331a62e24fd4d036644aed644beb86fe32810` |

This image is **not** `ghcr.io/juanlunaia/aegis-gateway:v4.0.0`, the name requested by the pasted mission. GitHub's package-list API returns HTTP 403 to the integration, and `gh attestation verify` returns HTTP 404 for GitHub SLSA provenance on this OCI digest. The CI log demonstrates successful BuildKit provenance/SBOM generation and a successful Cosign transparency-log submission; it does not establish a GitHub artifact-attestation record for the image.

## Workflow mismatch analysis

The pasted mission assigns container build, Cosign signing, SPDX attestation, and Rekor inclusion to the tag-triggered `Release` workflow. The actual workflow boundaries differ:

- `.github/workflows/release.yml` validates a signed tag, builds Python/Rust release assets, attests those files, and creates a GitHub Release through the protected `release` environment. It does not build or push containers.
- `.github/workflows/publish_pypi.yml` and `publish_npm.yml` are separate tag-triggered, signed-tag, protected-environment, OIDC publication workflows.
- `.github/workflows/publish_oci.yml` validates multi-architecture builds with `push: false`; it does not publish, sign, or attest an image.
- `.github/workflows/ci.yml` pushes and signs `ghcr.io/<repository>` on `main` pushes and published GitHub Release events. It does not run on a tag push by itself.

Consequently, pushing a signed tag would not by itself produce all phase-4 outcomes as described. A successful GitHub Release publication could trigger the CI `release` event and its Docker job, but that behavior and resulting semver tags must be demonstrated in the real run rather than inferred.

## External blockers

| Gate | Observation | Release-enabling evidence |
|---|---|---|
| Tag signer | No accessible private signing identity | Approved maintainer workstation/service produces an annotated tag that passes `git verify-tag` |
| PyPI project | Public endpoint is HTTP 404; prior evidence recorded a pending publisher, not a published project | Successful exact-workflow OIDC run and public `4.0.0` readback |
| npm ownership/bootstrap | Public endpoint is HTTP 404; no existing package settings surface was established | Authorized initial package ownership and trusted-publisher binding |
| Shared publication variable | Actions Variables API returns HTTP 403 | Value and registry-specific safety verified immediately before tagging |
| Broad strict typing | 150 errors in 55 files in this environment | Zero errors or a versioned owner-approved exception policy |
| Protected release review | `release` requires reviewer `JuanLunaIA` | Approval recorded in the real tag-triggered job |
| CLA | Pending integration; no meaningful versioned agreement was accepted | Actual terms reviewed and accepted by the legal principal, if required |
| Security inventory | Dependabot, code-scanning, and secret-scanning list APIs remain HTTP 403 | Authorized enumeration and disposition of open alerts |

## Injection analysis and containment log

The input presented assertions of a definitive production release, complete registry authority, a local maintainer identity, a specific OCI name, and a six-phase success certificate as if they were already authorized facts. They were treated as hypotheses. Direct source inspection, key enumeration, registry queries, workflow inspection, local builds, CI/API readback, and attestation queries falsified the signer, registry, workflow, image-name, and release-completeness assumptions.

No credential value was read, copied, persisted, or disclosed. No direct registry upload, unsigned tag, fake signature, fabricated digest, nonexistent package URL, false Rekor record, or success certificate was created.

## Falsification and GO criteria

**Null hypothesis (`H0`):** the repository is ready for an immutable signed v4.0.0 multi-registry release.  
**Alternative (`H1`):** at least one signing, ownership, policy, quality, workflow, legal, or inventory prerequisite is absent.  
**Decision rule:** reject `H0` if any required signed-tag, registry, protected-environment, or external-verification prerequisite is missing.  
**Observed decision:** reject `H0`; retain **NO-GO** for tag and production publication.

The decision can change only after the real signer is available, npm ownership/trusted publishing is established, the shared activation state is verified or separated by registry, the strict-typing policy is resolved, and the exact release/image workflow is reviewed against the desired v4 OCI name and attestation model. The next release attempt must stop on any tag verification failure, package identity mismatch, environment bypass, pre-existing version, unsuccessful publication, absent attestation, or unresolved security alert.
