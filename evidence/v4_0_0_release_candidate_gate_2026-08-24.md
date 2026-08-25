# v4.0.0 release-candidate gate

**Repository:** `JuanLunaIA/aegis-latent-core`
**Candidate branch:** `manus/v4-candidate-20260824`
**Base:** `origin/main` at `844d9287586090eb51affaf183938bca8dddb519` when the candidate branch was created
**Decision:** **SOURCE CANDIDATE GO; SIGNED TAG AND MULTI-REGISTRY PUBLICATION BLOCKED**

## Candidate changes

The Python distribution and TypeScript package are both named `aegis-latent-sdk`. Fourteen release anchors are synchronized to `4.0.0`: core package/runtime, Python SDK package/runtime, TypeScript package/lock, dashboard package/lock, Rust Cargo/pyproject/lock, Helm chart/app/image. The Rust extension now derives its exported `__version__` from `CARGO_PKG_VERSION`; the source contract rejects a future hardcoded runtime version or package-name drift.

The exact source contract passes for `v4.0.0`. Public registry preflight returned HTTP 404 for both `https://pypi.org/pypi/aegis-latent-sdk/json` and `https://registry.npmjs.org/aegis-latent-sdk`, and no remote `v4.0.0` tag or GitHub Release existed at preflight time.

## Executed gates

| Gate | Result |
|---|---|
| Full Python suite | **PASS:** 5,707 passed, 37 skipped in 92.05 seconds |
| Python coverage | **PASS:** 14,832/16,532 statements; 89.7169%, threshold 89% |
| Focused release/runtime regression | **PASS:** 30 tests |
| Configured mypy CI gate | **PASS:** 177 source files |
| Broad `mypy --strict aegis sdk/python/src` | **FAIL:** 151 errors in 54 files; not a configured release workflow gate and not represented as clean |
| Ruff lint/format | **PASS:** 407 files formatted; no lint errors |
| Rust CI-equivalent gate | **PASS:** fmt, clippy `-D warnings`, 29 release tests, abi3 wheel build; installed wheel exports `4.0.0` |
| Python SDK | **PASS:** lint, strict SDK mypy, 16 tests, wheel/sdist build, `twine check` |
| TypeScript SDK | **PASS:** typecheck, 12 tests, build, `npm pack --dry-run` as `aegis-latent-sdk@4.0.0` |
| Dashboard | **PASS:** typecheck, 6 tests, production build |
| Formal artifacts | **PASS:** bounded Lean, Z3, and TLC harness; not an implementation refinement proof |
| Documentation | **PASS:** strict verifier, zero errors/warnings |
| GitHub Actions | **PASS:** actionlint and 95 SHA-pinned remote references |
| Dependency audit | **PASS with scope note:** no known vulnerabilities in the installed environment; the unpublished local root distribution cannot be resolved from PyPI |
| Root package | **PASS:** wheel/sdist build and `twine check` |
| Helm | **PASS:** chart lint; icon recommendation only |

## GitHub governance applied

The `main` branch protection requires the exact contexts `Python SDK`, `TypeScript SDK`, `Formal Verification (Z3, Lean, TLC)`, `Generate SBOM`, `Helm Lint`, `Rust Extension`, `Security Scan`, and `Test (Python 3.11)`. Strict status freshness, signed commits, and linear history are enabled, while administrator enforcement is disabled to preserve the requested administrator bypass. Release immutability and protected `release`, `pypi`, and `npm` environments were configured earlier.

The GitHub API initially continued to report force pushes enabled after a false/null update. The authenticated settings UI was then used to disable force pushes, GitHub sudo-mode reauthentication completed, and a REST readback confirmed `allow_force_pushes.enabled == false` and `allow_deletions.enabled == false`.

## Blocking external preconditions

1. **Signed tag:** GitHub lists signing-capable GPG key `F59290FFFA5B3FE5`, but its private key is not present in the sandbox. A signed annotated tag cannot be truthfully produced here. Adding a new account signing key would be a separate security-sensitive authorization change.
2. **npm first publication:** npm trusted publishing cannot bootstrap the initial version of a nonexistent package through OIDC alone. The first `aegis-latent-sdk` publication must establish package ownership through an authorized bootstrap path before trusted publishing can be bound.
3. **PyPI trusted publisher:** the unused PyPI name can use a pending publisher, but its exact account-side registration and the repository variable `AEGIS_TRUSTED_PUBLISHING_ENABLED` remain unverified by the current integration.
4. **GitHub environment approval:** the `release` environment requires `JuanLunaIA` approval. A tag-triggered workflow will pause until that protected-environment review occurs.
5. **Strict typing non-claim:** the broader strict mypy surface remains 151 errors and is explicitly not claimed as release-clean.

## Release kill criteria

Do not create or push `v4.0.0` if the merge commit is not GitHub-verified, the tag cannot be verified by `git verify-tag`, any required status context is absent or non-successful, the protected environment is bypassed, either registry name becomes occupied by another principal, trusted-publisher coordinates differ from the reviewed repository/workflow/environment, or any package/image already exists at version `4.0.0`.

## Rollback

Before a tag exists, revert the candidate merge through a reviewed pull request. After an immutable release exists, do not rewrite or delete it; publish an explicit corrective release and preserve the original evidence. Environment and branch-protection changes can be rolled back through repository settings if they prevent legitimate recovery work.
