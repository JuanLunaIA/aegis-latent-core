# Component, Package, and Workflow Matrix

This map separates **package identity**, **version synchronization**, **runtime linkage**, **GitHub publication**, **registry observation**, and **provenance**. Historical immutable source baseline `fdace8844568eb788216740b2cb5daf187d99d3b` has 14 anchors at `4.0.0`. Historical published GitHub Release `v4.0.1` is a lightweight tag targeting `6469904380218584ae0b5221334bc9a46500f5ba`. Prior public PyPI/npm `aegis-latent-sdk` packages were observed at `4.0.0`, without attribution to failed workflows. The source release target is `v4.1.2` with 14 synchronized `4.1.2` anchors, published on 2026-09-03 to the GitHub Release, PyPI and GHCR but **not to npm, which still carries `4.0.0`**. External lifecycle state (tag, GitHub Release, PyPI, npm, OCI, and attestations) must be independently read back and is never encoded by source metadata.

## Fourteen synchronized version anchors

The authoritative loader is `_load_versions` in [`scripts/verify_release_contract.py`](../scripts/verify_release_contract.py). Every row in the checked-out source release target resolves to `4.1.2`; this does not alter the independent historical source-baseline, GitHub Release, prior registry observations, or current external lifecycle state.

| Anchor label | Authoritative field | Component/package identity | Publication boundary |
|---|---|---|---|
| `core` | [`pyproject.toml`](../pyproject.toml) `project.version` | Python distribution `aegis-latent-core` | Source-target metadata only; PyPI state requires independent read-back. |
| `core-runtime` | [`aegis/__init__.py`](../aegis/__init__.py) `__version__` | Import package `aegis` | Runtime string is not release evidence. |
| `python-sdk` | [`sdk/python/pyproject.toml`](../sdk/python/pyproject.toml) `project.version` | Python distribution `aegis-latent-sdk` | PyPI 4.0.0 is a separate prior public observation; source-target 4.1.2 metadata is not publication evidence. |
| `python-sdk-runtime` | [`sdk/python/src/aegis_sdk/__init__.py`](../sdk/python/src/aegis_sdk/__init__.py) `__version__` | Import package `aegis_sdk` | Runtime string is not registry evidence. |
| `typescript-sdk` | [`sdk/typescript/package.json`](../sdk/typescript/package.json) `version` | npm package `aegis-latent-sdk` | npm carries `4.1.2` as of the 2026-09-04 readback; the version list is `4.0.0`, `4.1.2`, since the `4.1.1` publish step failed and was never rerun. Source metadata is never publication evidence. |
| `typescript-lock` | [`sdk/typescript/package-lock.json`](../sdk/typescript/package-lock.json) root package version | Locked TypeScript SDK workspace | Lock metadata is not publication evidence. |
| `dashboard` | [`dashboard/package.json`](../dashboard/package.json) `version` | Private package `aegis-audit-dashboard` | `private: true`; it is a private application package, built rather than published as npm package source. |
| `dashboard-lock` | [`dashboard/package-lock.json`](../dashboard/package-lock.json) root package version | Locked dashboard workspace | Lock metadata is not publication evidence. |
| `rust-cargo` | [`aegis_rust_v2/Cargo.toml`](../aegis_rust_v2/Cargo.toml) `package.version` | Rust crate/module `aegis_rust` | No v4 crates.io publication is asserted. |
| `rust-pyproject` | [`aegis_rust_v2/pyproject.toml`](../aegis_rust_v2/pyproject.toml) `project.version` | Python distribution `aegis-rust` | Built by release workflow; no v4 registry publication is asserted. |
| `rust-lock` | [`aegis_rust_v2/Cargo.lock`](../aegis_rust_v2/Cargo.lock) package `aegis_rust` | Locked Rust crate | Lock metadata is not publication evidence. |
| `helm-chart` | [`deploy/helm/Chart.yaml`](../deploy/helm/Chart.yaml) `version` | Helm chart `aegis-latent-core` | No v4 chart-registry publication is asserted. |
| `helm-app` | [`deploy/helm/Chart.yaml`](../deploy/helm/Chart.yaml) `appVersion` | Gateway application image contract | App metadata is not image publication evidence. |
| `helm-image` | [`deploy/helm/values.yaml`](../deploy/helm/values.yaml) `image.tag` | Configured gateway image tag | A configured tag does not prove that an image exists. |

## Component and adapter links

| Surface | Identity/link | Authoritative source | Verification boundary |
|---|---|---|---|
| Gateway provider registry | `openai → OpenAIAdapter`, `anthropic → AnthropicAdapter`, `gemini → GeminiAdapter`, `openrouter → OpenRouterAdapter` | [`aegis/providers/__init__.py`](../aegis/providers/__init__.py), [`base.py`](../aegis/providers/base.py), [`openai_provider.py`](../aegis/providers/openai_provider.py), [`anthropic_provider.py`](../aegis/providers/anthropic_provider.py), [`gemini_provider.py`](../aegis/providers/gemini_provider.py) | Registry membership and tests define supported routing; they do not prove every provider endpoint/version. |
| Python SDK official-client links | Drop-in OpenAI and Anthropic clients; proof verifier exported from `aegis_sdk` | [`sdk/python/src/aegis_sdk/openai.py`](../sdk/python/src/aegis_sdk/openai.py), [`anthropic.py`](../sdk/python/src/aegis_sdk/anthropic.py), [`__init__.py`](../sdk/python/src/aegis_sdk/__init__.py) | Optional dependencies and SDK tests bound compatibility. |
| TypeScript SDK official-client links | OpenAI/Anthropic wrappers, gateway options, instrumentation, portable proof verifier | [`sdk/typescript/src/index.ts`](../sdk/typescript/src/index.ts), [`openai.ts`](../sdk/typescript/src/openai.ts), [`anthropic.ts`](../sdk/typescript/src/anthropic.ts) | Peer dependency ranges and tests bound compatibility. |
| Dashboard-to-SDK link | Local dependency `aegis-latent-sdk: file:../sdk/typescript` | [`dashboard/package.json`](../dashboard/package.json) | Local workspace linkage is not npm resolution or publication evidence. |

## Workflow roles and no-publish boundaries

| Workflow | Source role | Publication boundary |
|---|---|---|
| [`ci.yml`](../.github/workflows/ci.yml) | Tests, lint, type checks, SDK/dashboard builds, Rust, formal, Helm, SBOM, Docker validation | Validation only; not a registry publication record. |
| [`create_release_tag.yml`](../.github/workflows/create_release_tag.yml) | Manually authorize, create, verify, and push a Sigstore-signed annotated release tag, then dispatch downstream workflows | Configured mechanism only; it does not prove a run succeeded or retroactively establish provenance for the lightweight v4.0.1 tag or observed 4.0.0 registry packages. |
| [`forensic.yml`](../.github/workflows/forensic.yml) | Scheduled/push/PR forensic checks | No release or package publication role. |
| [`pqc-timing.yml`](../.github/workflows/pqc-timing.yml) | Manually initiated timing assessment | Measurement workflow, not publication. |
| [`publish.yml`](../.github/workflows/publish.yml) | Compatibility package construction | Explicitly build-validation-only: no tag trigger, OIDC write, upload, or release command. |
| [`publish_oci.yml`](../.github/workflows/publish_oci.yml) | Publish linux/amd64 and linux/arm64 gateway and dashboard images to GHCR | Configured to push both images, attest each digest, and keyless-sign each digest with Sigstore; this mechanism is not evidence that a run or external publication succeeded. |
| [`publish_pypi.yml`](../.github/workflows/publish_pypi.yml) | Build Python SDK and conditionally publish exact artifacts | Requires a matching signed tag, main ancestry, `pypi` environment, OIDC, and `AEGIS_TRUSTED_PUBLISHING_ENABLED == 'true'`; observed PyPI 4.0.0 existence is not proof this workflow succeeded. |
| [`publish_npm.yml`](../.github/workflows/publish_npm.yml) | Build TypeScript SDK and conditionally publish exact package with provenance | Requires a matching signed tag, main ancestry, `npm` environment, OIDC, and `AEGIS_TRUSTED_PUBLISHING_ENABLED == 'true'`; observed npm `4.0.0` existence is not proof this workflow succeeded. Its `4.1.2` run reached the publish step and failed there. |
| [`release.yml`](../.github/workflows/release.yml) | Validate tag, build assets, attest, and create a new GitHub Release | Source contract only. Public v4.0.1 exists at a lightweight tag, so it does not satisfy the workflow's signed-annotated-tag contract and must not be attributed to that workflow. |
| [`security.yml`](../.github/workflows/security.yml) | CodeQL, Bandit, dependency/container/OSV/Cargo audits | Findings are scoped workflow evidence, not a vulnerability-absence or publication claim. |

**Stop conditions:** block a release statement if any anchor differs, a package identity changes, an adapter link lacks source/tests, PyPI/npm loses its variable or environment gate, OCI loses its platform/image/attestation/signing contract, or source-target, workflow configuration, run, external lifecycle, and provenance evidence are being conflated.
