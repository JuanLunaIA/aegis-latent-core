# Component, Package, and Workflow Matrix

This source-derived map separates **package identity**, **version synchronization**, **runtime linkage**, and **publication authority**. It describes merged source anchored at `2050a310ec295afc61d033ff842c9a535a4f3105`; it does not claim that v4 was tagged, released, or published to any registry. The immutable published baseline remains **v3.1.0**.

## Fourteen synchronized version anchors

The authoritative loader is `_load_versions` in [`scripts/verify_release_contract.py`](../scripts/verify_release_contract.py). Every row currently resolves to `4.0.0`.

| Anchor label | Authoritative field | Component/package identity | Publication boundary |
|---|---|---|---|
| `core` | [`pyproject.toml`](../pyproject.toml) `project.version` | Python distribution `aegis-latent-core` | Source metadata only; no v4 PyPI publication is asserted. |
| `core-runtime` | [`aegis/__init__.py`](../aegis/__init__.py) `__version__` | Import package `aegis` | Runtime string is not release evidence. |
| `python-sdk` | [`sdk/python/pyproject.toml`](../sdk/python/pyproject.toml) `project.version` | Python distribution `aegis-latent-sdk` | `publish_pypi.yml` is tag- and environment-gated; no v4 PyPI publication is asserted. |
| `python-sdk-runtime` | [`sdk/python/src/aegis_sdk/__init__.py`](../sdk/python/src/aegis_sdk/__init__.py) `__version__` | Import package `aegis_sdk` | Runtime string is not registry evidence. |
| `typescript-sdk` | [`sdk/typescript/package.json`](../sdk/typescript/package.json) `version` | npm package `aegis-latent-sdk` | `publish_npm.yml` is tag- and environment-gated; no v4 npm publication is asserted. |
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
| [`forensic.yml`](../.github/workflows/forensic.yml) | Scheduled/push/PR forensic checks | No release or package publication role. |
| [`pqc-timing.yml`](../.github/workflows/pqc-timing.yml) | Manually initiated timing assessment | Measurement workflow, not publication. |
| [`publish.yml`](../.github/workflows/publish.yml) | Compatibility package construction | Explicitly build-validation-only: no tag trigger, OIDC write, upload, or release command. |
| [`publish_oci.yml`](../.github/workflows/publish_oci.yml) | Multi-architecture gateway/dashboard image build validation | Explicit `push: false`; no registry login, signing, or publication path. |
| [`publish_pypi.yml`](../.github/workflows/publish_pypi.yml) | Build Python SDK and conditionally publish exact artifacts | Requires a matching signed tag, main ancestry, `pypi` environment, OIDC, and `AEGIS_TRUSTED_PUBLISHING_ENABLED == 'true'`; source presence does not prove a run or PyPI state. |
| [`publish_npm.yml`](../.github/workflows/publish_npm.yml) | Build TypeScript SDK and conditionally publish exact package with provenance | Requires a matching signed tag, main ancestry, `npm` environment, OIDC, and explicit enablement; source presence does not prove npm state. |
| [`release.yml`](../.github/workflows/release.yml) | Validate tag, build assets, attest, and create a new GitHub Release | Tag-only and create-only source contract; no v4 tag or successful release run is asserted. |
| [`security.yml`](../.github/workflows/security.yml) | CodeQL, Bandit, dependency/container/OSV/Cargo audits | Findings are scoped workflow evidence, not a vulnerability-absence or publication claim. |

**Stop conditions:** block a release statement if any anchor differs, a package identity changes, an adapter link lacks source/tests, a publication workflow loses its gates, OCI validation gains a push/login/signing path, or external tag/release/registry state has not been independently verified.
