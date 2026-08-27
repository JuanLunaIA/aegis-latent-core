# Developer Quickstart — Aegis Latent Core

**Last verified:** 2026-08-27 UTC
**Release baseline:** `v4.0.2` source; external release status requires independent readback
**Source baseline:** `v4.0.2`; source metadata alone does not establish publication
**Retained evidence baseline:** previously published `v3.1.0` artifacts; retained measurements remain historical
**Distribution verification:** confirm the signed tag, release assets, registry versions, OCI digest, and attestations before using a registry install

This is a source-tree quickstart. It does not assume that `aegis-latent-core`, `aegis-latent-sdk`, or `aegis-rust` can be installed from a public registry, and it does not establish a production deployment or external acceptance.

## Prerequisites

Use Git, Python 3.11 or newer, and a POSIX shell. Node.js/npm and Rust/Cargo are optional unless you work on their source trees.

```bash
git clone https://github.com/JuanLunaIA/aegis-latent-core.git
cd aegis-latent-core
python3 --version
git status --short
```

For exact historical reproduction, check out the revision named by the relevant evidence record. A moving branch is not an immutable evidence locator.

## Install from the clone

Create an isolated environment, install the hash-locked runtime dependencies, then install the root source and development tools in editable mode without resolving runtime dependencies again:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e .
python -m pip install pytest pytest-asyncio pytest-cov pytest-httpserver hypothesis ruff mypy bandit pip-audit aiosqlite ldap3 'PyJWT[crypto]>=2.10.1,<3'
python -m compileall -q aegis aegis_server
```

`requirements.lock` is generated with hashes from `requirements.txt`. The separate development-tool command follows the repository's minimum-version ranges and is not hash locked; record `python -m pip freeze` when producing evidence. The editable install uses the checked-out root, not a registry package.

## First productive check: offline application and proof tests

These tests use the real `create_app()` factory and portable-proof implementation without requiring Redis, a model provider, the dashboard, or the Rust extension:

```bash
python -m pytest -q tests/test_health.py tests/test_mmr_portable.py
```

Then run the documentation contract and whitespace check:

```bash
python tools/docs/verify_documentation.py --strict
git diff --check
```

## Launch the actual gateway entry point

The installed console scripts `aegis` and `aegis-server` both call `aegis.proxy.app:main`. The equivalent source command is `python -m uvicorn aegis.proxy.app:app`. This isolated development launch provides health and OpenAPI inspection; chat forwarding still requires a disposable upstream at the configured URL.

```bash
export AEGIS_SECURITY_ENFORCEMENT_MODE=development
export AEGIS_DEBUG_MODE=true
export AEGIS_AUTH_DISABLED=true
export AEGIS_BACKEND_URL=http://127.0.0.1:9001/v1
export AEGIS_BACKEND_API_KEY=local-disposable-value
export AEGIS_WAL_PATH=/tmp/aegis-developer.wal.jsonl
export AEGIS_HOST=127.0.0.1
export AEGIS_PORT=8080
python -m uvicorn aegis.proxy.app:app --host 127.0.0.1 --port 8080
```

In another shell with the virtual environment active:

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/health
```

Do not send real prompts or credentials through this development configuration. `AEGIS_AUTH_DISABLED=true` is accepted only with debug mode and development enforcement. Strict operation requires the controls described in [`PLATFORM_OPERATOR_GUIDE.md`](PLATFORM_OPERATOR_GUIDE.md) and target-specific validation.

## Run focused core gates

```bash
python -m pytest -q tests/test_p0_release_gates.py
python -m pytest -q tests/test_enterprise_durable_evidence.py
python -m pytest -q tests/test_proxy_streaming.py tests/test_mmr_portable.py
```

A full local suite is `python -m pytest -q`. Its result depends on the interpreter, operating system, optional native extension, and optional services. Do not copy a historical pass count into a current claim.

## Work on the Python SDK from source

The Python distribution metadata name is `aegis-latent-sdk`; the import package is `aegis_sdk`. Install the local SDK path rather than assuming PyPI availability:

```bash
python -m pip install -e './sdk/python[dev]'
python -m pytest -q sdk/python/tests
python -c 'import aegis_sdk; print(aegis_sdk.__version__)'
```

Example imports are:

```python
from aegis_sdk.openai import OpenAI
from aegis_sdk.anthropic import Anthropic
```

The provider extras installed by `[dev]` are bounded to the dependency ranges and tests in `sdk/python/pyproject.toml`; they do not claim universal provider compatibility.

## Work on the TypeScript SDK and dashboard from source

```bash
(cd sdk/typescript && npm ci --ignore-scripts && npm run check)
(cd dashboard && npm ci --ignore-scripts && npm run check)
```

The local TypeScript package metadata is `aegis-latent-sdk`; the dashboard is private. These commands consume the committed lockfiles and do not imply npm publication or a deployed dashboard.

## Work on the Rust extension from source

The source directory is `aegis_rust_v2/`, but the Cargo crate/library and Python import are `aegis_rust`; the Python distribution metadata is `aegis-rust`.

```bash
cargo test --manifest-path aegis_rust_v2/Cargo.toml --release --locked
python -m pip install 'maturin>=1.5,<2'
maturin develop --manifest-path aegis_rust_v2/Cargo.toml --release --features extension-module
python -c 'import aegis_rust; print(aegis_rust.__version__)'
```

See [`RUST_BUILD.md`](RUST_BUILD.md) for compiler/linker troubleshooting and naming boundaries.

## Run documentation and source quality checks

```bash
python tools/docs/verify_documentation.py --strict
python -m ruff check .
python -m ruff format --check .
git diff --check
```

Broad strict typing has known debt recorded in the post-merge audit; do not represent a narrower configured mypy pass as repository-wide strict typing.

## Evidence discipline

Historical v3.1.0 benchmark and security records remain valid only for their named source, command, environment, and sample. New results must record those fields, retain raw output, state limitations, and use a new path rather than overwriting historical material. See [`evidence/INDEX.md`](../evidence/INDEX.md).

## Related documents

- [`README.md`](../README.md)
- [`docs/README.md`](README.md)
- [`docs/REPOSITORY_MAP.md`](REPOSITORY_MAP.md)
- [`docs/PLATFORM_OPERATOR_GUIDE.md`](PLATFORM_OPERATOR_GUIDE.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`CONTRIBUTING.md`](../CONTRIBUTING.md)
