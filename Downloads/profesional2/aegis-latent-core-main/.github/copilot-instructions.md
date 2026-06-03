# Copilot instructions — aegis-latent-core

This file gives Copilot sessions repository-specific guidance: how to build/test/lint, where the important components live, and conventions to follow when suggesting code or tests.

---

## Quick developer commands (Makefile / explicit)

Prereqs: Python 3.11+; create a venv: `python -m venv .venv && . .venv/bin/activate`

Install
- Runtime: `pip install -r requirements.txt` or `make install` (`pip -e .`).
- Dev: `pip install -e '.[dev]'` or `make dev` (installs pytest, ruff, mypy, bandit, etc.).

Lint / Type / Security
- Lint: `make lint` → runs `ruff check .` and `ruff format --check .` (config in pyproject.toml).
- Type checking: `make type` → `mypy aegis/ --ignore-missing-imports`.
- SAST: `make security` → `bandit -r aegis/ -c pyproject.toml -ll`.

Tests
- Run full suite: `make test` or `pytest tests/ -v`.
- Single test file: `pytest tests/test_core.py -q`.
- Single test function: `pytest tests/test_core.py::test_name -q` or `pytest -k "expr" -q`.
- Coverage gate (dev): `make test-cov` (Makefile target uses `--cov-fail-under=65`).
- CI uses: `pytest -q --maxfail=1 --cov=aegis --cov-report=xml`.

Run / Smoke
- Start server: `aegis-server` (console script) or `python -m aegis_server.main`.
- Smoke test: `make smoke` or `./scripts/smoke_test.sh` (exports AEGIS_BASE_URL, AEGIS_TEST_API_KEY, etc.).

Packaging / Release / Rust
- Build wheels/source: `python -m build` (release workflow uses this).
- Rust extension: `make build-rust` (requires `maturin`); builds `aegis_rust` and copies `.so` to `aegis/proxy/aegis_rust.so`.
- SBOM: `scripts/generate_sbom.sh`.
- Apply license headers: `python scripts/apply_license_headers.py` (script available).

---

## High-level architecture (big picture)

- Purpose: production-grade forensic telemetry proxy for LLM inference pipelines (FastAPI-based proxy + enterprise audit server).

- Main runtime pieces:
  - aegis.proxy (FastAPI proxy): request WAF/auth → forward to upstream LLM → immediate response to client; telemetry + forensic work done off-path in BackgroundTasks.
  - Merkle ledger / MMR: `aegis/core/mmr.py` — builds append-only Merkle Mountain Range for audit proofs.
  - Telemetry & analytics: entropy/KL/MoE gate analysis implemented in `aegis/core/telemetry.py` and related modules; integrations post telemetry to `/v1/internal/telemetry`.
  - Storage & signer (enterprise layer): `aegis_server` package — pluggable StorageProvider (sqlite/postgres/dynamodb) and SignerProvider (HMAC / Vault transit); wired in `aegis_server/main.py` lifespan.
  - Integrations: `integrations/` contains adapters (HuggingFace, vLLM) that attach forward hooks and post telemetry asynchronously.
  - Rust extension: `aegis_rust_v2/` — performance/PQC-critical code, built with `maturin` and optional at runtime.

- Typical request flow: client → proxy + WAF/auth → forwarded to provider → immediate response returned → BackgroundTask computes analytics, signs Merkle root, persists audit node.

- Entrypoints: `aegis` / `aegis-server` console scripts point to `aegis.proxy.app:main` and `aegis.proxy.app:main` (aliases). `aegis_server.main` implements the enterprise API.

---

## Key repository conventions and notes for Copilot

- Configuration sources to consult first:
  - `pyproject.toml` (dependencies, ruff/mypy/bandit settings, project.scripts, coverage settings)
  - `Makefile` (developer shortcuts)
  - `pytest-core.ini` (core tests selection / coverage settings)
  - `.github/workflows/ci.yml` and `DEPLOYMENT_GUIDE.md` (CI matrix, release steps, SBOM and signing)

- Linting & formatting:
  - Ruff is the canonical linter/formatter; `line-length = 100` (pyproject). Use `make lint`/`ruff` to validate.
  - There are per-file ruff ignores (tests, generated protobufs) — do not suggest autofixes that violate those ignores.

- Typing and static checks:
  - Mypy is configured with `strict = true` in pyproject but CI/Makefile run with `--ignore-missing-imports`. Suggest typed signatures and Pydantic models (project expects typed code).

- Tests and optional dependencies:
  - Many tests exercise optional integrations (vLLM, HuggingFace, PQC Rust). Running the full suite may require `pip install -e '.[dev]'` plus optional extras (`vllm`, `hf`, `gpu`) or building the Rust extension.
  - `tests/test_rust_extension.py` and tests that reference heavy ML stacks should be run only when the relevant extras/extension are present.

- Coverage conventions:
  - There are two coverage scopes in repo config: project-level (pyproject.toml) and a narrower `pytest-core.ini` (core tests). Use `make test-cov` to run the repository's expected coverage gate.

- Generated / vendor files:
  - Do not edit generated protobufs (`aegis/core/audit_node_pb2.py`) or other auto-generated artifacts. They are excluded/ignored in lint/coverage rules.

- Security / release process:
  - Releases are triggered by tagging (`v*`) and the Release workflow builds wheels (`python -m build`) and generates SHA256 artifacts. SBOM generation and image signing are handled in `scripts/` and workflows; check `DEPLOYMENT_GUIDE.md` for details.

- Where to add new code:
  - Core telemetry, MMR, and forensic logic → `aegis/core/`.
  - Runtime proxy & WAF → `aegis/proxy/`.
  - Provider adapters → `aegis/providers/` (HTTP-based providers) and `integrations/` for framework hooks.
  - Enterprise storage/signing → `aegis_server/storage` and `aegis_server/crypto`.

- Rust extension convention:
  - Build with `maturin develop --release` in `aegis_rust_v2` and copy `libaegis_rust.so` → `aegis/proxy/aegis_rust.so`. Makefile target `build-rust` automates this.

- License and headers:
  - Dual-license (AGPLv3 or commercial). License headers are applied via `scripts/apply_license_headers.py` — avoid removing or altering headers in suggestions.

---

## Helpful quick references for Copilot

- If asked for build/test/lint commands, prefer Makefile targets as authoritative (e.g., `make lint`, `make test`, `make dev`).
- When editing code, prefer minimal, surgical changes; do not modify generated files or license headers. Respect ruff/mypy settings in pyproject.
- When suggesting test runs, include guidance about optional extras (e.g., `pip install -e '.[dev]'` or building the Rust extension) where relevant.

---

Files to consult (authoritative): `pyproject.toml`, `Makefile`, `pytest-core.ini`, `DEPLOYMENT_GUIDE.md`, `.github/workflows/ci.yml`, `README.md`.


*No existing Copilot/Claude/Cursor/Jules assistant config files detected.*

---

If this should include extra examples (common `pytest` invocations, common debug commands, or a short list of "heavy" tests to skip by default), say which examples to add and Copilot will append them.
