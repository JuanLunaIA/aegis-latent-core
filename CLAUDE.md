# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Aegis Latent Core is an **OpenAI-compatible governance proxy** for LLM inference. It sits between a client (any OpenAI-SDK app) and an upstream LLM provider, applies auth + WAF + rate limiting on the request hot path, forwards the call, and — *after* the response is returned to the client — commits a SHA-256 hash-chained, HMAC-signed, tamper-evident audit record on a background task. The defining architectural constraint is that **forensic auditing must add zero I/O wait to the client-visible response path**.

Python is the source of truth; a Rust PyO3 extension (`aegis_rust`) optionally accelerates 7 tiers, each with a functionally-complete pure-Python fallback. The proxy passes the full test suite without Rust.

## Commands

```bash
make dev              # pip install -e ".[dev]"  — set up dev environment
make lint             # ruff check . && ruff format --check .
make type             # mypy aegis/ --ignore-missing-imports
make security         # bandit -r aegis/ -c pyproject.toml -ll
make test             # pytest tests/ -v
make test-cov         # tests + coverage, 65% gate (the default gate)
make build-rust       # maturin develop --release, copies .so into aegis/proxy/

# Run a single test file / test / keyword
pytest tests/test_waf_unit.py -q
pytest tests/test_crypto_audit.py::TestVerifyIntegrity::test_detects_tampering -q
pytest tests/ -k "waf and not slow" -q

# Run the proxy locally (factory pattern — note --factory)
AEGIS_PROVIDER=openai AEGIS_BACKEND_API_KEY=... AEGIS_API_KEYS=dev-key \
AEGIS_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')" \
uvicorn aegis.proxy.app:app --factory --port 8080

# Self-contained 5-minute eval (mock upstream, no API key needed)
python -m examples.demo          # expect: "RESULT: 5/5 checks OK"

# Mission Control dashboard (separate app, local dev only)
uvicorn tools.visualizer.app:app --reload --port 8081

# Rust tests
cargo test --manifest-path aegis_rust_v2/Cargo.toml --all-features
```

Coverage gates differ by config: `pyproject.toml` (default `pytest`) enforces 65% over `aegis`; `pytest-core.ini` enforces 85% over `aegis.core`; `pytest-proxy.ini` 60%. The default invocation uses `pyproject.toml`.

## Architecture

There are **two separate FastAPI apps** — don't conflate them:

1. **`aegis.proxy.app`** (port 8080) — the runtime proxy. `create_app()` builds it; module-level `app = create_app()` is the `--factory` target. This is what governs live LLM traffic and serves `/v1/chat/completions`, `/health`, `/metrics`, and `/v1/audit/*`.
2. **`aegis_server.main`** (port 8090 by convention) — the enterprise compliance/export server. Owns `/v1/enterprise/compliance/export`, pluggable storage backends (`aegis_server/storage/`: sqlite/postgres/dynamodb), and `ComplianceExporter` for sealed-bundle generation + offline re-verification. Separate from the proxy.

### Request lifecycle (`aegis/proxy/app.py`)

Hot path (client waits): **auth → WAF → rate limit → provider adapter (translate request) → forward → provider adapter (translate response) → return**. Only after `return JSONResponse(...)` does `_spawn_background()` dispatch the audit work via `asyncio.create_task()`. Background tasks are held in a module-level `_BACKGROUND_TASKS` set (asyncio only weakly references tasks; without the strong ref a commit can be GC'd mid-flight — do not remove this).

Background path (zero client wait): `ResponseAnalyzer` (Shannon entropy / KL / JS divergence per token) → `CryptographicAuditLedger.commit_forensic()` (hash chain + Merkle Mountain Range + HMAC/ML-DSA signature) → Write-Ahead Log (`fsync`, mode `0o600`).

### Key modules

- `aegis/proxy/` — the proxy itself: `app.py` (orchestration), `waf.py` (`AegisWAF`), `forwarder.py` (`LLMForwarder` — Rust reqwest pool with httpx fallback), `analyzer.py`, `audit_api.py` / `attestation_api.py` (routers built via `build_*_router()`), `auth` deps in `dependencies.py`, middleware in `dmz_middleware.py` / `egress_guard.py`, `mtls.py`.
- `aegis/core/` — ~130 modules. The runtime-critical ones: `crypto_audit.py` (`CryptographicAuditLedger`, the hash chain + MMR + signing), `ratelimiter.py` (`create_rate_limiter`), `circuit_breaker.py`, `normalization.py` (NFKC + zero-width strip feeding the WAF), `session_manager.py`, plus detection engines (`adversarial_suffix_detector.py`, `classified_marker_detector.py`, `ioc_correlator.py`, etc.). **Many `aegis/core/*` files are roadmap/platform modules not on the proxy runtime path** — see the long `omit` list in `pyproject.toml [tool.coverage.run]` (e.g. `sandbox*.py`, `tpm.py`, `enclave_provider.py`, `formal_*.py`). Treat those as aspirational/specialized, not part of the request hot path.
- `aegis/providers/` — provider adapters (`base.py` + `openai_provider.py`, `anthropic_provider.py`, `gemini_provider.py`) translating between OpenAI format and each upstream.
- `aegis/auth/` — `apikey.py` (`ProxyKeyAuth`/`AuditKeyAuth`, all comparisons via `hmac.compare_digest()`), plus `rbac.py`, `abac.py` (Bell-LaPadula), `ldap_auth.py`, `scim.py`, `scopes.py`.
- `aegis_rust_v2/` — Rust crate, compiled as Python module **`aegis_rust`** (crate name differs from dir name). One `.rs` file per acceleration tier: `forwarder.rs`, `waf.rs`, `rate_limit.rs`, `session.rs`, `audit.rs`/`ledger.rs`/`mmr.rs`, `wal.rs`, `hasher.rs`, `pqc.rs`. Import is `try: import aegis_rust` with graceful Python fallback everywhere.
- `tools/visualizer/` — the 12-page Mission Control dashboard (`POST /api/scan` runs the *real* detection engines). Local dev only; never expose.
- `integrations/` — `vllm_plugin.py`, `huggingface_plugin.py`.

### Audit chain invariants (do not break)

`crypto_audit.py` is the forensic heart. `node_hash[i] = SHA256(prev_hash[i-1] ‖ state_id ‖ ... ‖ request_hash ‖ response_hash)` — `prev_hash` is the **first** input so reordering cascades into detectable mismatches. `verify_integrity()` does an O(N) sweep checking field tampering, chain linkage, and HMAC signatures (constant-time compare). Any change to node serialization, field order, or the WAL frame format requires the forensic regression tests to pass: `pytest tests/test_security_fixes.py` (and `tests/test_crypto_audit.py`).

## Conventions

- **License header required on every new source file**: the 3-line `Copyright (c) 2026 Juan Luna ... AGPLv3 OR Proprietary Commercial` block (see any existing file).
- **Commits must be DCO signed-off** (`git commit -s`); see `CONTRIBUTING.md`.
- Rust changes must pass `cargo test --all-features`; Python changes must pass `pytest tests/ -x -q` and `mypy aegis/ --ignore-missing-imports`.
- New performance claims require a script in `benchmarks/` and a results entry in `docs/BENCHMARKS.md`. `docs/ROADMAP.md` is the single source of truth for per-feature implementation status.
- `ruff` line-length 100; security lint via `S`-rules (bandit-equivalent) is on — test files and `aegis/core/**` have documented per-file ignores in `pyproject.toml`.
- `AEGIS_SIGNING_KEY` (64-char hex) is the one non-optional production secret: without it the chain falls back to ephemeral Ed25519 and `legal_admissibility` becomes `Compromised`. See `.env.example` for the full env-var surface.
