# Aegis Latent Core — Forensic LLM Proxy (Enterprise Grade)

Aegis Latent Core is a production-hardened, forensic telemetry proxy for LLM inference pipelines. It provides an append-only Merkle chain-of-custody, pluggable provider adapters, layered WAF defenses, and developer-friendly integrations for secure, auditable LLM deployment.

Key differentiators
- Cryptographic Merkle ledger with per-request commitment and integrity verification (HMAC / PQC-ready hooks).
- Merkle Mountain Range (MMR) for efficient inclusion & consistency proofs.
- Optional Redis-backed distributed lock for safe multi-process SQLite deployments.
- Adversarial pre-filtering combined with a static WAF; designed for ML-hardening extension.
- CI-ready: tests, type checks, linting and coverage in a single workflow.

---

## Quickstart (short)

1. Copy `.env.example` to `.env` and populate required values.
2. Create a virtualenv: `python -m venv .venv && . .venv/bin/activate`
3. Install deps: `pip install -r requirements.txt` (or `pip install -e '.[dev]'` for dev extras)
4. Run tests: `pytest -q` (see Developer Commands below for single-test invocation)
5. Start server: `aegis-server` or `python -m aegis_server.main` (see DEPLOYMENT_GUIDE.md)

---

## Configuration (from `.env.example`)

Copy `.env.example` to `.env` and set values.  Required vs optional are noted below.

| Variable | Required | Default / Example | Notes |
|---|---:|---|---|
| AEGIS_PROVIDER | required | `openai` | Provider key to use (openai, anthropic, gemini, openrouter) |
| AEGIS_BACKEND_API_KEY | required | `sk-your-key-here` | API key forwarded to the provider |
| AEGIS_API_KEYS | required | `your-proxy-key-1,your-proxy-key-2` | Comma-separated proxy client keys (Bearer tokens) |
| AEGIS_SIGNING_KEY | required for audit | (generate with `python -c "import secrets; print(secrets.token_hex(32))"`) | Dedicated HMAC-SHA256 key for Merkle audit chain; MUST differ from AEGIS_API_KEYS |
| AEGIS_STORAGE_PROVIDER | optional | `sqlite` | `sqlite` | `postgres` | `dynamodb` (select storage backend)
| AEGIS_SQLITE_DB_PATH | optional | `./data/aegis.db` | used when `sqlite` selected
| AEGIS_DEBUG_MODE | optional | `false` | Enables /docs and /redoc when true (dev only)
| AEGIS_HOST / AEGIS_PORT | optional | `0.0.0.0` / `8080` | Server bind address and port
| AEGIS_RATE_LIMIT_BACKEND | optional | `memory` | `memory` or `redis` (requires AEGIS_REDIS_URL)
| AEGIS_FORCE_LOGPROBS | optional | `false` | Enable logprobs telemetry for compatible backends (OpenAI-like)

Also consult `pyproject.toml` for optional extras (vllm, hf, gpu, pqc, dev, storage extras).

---

## Developer quick commands

Most developer workflows use the Makefile targets declared in the repo root. Prefer Makefile targets unless you need custom flags.

- Install runtime deps: `make install` (runs `pip install -e .`) or `pip install -r requirements.txt`
- Install dev deps: `make dev` or `pip install -e '.[dev]'
- Lint: `make lint` (runs `ruff check .` and `ruff format --check .`)
- Type check: `make type` (runs `mypy aegis/ --ignore-missing-imports`)
- Security SAST: `make security` (runs `bandit -r aegis/ -c pyproject.toml -ll`)
- Run full tests: `make test` or `pytest tests/ -v`
- Run a single test file: `pytest tests/test_core.py -q`
- Run a single test function: `pytest tests/test_core.py::test_name -q`
- Coverage gate (dev): `make test-cov` (Makefile: `--cov-fail-under=65`)
- Smoke test (against a running server): `make smoke` or `./scripts/smoke_test.sh`
- Build Rust extension: `make build-rust` (requires `maturin`, copies `.so` to `aegis/proxy/`)

Notes:
- Many tests depend on optional extras (vLLM, HuggingFace, GPU libs) or the Rust extension. Install extras or skip heavy tests when not available.
- CI runs: `pytest -q --maxfail=1 --cov=aegis --cov-report=xml` (see `.github/workflows/ci.yml`).

---

## Optional extras & heavy tests

The project supports optional extras for ML and performance:
- `vllm` integration (vLLM server hooks): `pip install '.[vllm]'` and ensure `vllm>=0.4.0`.
- HuggingFace hooks: `pip install '.[hf]'` (requires `transformers>=4.40.0`, `torch>=2.0`).
- GPU support: `pip install '.[gpu]'` (requires `torch>=2.0` and CUDA environment).
- Rust acceleration / PQC: compile `aegis_rust_v2` via `maturin develop --release` (Makefile `make build-rust` automates this).

Tests that exercise these integrations are marked in `tests/` and in `pytest-core.ini`; skip or run them only when the extras are installed.

---

## API examples (curl)

Health:

```bash
curl -sS http://localhost:8080/health
```

Audit health (requires audit key):

```bash
curl -sS -H "Authorization: Bearer ${AEGIS_TEST_AUDIT_KEY:-sk-audit-readonly-key}" http://localhost:8080/v1/audit/health
```

Chat completion (example):

```bash
curl -sS -H "Authorization: Bearer ${AEGIS_TEST_API_KEY:-sk-aegis-key1}" \
  -H "Content-Type: application/json" \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"ping"}]}' \
  http://localhost:8080/v1/chat/completions
```

---

## Docker / local dev snippet

There is no official Dockerfile in this README (see `DEPLOYMENT_GUIDE.md` and CI workflows for the canonical image build). For simple local testing, a minimal recipe:

```bash
# build a local image (example, assumes Dockerfile present)
docker build -t aegis-local:dev .
# run with env file
docker run --rm -p 8080:8080 --env-file .env aegis-local:dev
```

SBOM generation and signing are provided in `scripts/generate_sbom.sh` and CI uses Cosign for image signing. See `DEPLOYMENT_GUIDE.md` for release steps.

---

## Architecture (diagram)

Client requests flow through the proxy, which forwards to an upstream LLM and returns responses immediately. Forensic work is performed off-path in BackgroundTasks; signer and storage make the Merkle audit chain persistent.

Mermaid diagram (renders on GitHub):

```mermaid
flowchart LR
  Client[Client]
  AegisProxy[Aegis Proxy<br/>(FastAPI)<br/>WAF · Auth · RateLimit]
  Client -->|request| AegisProxy
  AegisProxy -->|forward| LLM[Upstream LLM / Provider<br/>(OpenAI · vLLM · Ollama)]
  AegisProxy -->|immediate response| Client
  AegisProxy --> Background[BackgroundTasks<br/>(Telemetry · Entropy/KL · MMR · Signer · Persist)]
  Background --> Signer[Signer<br/>(HMAC · Vault · PQC)]
  Background --> Storage[Storage Provider<br/>(sqlite · postgres · dynamodb)]
  Integrations[Integrations<br/>(vLLM / HuggingFace hooks)]
  Integrations --> Background
  AegisProxy --> Integrations
  Rust[aegis_rust_v2<br/>(Rust · PQC · Perf)]
  Rust --> Signer
  Rust --> Background
```

Notes:
- GitHub renders Mermaid diagrams in PRs and README. If your viewer doesn't render, use a Mermaid preview extension or view on GitHub UI.
- The proxy returns upstream responses immediately to avoid adding latency; forensic processing is handled asynchronously.

---

## CI & Coverage

- CI workflow (`.github/workflows/ci.yml`) runs tests on Python 3.11 and 3.12, performs best-effort lint/type checks, and uploads coverage XML.
- Coverage gates: the repository Makefile uses `--cov-fail-under=65` for full test-cov; `pytest-core.ini` uses an 85% gate for a smaller "core" test selection. Be explicit when running coverage locally which target you intend.

---

## Troubleshooting (common issues)

- `maturin` missing when running `make build-rust`: install via `pip install maturin` or follow maturin docs.
- Optional extras missing (vllm/hf/gpu): heavy tests may fail with ImportError — install the relevant extras or skip tests.
- SQLite permission errors: ensure directory exists and AEGIS_SQLITE_DB_PATH is writable.
- If smoke tests fail, confirm backend LLM (Ollama/vLLM/OpenRouter) is reachable and model name is valid.

---

## Where to look in the code

- `aegis/` — core proxy, telemetry, MMR, WAF, analysis modules
- `integrations/` — HuggingFace and vLLM forward-hook adapters
- `aegis_rust_v2/` — Rust extension (optional; build with maturin)
- `aegis_server/` — enterprise storage/signing and compliance exporter
- `tests/` — test suite; `pytest-core.ini` contains core test selection
- `pyproject.toml` — dependencies, ruff/mypy/bandit config, scripts
- `Makefile` and `scripts/` — developer convenience commands and utilities

---

## Contributing & Security

- Please open PRs for features, fixes, tests and security advisories. Pull request templates and issue templates exist under `.github/`.
- Consider adding `CONTRIBUTING.md` and `SECURITY.md` if you want explicit contributor and disclosure workflows documented in-repo.

---

License

Dual-licensed (AGPLv3 or Commercial). See LICENSE and COMMERCIAL.md for details.
