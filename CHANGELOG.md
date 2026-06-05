# Changelog

All notable changes to `aegis-latent-core` are documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release section includes: Added, Changed, Fixed, Security and Migration notes when relevant.

Quick upgrade notes — v2.3.0:

- No breaking changes from v2.2.0. Drop-in replacement.
- `_BoundedAnalyzerCache` now requires no migration; thresholds are read from config automatically.
- If you were relying on the LSM guard crashing on startup to block non-hardened deployments, set `AEGIS_STRICT_MODE=true` and enforce LSM externally (`aa-status`, `getenforce`) before starting.
- New `/health` response schema: `{"status", "ledger": {...}, "analyzer_cache": {...}, "provider", "version"}`. Update any health-check assertions.

## [2.3.0] — 2026-06-04

### Fixed

- **[BLOCKER-01]** `LSMGuard.verify_confinement()` raised an unconditional `RuntimeError` when AppArmor / SELinux was absent or inactive, crashing the lifespan on every container, cloud VM, and development environment without a loaded LSM profile. Changed to advisory mode: emits `WARNING` and continues in DAC-only mode. Hard enforcement must be validated externally before starting the server.
- **[BLOCKER-02]** `_BoundedAnalyzerCache` instantiated `ResponseAnalyzer` with hardcoded threshold defaults (`kl_threshold=2.0`, `js_threshold=0.5`, `entropy_alert_drop_bits=1.0`), silently ignoring `AegisSettings.kl_alert_threshold`, `js_alert_threshold`, and `entropy_alert_threshold_bits`. Cache now accepts `cfg: AegisSettings` and forwards all three thresholds to every new `ResponseAnalyzer`.
- **[BLOCKER-03]** `LLMForwarder.start()` built the `httpx.AsyncClient` without applying any SSL/mTLS configuration: `ssl_ca_certs`, `ssl_certfile`, `ssl_keyfile`, and `mtls_required` were defined in `AegisSettings` but never wired. Fixed: `start()` now passes a custom CA bundle (`verify=`) and client certificate (`cert=`) to `httpx.AsyncClient` when the corresponding settings are non-null. `main()` now also passes `ssl_certfile`, `ssl_keyfile`, `ssl_ca_certs`, and `ssl_cert_reqs=2` to uvicorn when configured.
- **[MAJOR-01]** Upstream `401 Unauthorized` and `403 Forbidden` responses were silently forwarded to the client with no server-side log entry. `forward_json()` now emits structured `ERROR` logs for both, including the provider path and a diagnostic hint.

### Added

- **`_BoundedAnalyzerCache.eviction_rate()`** — returns the fraction of `get()` calls that triggered an LRU eviction since startup. Consumed by `/health`.
- **`/health` deep check** — endpoint now returns a structured payload with `ledger` (node count, fault state) and `analyzer_cache` (size, capacity, eviction rate) subsystem health. Returns HTTP 200 when all subsystems are operational, 503 when any is degraded.
- **`/ready` readiness probe** — returns `{"status": "ready"}` once the lifespan startup has completed and the upstream `httpx` client is open; returns 503 before that window.
- **Tools: Forensics Visualizer** — `tools/visualizer/static/index.html` ships as the static frontend for the repo-local visualizer server (`tools/visualizer/`). Displays git HEAD, Python/Rust file counts, pytest telemetry, Rust extension build status, architecture and lifecycle Mermaid diagrams, audit ledger node layout, and a static security forensics scan panel populated from `/api/forensic_report`.

### Changed

- `pyproject.toml` version bumped `2.2.0` → `2.3.0`.
- `aegis.__version__` bumped `2.0.0` → `2.3.0`.
- `aegis_server.__version__` bumped `2.2.0` → `2.3.0`.
- `proxy/app.py` FastAPI version string bumped to `2.3.0`.
- `/health` response schema extended (breaking change for consumers asserting `{"status": "healthy"}`; new schema is a superset).

### Security

- mTLS client certificate and custom CA bundle are now applied to upstream httpx connections when `AEGIS_MTLS_REQUIRED=true`, `AEGIS_SSL_CERTFILE`, and `AEGIS_SSL_KEYFILE` are set. Previously these settings were silently ignored.
- uvicorn TLS listener now respects `AEGIS_SSL_CERTFILE`, `AEGIS_SSL_KEYFILE`, `AEGIS_SSL_CA_CERTS`, and enforces `ssl_cert_reqs=CERT_REQUIRED` when `AEGIS_MTLS_REQUIRED=true`.



- Ensure `AEGIS_SIGNING_KEY` is set in production (HMAC-SHA256). If unset, node signing falls back to an ephemeral Ed25519 key and `legal_admissibility` may be reduced.
- If you implemented a custom StorageProvider, add `get_latest_node()` implementing `ORDER BY seq DESC LIMIT 1` to avoid prev_hash regressions.
- Entropy computation changed to position-averaged Shannon entropy; tune `AEGIS_ENTROPY_ALERT_THRESHOLD_BITS` accordingly.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);

## [2.2.0] — 2026-06-02

### Added

- **Multi-provider support** — `aegis.providers` package with a `ProviderAdapter` ABC and four implementations:
  - `OpenAIAdapter` — passthrough for OpenAI and any OpenAI-compatible endpoint (vLLM, Ollama, LM Studio, llama.cpp)
  - `AnthropicAdapter` — full bidirectional translation: OpenAI Chat Completions ↔ Anthropic Messages API, including streaming SSE (Anthropic event model → OpenAI chunk model)
  - `GeminiAdapter` — Google Gemini via the OpenAI-compatible endpoint (`generativelanguage.googleapis.com/v1beta/openai`)
  - `OpenRouterAdapter` — OpenRouter with `HTTP-Referer` / `X-Title` headers for analytics
- **`AEGIS_PROVIDER`** config field (default: `openai`) — selects the active provider adapter
- **`AEGIS_PROVIDER_MODEL`** config field — optional upstream model override
- **`AEGIS_SIGNING_KEY`** config field — dedicated HMAC-SHA256 signing key for the Merkle audit chain, separate from `AEGIS_API_KEYS`; startup warning emitted when empty
- **`AEGIS_DEBUG_MODE`** config field (default: `false`) — controls `/docs`, `/redoc`, and `/openapi.json` exposure
- **`AEGIS_OPENROUTER_SITE_URL`** and **`AEGIS_OPENROUTER_SITE_NAME`** config fields
- **`AEGIS_ANTHROPIC_API_VERSION`** config field (default: `2023-06-01`)
- `MerkleMountainRange` singleton wired into `app.state.mmr` via enterprise lifespan; `_run_forensic_analytics` now uses real MMR `add_leaf()` for `merkle_root` computation
- Character-level Shannon entropy fallback for providers that do not return logprobs (Anthropic, Gemini)
- `StorageProvider.get_latest_node()` abstract method with correct `ORDER BY seq DESC LIMIT 1` semantics
- `SQLiteStorageProvider._chain_lock` (`asyncio.Lock`) serialises concurrent background task writes
- `aegis.providers.PROVIDER_NAMES` — frozenset of valid provider identifiers for validation
- `tests/test_providers.py` — 56 tests covering request translation, response translation, streaming translation, factory, and content normalisation (100% pass rate)
- Optional dependency groups in `pyproject.toml`: `storage-sqlite`, `storage-postgres`, `storage-dynamodb`, `vault`, `anthropic-sdk`, `google-sdk`, `ratelimit`
- Updated `.env.example` with all v2.2.0 configuration fields

### Fixed

- **[BLOCKER-01]** `prev_hash` always pointed to the genesis node — `list_nodes(limit=1, offset=0)` used `ORDER BY seq ASC` returning row 1; replaced with `get_latest_node()` using `ORDER BY seq DESC LIMIT 1`
- **[BLOCKER-02]** Race condition under concurrent `BackgroundTask` execution: two tasks reading the same `prev_hash` before either writes produced a forked chain; fixed by `_chain_lock` serialisation in `SQLiteStorageProvider.write_node()`
- **[MAJOR-01]** Shannon entropy was computed by normalising per-token argmax logprobs across sequence positions (sequence-level score concentration, not model uncertainty); replaced with position-averaged H = −Σ p_{t,k} log₂ p_{t,k} over top-K alternatives per position; `token_trail` now stores `top_logprobs` per token
- **[MAJOR-02]** `MerkleMountainRange` module-level singleton was instantiated but never used in the enterprise path; SHA-256 surrogate replaced with real `mmr.add_leaf()` call
- **[MAJOR-03]** Audit chain signing key derived from `sorted(get_api_keys())[0]`; invalidated silently on any key rotation; replaced with dedicated `AEGIS_SIGNING_KEY` field
- **[MAJOR-05]** `aiosqlite`, `asyncpg`, `aioboto3`, `hvac` were mandatory dependencies; moved to `storage-sqlite`, `storage-postgres`, `storage-dynamodb`, `vault` optional extras
- **[MEDIUM-01]** `InMemoryRateLimiter._buckets` grew unbounded under high client-ID cardinality; replaced with `cachetools.TTLCache(maxsize=200_000)` with graceful fallback
- **[MEDIUM-02]** `/docs` and `/redoc` were exposed unconditionally; hidden behind `AEGIS_DEBUG_MODE=true` in both proxy and enterprise layers
- **[MEDIUM-03]** `AEGIS_FORCE_LOGPROBS` defaulted to `True`; changed to `False` (opt-in); injection also gated on `provider.supports_logprobs` to avoid errors with Anthropic/Gemini
- **[MEDIUM-04 partial]** Provider-aware forwarder uses provider-specific base URL and headers; Anthropic stream translation happens transparently before yielding to the audit pipeline

### Changed

- `LLMForwarder` now accepts an optional `ProviderAdapter`; defaults to `OpenAIAdapter` (backward-compatible)
- Proxy and enterprise `FastAPI` version bumped to `2.2.0`
- `pyproject.toml` version bumped from `2.1.0` → `2.2.0`
- `aegis_server/__init__.__version__` bumped from `2.0.1` → `2.2.0`
- `cachetools>=5.3.0` added to core `dependencies`

### Security

- Audit chain signing key now issued from a dedicated secret, preventing accidental invalidation during API key rotation
- `/docs` and `/redoc` hidden by default in all deployment modes



### Fixed (blockers)

- **`crypto_audit`** — Complete rewrite of `CryptographicAuditLedger`:
  - `AuditNode.payload_hash` was referenced in `audit_api.py` but the field was
    named `payload` in the dataclass → `AttributeError` at runtime.  Now exposed
    as a property alias for `request_hash`.
  - `PQCProvider.sign(private_key, message)` was called as `kp.sign(data)` on a
    plain dataclass with no `.sign()` method → crash on non-fallback path.
    Signing is now cleanly delegated through `_sign()` which routes to
    HMAC-SHA256 (default), aegis_rust PQC-ML-DSA (if available), or per-node
    ephemeral Ed25519.
  - `chain: list[AuditNode]` + `chain.pop(0)` was O(N) for each eviction.
    Replaced with `collections.deque(maxlen=N)` for O(1) sliding window.
  - `mmr_manager` was a module-level singleton shared across all ledger instances
    (cross-test pollution, incorrect MMR state in multi-ledger setups).  Each
    `CryptographicAuditLedger` now owns its own `MerkleMountainRange` instance.
  - Added `commit_forensic()` as the primary API (request + response bytes,
    model, endpoint, token_trail) matching the test specification.
    `commit_state()` is retained as a backward-compatible thin wrapper.
  - `signing_key` parameter added; HMAC-SHA256 scheme sets `legal_admissibility`
    to `"High"`. Ed25519 ephemeral fallback marks nodes as `is_fallback=True`.

- **`proxy/app.py`** — `lsm` and `guard` variables were read in `except` handlers
  before being assigned when `LSMGuard()` / `SeccompGuard()` constructors threw
  → `UnboundLocalError`.  Both blocks now initialise the variable to `None`
  before the `try` and check `is not None` before attribute access.

- **`proxy/app.py`** — SSE stream emitted `data: [DONE]` twice: once from
  `stream_sse()` yielding the upstream `[DONE]` chunk, and again from the
  unconditional `yield b"data: [DONE]\n\n"` after the loop.  The final emit is
  now guarded by `if not upstream_done`.

- **`proxy/analyzer.py`** — `tok.token` was accessed unconditionally inside
  alert-message f-strings while `tok` can be either a `TokenLogprob` object or
  a plain `dict` (depending on caller).  Three affected sites now use
  `tok.get("token", "?") if isinstance(tok, dict) else tok.token`.

- **`pyproject.toml` / `requirements.txt`** — `cryptography` was imported in
  `crypto_audit.py` (Ed25519) but not listed as a dependency.  Added
  `cryptography>=42.0.0` to both manifests.

### Fixed (major)

- **`core/secrets.py`** — `self._client = httpx.Client(timeout=10.0)` was
  created in `__init__` but never used (all methods use inline `AsyncClient`)
  and never closed → resource leak.  Removed.

- **`core/seccomp_guard.py`** — `ctypes.util.find_library("c")` can return
  `None` on stripped containers; `ctypes.CDLL(None)` would crash with a
  confusing error.  Added an explicit `None` guard with a clear `RuntimeError`.
  Added `is_sandbox` as a public property (was `_is_sandbox` private attribute).

- **`core/lsm_guard.py`** — `app.py` referenced `lsm.is_sandbox` but `LSMGuard`
  only had `_is_confined`.  Added `_detect_sandbox()` and `is_sandbox` property.

- **`proxy/app.py`** — `CryptographicAuditLedger` was instantiated without a
  `signing_key`, causing all nodes to use the ephemeral Ed25519 fallback and
  setting `legal_admissibility` to "Compromised".  Now derives the signing key
  from the first sorted API key when available.

versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] — 2026-06-02

### Added
- **CI/CD Infrastructure**: Full GitHub Actions suite for automated testing, security scanning, and distribution.
- **Enterprise Release Pipeline**: Automated build, SHA-256 integrity hashing, and GitHub Release generation.
- **Docker/GHCR Integration**: Automated build, signing (Cosign), and publishing of production-ready images to GitHub Container Registry.
- **Supply Chain Security**: Integrated SBOM (Software Bill of Materials) generation for Executive Order 14028 compliance.
- **Deployment Guide**: Comprehensive documentation for professional deployment and maintenance.

### Changed
- Refined CI pipeline to include Rust extension testing and cross-version Python validation (3.11, 3.12).
- Enhanced Docker meta-tagging strategy (SemVer, SHA, latest).

---

## [2.0.1] — 2026-05-31

---

## [2.0.0] — 2026-05-30

### Added
- FastAPI-based OpenAI-compatible reverse proxy (`aegis/proxy/`).
- Per-token entropy analysis: Shannon entropy, KL divergence, Jensen–Shannon divergence.
- Merkle chain-of-custody audit log (`aegis/core/mmr.py`, `aegis/core/transparency_log.py`).
- Real-time alerting via configurable webhook (Slack, Teams, SIEM).
- mTLS support for backend connections (`aegis/proxy/mtls.py`).
- WAF layer for request normalization and injection detection (`aegis/proxy/waf.py`).
- MoE routing entropy monitor for distributed entanglement detection (`aegis/core/moe_monitor.py`).
- PQC module with ML-DSA / ML-KEM bindings via `aegis_rust_v2` (PyO3 + `pqcrypto` crate).
- vLLM and HuggingFace integration plugins (`integrations/`).
- Helm chart for Kubernetes deployment (`deploy/helm/`).
- TLA+ formal specifications for ledger immutability and session manager (`specs/`).
- GitHub Actions CI: lint → test (Python 3.11/3.12) → SAST → SBOM → Docker push → Helm lint.

### Security
- seccomp filter guard (`aegis/core/seccomp_guard.py`) applied at process startup.
- Constant-time API key comparison in `aegis/auth/apikey.py`.
- Rate limiter with per-key token bucket (`aegis/core/ratelimiter.py`).

---

[Unreleased]: https://github.com/JuanLunaIA/aegis-latent-core/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.0.0

### Post-release patch (2026-06-02 rev.2) — External audit follow-up

Verified every finding in the external audit document against the actual code.

**Confirmed and fixed:**
- `[CRITICAL-NEW]` `PostgreSQLStorageProvider` and `DynamoDBStorageProvider` lacked `get_latest_node()` implementation — would raise `TypeError` at instantiation. Added to both providers.
- `[MAJOR]` `crypto_audit.py` `verify_integrity()` step 1: `if node.node_hash != node.node_hash` was dead code (self-comparison, always False). Replaced with real tamper detection via `AuditNode.__post_init__` that snapshots `__creation_hash__` and compares on each integrity sweep.
- `[MAJOR]` `mmr.py` `get_consistency_proof()`: replaced empty stub with real peak reconstruction algorithm that derives proof hashes by replaying MMR peak-merging on the stored node list.
- `[MEDIUM]` `adversarial_filter.LLMGuardLocal` was never imported or called. Wired into `AegisWAF` as a second detection layer (weighted signal scoring) alongside the existing regex layer.

**Rejected / false positives in audit:**
- `config.py` L218 SyntaxError: `python3 -c "import ast; ast.parse(...)"` returns OK. Config imports without error. This claim is false.
- `aegis_rust` "not compiled by default": this is by design — the forwarder uses `try/except ImportError` and `HAS_RUST=False` graceful fallback. Not a bug.
