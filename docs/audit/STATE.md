# Aegis Latent Core — Repository State Audit

**Version audited**: 2.3.0  
**Date**: 2026-06-19  
**Method**: Direct code reading (aegis/, aegis_server/, aegis_rust_v2/, tools/)  
**Epistemic policy**: [PROVEN] = code confirms claim | [PARTIAL] = partially implemented | [GAP] = not found or does not meet claim | [UNKNOWN] = insufficient information to decide

---

## 1. MODULE INVENTORY

### `aegis/` — Core Proxy Layer

| Module | LOC | Responsibility | Key Exports | Mutable State |
|--------|-----|----------------|-------------|---------------|
| `config.py` | ~312 | Pydantic settings from env vars; provider validation; backend URL resolution | `AegisSettings`, `get_settings()` | `@lru_cache` singleton |
| `proxy/app.py` | ~692 | FastAPI app factory; full request pipeline; middleware chain; BackgroundTask orchestration | `create_app()`, `_BoundedAnalyzerCache`, `_AppState` | `_AppState.analyzers` (LRU dict), `_AppState.alert_store` (deque), `_AppState.ledger` |
| `proxy/forwarder.py` | ~327 | HTTP client; provider request/response translation; streaming; optional Rust acceleration path | `LLMForwarder` | `_client` (httpx.AsyncClient), `_rust_forwarder` (PyO3 object) |
| `proxy/analyzer.py` | ~323 | Shannon entropy + KL/JS divergence detection over response logprobs; per-session EMA | `ResponseAnalyzer`, `ResponseAnalysis` | EMA running state per session |
| `proxy/waf.py` | ~177 | Two-layer WAF: critical pattern hard-block + LLMGuardLocal weighted scoring | `AegisWAF`, `WAFResult` | None (stateless) |
| `proxy/audit_api.py` | ~116 | Read-only audit endpoints (`/v1/audit/integrity`, `/v1/audit/chain`) | Router | None |
| `proxy/schemas.py` | ~173 | Pydantic OpenAI-compatible request/response models | `ChatCompletionRequest`, `ChatCompletionChoice`, `ChoiceLogprobs` | None |
| `proxy/dependencies.py` | ~111 | FastAPI dependency injection wiring | `validate_proxy_auth()` | None |
| `proxy/mtls.py` | ~74 | mTLS certificate handling (advisory, partial integration) | Identity manager stub | None |
| `auth/apikey.py` | ~143 | Constant-time API key validation; Vault-backed key retrieval | `ProxyKeyAuth`, `AuditKeyAuth`, `constant_time_key_in()` | Frozenset of keys (immutable after init) |
| `core/crypto_audit.py` | ~530 | Merkle chain node construction, HMAC/PQC signing, WAL persistence, in-memory chain | `CryptographicAuditLedger`, `AuditNode` | `_lock` (threading.Lock), `chain` (deque), `_wal_handle` (file), `_mmr` (MerkleMountainRange) |
| `core/mmr.py` | ~323 | Merkle Mountain Range: leaf addition, peak merging, inclusion/consistency proofs, Rust-backed variant | `MerkleMountainRange`, `RustBackedMMR`, `mmr_manager` | `nodes` (list), `peaks` (list), `_leaf_count` |
| `core/ratelimiter.py` | ~154 | Token-bucket rate limiter; memory (TTLCache) or Redis backend | `InMemoryRateLimiter`, `DistributedRateLimiter` | `_buckets` (TTLCache), `_lock` (asyncio.Lock) |
| `core/session_manager.py` | ~109 | Per-session lifecycle; LRU eviction; entropy monitor isolation | `SessionLifecycleManager` | `_sessions` (OrderedDict), `_lock` (threading.RLock) |
| `core/telemetry.py` | ~143 | Per-token logit entropy monitoring; EMA state machine | `LogitEntropyMonitor` | EMA alpha, running mean/variance |
| `core/secrets.py` | ~119 | HashiCorp Vault integration for API key retrieval | `VaultManager` | Vault connection state, secret cache |
| `core/forensic.py` | ~50 | Merkle leaf encoding; token trail construction | `build_merkle_leaf()`, `build_token_trail()` | None (pure functions) |
| `providers/base.py` | ~142 | Abstract provider adapter interface | `ProviderAdapter` (ABC) | None |
| `providers/openai_provider.py` | ~84 | OpenAI passthrough (noop adapter) | `OpenAIAdapter` | None |
| `providers/anthropic_provider.py` | ~476 | Full Anthropic ↔ OpenAI request/response/stream translation | `AnthropicAdapter` | None (stateless) |
| `providers/gemini_provider.py` | ~75 | Google Gemini ↔ OpenAI translation | `GeminiAdapter` | None |
| `providers/__init__.py` | ~120 | Provider factory; model-string → adapter routing | `build_provider()` | None |

**Total aegis/ estimated LOC**: ~9,700 (includes runtime modules + optional advisory modules: ebpf_monitor, seccomp_guard, tpm, hsm, enclave_provider, formal_proofs — these are present in the tree but excluded from the runtime packaging omit list in pyproject.toml)

---

### `aegis_server/` — Enterprise Layer

| Module | LOC | Responsibility | Key Exports |
|--------|-----|----------------|-------------|
| `main.py` | ~800 (est.) | Enterprise FastAPI app; storage/signer DI; compliance/health endpoints | `create_server_app()` |
| `config.py` | ~200 (est.) | Enterprise settings: storage backend, signer type, export paths | `EnterpriseSettings` |
| `storage/base.py` | ~200 | Abstract storage interface | `StorageProvider` (ABC), `StorageNode`, `IntegrityReport` |
| `storage/sqlite_provider.py` | ~200+ | SQLite WAL-backed persistence | `SQLiteStorageProvider` |
| `storage/postgres_provider.py` | ~200+ | PostgreSQL async persistence via asyncpg | `PostgresStorageProvider` |
| `storage/dynamodb_provider.py` | ~200+ | AWS DynamoDB async persistence via aioboto3 | `DynamoDBStorageProvider` |
| `compliance/exporter.py` | ~200+ | SOC2/HIPAA bundle export: chain_hash + bundle_signature + sealed JSON | `ComplianceExporter`, `ExportResult` |
| `crypto/base.py` | ~100 | Signer provider interface | `SignerProvider` (ABC) |
| `crypto/vault_signer.py` | ~100 | HashiCorp Vault Transit signing | `VaultTransitSigner` |

---

### `aegis_rust_v2/` — Rust PyO3 Extension

| File | LOC | Responsibility |
|------|-----|----------------|
| `src/lib.rs` | 71 | PyO3 module registration; exports RustForwarder, MmrAccumulator, PqcKeypair |
| `src/forwarder.rs` | 140 | Blocking reqwest HTTP client; `forward_json_sync()` releases GIL via `py.allow_threads()` |
| `src/mmr.rs` | 130 | High-speed Merkle Mountain Range accumulator; SHA-256 peak merging |
| `src/pqc.rs` | 73 | ML-DSA (CRYSTALS-Dilithium) keypair generation + signing; Zeroize on drop |
| `src/ledger.rs` | 33 | SHA-256 and HMAC-SHA256 helper functions |
| `Cargo.toml` | 31 | Deps: reqwest (blocking), pyo3, sha2, pqcrypto-mldsa; LTO in release |

**Total Rust LOC**: ~447

---

### `tools/`

| Module | LOC | Purpose |
|--------|-----|---------|
| `visualizer/app.py` | ~52 | FastAPI dashboard for audit chain inspection |
| `visualizer/generate_summary.py` | ~85 | Git/pytest/Rust build telemetry aggregation |
| `forensic/forensic_checks.py` | ~112 | Static pattern scanning for credentials/hardcoded privileges |
| `forensic/triage_unsafe.py` | ~47 | Unsafe code detection helper |

---

## 2. REQUEST LIFECYCLE — `POST /v1/chat/completions`

Real trace through `proxy/app.py`, `proxy/waf.py`, `core/ratelimiter.py`, `proxy/forwarder.py`, `providers/`, `core/crypto_audit.py`, `core/mmr.py`.

```
CLIENT: POST /v1/chat/completions
        {"model": "gpt-4o", "messages": [...], "stream": false}
        Authorization: Bearer <proxy_key>
              │
              ▼
┌─────────────────────────────────────────┐
│ MIDDLEWARE CHAIN (app.py:~416)          │
│ 1. RequestSmugglingProtectionMiddleware  │
│    Validates Content-Length header       │
│    Validates Transfer-Encoding header    │
│ 2. CORSMiddleware (cors_origins config)  │
└──────────────────────┬──────────────────┘
                       │
              ▼
┌─────────────────────────────────────────────────────────┐
│ ROUTE HANDLER: chat_completions() (app.py:~501)         │
│                                                         │
│ STEP 1 — AUTH                                           │
│   validate_proxy_auth(request, _key)                    │
│   → constant_time_key_in(key, frozenset_of_valid_keys)  │
│   → 401 if missing or invalid                           │
│                                                         │
│ STEP 2 — PARSE + NORMALIZE                             │
│   raw_body = await request.body()                       │
│   body = canonical_normalize(json.loads(raw_body))      │
│   (normalizes field order for deterministic hashing)    │
│                                                         │
│ STEP 3 — WAF (waf.py:88-177)                           │
│   Layer 1 (critical, always blocks):                    │
│     "ignore previous instructions"                      │
│     "system override" / "DAN mode"                      │
│     "print system prompt" / template injection {{...}}  │
│   Layer 2 (weighted scoring):                           │
│     LLMGuardLocal adversarial filter                    │
│   → WAFResult(allowed=bool, reason=str)                 │
│   → 400 if not allowed                                  │
│                                                         │
│ STEP 4 — REQUEST ENTROPY GUARD (if enabled)             │
│   TaintEngine.taint(payload)                            │
│   PayloadEntropyAnalyzer.analyze()                      │
│   → 400 if anomaly detected                             │
│                                                         │
│ STEP 5 — SESSION + REQUEST ID                          │
│   session_id = x-session-id header OR body["user"]      │
│             OR uuid.uuid4()                             │
│   request_id = uuid.uuid4()                             │
│                                                         │
│ STEP 6 — RATE LIMITER                                   │
│   state.ratelimiter.check_limit(session_id)             │
│   InMemoryRateLimiter:                                  │
│     async with _lock (asyncio.Lock)                     │
│     _buckets[sid]: TTLCache[str, (float, float)]        │
│     token_bucket: tokens = min(burst, tokens + Δt * r) │
│   → 429 if tokens < 1                                   │
│                                                         │
│ STEP 7 — GET/CREATE RESPONSE ANALYZER                   │
│   state.get_analyzer(session_id)                        │
│   BoundedAnalyzerCache.get(sid):                        │
│     with threading.Lock                                 │
│     LRU eviction when cap (4,096) hit                   │
│   → ResponseAnalyzer(kl_thresh, js_thresh)              │
│                                                         │
│ STEP 8 — PROVIDER TRANSLATION (forwarder.py)            │
│   provider = build_provider(config)                     │
│   (path, body) = provider.translate_request(path, body) │
│   OpenAI → passthrough                                  │
│   Anthropic → /v1/messages, field remapping             │
│   Gemini → /v1/models/.../generateContent               │
│                                                         │
│ STEP 9 — HTTP FORWARD                                   │
│   ┌─ Rust path (if aegis_rust available):               │
│   │  rust_forwarder.forward_json_sync()                 │
│   │  reqwest blocking; py.allow_threads() (GIL free)    │
│   │  timeout = backend_timeout_seconds                  │
│   └─ Python path (httpx fallback):                      │
│      client.post(url, json=body, headers=...)           │
│      timeout applied via httpx.Timeout                  │
│   If provider != openai:                                │
│     response = provider.translate_response(raw_bytes)   │
│                                                         │
│ STEP 10 — RETURN RESPONSE TO CLIENT ◄──────────────┐   │
│   Response(content=..., status_code=200)            │   │
│   X-Aegis-Request-ID: request_id                    │   │
│   X-Aegis-Session-ID: session_id                    │   │
│   X-Aegis-Alert-Count: len(alerts)                  │   │
│                             CLIENT RECEIVES THIS NOW │   │
│                                                         │
│ STEP 11 — BACKGROUND TASK (asyncio.create_task)        │
│   _commit_and_alert(request_id, session_id,             │
│                     raw_body, resp_bytes, analyzer)     │
│                                                         │
│   a. ResponseAnalyzer.analyze(logprobs_data)            │
│      _logprobs_to_numpy(top_k) → np.ndarray            │
│      per-token Shannon entropy: H[i] = -Σ p log₂ p     │
│      mean_entropy = Σ H[i] / T                         │
│      EMA update: ema = α*H[i] + (1-α)*ema              │
│      KL divergence vs baseline                          │
│      JS divergence (symmetric)                          │
│      emit Alert if threshold exceeded                   │
│                                                         │
│   b. ledger.commit_state(node_data)                     │
│      with _lock (threading.Lock):                       │
│        get_latest_node() → prev_hash                    │
│        _mmr.add_leaf(req_hash || resp_hash)             │
│        Sign merkle_root (HMAC-SHA256 or PQC-ML-DSA)    │
│        _persist_node() → WAL write + fsync             │
│        chain.append(AuditNode)                          │
│                                                         │
│   c. alert_store.append(alert)                          │
│      async with _lock (asyncio.Lock)                    │
│                                                         │
│   Exception: logged, request unaffected                 │
└─────────────────────────────────────────────────────────┘
```

**Streaming path** differs at STEP 9: `forwarder.stream_sse()` returns an async generator. Chunks are yielded to client as SSE. After stream exhaustion, the same BackgroundTask runs for entropy analysis + ledger commit. Anthropic streams are translated chunk-by-chunk from `message_delta` events to OpenAI `choices[0].delta.content` format.

---

## 3. README CLAIMS VERIFICATION

| Claim | Code Location | Status | Detail |
|-------|---------------|--------|--------|
| "Cryptographically verifiable audit chain" | `core/crypto_audit.py:185-530`, `core/mmr.py:28-273` | [PROVEN] | HMAC-SHA256 default. PQC-ML-DSA via Rust. Deterministic node_hash. Append-only deque + WAL. Chain linkage: prev_hash in each node. |
| "Zero forensic latency" | `proxy/app.py:~593, ~650` | [PROVEN] | Response returned in STEP 10. BackgroundTask runs after. Client latency added = 0 ms. Exception in background task logs only, never propagates to client. |
| "SOC2/HIPAA export" | `aegis_server/compliance/exporter.py` | [PROVEN] | Sealed JSON bundle: audit nodes + chain_hash (SHA-256 of canonical JSON) + bundle_signature (HMAC or Vault Transit). Integrity report included. External verifier can replay: reconstruct chain_json → sha256 → verify signature. |
| "Multi-provider" (OpenAI, Anthropic, Gemini, OpenRouter) | `providers/{openai,anthropic,gemini}_provider.py`, `providers/__init__.py` | [PROVEN] | Full bidirectional translation for Anthropic. Gemini translation implemented. OpenRouter treated as OpenAI-compat passthrough. Streaming translation for Anthropic SSE → OpenAI SSE. |
| "Rust fallback / acceleration" | `aegis_rust_v2/`, `proxy/forwarder.py:~76-80` | [PROVEN] | PyO3 extension provides `RustForwarder`, `MmrAccumulator`, `PqcKeypair`. Python detects extension at startup. Falls back to pure Python if import fails. |
| "Shannon entropy detection" | `proxy/analyzer.py:127-200` | [PROVEN] | `H[i] = -Σ p * log₂(p)` per token position, EMA over sequence, position-averaged mean entropy. Configurable alert threshold. |
| "KL divergence detection" | `proxy/analyzer.py:~160-195` | [PROVEN] | KL(p‖q) and JS divergence computed against session baseline. Alert emitted when KL > `kl_alert_threshold` or JS > `js_alert_threshold` (from config). |
| "WAF — prompt injection detection" | `proxy/waf.py:49-177` | [PROVEN] | Layer 1: hard-block on critical patterns regardless of `strict_mode`. Layer 2: weighted scoring via LLMGuardLocal. Both layers active on every request. |
| "Entropy guard on request payload" | `proxy/app.py:~520-540` | [PARTIAL] | TaintEngine + PayloadEntropyAnalyzer present. Conditional on `enable_entropy_guard` config flag. Not enabled by default in .env.example. |
| "mTLS between proxy and upstream" | `proxy/mtls.py`, `proxy/forwarder.py` | [PARTIAL] | `ssl_certfile`/`ssl_keyfile` accepted via config and passed to httpx. Identity manager in mtls.py not exposed in request context. Certificate identity not asserted during auth. |
| "PQC key material zeroized" | `aegis_rust_v2/src/pqc.rs` | [PARTIAL] | Rust side: `Zeroize` derive on `PqcKeypair.private_key`. Python fallback path (Ed25519 via `cryptography` library): no explicit zeroize call. |
| "Logprobs for Anthropic/Gemini providers" | `providers/anthropic_provider.py`, `proxy/analyzer.py:~170` | [PARTIAL] | Anthropic and Gemini APIs do not expose token logprobs. Analyzer falls back to character-level entropy for these providers. Less precise than token-level. |

---

## 4. MUTABLE SHARED STATE & RISK SURFACE

### Critical Locks

| Component | Lock | Type | Held During | Risk |
|-----------|------|------|-------------|------|
| `CryptographicAuditLedger._lock` | `threading.Lock` | sync | WAL write, chain append, integrity verify | fsync() holds lock with no timeout — filesystem hang = process hang |
| `InMemoryRateLimiter._lock` | `asyncio.Lock` | async | Token bucket read-modify-write | Low risk — not held during I/O |
| `SessionLifecycleManager._lock` | `threading.RLock` | sync (reentrant) | LRU dict access and eviction | Recursive lock use — ensure no double-acquire path |
| `BoundedAnalyzerCache._lock` | `threading.Lock` | sync | Analyzer create/evict | threading.Lock in async context — blocks event loop briefly on eviction |
| `AlertStore._lock` | `asyncio.Lock` | async | Alert deque append/read | Low risk — bounded deque (maxlen=10_000) |

### Trust Boundaries

| Boundary | What crosses | Validation |
|----------|-------------|------------|
| Client → Proxy | Raw request body, Authorization header | Auth: constant-time key check. Body: WAF + entropy guard. |
| Proxy → Upstream LLM | Translated HTTP request | No SSRF protection on `backend_url` config — operator-level trust only. |
| Upstream → Proxy | LLM response JSON | Schema validated by Pydantic. No content-level validation of response. |
| Proxy → WAL | AuditNode JSON | Signed with HMAC/PQC. Tamper-evident but not encrypted at rest. |
| Proxy → Redis | Rate limit tokens | RESP protocol. No TLS configured by default. Sensitive if session IDs are PII. |

### I/O Without Explicit Timeout

| Call | Location | Risk |
|------|----------|------|
| `os.fsync()` on WAL | `crypto_audit.py:_persist_node()` | Filesystem hang blocks `_lock` indefinitely |
| `await vault.authenticate()` | `core/secrets.py` | Uses hvac default timeout (likely 30s); not overridable from config |
| asyncpg/aiosqlite queries | `aegis_server/storage/*.py` | No per-statement `command_timeout` visible at storage layer |
| `httpx.AsyncClient` upstream | `proxy/forwarder.py` | Timeout IS configured via `backend_timeout_seconds` (default 30s) — OK |

### Global / Module-Level State

- `get_settings()` → `@lru_cache(maxsize=None)`: single instance, immutable after first call. Safe.
- `mmr_manager` in `core/mmr.py`: module-level singleton. Accessed only by ledger under `_lock`. Safe.
- Advisory modules (ebpf, seccomp, LSM): all run in advisory mode; failures log warnings, do not propagate.

---

## 5. DEPENDENCY MAP

```
proxy/app.py
  ├── proxy/dependencies.py     (auth)
  ├── proxy/waf.py
  ├── proxy/analyzer.py
  │     └── core/telemetry.py
  ├── proxy/forwarder.py
  │     ├── providers/openai_provider.py
  │     ├── providers/anthropic_provider.py
  │     ├── providers/gemini_provider.py
  │     └── aegis_rust (optional PyO3)
  ├── core/crypto_audit.py
  │     ├── core/mmr.py
  │     │     └── aegis_rust (optional, RustBackedMMR)
  │     ├── core/forensic.py
  │     └── aegis_rust (optional, PqcKeypair for signing)
  ├── core/ratelimiter.py
  ├── core/session_manager.py
  ├── auth/apikey.py
  └── config.py

aegis_server/main.py
  ├── aegis_server/storage/{sqlite,postgres,dynamodb}_provider.py
  ├── aegis_server/crypto/vault_signer.py
  └── aegis_server/compliance/exporter.py

tools/visualizer/app.py
  ├── config.py
  └── core/crypto_audit.py  (read-only ledger inspection)
```

---

## 6. OPEN ISSUES (read from code, not inferred)

| # | Severity | Finding | Location | Resolution |
|---|----------|---------|----------|------------|
| I-01 | HIGH | `os.fsync()` called under `threading.Lock` with no timeout — filesystem hang blocks entire audit pipeline | `crypto_audit.py:_persist_node()` | Wrap in `asyncio.wait_for` or move to dedicated writer thread with queue |
| I-02 | MEDIUM | Vault auth call has no explicit timeout visible in `VaultManager` | `core/secrets.py` | Pass `timeout=` to hvac client constructor |
| I-03 | MEDIUM | Storage providers (sqlite/postgres/dynamodb) have no per-statement timeout | `aegis_server/storage/*.py` | Add `command_timeout` to asyncpg pool; `timeout=` to aiosqlite |
| I-04 | MEDIUM | Redis connection for distributed rate limiter: TLS not configured by default | `core/ratelimiter.py` | Set `ssl=True` + `ssl_cert_reqs=required` when `REDIS_URL` is remote |
| I-05 | LOW | mTLS identity not asserted in request context — cert present but not validated per-request | `proxy/mtls.py` | Wire `IdentityManager.get_identity(request)` into `dependencies.py` |
| I-06 | LOW | `BoundedAnalyzerCache` uses `threading.Lock` in async context; eviction blocks event loop | `proxy/app.py:_BoundedAnalyzerCache` | Replace with `asyncio.Lock` or use `lru_cache` |
| I-07 | INFO | Anthropic/Gemini entropy analysis falls back to character-level (no logprobs API) | `proxy/analyzer.py:~170` | Document explicitly; consider perplexity estimation via optional local model |
| I-08 | INFO | PQC key material not zeroized in Python fallback path | `auth/apikey.py`, Ed25519 paths | Call `.private_bytes()` then `memoryview` clear on GC; or enforce Rust path for PQC |

---

## 7. CURRENT VERSION

`pyproject.toml`: **2.3.0**  
Next version: **2.4.0** (minor bump — non-breaking additions)
