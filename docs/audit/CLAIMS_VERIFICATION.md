# Aegis — Claims Verification Matrix

> **Purpose:** every public claim in `README.md` maps to exactly one row here,
> and every row maps to source evidence (code location, audit doc, or measured
> benchmark). If a claim cannot be backed, it is not made.
>
> **Method:** consolidated from direct code reading (`docs/audit/STATE.md` §3),
> the audit-chain security pass (`docs/audit/SECURITY_AUDIT.md`), the executable
> baseline (`docs/audit/BASELINE.md`), and measured benchmarks
> (`docs/BENCHMARKS.md`). No number in this file is estimated.
>
> **Epistemic policy (CLAUDE.md I-03):**
> `[PROVEN]` code/executor confirms · `[MEASURED]` executor benchmark output ·
> `[PARTIAL]` implemented with a documented limitation · `[SPECULATIVE]`
> unverified, resolves via a named measurement.

Audited version: **2.4.0** · Date: **2026-06-19**

---

## 1. Core claims (fully backed)

| # | Claim | Verdict | Evidence |
|---|-------|---------|----------|
| C1 | Cryptographically verifiable, tamper-evident audit chain | `[PROVEN]` | `aegis/core/crypto_audit.py` (HMAC-SHA256 default; deterministic `node_hash`; `prev_hash` is the first hashed field → reordering breaks the chain). Reorder attack caught by `tests/test_security_fixes.py::test_node_reorder_detected_by_signature`. See `SECURITY_AUDIT.md` §2. |
| C2 | `prev_hash` linkage holds under concurrency (no chain fork) | `[PROVEN]` | Whole read-modify-write is inside one `threading.Lock`. `tests/test_red_team.py::test_S1_Massive_Concurrency_Burst` (100 threads × 50 commits) asserts `verify_integrity()`. See `SECURITY_AUDIT.md` §1 & §3. |
| C3 | SSE streaming commits survive client disconnect | `[PROVEN]` | Commit moved into a `finally` block scheduled via tracked `_spawn_background`. `tests/test_app_coverage.py::test_sse_commit_on_client_disconnect`. See `SECURITY_AUDIT.md` §4. |
| C4 | SOC2 / HIPAA sealed compliance export, independently re-verifiable | `[PROVEN]` | `aegis_server/compliance/exporter.py`: SHA-256 canonical `chain_hash` + `bundle_signature` over it; `ComplianceExporter.verify_bundle()` re-checks both. Exercised end-to-end by `examples/demo.py` (step 5). |
| C5 | Multi-provider (OpenAI, Anthropic, Gemini, OpenRouter) with OpenAI-format in/out | `[PROVEN]` | `aegis/providers/`. Full bidirectional Anthropic translation incl. SSE; Gemini translation; OpenRouter as OpenAI-compat passthrough. Contract tests in `tests/test_provider_contracts.py`. |
| C6 | Shannon-entropy + KL/JS divergence response forensics | `[PROVEN]` | `aegis/proxy/analyzer.py`: `H = (1/T) Σ -Σ p·log₂p` per token, EMA, KL/JS vs session baseline; thresholds from `AegisSettings`. See `STATE.md` §3. |
| C7 | Two-layer WAF (hard-block + weighted scoring) on every request | `[PROVEN]` | `aegis/proxy/waf.py`: Layer 1 critical-pattern hard block; Layer 2 weighted scoring. See `STATE.md` §3. |
| C8 | Token-bucket rate limiting (memory or Redis) | `[PROVEN]` | `aegis/core/ratelimiter.py`. |
| C9 | WAL persisted owner-only (`0o600`); stores hashes, not prompt bodies | `[PROVEN]` | `aegis/core/crypto_audit.py` (both open paths); `tests/...::test_wal_file_mode_is_owner_only`. See `SECURITY_AUDIT.md` §7. |
| C10 | `auth_disabled` cannot be set without `debug_mode` (no silent prod bypass) | `[PROVEN]` | `AegisSettings._enforce_auth_posture` model validator; `tests/test_security_fixes.py::test_auth_disabled_requires_debug_mode`. See `SECURITY_AUDIT.md` §6. |

---

## 2. Performance claims (measured, not estimated)

All values from `docs/BENCHMARKS.md`. Environment: Intel Xeon @ 2.80 GHz, 4 cores,
Linux 6.18.5, Python 3.11.15. Reproduce with the commands in that file.

| # | Claim | Verdict | Measured value |
|---|-------|---------|----------------|
| P1 | "Zero forensic latency" — the audit commit adds **no I/O wait** to the client response | `[PROVEN]` | The commit coroutine is scheduled via `asyncio.create_task()` and runs **after** `return JSONResponse(...)`. No `await commit` precedes the return. |
| P2 | Hot-path scheduling overhead of the background commit | `[MEASURED]` | `_spawn_background()` block = **77.56 µs p50 / 131.52 µs p99** (n=5,000). This is the full bookkeeping cost on the response path; the commit itself runs off-path. |
| P3 | Python MMR throughput | `[MEASURED]` | 172.7k leaves/s @ N=100 → 121.4k leaves/s @ N=100,000 (best-of-k=5). |
| P4 | Rust extension "significant performance gains" over Python | `[SPECULATIVE]` | **UNKNOWN — resolves via** `cd aegis_rust_v2 && maturin develop --release && python -m benchmarks.bench_mmr`. The extension was not compiled in the measurement environment; no speedup ratio may be quoted until then. |

---

## 3. Partial / limited claims (stated honestly)

| # | Claim | Verdict | Limitation |
|---|-------|---------|-----------|
| L1 | Logprob-based entropy for Anthropic & Gemini | `[PARTIAL]` | Neither API exposes token logprobs; analyzer falls back to **character-level** entropy (less precise). `STATE.md` §3 / I-07. |
| L2 | mTLS between proxy and upstream | `[PARTIAL]` | `ssl_certfile`/`ssl_keyfile`/CA bundle are applied to uvicorn and the upstream `httpx` client (fixed in 2.3.0), but per-request client-certificate **identity is not asserted** in auth. `STATE.md` §3 / I-05. |
| L3 | PQC (ML-DSA) signing | `[PARTIAL]` | Active only when the Rust extension is built; otherwise audit nodes sign with HMAC-SHA256 (key set) or ephemeral Ed25519 (no key → `legal_admissibility="Compromised"`). Rust path zeroizes key material; the Python Ed25519 fallback does not. `STATE.md` §3 / `BASELINE.md` §5. |
| L4 | Request-payload entropy guard | `[PARTIAL]` | Implemented (`TaintEngine` + `PayloadEntropyAnalyzer`) but **off by default** (`enable_entropy_guard`). `STATE.md` §3. |

---

## 4. Known open issues (do not claim as fixed)

From `STATE.md` §6 — read from code, not inferred. These are operator/roadmap items:

| ID | Severity | Issue |
|----|----------|-------|
| I-01 | HIGH | `os.fsync()` runs under the audit `threading.Lock` with no timeout — a filesystem hang blocks the audit pipeline. |
| I-02 | MEDIUM | Vault auth has no explicit timeout. |
| I-03 | MEDIUM | Storage providers lack per-statement timeouts. |
| I-04 | MEDIUM | Redis (distributed rate limiter) has no TLS by default. |
| I-05 | LOW | mTLS identity not asserted per request (see L2). |

Dependency posture (`BASELINE.md` §4): Bandit **0 HIGH**; actionable dependency
floors (`idna>=3.15`, `urllib3>=2.7.0`) pinned in `requirements.txt`.

---

*This matrix is the single source of truth for README claims. Update it in the
same change that alters any claim. Anchors: `STATE.md`, `SECURITY_AUDIT.md`,
`BASELINE.md`, `../BENCHMARKS.md`.*
