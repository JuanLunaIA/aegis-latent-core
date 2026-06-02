# Changelog

All notable changes to `aegis-latent-core` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);

## [2.0.1] — 2026-05-31

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
