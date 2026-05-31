# Changelog

All notable changes to `aegis-latent-core` are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Initial public release preparation.

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
