# Aegis Latent Core — Forensic LLM Proxy (Enterprise Grade)

Aegis Latent Core is a production-hardened, forensic telemetry proxy for LLM inference pipelines. It provides an append-only Merkle chain-of-custody, pluggable provider adapters, layered WAF defenses, and developer-friendly integrations for secure, auditable LLM deployment.

Key differentiators
- Cryptographic Merkle ledger with per-request commitment and integrity verification (HMAC / PQC-ready hooks).
- Merkle Mountain Range (MMR) for efficient inclusion & consistency proofs.
- Optional Redis-backed distributed lock for safe multi-process SQLite deployments.
- Adversarial pre-filtering combined with a static WAF; designed for ML-hardening extension.
- CI-ready: tests, type checks, linting and coverage in a single workflow.

Quickstart
1. Copy `.env.example` to `.env` and populate required values.
2. Create a virtualenv: `python -m venv .venv && . .venv/bin/activate`
3. Install deps: `pip install -r requirements.txt`
4. Run tests: `pytest -q`
5. Start server: `aegis-server` or `python -m aegis_server.main` (see DEPLOYMENT_GUIDE.md)

Security & Compliance
- Designed to operate with a dedicated HMAC signing key for high legal admissibility.
- Optional PQC signing via the aegis_rust extension (hooked — build and enable in production for post-quantum signature support).
- Sandbox hardening via seccomp/LSM guards and explicit runtime checks.

Contribution & Support
Open to enterprise partnerships and security reviews. Please open issues or PRs for feature requests, test additions, and security advisories.

License
Dual-licensed (AGPLv3 or Commercial). See LICENSE and COMMERCIAL.md for details.
