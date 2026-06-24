# Changelog

All notable changes to **Aegis Latent Core** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.1] - 2026-06-24

Release-hardening and capability-expansion release. Twenty roadmap controls were
implemented and tested across all five target domains (Defense, Healthcare,
Industrial, Enterprise HA, Forensics), advancing the roadmap scorecard to
151/193 (~78%). All 4,575 tests pass (3 skipped) at 94.79% coverage.

### Added

**Defense & Government (Domain 1)**
- ML-KEM-1024 (FIPS 203) session-key bootstrap (`aegis/core/mlkem_session.py`).
- Cross-domain solution (CDS) guard with classification-domain transfer
  sanitization (`aegis/core/cds_guard.py`).
- Offline license validation — HMAC-SHA256 over canonical JSON, no phone-home,
  enforced key separation (`aegis/core/offline_license.py`).
- Pinned CA bundle for air-gapped signature verification, SHA-256 DER
  fingerprints, no runtime CA fetch (`aegis/core/pinned_ca_bundle.py`).
- LSM confinement guard — AppArmor/SELinux detection and advisory enforcement
  (`aegis/core/lsm_guard.py`, `deploy/apparmor/aegis.profile`).
- Hardware-bound session tokens (TPM 2.0 / software backends, HMAC-SHA256
  binding) (`aegis/core/hardware_token.py`).
- Rust build hardening — full RELRO, noexecstack, embedded size profile
  (`aegis_rust_v2/.cargo/config.toml`).
- **Fully air-gapped Docker image** — `deploy/docker/Dockerfile.airgap` with
  sha256-pinned base, `pip install --no-index --find-links /wheels`, vendored
  wheel workflow (`scripts/vendor_wheels.sh`), and `make docker-airgap`.

**Healthcare & Life Sciences (Domain 2)**
- GxP Installation/Operational Qualification (IQ/OQ) protocols with JSON evidence
  artifacts (`tools/qualification/iq_checks.py`, `oq_checks.py`).

**Industrial Automation & OT (Domain 3)**
- Real-time scheduling via `sched_setscheduler` (FIFO/RR/DEADLINE)
  (`aegis/core/rt_scheduler.py`).
- CPU affinity pinning via `sched_setaffinity` (`aegis/core/cpu_affinity.py`).
- Gossip-protocol WAL synchronization for disconnected edge nodes
  (`aegis/core/gossip_wal_sync.py`).
- CRDT audit-node ordering with vector clocks for deterministic distributed
  ordering (`aegis/core/crdt_ordering.py`).

**Enterprise Hyperscale & HA (Domain 4)**
- Raft consensus state machine (Ongaro & Ousterhout 2014) — leader election,
  log replication, SHA-256 entry-hash tamper detection (`aegis/core/raft_consensus.py`).
- Split-brain prevention via monotonic fencing tokens (Kleppmann 2016),
  gating every WAL write (`aegis/core/split_brain.py`).
- Kubernetes operator — `AegisProxy` CRD + kopf controller
  (`deploy/k8s/aegis-operator/`).

**Advanced Forensics & WAF (Domain 5)**
- Semantic similarity clustering of jailbreak families (SimHash + Hamming)
  (`aegis/core/semantic_sim_clustering.py`).
- Token-split reassembly WAF detector for boundary-split attack patterns
  (`aegis/core/token_split_detector.py`).
- Court-ready forensic PDF report with SHA-256 seal, no external PDF dependency
  (`aegis/core/forensic_pdf_report.py`).
- Anonymized threat-intelligence sharing with STIX 2.1 indicator export
  (`aegis/core/ti_sharing.py`).

**Tooling & Benchmarks**
- New `benchmarks/bench_crypto_audit.py` — measures HMAC signing, durable
  `commit_forensic()`, and `verify_integrity()` throughput (documented as
  Claim 4 in `docs/BENCHMARKS.md`).

### Changed

- Bumped version to 2.4.1 across `pyproject.toml`, `aegis`, `aegis_server`,
  Docker images, README, and deployment guide.
- README test evidence and badges refreshed to 4,575 passing tests.

### Fixed

- **Version drift:** `aegis_server.__version__` and the standard
  `deploy/docker/Dockerfile` were stale at 2.3.0; the `aegis_server` `/health`
  and `/ready` endpoints now report the correct release version.
- **Forensic tool environment bug:** `tools/forensic/forensic_checks.py` invoked
  `cargo test` with an empty environment (no `PATH`), which prevented the Rust
  toolchain from resolving; it now inherits the process environment.
- Resolved 30 lint findings across recently added consensus, qualification, and
  test modules (import ordering, unused imports, `StrEnum` migration, ambiguous
  identifiers); full repository is now `ruff` lint- and format-clean.
- Skipped a flaky concurrent-load scheduling-jitter test on shared CI runners
  (`tests/test_determinism.py`), which require dedicated real-time hosts.

### Security

- `aegis_server.crypto` previously imported `hvac` eagerly at package level,
  breaking the HMAC-only compliance-export path on installs without the optional
  `vault` extra; `VaultSigner` is now lazy-imported. (Carried from 2.4.0.)

## [2.4.0] - 2026-06-21

### Added

- Broad roadmap expansion across Defense, Healthcare, Industrial, Enterprise,
  and Forensics domains (SCIM 2.0, RBAC/ABAC zero-trust, LDAP/AD, WORM ledger,
  RAG injection scanning, SLO burn-rate alerting, DFIR export formats, and more).

### Fixed

- `aegis_server.crypto` eagerly imported `hvac` at package level, breaking the
  HMAC-only compliance export path on installs without the optional `vault`
  extra; `VaultSigner` is now lazy-imported. *(Severity: Low)*

## [2.3.0] - 2026-06

### Fixed

- mTLS settings were defined in `AegisSettings` but never applied to the uvicorn
  listener or the upstream `httpx` client. *(Severity: High)*
- `ResponseAnalyzer` thresholds were hardcoded, ignoring `AegisSettings`;
  alerting could not be tuned at runtime. *(Severity: Medium)*

## [2.2.0] - 2026-05

### Fixed

- Audit chain signing key was derived from the first sorted API key; unannounced
  rotation silently invalidated the chain. *(Severity: High)*
- `/docs` and `/redoc` were exposed unconditionally in all deployment modes.
  *(Severity: Medium)*
- `prev_hash` always pointed to the genesis node due to a wrong `ORDER BY`
  direction in `list_nodes()`. *(Severity: Critical)*
- Concurrent `BackgroundTask` writes could fork the audit chain (no chain lock).
  *(Severity: Critical)*

[2.4.1]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.4.1
[2.4.0]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.4.0
[2.3.0]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.3.0
[2.2.0]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.2.0
