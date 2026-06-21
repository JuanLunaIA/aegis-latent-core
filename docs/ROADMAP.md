<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Definitive Technical Roadmap

**Principal Systems Architect · Defense-Grade DevSecOps · Global Compliance Officer**
**Scope:** FedRAMP High · DoD IL5/IL6 · HIPAA · GxP · IEC 62443 · ISO 27001 · SOC 2 Type II

This document is the **single source of truth for engineering progress**. Every
future change should advance one or more checklist items below. The rules are
strict:

- `[x]` — feature is **fully implemented and tested** in the current codebase.
- `[ ]` — **not yet implemented** (stub-only, partial, or absent).

When an item is completed, flip its box to `[x]` **in the same pull request that
implements it**, add or update the test that proves it, and update the
[Summary Scorecard](#summary-scorecard) counts at the bottom of this file. Do not
mark an item `[x]` on the basis of a stub, a docstring claim, or a benchmark that
is not committed to `docs/BENCHMARKS.md`.

> **Last verified against codebase:** 2026-06-21 (tests: 1396 passed, 1 skipped, 95.08% coverage).

---

## Domain 1 — Defense & Government Compliance Tier
### FedRAMP High · DoD Impact Level 5/6 · NIST SP 800-53 Rev 5 · CNSSP-15

#### 1.1 Cryptographic Baseline (NIST FIPS 140-3 / CNSSP-15)

- [x] ML-DSA-65 (FIPS 204) post-quantum signing per audit node via `pqcrypto-mldsa` + `zeroize`
- [x] HMAC-SHA256 (32-byte key from `AEGIS_SIGNING_KEY`) as classical signing baseline
- [x] BLAKE3 SIMD hashing in Rust extension (audit chain integrity, ~4 GB/s)
- [x] SHA-256 tamper-evident hash chain: `node_hash[i] = SHA256(prev_hash ‖ state_id ‖ timestamp ‖ entropy ‖ tenant_id ‖ merkle_root ‖ signature ‖ request_hash ‖ response_hash)`
- [x] `zeroize` derive on Rust signing key structs (memory scrubbing on drop)
- [x] HSM/PKCS#11 signing integration (e.g., `python-pkcs11`, `opensc`, Thales Luna / AWS CloudHSM): `aegis/core/hsm.py` implements `HSMSigningBackend` with RSA-PSS and ECDSA-SHA256; graceful fallback when library absent; integrated into `CryptographicAuditLedger` signing priority chain
- [ ] FIPS 140-3 Level 3 validated module boundary (currently uses upstream Rust crates, not a validated boundary)
- [ ] NSA Suite B / CNSA 2.0 algorithm negotiation (P-384 ECDH, AES-256-GCM, SHA-384 where Suite B mandated)
- [ ] Kyber-1024 (FIPS 203 ML-KEM) key encapsulation for session bootstrap
- [ ] Cross-domain solution (CDS) guard integration for classified ↔ unclassified boundary enforcement

#### 1.2 Access Control & Identity (NIST AC-2, AC-3, IA-2, IA-5)

- [x] Bearer token API key authentication (`AEGIS_API_KEYS`, header `Authorization: Bearer …`)
- [x] `auth_disabled=True` gated behind `debug_mode=True` (prevents production bypass)
- [x] Per-tenant isolation via `tenant_id` in every audit node
- [x] Vault/AppRole secret management integration (`hvac>=2.1.0`)
- [x] mTLS client certificate authentication with CAC/PIV card (DoD Common Access Card) via PKCS#11 slot
- [x] LDAP/Active Directory integration for multi-factor identity assertion (`aegis/auth/ldap_auth.py`: `LDAPAuthenticator` with service-bind → user-lookup → user-bind → group-assertion flow; AD nested-group OID `1.2.840.113556.1.4.1941` + RFC 2307 group search; RFC 4515 LDAP-injection escaping; `ldaps://`/StartTLS with CA bundle verification; `AEGIS_LDAP_*` config fields; `ldap3` optional dep; `pytest tests/test_ldap_auth.py` — 42 tests, fully mocked, no live directory)
- [ ] Role-Based Access Control (RBAC) with NIST SP 800-207 Zero Trust attribute evaluation
- [ ] Attribute-Based Access Control (ABAC) for IL5/IL6 data compartmentalization
- [ ] SCIM 2.0 provisioning/deprovisioning lifecycle
- [ ] Hardware-bound session tokens (TPM 2.0 attestation-sealed)

#### 1.3 Air-Gap & Disconnected Operations

- [x] Offline WAL persistence: JSONL WAL (0o600, fsync) survives network loss; reconstructed on startup
- [x] Rust mmap WAL with CRC32 framing (integrity without connectivity)
- [x] All provider adapters configurable to local endpoints (vLLM, Ollama)
- [ ] Fully air-gapped Docker image (no external registry pulls; all layers vendored)
- [ ] OCSP stapling / CRL distribution point hosted in enclave network (no public CA connectivity)
- [ ] Offline license validation (no phone-home for commercial license enforcement)
- [ ] Air-gapped signature verification chain (pinned root CA bundle, no runtime CA fetch)
- [ ] Classified-data cryptographic blocking: pattern-match against SCI/SAP markers pre-forwarding

#### 1.4 Audit & Non-Repudiation (NIST AU-2, AU-9, AU-10)

- [x] Merkle Mountain Range (MMR) with O(log N) leaf insertion, inclusion proofs, consistency proofs
- [x] `GET /v1/audit/integrity` — full chain verification endpoint
- [x] `GET /v1/audit/nodes/{hash}` — individual node retrieval
- [x] Background forensic commits dispatched after response return (zero client-path latency)
- [x] Sealed compliance export bundles (`chain_hash` + `bundle_signature` + `signer_scheme` + `integrity=True/False`)
- [x] Bundles re-verifiable offline without running proxy
- [ ] Common Criteria EAL4+ Security Target (ST) and Protection Profile (PP) documentation artifacts
- [ ] Independent Evaluation Facility (ITSEF) test evidence package
- [ ] STIG (Security Technical Implementation Guide) hardening checklist and compliance scan results
- [ ] DoD-DISA APL (Approved Products List) submission package
- [ ] Time-stamping authority (RFC 3161 TSA) integration for legally admissible timestamp proofs
- [ ] Classified audit node encryption: AES-256-GCM envelope per node for IL6 data-at-rest

#### 1.5 Runtime Hardening

- [x] Seccomp BPF syscall allowlist (Linux): `clone`/`clone3` forbidden post-startup; `execve`, `ptrace`, `mount`, `reboot` permanently blocked
- [x] Seccomp applied LAST in lifespan after Rust tokio worker pool warmup
- [x] Graceful seccomp fallback in non-Linux sandboxes (CI, macOS dev)
- [ ] Linux Security Module (LSM) AppArmor profile or SELinux type enforcement policy
- [ ] `PR_SET_NO_NEW_PRIVS` + `PR_SET_DUMPABLE=0` prctl flags on startup
- [ ] AMD SEV-SNP or Intel TDX confidential VM attestation (memory encryption + remote attestation quote)
- [ ] Intel SGX enclave for signing key material isolation (`sgx-sdk` or `Enarx`)
- [ ] Kernel lockdown mode compatibility (`LOCK_INTEGRITY` or `LOCK_CONFIDENTIALITY`)
- [ ] cgroups v2 memory + CPU quotas enforced at process level (not just container level)
- [ ] RELRO (full), stack canary, PIE, FORTIFY_SOURCE=3 enforced in Rust build profile

---

## Domain 2 — Healthcare, Bio-Pharma & Life Sciences Tier
### HIPAA Security Rule · HITECH · 21 CFR Part 11 · GxP (GMP/GLP/GCP) · HiTRUST CSF · ISO 13485

#### 2.1 PHI/PII Protection (HIPAA §164.312, NIST SP 800-188)

- [x] `tenant_id` SHA-256 prefix pseudonymization (first 8 hex chars stored)
- [x] WAL stored at 0o600 (owner-only), audit payload treated as sensitive at rest
- [x] Sealed compliance bundle with `chain_hash` for chain-of-custody assertions
- [x] Real-time PHI de-identification on the hot request/response path (NIST SP 800-188 Safe Harbor method): regex engine covering 18 HIPAA Safe Harbor identifier categories (name, DOB, SSN, MRN, phone, email, URL, IP address, ZIP, VIN, device ID, NPI, health plan ID, license, biometric references, etc.). Enabled via `AEGIS_PHI_DEIDENTIFY=true`. Scrubs request messages before forwarding and response content before returning. (`aegis/core/phi_deidentifier.py`; `pytest tests/test_phi_deidentifier.py`)
- [x] PHI scrubbing confirmation field per audit node (`phi_scrubbed: bool`, `scrub_method: str`)
- [x] Differential privacy noise injection for aggregate analytics queries (`epsilon`, `delta` parameters)
- [x] Field-level encryption for PHI within audit node `payload` bytes (AES-256-GCM, per-tenant DEK)
- [x] De-identification audit trail: which entities were scrubbed, confidence scores, scrub timestamps
- [x] HIPAA minimum-necessary access enforcement per API key scope (`aegis/auth/scopes.py`: `ScopedKeyRegistry`, `parse_scope_config()`, `ScopeViolationError`; 4 scope constants; constant-time key validation; `AEGIS_API_KEY_SCOPES` config field; `pytest tests/test_api_key_scopes.py` — 45 tests)

#### 2.2 Clinical Audit Trail (21 CFR Part 11, EU Annex 11)

- [x] Immutable append-only audit chain with tamper detection via `verify_integrity()`
- [x] Per-node `timestamp` (float, UTC) and `state_id` (UUID-based) for chronological ordering
- [x] Hash chain linkage prevents retroactive insertion
- [x] 21 CFR Part 11 compliant electronic signature: human-readable meaning annotation ("approved", "reviewed", "authored"), printed name + date in signature manifest
- [ ] Audit trail lock-out: once a node is sealed it cannot be deleted (WORM enforcement at storage layer)
- [ ] `audit_trail_version` schema field for migration traceability (Annex 11 §4.8)
- [ ] System clock integrity assertion: NTP sync status logged at startup + per-node clock drift check
- [ ] Audit viewer UI with filter by tenant, time range, event type (required for 21 CFR Part 11 retrieval)
- [x] Backup and restore with integrity re-verification (Annex 11 §7.1): `WALBackupManager` in `aegis/core/wal_backup.py` — timestamped backup snapshots with manifest, integrity-verified copy before completing, safe restore with pre-restore backup and post-restore verification; 19 tests

#### 2.3 GxP Validation & IQ/OQ/PQ

- [ ] Installation Qualification (IQ) protocol document and evidence artifacts
- [ ] Operational Qualification (OQ) test protocol: automated test scripts producing PDF evidence
- [ ] Performance Qualification (PQ) protocol: production-representative load test with sign-off
- [ ] Change control integration: version-gated deployment requiring approved change record
- [ ] Traceability matrix: requirement → design → test → evidence (RTM) for each GxP control
- [ ] Vendor qualification package (VQP) for GxP regulated customers

#### 2.4 Domain-Specific Anomaly Detection

- [x] Shannon entropy + KL/JS divergence per-token (general statistical anomaly detection)
- [x] WAF with 23 critical + 11 soft patterns (prompt injection, jailbreak)
- [ ] ICD-11 / SNOMED-CT ontology-aware anomaly detection: flag responses containing clinical codes mismatched to the request context
- [ ] Dosage hallucination detection: numeric range check for drug dosage claims against reference database (RxNorm, NLM DailyMed)
- [ ] PII confidence scoring per response (entity recognition confidence threshold → block/flag/log)
- [ ] Adverse event (AE) keyword detection aligned to MedDRA preferred terms
- [ ] De-novo clinical claim detection: block generation of novel clinical trial results without citation

---

## Domain 3 — Industrial Automation & OT Tier
### IEC 62443-3-3 · NERC CIP · IEC 61511 (SIL) · NIST SP 800-82 Rev 3

#### 3.1 Edge & Embedded Deployment

- [x] Pure-Python fallbacks for all Rust tiers (enables deployment without native compilation)
- [x] `aarch64-unknown-linux-gnu` supported (Rust cross-compilation possible via cargo cross)
- [ ] Pre-built `aarch64-unknown-linux-musl` binary wheels (static musl libc, zero glibc dependency)
- [ ] `riscv64gc-unknown-linux-gnu` Rust target support (RISC-V edge AI accelerators: SiFive P670, Esperanto ET-SoC-1)
- [ ] `armv7-unknown-linux-musleabihf` target for ARM Cortex-A class PLCs
- [ ] Embedded profile: compile-time feature flags to strip Prometheus, OpenTelemetry, Vault, compliance exporter (~60% binary size reduction)
- [ ] Firmware signing of the Rust extension module (Secure Boot chain: UEFI → shim → kernel → module)
- [ ] Read-only rootfs operation: all writable state (WAL, logs) directed to tmpfs or external NFS mount

#### 3.2 Deterministic Latency (IEC 62443 SL-3, SIL-2)

- [x] Background forensic path: asyncio.create_task() dispatched after `return JSONResponse(...)` — audit never blocks response
- [x] Scheduling overhead p50=2.43µs, p99=6.78µs (measured 2026-06-20, n=5,000)
- [x] End-to-end proxy p50=0.300ms, p99=0.491ms (measured with mock upstream, n=2,000)
- [ ] Deterministic <50µs p99 overhead guarantee with real upstream (currently 0.491ms p99 includes mock network round-trip; no real upstream guarantee stated)
- [ ] Real-time scheduling: `SCHED_FIFO` or `SCHED_DEADLINE` for Rust forwarder thread pool
- [ ] CPU pinning (`taskset` / `cpuset` cgroup) for hot-path Rust threads to isolated cores
- [ ] NUMA-aware memory allocation (`libnuma`) for multi-socket OT servers
- [ ] Jitter histogram: p999 and p9999 latency tracked and alarmed (not just p99)
- [ ] Determinism test: latency variance must be <10µs σ under synthetic load (no such test exists)
- [ ] Interrupt coalescing configuration guide for NIC offload (DPDK / XDP path)

#### 3.3 Offline-First & Mesh WAL Sync

- [x] Local WAL (JSONL + fsync) survives connectivity loss; replays on reconnect
- [x] WAL reconstructed on startup via `_load_from_wal()`
- [ ] Gossip-based WAL synchronization between edge nodes (e.g., `memberlist` / `SWIM` protocol in Rust)
- [ ] Conflict-free replicated data type (CRDT) for distributed audit node ordering without a central coordinator
- [ ] Offline-first merge: deterministic conflict resolution when two edge nodes have diverged WALs
- [x] WAL segment rotation & archival: size-bounded active WAL rotates into immutable, owner-only (0o600) archived segments (`<wal_path>.NNNNNN`); the full chain is replayed across all segments on startup and rotation never drops nodes. Configurable via `AEGIS_MAX_WAL_BYTES` (`aegis/core/crypto_audit.py`; `pytest tests/test_wal_rotation.py`)
- [ ] Intermittent-connectivity mode: WAL queues indefinitely; backpressure signals upstream when queue depth exceeds threshold

#### 3.4 OT Network Isolation

- [x] Seccomp BPF: `ptrace`, `mount`, `reboot` blocked permanently
- [x] mTLS configurable CA bundle + client cert
- [ ] MODBUS/DNP3/OPC-UA protocol parser to detect SCADA command injection in LLM-suggested outputs
- [ ] Air-gapped network zone enforcement: configuration option to block all outbound connections except configured upstream (no current egress firewall at application layer)
- [ ] DMZ-mode: proxy accepts connections only from configured source IP allowlist
- [ ] IEC 62443 Zone and Conduit model documentation for customer network segmentation guidance

---

## Domain 4 — Enterprise Hyperscale & High Availability Tier
### 99.999% SLA · Multi-Region · Zero-Downtime Deploy · ZK Audit Proofs

#### 4.1 Distributed Consensus & WAL Replication

- [x] Redis GCRA rate limiting (external Redis, survives single-instance failure with Redis Cluster/Sentinel)
- [x] Redis-backed session state (configurable)
- [ ] Raft consensus for replicated WAL (e.g., `openraft` crate): leader election, log replication, snapshot installation
- [ ] Multi-region WAL replication with configurable consistency level (strong / eventual / quorum)
- [ ] WAL segment replication lag metric: `aegis_wal_replication_lag_bytes` in Prometheus
- [ ] Automatic leader failover with <30s RTO (Recovery Time Objective)
- [ ] Split-brain prevention: fencing tokens or lease-based locking before WAL writes on network partition
- [ ] Active-active proxy deployment: consistent hashing for tenant affinity, WAL dedup by `state_id`

#### 4.2 Zero-Knowledge Audit Proofs

- [x] Merkle Mountain Range inclusion proofs (cryptographic, not zero-knowledge)
- [x] Consistency proofs between two MMR states
- [ ] ZK-SNARK (Groth16 or PLONK) proof of audit node inclusion without revealing node content (privacy-preserving audit for regulated data)
- [ ] ZK-STARK proof of hash chain validity (post-quantum secure, no trusted setup)
- [ ] Proof generation: `aegis_server` endpoint `POST /v1/audit/zk-proof` returning serialized proof
- [ ] Proof verification: lightweight verifier deployable without full chain state (~1ms verify time target)
- [ ] Recursive SNARK: single proof covering N consecutive audit batches (amortized verification)
- [ ] On-chain proof anchoring: Ethereum / Hyperledger Fabric smart contract for public proof timestamps (currently `aegis/core/blockchain_anchor.py` is a roadmap stub)

#### 4.3 Confidential Computing

- [x] Seccomp BPF syscall isolation (process-level)
- [ ] AMD SEV-SNP: memory encryption at hypervisor boundary; remote attestation report via `sev-guest` ioctl
- [ ] Intel TDX: Trust Domain Extensions; TD Quote generation and verification
- [ ] Intel SGX: enclave for signing key material; `sgx_seal_data` / `sgx_unseal_data` for WAL encryption key
- [ ] Enarx / Gramine confidential container runtime compatibility
- [ ] Remote attestation API: `GET /v1/attestation/quote` returning hardware attestation evidence (not implemented)
- [ ] Attestation-gated key release: signing key only unsealed after TEE attestation verification

#### 4.4 High Availability Operations

- [x] Prometheus metrics (`prometheus-fastapi-instrumentator`, `prometheus-client`)
- [x] OpenTelemetry spans (`opentelemetry-sdk`, `opentelemetry-exporter-otlp-proto-grpc`)
- [x] `GET /health` and `GET /ready` liveness/readiness probes
- [x] Graceful shutdown: uvicorn lifespan context manager
- [ ] Kubernetes operator: `AegisProxy` CRD with automatic rolling update, canary traffic splitting, HPA by `aegis_request_latency_p99`
- [x] Helm chart with production-grade defaults (PodDisruptionBudget, topologySpreadConstraints, resource limits)
- [ ] Zero-downtime rolling deploy: WAL leader lease hand-off protocol during pod replacement
- [ ] Circuit breaker per upstream provider (e.g., `tenacity` with per-host breaker state in DashMap)
- [ ] Chaos engineering test suite: `pytest-chaos` or Toxiproxy integration for WAL write failure, Redis failure, upstream timeout scenarios
- [ ] SLO burn-rate alerting: PrometheusRule manifests for 1h/6h/24h/72h burn-rate windows

---

## Domain 5 — Advanced Forensics & Counter-Adversarial WAF Tier
### ISO/IEC 27037 · NIST SP 800-86 · Multi-Turn Behavioral Analysis · Evasion-Resistant Detection

#### 5.1 Multi-Turn & Session-Level Threat Detection

- [x] Per-request WAF scan (Rust Aho-Corasick SIMD + Python regex)
- [x] NFKC Unicode normalization + zero-width character strip (U+200B/C/D/E/F, U+00AD, U+FEFF)
- [x] Payload depth guard (>10 nesting levels → block)
- [x] Shannon entropy anomaly detection per token
- [x] KL/JS divergence from baseline distribution
- [x] Multi-turn behavioral jailbreak detection: `WAFSessionState` state machine in `aegis/core/waf_session.py` tracks cumulative WAF scores and consecutive soft-hit (crescendo) patterns across a configurable sliding window; integrated into both `/v1/chat/completions` and `/v1/completions` handlers
- [x] Conversation graph analysis: detect "crescendo" attack (gradual constraint erosion over session)
- [ ] Cross-session correlation: detect coordinated multi-account attacks sharing jailbreak templates
- [ ] Semantic similarity clustering: flag requests within cosine distance threshold of known jailbreak embeddings
- [ ] Adversarial suffix detection: gradient-based suffix patterns (GCG, AutoDAN) via fixed signature set
- [ ] Many-shot jailbreak detection: flag prompts with >N examples in few-shot context (configurable threshold, currently no count-based guard)
- [ ] Prompt injection in retrieved context: RAG-aware WAF that scans tool outputs and retrieved documents, not just user input

#### 5.2 Evasion-Resistant Pattern Matching

- [x] 23 critical + 11 soft WAF patterns
- [x] NFKC normalization (catches lookalike Unicode substitution attacks)
- [x] Zero-width character strip (catches invisible character injection)
- [x] Rust Aho-Corasick SIMD for throughput; Python regex as authoritative second pass
- [ ] Homoglyph normalization beyond NFKC: Cyrillic/Greek/Latin lookalike mapping table (e.g., `а` U+0430 → `a` U+0061)
- [ ] Base64/URL/HTML entity decode pipeline: iterative decode up to depth 5 before WAF scan
- [ ] Token-split reassembly attack detection: detect patterns split across token boundaries (requires tokenizer-aware scan)
- [ ] Language model-based semantic WAF: lightweight classifier (DistilBERT or FastText) as tertiary pass for novel jailbreaks not matching known patterns
- [ ] WAF pattern hot-reload: push new patterns without restart via inotify watch on pattern file
- [ ] WAF shadow mode: log would-be blocks without enforcing, for rule tuning without production risk
- [ ] Differential fuzzing harness: `hypothesis`-driven WAF bypass attempt generation (currently `aegis/core/fuzzing_harness.py` is a stub excluded from coverage)

#### 5.3 ISO/IEC 27037 Digital Forensic Export

- [x] Sealed compliance bundles: `chain_hash` + `bundle_signature` + `signer_scheme` + `integrity: bool`
- [x] Re-verifiable offline without running proxy
- [x] ML-DSA-65 or HMAC-SHA256 bundle signing (operator-selectable)
- [x] `POST /v1/enterprise/compliance/export` on aegis_server (separate process)
- [ ] ISO/IEC 27037 compliant evidence package format: chain of custody manifest, acquisition metadata (tool name, version, operator identity, acquisition timestamp), hash algorithm declaration, evidence integrity seal
- [ ] RFC 3161 trusted timestamp on each forensic bundle (time-stamping authority integration)
- [ ] DFIR-compatible export formats: PKCS#7 SignedData envelope; E01 (Expert Witness Format) encapsulation for block-level evidence
- [ ] Evidence acquisition log: who exported, when, from what IP, under what authorization (non-repudiable export audit trail)
- [ ] Legal admissibility attestation field: `legal_admissibility` enum (`Admissible` / `Conditional` / `Compromised`) currently set at chain level — needs per-bundle override with justification
- [ ] Court-ready PDF report generation: human-readable summary of audit chain, signing key metadata, integrity verification results, chain-of-custody narrative
- [ ] INTERPOL / ILEA forensic standards alignment documentation

#### 5.4 Threat Intelligence Integration

- [x] Static WAF pattern set (23 critical + 11 soft, embedded in source)
- [ ] STIX 2.1 / TAXII 2.1 threat feed ingestion: pull adversarial prompt indicators from sharing community
- [ ] MITRE ATLAS (Adversarial Threat Landscape for AI Systems) tactic mapping per WAF hit
- [ ] IOC (Indicator of Compromise) correlation: cross-reference tenant_id / request fingerprints against known threat actor TTPs
- [ ] Threat intelligence sharing: aegis_server endpoint to publish anonymized attack telemetry to ISAC feeds
- [ ] YARA rule engine integration: apply YARA rules to request/response payloads for malware-derived string detection

#### 5.5 Forensic Chain of Custody

- [x] Append-only WAL (no delete/overwrite path in audit node storage)
- [x] `verify_integrity()` detects gaps, hash mismatches, reordering
- [x] `legal_admissibility` field in audit chain health response
- [ ] Operator signature on chain seal: require HSM-signed attestation before bundle export
- [ ] Witness co-signing: two-of-three threshold signing for bundle export (multi-party authorization)
- [ ] Tamper-evident export log: every call to `POST /v1/enterprise/compliance/export` recorded in a separate non-repudiable log signed independently from the audit chain
- [ ] Custody transfer protocol: structured handoff record when evidence moves between custodians
- [ ] Long-term archival: evidence bundle format compatible with 30-year retention (algorithm agility for hash/signature migration)

---

## Summary Scorecard

| Domain | Implemented | Planned | Completion |
|---|---|---|---|
| Defense & Government | 20 | 28 | ~71% |
| Healthcare & Life Sciences | 16 | 24 | ~67% |
| Industrial Automation & OT | 11 | 21 | ~34% |
| Enterprise Hyperscale & HA | 10 | 23 | ~30% |
| Advanced Forensics & WAF | 16 | 26 | ~62% |
| **Total** | **73** | **122** | **~60%** |

**Current foundation strengths (production-ready today):** cryptographic audit
chain, ML-DSA-65 PQC signing, multi-provider proxy with zero-latency background
forensics, WAF with evasion-resistant normalization, sealed compliance export,
Redis-backed HA rate limiting, Prometheus + OTel observability, Vault secrets.

**Highest-leverage next items (unblocked, high ROI):**

1. Role-Based Access Control (RBAC) with NIST SP 800-207 Zero Trust attribute evaluation (Domain 1.2).
2. Attribute-Based Access Control (ABAC) for IL5/IL6 data compartmentalization (Domain 1.2).
3. Prompt injection resistance scoring — ML classifier for indirect injection (Domain 5.1).
4. SCIM 2.0 provisioning/deprovisioning lifecycle (Domain 1.2).

> **Done:** WAL segment rotation & archival (Domain 3.3) — completed 2026-06-20.
> **Done:** Real-time PHI de-identification, NIST SP 800-188 Safe Harbor (Domain 2.1) — completed 2026-06-20.
> **Done:** HSM/PKCS#11 signing integration with RSA-PSS and ECDSA-SHA256 (Domain 1.1) — completed 2026-06-20.
> **Done:** Multi-turn behavioral WAF session state machine (Domain 5.1) — completed 2026-06-20.
> **Done:** WAL backup and restore with integrity re-verification, Annex 11 §7.1 (Domain 2.2) — completed 2026-06-20.
> **Done:** PHI scrubbing confirmation field per audit node (`phi_scrubbed`, `scrub_method`) (Domain 2.1) — completed 2026-06-20.
> **Done:** Helm chart production-grade defaults: topologySpreadConstraints, HPA, ServiceAccount (Domain 4.4) — completed 2026-06-20.
> **Done:** 21 CFR Part 11 electronic signature annotations: signer_name, signature_meaning, Part 11 manifest export (Domain 2.2) — completed 2026-06-20.
> **Done:** mTLS CAC/PIV client certificate authentication — DoD CAC (DoDI 8520.02) and GSA PIV (NIST SP 800-73-4) policy OID verification, EDIPI and UUID identity extraction, `CACPIVAuth` middleware, `cac_piv_required` config flag (Domain 1.2) — completed 2026-06-20.
> **Done:** Conversation graph crescendo analysis — `ConversationGraphTracker` with monotone entropy decline detection and baseline drift detection; combined WAF+entropy signal; LRU session registry (Domain 5.1 follow-on) — completed 2026-06-20.
> **Done:** Differential privacy noise injection — `LaplaceDP` (Laplace mechanism, ε-DP) + `DPAggregator` for audit chain aggregate analytics; `/v1/audit/analytics/dp` endpoint with configurable epsilon; 24 tests (Domain 2.1) — completed 2026-06-20.
> **Done:** Field-level AES-256-GCM PHI encryption — `PHIPayloadEncryptor` with HKDF-SHA256 per-tenant DEK derivation, random nonce per encrypt, GCM authentication tag; `AEGIS_PHI_MASTER_KEY` config flag; 23 tests covering round-trip, tamper detection, tenant isolation (Domain 2.1) — completed 2026-06-20.
> **Done:** De-identification audit trail — `ScrubAuditRecord` with per-category hit counts, confidence scores (0.75–0.99 by category specificity), UTC scrub timestamp, JSON-serializable `to_dict()`; `scrub_with_audit()` on `PHIDeidentifier`; 17 tests (Domain 2.1) — completed 2026-06-20.
> **Done:** HIPAA minimum-necessary access enforcement per API key scope — `ScopedKeyRegistry` with constant-time key validation, per-key scope restrictions, `ScopeViolationError`, `parse_scope_config()` for `AEGIS_API_KEY_SCOPES` env var; `api_key_scopes` config field; 45 tests (Domain 2.1) — completed 2026-06-20.
> **Done:** LDAP/Active Directory multi-factor identity assertion — `LDAPAuthenticator` (service-bind → user-lookup → user-bind → group-assert), AD nested-group OID + RFC 2307 group search, RFC 4515 injection escaping, ldaps:///StartTLS with CA verification, `AEGIS_LDAP_*` config, `ldap3` optional dep; 42 tests (Domain 1.2) — completed 2026-06-21.

---

## How to update this file

1. Implement the feature on the development branch.
2. Add or update the test(s) that prove it (`pytest`, `cargo test`, or a
   benchmark committed to `docs/BENCHMARKS.md`).
3. Flip the checklist item from `[ ]` to `[x]` in the **same** pull request.
4. Recompute the affected row(s) and the **Total** in the Summary Scorecard.
5. Update the "Last verified against codebase" date at the top.
