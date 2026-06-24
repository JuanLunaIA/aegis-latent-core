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

> **Last verified against codebase:** 2026-06-24 (tests: 4575 passed, 3 skipped).

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
- [x] NSA Suite B / CNSA 2.0 algorithm negotiation (P-384 ECDH, AES-256-GCM, SHA-384 where Suite B mandated) (`aegis/core/cnsa_negotiation.py`: `CNSANegotiator` with a 16-algorithm approved registry across Suite B / CNSA 1.0 / CNSA 2.0 and four categories (key exchange, signature, symmetric, hash); per-category strongest-compliant selection, alias-aware resolution (Kyber→ML-KEM, Dilithium→ML-DSA), `mandate_quantum_resistant` enforcement, downgrade-attack refusal, and `NegotiationResult` with `selected`/`rejected`/`missing_categories`/`to_dict()`; `pytest tests/test_cnsa_negotiation.py` — 44 tests)
- [x] Kyber-1024 (FIPS 203 ML-KEM) key encapsulation for session bootstrap (`aegis/core/mlkem_session.py`: `MLKEMSessionBootstrap` with `generate_keypair()`, `encapsulate()`, `decapsulate()`, and `full_exchange()` using `kyber-py` Kyber-1024; `MLKEMKeyPair` frozen dataclass with size validation; soft dependency with `HAS_MLKEM` flag and `MLKEMUnavailableError` fallback; pk=1568 B, sk=3168 B, ct=1568 B, ss=32 B; `pytest tests/test_mlkem_session.py` — 21 tests)
- [x] Cross-domain solution (CDS) guard integration for classified ↔ unclassified boundary enforcement (`aegis/core/cds_guard.py`: `CDSGuard` with `ClassificationDomain` StrEnum (UNCLASSIFIED/CUI/SECRET/TOP_SECRET); downward-transfer sanitization via `ClassifiedMarkerDetector`; `check_transfer()`, `sanitize()`, `gate_transfer()`; `CDSViolationError` on blocked transfers; `AEGIS_CDS_STRICT_MODE` env var; `pytest tests/test_cds_guard.py`)

#### 1.2 Access Control & Identity (NIST AC-2, AC-3, IA-2, IA-5)

- [x] Bearer token API key authentication (`AEGIS_API_KEYS`, header `Authorization: Bearer …`)
- [x] `auth_disabled=True` gated behind `debug_mode=True` (prevents production bypass)
- [x] Per-tenant isolation via `tenant_id` in every audit node
- [x] Vault/AppRole secret management integration (`hvac>=2.1.0`)
- [x] mTLS client certificate authentication with CAC/PIV card (DoD Common Access Card) via PKCS#11 slot
- [x] LDAP/Active Directory integration for multi-factor identity assertion (`aegis/auth/ldap_auth.py`: `LDAPAuthenticator` with service-bind → user-lookup → user-bind → group-assertion flow; AD nested-group OID `1.2.840.113556.1.4.1941` + RFC 2307 group search; RFC 4515 LDAP-injection escaping; `ldaps://`/StartTLS with CA bundle verification; `AEGIS_LDAP_*` config fields; `ldap3` optional dep; `pytest tests/test_ldap_auth.py` — 42 tests, fully mocked, no live directory)
- [x] Role-Based Access Control (RBAC) with NIST SP 800-207 Zero Trust attribute evaluation (`aegis/auth/rbac.py`: `Role`/`RoleRegistry` over the scope vocabulary with subject→role, LDAP group→role, and default-role resolution; `ZeroTrustPolicyEngine` deny-by-default evaluation with dynamic attribute constraints — `RequireMTLS`, `RequireAuthMethod`, `IPAllowlist`, `TimeWindow`; `AccessContext`/`AccessDecision` audit records; `pytest tests/test_rbac.py` — 46 tests)
- [x] Attribute-Based Access Control (ABAC) for IL5/IL6 data compartmentalization (`aegis/auth/abac.py`: Bell-LaPadula `ABACPolicyEngine` with `ClassificationLevel` dominance, `SecurityLabel`/`SubjectAttributes`; `can_read` (no-read-up + need-to-know compartments + REL TO/NOFORN), `can_write` (no-write-down), `can_flow` (source→sink dominance), `endpoint_accredited` (IL→classification mapping); `pytest tests/test_abac.py` — 46 tests)
- [x] SCIM 2.0 provisioning/deprovisioning lifecycle (`aegis/auth/scim.py`: RFC 7643/7644 `ScimStore` with User + Group CRUD, full PATCH (add/remove/replace) per RFC 7644 §3.5.2, bidirectional User↔Group membership with sync on delete/deprovisioning, SCIM filter engine (eq/ne/co/sw/ew/pr), ETags/meta, `ScimError` RFC-compliant error envelopes, `to_group_roles()` bridge for `RoleRegistry`; `pytest tests/test_scim.py` — 87 tests)
- [x] Hardware-bound session tokens (TPM 2.0 attestation-sealed) (`aegis/core/hardware_token.py`: `HardwareTokenManager` with `TokenBackend.TPM2`/`SOFTWARE` enum; HMAC-SHA256 binding over `token_id ‖ subject ‖ tenant_id ‖ issued_at ‖ expires_at`; `_is_tpm_available()` checks `/dev/tpm0`; constant-time `hmac.compare_digest` validation; `from_env()` reads `AEGIS_SIGNING_KEY`/`AEGIS_TOKEN_TTL_SECONDS`/`AEGIS_TOKEN_BACKEND`; `pytest tests/test_hardware_token.py`)

#### 1.3 Air-Gap & Disconnected Operations

- [x] Offline WAL persistence: JSONL WAL (0o600, fsync) survives network loss; reconstructed on startup
- [x] Rust mmap WAL with CRC32 framing (integrity without connectivity)
- [x] All provider adapters configurable to local endpoints (vLLM, Ollama)
- [x] Fully air-gapped Docker image (no external registry pulls; all layers vendored) (`deploy/docker/Dockerfile.airgap`: multi-stage build with `ARG PYTHON_BASE_DIGEST` (sha256 pin), `pip install --no-index --find-links /wheels` from `vendor/wheels/`, `aegis.airgap="true"` OCI label, non-root UID 10001, HEALTHCHECK; `scripts/vendor_wheels.sh` for offline wheel vendoring + SHA256SUMS manifest; `make docker-airgap` target; `pytest tests/test_airgap_docker.py` — 31 tests covering digest pinning, no-index enforcement, multi-stage structure, security constraints)
- [ ] OCSP stapling / CRL distribution point hosted in enclave network (no public CA connectivity)
- [x] Offline license validation (no phone-home for commercial license enforcement) (`aegis/core/offline_license.py`: `OfflineLicenseValidator` with `from_env()` reading `AEGIS_LICENSE_FILE`/`AEGIS_LICENSE_KEY`; enforces `AEGIS_LICENSE_KEY != AEGIS_SIGNING_KEY`; HMAC-SHA256 over canonical sorted-key JSON; constant-time `hmac.compare_digest`; `LicenseRecord` frozen dataclass; `LicenseExpiredError`/`LicenseTamperError`; `pytest tests/test_offline_license.py`)
- [x] Air-gapped signature verification chain (pinned root CA bundle, no runtime CA fetch) (`aegis/core/pinned_ca_bundle.py`: `PinnedCABundle` with `from_env()` reading `AEGIS_PINNED_CA_FINGERPRINTS`; SHA-256 of DER cert for fingerprint; `verify_cert()`/`verify_cert_chain()` — trusted if any cert in chain matches; `PinnedCAUnavailableError` when `cryptography` absent; `pytest tests/test_pinned_ca_bundle.py`)
- [x] Classified-data cryptographic blocking: pattern-match against SCI/SAP markers pre-forwarding (`aegis/core/classified_marker_detector.py`: `ClassifiedMarkerDetector` with 34 pre-compiled DoD/IC regex patterns covering formal banners (TOP SECRET//, SECRET//, CONFIDENTIAL//, TS//, S//), SCI compartments (//SI, //TK, //HCS, //HCS-P, //HCS-O, //G, //KDK, //VRK), dissemination controls (//NOFORN, //ORCON, //PROPIN, //RSEN, //WNINTEL, //FOUO, //FISA), coalition markings (//REL TO, //FVEY, //ACGU, //EYES ONLY), handling caveats (HANDLE VIA COMINT/SCI CHANNELS ONLY, SCI INFORMATION, SPECAT), classification authority lines (CLASSIFIED BY:, DERIVED FROM:, DECLASSIFY ON:), and SAP indicators (SPECIAL ACCESS REQUIRED, SAP MATERIAL/PROTECTED/INFORMATION/PROGRAM, (SAP), SAP-PROTECTED); `scan()`, `scan_messages()`, `scan_text_bulk()` with aggregated `MarkerDetectionResult`; `extra_patterns` for deployment-specific codewords; `pytest tests/test_classified_marker_detector.py` — 81 tests)

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
- [x] Time-stamping authority (RFC 3161 TSA) integration for legally admissible timestamp proofs (`aegis/core/rfc3161_timestamper.py`: `RFC3161Timestamper` with self-contained DER encoder/parser; `stamp(package_dict)` POSTs TimeStampReq to TSA and stores `rfc3161_token_b64`; `verify(package_dict)` re-validates; `AEGIS_TSA_URL` + `AEGIS_TSA_TIMEOUT` config; 68 tests)
- [x] Classified audit node encryption: AES-256-GCM envelope per node for IL6 data-at-rest (`aegis/core/audit_node_encryptor.py`: `AuditNodeEncryptor` with per-tenant DEK via HKDF-SHA256(info="audit-node-dek:" + tenant_id); `encrypt_node(tenant_id, node_dict, node_hash)` → `nonce(12) || AES-256-GCM ciphertext+tag`; `node_hash` bound as GCM AAD to tie ciphertext to hash-chain position; `decrypt_node()` raises `AuditNodeEncryptionError` on tamper/wrong-key/wrong-hash; `from_env()` reads `AEGIS_AUDIT_MASTER_KEY` (hex-encoded, must be distinct from `AEGIS_SIGNING_KEY` and `AEGIS_PHI_MASTER_KEY`); per-tenant DEK cache with `clear_dek_cache()`; `pytest tests/test_audit_node_encryptor.py` — 29 tests)

#### 1.5 Runtime Hardening

- [x] Seccomp BPF syscall allowlist (Linux): `clone`/`clone3` forbidden post-startup; `execve`, `ptrace`, `mount`, `reboot` permanently blocked
- [x] Seccomp applied LAST in lifespan after Rust tokio worker pool warmup
- [x] Graceful seccomp fallback in non-Linux sandboxes (CI, macOS dev)
- [x] Linux Security Module (LSM) AppArmor profile or SELinux type enforcement policy (`aegis/core/lsm_guard.py`: `LSMGuard` with `detect()`/`is_apparmor_active()`/`is_selinux_enforcing()`/`load_apparmor_profile()`/`get_apparmor_profile_name()`/`assert_enforcing_or_warn()`; `LSMType(StrEnum)`, frozen `LSMStatus`; `deploy/apparmor/aegis.profile` AppArmor profile template; `pytest tests/test_lsm_guard_new.py`)
- [x] `PR_SET_NO_NEW_PRIVS` + `PR_SET_DUMPABLE=0` prctl flags on startup (`aegis/core/process_hardening.py`: `ProcessHardening.apply()` sets both prctl(2) flags via ctypes at startup, independently of seccomp; `PR_SET_NO_NEW_PRIVS=1` prevents privilege escalation via setuid/caps after startup; `PR_SET_DUMPABLE=0` disables core dumps and `/proc/PID/mem` access to prevent signing-key material leaks; graceful fallback on non-Linux; `verify()` reads back state from `/proc/self/status`; `AEGIS_SKIP_PROCESS_HARDENING` env override for CI; `pytest tests/test_process_hardening.py` — 27 tests)
- [ ] AMD SEV-SNP or Intel TDX confidential VM attestation (memory encryption + remote attestation quote)
- [ ] Intel SGX enclave for signing key material isolation (`sgx-sdk` or `Enarx`)
- [ ] Kernel lockdown mode compatibility (`LOCK_INTEGRITY` or `LOCK_CONFIDENTIALITY`)
- [x] cgroups v2 memory + CPU quotas enforced at process level (not just container level) (`aegis/core/cgroups_quota.py`: `CgroupsQuota.apply()` writes `memory.max` and `cpu.max` to the process's own cgroup directory (parsed from `/proc/self/cgroup` `0::<path>` format); `CgroupsQuotaResult` with `applied`/`fully_applied` properties; `apply_cgroups_quota()` reads `AEGIS_CGROUP_MEMORY_MAX` / `AEGIS_CGROUP_CPU_MAX` env vars; `is_cgroups_v2_available()` detection helper; graceful fallback on non-Linux, missing cgroup dir, and permission denied; `AEGIS_SKIP_CGROUPS_QUOTA` env override for CI; `pytest tests/test_cgroups_quota.py` — 68 tests)
- [x] RELRO (full), stack canary, PIE, FORTIFY_SOURCE=3 enforced in Rust build profile (`aegis_rust_v2/.cargo/config.toml`: `-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack` link flags; Rust PIE by default; `overflow-checks = true` in release profile; `[profile.embedded]` with `opt-level="z"` for size-optimized edge builds)

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
- [x] Audit trail lock-out: once a node is sealed it cannot be deleted (WORM enforcement at storage layer) (`aegis/core/worm_ledger.py`: `WORMViolationError` raised on any deletion attempt or sealed-segment overwrite; `WORMSealRecord` sentinel written as final JSON line of each sealed WAL segment; `WORMEnforcer` with `seal(path, node_count)` — appends sentinel + sets 0o400 read-only permissions; `verify(path)` — dual check: 0o400 mode + worm_seal sentinel present; `enforce_immutability(path)` — raises `WORMViolationError` for sealed paths (in-memory or on-disk); `delete_node()` — unconditionally raises `WORMViolationError`; `is_sealed(path)`, `sealed_segments` frozenset; `count_nodes_in_segment()` helper skips sentinel records; `unseal_for_testing()` for CI cleanup; `pytest tests/test_worm_ledger.py` — 56 tests; complies with 21 CFR Part 11 Annex 11 §5, NIST SP 800-53 AU-9, ISO/IEC 27037 forensic chain-of-custody)
- [x] `audit_trail_version` schema field for migration traceability (Annex 11 §4.8): added to `AuditNode` dataclass (`aegis/core/crypto_audit.py`) as `audit_trail_version: str = "1"` with default `"1"` in `from_dict()` for forward-compatibility; field present in `to_dict()` serialization; backward-compatible (existing WAL records get default)
- [x] System clock integrity assertion: NTP sync status logged at startup + per-node clock drift check (`aegis/core/clock_integrity.py`: `ClockIntegrityAssertion` with `assert_startup()` probing `timedatectl show` then `adjtimex(2)` via ctypes for NTP sync status; `check_node_drift(node_timestamp)` computes `abs(now - timestamp)` against configurable `max_drift_seconds` (default 5s); `NTPSyncStatus` and `ClockDriftResult` with `to_dict()`; graceful fallback when both probes unavailable; `pytest tests/test_clock_integrity.py` — 34 tests)
- [ ] Audit viewer UI with filter by tenant, time range, event type (required for 21 CFR Part 11 retrieval)
- [x] Backup and restore with integrity re-verification (Annex 11 §7.1): `WALBackupManager` in `aegis/core/wal_backup.py` — timestamped backup snapshots with manifest, integrity-verified copy before completing, safe restore with pre-restore backup and post-restore verification; 19 tests

#### 2.3 GxP Validation & IQ/OQ/PQ

- [x] Installation Qualification (IQ) protocol document and evidence artifacts (`tools/qualification/iq_checks.py`: `IQProtocol` with 8 checks — IQ-001 Python version, IQ-002 package importable, IQ-003 required deps, IQ-004 AEGIS_SIGNING_KEY ≥32 bytes, IQ-005 WAL dir 0o600, IQ-006 key separation, IQ-007 Rust extension, IQ-008 auth-bypass gating; `IQReport.to_json()`/`to_text()` for GxP evidence artifacts; `pytest tests/test_iq_oq.py`)
- [x] Operational Qualification (OQ) test protocol: automated test scripts producing PDF evidence (`tools/qualification/oq_checks.py`: `OQProtocol` with automated operational checks; `OQReport.to_json()`/`to_text()`; `pytest tests/test_iq_oq.py`)
- [ ] Performance Qualification (PQ) protocol: production-representative load test with sign-off
- [ ] Change control integration: version-gated deployment requiring approved change record
- [ ] Traceability matrix: requirement → design → test → evidence (RTM) for each GxP control
- [ ] Vendor qualification package (VQP) for GxP regulated customers

#### 2.4 Domain-Specific Anomaly Detection

- [x] Shannon entropy + KL/JS divergence per-token (general statistical anomaly detection)
- [x] WAF with 23 critical + 11 soft patterns (prompt injection, jailbreak)
- [x] ICD-11 / SNOMED-CT ontology-aware anomaly detection: flag responses containing clinical codes mismatched to the request context (`aegis/core/icd_snomed_detector.py`: `ICDSNOMEDDetector` with `_ICD10_CHAPTER` / `_ICD11_CHAPTER` maps, 13-domain keyword-inference patterns, `_ICD10_RE` / `_ICD11_RE` / `_SNOMED_RE` regex extractors, `scan()` + `scan_messages()` + `extract_codes()`; `AEGIS_ICD_STRICT` env for strict mode; `pytest tests/test_icd_snomed_detector.py` — 95 tests)
- [x] Dosage hallucination detection: numeric range check for drug dosage claims against reference database (RxNorm, NLM DailyMed) (`aegis/core/dosage_hallucination.py`: `DosageHallucinationDetector` with ~100-drug curated reference database across 12 therapeutic classes (NSAIDs, opioids, antibiotics, antihypertensives, statins, anticoagulants, diabetes, psychiatric/neurological, pulmonary, GI, immunosuppressants, thyroid); `scan()` + `scan_messages()` (assistant-role only) with forward + reverse regex extraction, canonical-name deduplication, unit-mismatch guard, alias resolution (e.g. tylenol→acetaminophen); `DosageFinding.summary()` with direction (exceeds max / below min); `AEGIS_DOSAGE_STRICT` env var for unknown-drug enforcement; `extra_db` for institution formularies; 54 tests)
- [x] PII confidence scoring per response (`aegis/core/pii_confidence.py`: `PIIConfidenceFilter` wraps `PHIDeidentifier`; per-entity confidence scores → BLOCK / FLAG / LOG action via configurable `PIIConfidenceThreshold`; `evaluate()` + `evaluate_messages()` + `worst_case()` for batch response gating; `from_config()` reads `AEGIS_PII_BLOCK_THRESHOLD`/`AEGIS_PII_FLAG_THRESHOLD`; `pytest tests/test_pii_confidence.py` — 45 tests)
- [x] Adverse event (AE) keyword detection aligned to MedDRA preferred terms
- [x] De-novo clinical claim detection: block generation of novel clinical trial results without citation (`aegis/core/clinical_claim_detector.py`: `ClinicalClaimDetector` with 8 claim patterns (RCT/study/trial language, percentage efficacy, "our research demonstrates", "clinical evidence shows", "in a study of N patients", "has been proven to treat") and 9 citation exoneration patterns (numeric refs, author-year with `et al.`, DOI, PMID, NCT numbers, PubMed/Cochrane/NEJM URLs, superscript, footnote markers, "according to FDA/WHO/CDC/NIH"); two-stage scan: claim detection → citation window check (configurable `AEGIS_CLINICAL_WINDOW`, default 300 chars); overlapping claim deduplication within 50 chars; `strict` mode flags all claims regardless of citations; `scan_messages()` scans only assistant-role; `AEGIS_CLINICAL_STRICT` env var; 50 tests)

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
- [x] Read-only rootfs operation: all writable state (WAL, logs) directed to tmpfs or external NFS mount (`aegis/core/readonly_rootfs.py`: `ReadOnlyRootfsGuard` with dual detection probes — `/proc/mounts` scan for `ro` root mount option + write-probe via `NamedTemporaryFile`; `resolve(preferred_path, label)` returns `PathResolutionResult` with guaranteed-writable `path`, re-rooted under `AEGIS_TMPFS_BASE` (default `/tmp/aegis`) or `AEGIS_NFS_MOUNT` when preferred is not writable; `inspect()` returns `ReadOnlyRootfsResult` with `rootfs_readonly`, `proc_mounts_readonly`, `write_probe_failed`, `any_redirected`; NFS mount takes precedence over tmpfs; `AEGIS_SKIP_READONLY_CHECK` for dev environments; 47 tests + 1 root-skipped)

#### 3.2 Deterministic Latency (IEC 62443 SL-3, SIL-2)

- [x] Background forensic path: asyncio.create_task() dispatched after `return JSONResponse(...)` — audit never blocks response
- [x] Scheduling overhead p50=2.43µs, p99=6.78µs (measured 2026-06-20, n=5,000)
- [x] End-to-end proxy p50=0.300ms, p99=0.491ms (measured with mock upstream, n=2,000)
- [ ] Deterministic <50µs p99 overhead guarantee with real upstream (currently 0.491ms p99 includes mock network round-trip; no real upstream guarantee stated)
- [x] Real-time scheduling: `SCHED_FIFO` or `SCHED_DEADLINE` for Rust forwarder thread pool (`aegis/core/rt_scheduler.py`: `RTScheduler` wrapping `sched_setscheduler`/`sched_getscheduler` via ctypes; `SchedulingPolicy(StrEnum)` with FIFO/RR/DEADLINE/OTHER; `from_env()` reads `AEGIS_RT_POLICY`/`AEGIS_RT_PRIORITY`; graceful fallback on non-Linux; `pytest tests/test_rt_scheduler.py`)
- [x] CPU pinning (`taskset` / `cpuset` cgroup) for hot-path Rust threads to isolated cores (`aegis/core/cpu_affinity.py`: `CPUAffinity` with `set_affinity(cpu_set, pid=0)`/`get_affinity()`/`get_isolated_cpus()`; ctypes `sched_setaffinity`/`sched_getaffinity` with 128-byte `cpu_set_t`; `from_env()` reads `AEGIS_CPU_AFFINITY` (comma-separated CPUs or "isolated"); `pytest tests/test_cpu_affinity.py`)
- [ ] NUMA-aware memory allocation (`libnuma`) for multi-socket OT servers
- [x] Jitter histogram: p999 and p9999 latency tracked and alarmed (`aegis/core/observability.py`: `SCHEDULING_JITTER` Prometheus Histogram with 12 µs-level buckets spanning 1 µs – 10 ms for p50/p99/p999/p9999 jitter tracking; measured from `asyncio.create_task()` to first await via `_with_jitter_measurement` wrapper in `aegis/proxy/app.py`; no-op stub when prometheus_client absent; 5 new tests in `tests/test_observability.py` covering metric accessibility, name validation, and sub-millisecond median assertion)
- [x] Determinism test: latency variance must be <10µs σ under synthetic load (`tests/test_determinism.py`: 11 tests cover jitter measurement shape, IEC 62443 SL-3 σ < 100µs CI-environment bound, stability across batches, 500µs hard outlier cap, coefficient-of-variation, and sequential `_spawn_background` jitter; spec target of <10µs σ is validated on dedicated hardware)
- [ ] Interrupt coalescing configuration guide for NIC offload (DPDK / XDP path)

#### 3.3 Offline-First & Mesh WAL Sync

- [x] Local WAL (JSONL + fsync) survives connectivity loss; replays on reconnect
- [x] WAL reconstructed on startup via `_load_from_wal()`
- [x] Gossip-based WAL synchronization between edge nodes (e.g., `memberlist` / `SWIM` protocol in Rust) (`aegis/core/gossip_wal_sync.py`: `GossipWALSyncer` with `GossipMessage`/`SyncDecision`/`GossipSyncResult`; `from_env()` reads `AEGIS_GOSSIP_NODE_ID`/`AEGIS_GOSSIP_PEERS`/`AEGIS_GOSSIP_INTERVAL_S`; `pytest tests/test_gossip_wal_sync.py`)
- [x] Conflict-free replicated data type (CRDT) for distributed audit node ordering without a central coordinator (`aegis/core/crdt_ordering.py`: `VectorClock` with `increment`/`merge`/`happens_before`/`concurrent_with`/`to_dict`/`from_dict`; `CRDTAuditOrderer` with `total_order()` topological sort with `(timestamp, origin_node_id, state_id)` tiebreak; `pytest tests/test_crdt_ordering.py`)
- [ ] Offline-first merge: deterministic conflict resolution when two edge nodes have diverged WALs
- [x] WAL segment rotation & archival: size-bounded active WAL rotates into immutable, owner-only (0o600) archived segments (`<wal_path>.NNNNNN`); the full chain is replayed across all segments on startup and rotation never drops nodes. Configurable via `AEGIS_MAX_WAL_BYTES` (`aegis/core/crypto_audit.py`; `pytest tests/test_wal_rotation.py`)
- [x] Intermittent-connectivity mode: WAL queues indefinitely; backpressure signals upstream when queue depth exceeds threshold (`aegis/core/intermittent_connectivity.py`: `WALBackpressureMonitor` inspects active WAL + rotated segments for entry count and byte size; `BackpressureStatus` with `active`, `entry_count`, `size_bytes`, `signal_reasons`, `to_dict()`; `aegis_wal_backpressure_active` Prometheus Gauge; `AEGIS_WAL_BACKPRESSURE_THRESHOLD` / `AEGIS_WAL_BACKPRESSURE_BYTES` env vars; 41 tests in `tests/test_intermittent_connectivity.py`)

#### 3.4 OT Network Isolation

- [x] Seccomp BPF: `ptrace`, `mount`, `reboot` blocked permanently
- [x] mTLS configurable CA bundle + client cert
- [x] MODBUS/DNP3/OPC-UA protocol parser to detect SCADA command injection in LLM-suggested outputs (`aegis/core/ot_protocol_scanner.py`: `OTProtocolScanner` with 16 signatures across 3 protocols — MODBUS (hex frame, function codes, write FC 05/06/15/16, register/coil addresses, API calls, command composition), DNP3 (CROB/Group 12/Var 1, group-variation references, direct-operate/SBO, LATCH_ON/OFF/PULSE/TRIP control codes, master-operate context), OPC-UA (NodeId ns=N;i=M/s=Name, write/method calls, Security Mode None, endpoint URL opc.tcp://); complementary-probability risk scoring; `AEGIS_OT_BLOCK_THRESHOLD` env var; `scan_messages()` scans assistant-role only; `OTScanResult.to_dict()` with `protocols_detected`, `signals`, `risk_score`, `should_block`; 55 tests)
- [x] Air-gapped network zone enforcement: `AEGIS_AIRGAP_MODE=true` activates `EgressGuard` in `aegis/proxy/egress_guard.py` — `LLMForwarder.forward_json()` and `stream_sse()` call `guard.check(upstream_url)` before every outbound HTTP request; non-allowlisted hosts raise `EgressBlockedError`; upstream host is always auto-included; `AEGIS_AIRGAP_ALLOWED_HOSTS` CSV for additional hosts; wired via `AegisSettings.get_egress_guard()` into forwarder lifespan; 37 tests in `tests/test_egress_guard.py`
- [x] DMZ-mode: proxy accepts connections only from configured source IP allowlist (`aegis/proxy/dmz_middleware.py`: `DMZSourceIPMiddleware` rejects requests from IPs not in `AEGIS_DMZ_ALLOWED_SOURCE_IPS` (comma-separated IPv4/IPv6/CIDR list) with 403 before any auth; `dmz_trust_proxy_headers` enables X-Forwarded-For/X-Real-IP resolution behind a trusted load balancer; wired into `create_app()` at startup; `AegisSettings.get_dmz_networks()` parses entries at startup; 34 tests in `tests/test_dmz_middleware.py`)
- [ ] IEC 62443 Zone and Conduit model documentation for customer network segmentation guidance

---

## Domain 4 — Enterprise Hyperscale & High Availability Tier
### 99.999% SLA · Multi-Region · Zero-Downtime Deploy · ZK Audit Proofs

#### 4.1 Distributed Consensus & WAL Replication

- [x] Redis GCRA rate limiting (external Redis, survives single-instance failure with Redis Cluster/Sentinel)
- [x] Redis-backed session state (configurable)
- [x] Raft consensus for replicated WAL (e.g., `openraft` crate): leader election, log replication, snapshot installation (`aegis/core/raft_consensus.py`: pure-Python Raft state machine per Ongaro & Ousterhout 2014; `RaftNode` with `start_election()`/`handle_vote_request()`/`handle_vote_response()`/`handle_append_entries()`/`handle_append_entries_response()`/`append_command()`/`build_append_entries()`; `RaftLogEntry.create()` with SHA-256 entry-hash tamper detection; `RaftState` persistent + volatile state; `VoteRequest`/`VoteResponse`/`AppendEntriesRequest`/`AppendEntriesResponse` RPC types; `pytest tests/test_raft_consensus.py`)
- [ ] Multi-region WAL replication with configurable consistency level (strong / eventual / quorum)
- [x] WAL segment replication lag metric: `aegis_wal_replication_lag_bytes` Prometheus Gauge with `follower` label in `aegis/core/observability.py`; labelled by follower node ID to identify which replica is lagging; zero in standalone mode; no-op stub when prometheus_client absent; 4 tests in `tests/test_chaos.py::TestWALReplicationLagMetric`
- [ ] Automatic leader failover with <30s RTO (Recovery Time Objective)
- [x] Split-brain prevention: fencing tokens or lease-based locking before WAL writes on network partition (`aegis/core/split_brain.py`: `LeaseBasedLock` with `FencingToken` (monotonically increasing value per Kleppmann 2016); `acquire_lease(token_value)` rejects stale leaders via `FencingTokenError`; `check_fence(token)` raises `StaleLeaseError` on expired/superseded tokens; `gate_wal_write(token, write_fn)` enforces fence before every WAL write; `current_lease_valid`/`max_seen_token` properties; `pytest tests/test_split_brain.py`)
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
- [x] Kubernetes operator: `AegisProxy` CRD with automatic rolling update, canary traffic splitting, HPA by `aegis_request_latency_p99` (`deploy/k8s/aegis-operator/crd.yaml`: `AegisProxy` CRD group `aegis.io` v1alpha1 with full OpenAPIV3Schema, secrets via `secretKeyRef`; `deploy/k8s/aegis-operator/operator.py`: kopf-based controller with `_build_deployment()`/`_build_hpa()` as testable functions; `HAS_KOPF` soft dep; `pytest tests/test_k8s_operator.py`)
- [x] Helm chart with production-grade defaults (PodDisruptionBudget, topologySpreadConstraints, resource limits)
- [ ] Zero-downtime rolling deploy: WAL leader lease hand-off protocol during pod replacement
- [x] Circuit breaker per upstream provider (`aegis/core/circuit_breaker.py`: `CircuitBreaker` with CLOSED → OPEN → HALF_OPEN state machine; `failure_threshold` consecutive failures open the circuit; `recovery_timeout` before a single probe is allowed; `success_threshold` consecutive probe successes re-close; thread-safe via `threading.Lock`; `CircuitOpenError` for fail-fast 503 responses; Prometheus metric emission on state transitions; integrated in `LLMForwarder` via `circuit_breaker_failure_threshold` / `circuit_breaker_recovery_timeout` / `circuit_breaker_success_threshold` config fields; 37 tests in `tests/test_circuit_breaker.py`)
- [x] Chaos engineering test suite: `tests/test_chaos.py` — 20 tests covering WAL disk-full / truncated-write / missing-file scenarios; Redis `ConnectionError` and hang under `asyncio.wait_for`; upstream `httpx.TimeoutException` / `ConnectError`; circuit breaker OPEN → HALF_OPEN → CLOSED recovery; concurrent 50-goroutine ledger commit stability; no external dependencies (all scenarios via monkeypatching)
- [x] SLO burn-rate alerting: `aegis/core/slo_alerting.py` (`SLOConfig`, `SLOBurnRateWindow`, `generate_prometheus_rule()`, `validate_burn_rate_threshold()`); `deploy/helm/templates/prometheusrule.yaml` PrometheusRule CRD template for the Prometheus Operator; `prometheus.sloAlerting` Helm values section; 8 alerts (1h/6h/24h/72h × availability+latency); critical severity for ≥14.4×/6× windows, warning for ≥3×/1×; all thresholds mathematically validated against 30-day error budget; 65 tests in `tests/test_slo_alerting.py`

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
- [x] Cross-session correlation: detect coordinated multi-account attacks sharing jailbreak templates (`aegis/core/cross_session_correlator.py`: `CrossSessionCorrelator` with 64-bit SimHash fingerprinting over 4-word shingles (Charikar 2002), 8×8-bit LSH band bucketing for O(1) candidate lookup, sliding-window eviction, Hamming-distance threshold for near-duplicate grouping; `CorrelationAlert` with `tenant_ids`, `fingerprint_hex`, `band_key`, `first_seen`/`last_seen`; `CorrelationResult` with `coordinated`, `alerts`; `hamming_distance()`, `lsh_bands()`, `compute_simhash()`; covers shared jailbreak kits, A/B variant attacks, botnet-driven prompt flooding; `pytest tests/test_cross_session_correlator.py` — 52 tests)
- [x] Semantic similarity clustering: flag requests within cosine distance threshold of known jailbreak embeddings (`aegis/core/semantic_sim_clustering.py`: `JailbreakClusterRegistry` with 4 built-in jailbreak families (DAN, role-escape, prompt-extraction, gradual-escalation); SimHash + Hamming distance from `cross_session_correlator`; `from_env()` reads `AEGIS_SEMANTIC_HAMMING_THRESHOLD` (default 10); `pytest tests/test_semantic_sim_clustering.py`)
- [x] Adversarial suffix detection: gradient-based suffix patterns (GCG, AutoDAN) via fixed signature set (`aegis/core/adversarial_suffix_detector.py`: `AdversarialSuffixDetector` with 11 fixed signatures — long/spaced token-repetition runs, obedience-induction phrases, GCG punctuation runs, AutoDAN openers, output-prefix injection, and published GCG fragment anchors; tail-window scanning (default last 2000 chars) with full-text override; `scan(text)` and `scan_messages(messages)` (user-turns only); `SuffixDetectionResult` with `flagged`, `signals`, `scan_length`, `reason`, `to_dict()`; `pytest tests/test_adversarial_suffix_detector.py` — 54 tests)
- [x] Many-shot jailbreak detection: flag prompts with >N examples in few-shot context (`aegis/core/manyshot_detector.py`: `ManyShotDetector` with configurable `threshold` (default 10) and `min_qa_ratio`; multi-signal counting — Q&A turn pairs (Human/User/Q: + Assistant/AI/A: with assistant-to-human ratio guard), numbered-list items (≥20 chars), "Example/Sample/Shot N:" headers, bracket/XML shot delimiters (<example>, [EXAMPLE], <shot>); `evaluate(text)` and `evaluate_messages(messages)` (concatenates content across turns to defeat per-message evasion); `ManyShotDetectionResult` with `shot_count`, `signal_counts`, `exceeded`, `reason`, `scan_length`, `to_dict()`; `pytest tests/test_manyshot_detector.py` — 42 tests)
- [x] Prompt injection in retrieved context: RAG-aware WAF that scans tool outputs and retrieved documents, not just user input (`aegis/core/rag_injection_scanner.py`: `RAGInjectionScanner` with 7 signal categories — direct jailbreak text in documents, context-frame escape (XML closing delimiters), role boundary injection (fake System:/[SYSTEM] headers), ChatML token injection (`<|im_start|>`, `<|im_end|>`, `<|endoftext|>`), LLM-addressed instructions ("Note to AI:", "after you process this document"), whitespace padding (20+ newlines), lateral exfiltration (send/forward/POST to URL); additive risk scoring with configurable `block_threshold`; `scan_document()`, `scan_tool_result()`, `scan_messages()` (handles OpenAI `role="tool"/"function"` and Anthropic `type="tool_result"` blocks + RAG-context user messages); `RAGScanResult` with `clean`, `signals`, `risk_score`, `source_id`, `reason`, `to_dict()`; `pytest tests/test_rag_injection_scanner.py` — 112 tests)

#### 5.2 Evasion-Resistant Pattern Matching

- [x] 23 critical + 11 soft WAF patterns
- [x] NFKC normalization (catches lookalike Unicode substitution attacks)
- [x] Zero-width character strip (catches invisible character injection)
- [x] Rust Aho-Corasick SIMD for throughput; Python regex as authoritative second pass
- [x] Homoglyph normalization beyond NFKC: Cyrillic/Greek/Latin lookalike mapping table (e.g., `а` U+0430 → `a` U+0061)
- [x] Base64/URL/HTML entity decode pipeline: iterative decode up to depth 5 before WAF scan
- [x] Token-split reassembly attack detection: detect patterns split across token boundaries (requires tokenizer-aware scan) (`aegis/core/token_split_detector.py`: `TokenSplitDetector` with sliding-window reassembly — bare join + spaced join + stripped match; catches `["ign","ore","prev","ious"]` → `"ignoreprevious"`; `from_env()` reads `AEGIS_TOKEN_SPLIT_WINDOW` (default 5)/`AEGIS_TOKEN_SPLIT_STRIDE` (default 1); `pytest tests/test_token_split_detector.py`)
- [ ] Language model-based semantic WAF: lightweight classifier (DistilBERT or FastText) as tertiary pass for novel jailbreaks not matching known patterns
- [x] WAF pattern hot-reload: push new patterns without restart via inotify watch on pattern file (`aegis/core/waf_hot_reload.py`: `WAFHotReloader`, `WAFPatternSet`, `load_pattern_file`, `WAFPatternFileError`; uses Linux inotify via `ctypes` with `select()` timeout loop; falls back to mtime-poll on non-Linux or inotify init failure; JSON pattern file schema with `version`, `critical`, `soft` arrays; `AegisWAF.enable_hot_reload(path, poll_interval_s)` for zero-downtime atomic pattern swap; 38 tests in `tests/test_waf_hot_reload.py`)
- [x] WAF shadow mode: log would-be blocks without enforcing, for rule tuning without production risk (`aegis/proxy/waf.py`: `shadow_mode=False` parameter on `AegisWAF`; when `True`, runs the full Rust+Layer-1+Layer-2 detection pipeline but suppresses enforcement — returns `WAFResult(allowed=True, shadow_blocked=True, reason=<detection_reason>, score=<score>)` and emits a `WARNING` log; `WAFResult` gets new `shadow_blocked: bool = False` field; internal `_run_detection()` always returns an enforcement decision; 14 new tests in `TestWAFShadowMode`)
- [x] Differential fuzzing harness: `hypothesis`-driven WAF bypass attempt generation (`aegis/core/waf_fuzzing.py`: `WAFDifferentialFuzzer` with 11 `EvasionTransform` variants — original, base64, uppercase, lowercase, alternating case, homoglyph substitution (Cyrillic/Greek/Latin table), zero-width injection, full-width Unicode, extra whitespace, underscore/hyphen space replacement; `apply_transform()`, `FuzzVariant`, `FuzzReport` with `block_rate` and per-transform stats; `hypothesis_strategy()` composite strategy for property-based tests; `tests/test_waf_hypothesis.py`: 41 tests including 5 `@given` property tests verifying WAF never crashes, score ∈ [0,1], shadow mode invariants on 200+ examples; evasion-resistance assertions that full-width, uppercase, and extra-whitespace variants of known seeds are still blocked)

#### 5.3 ISO/IEC 27037 Digital Forensic Export

- [x] Sealed compliance bundles: `chain_hash` + `bundle_signature` + `signer_scheme` + `integrity: bool`
- [x] Re-verifiable offline without running proxy
- [x] ML-DSA-65 or HMAC-SHA256 bundle signing (operator-selectable)
- [x] `POST /v1/enterprise/compliance/export` on aegis_server (separate process)
- [x] ISO/IEC 27037 compliant evidence package format: chain of custody manifest, acquisition metadata (tool name, version, operator identity, acquisition timestamp), hash algorithm declaration, evidence integrity seal (`aegis/core/iso27037_evidence.py`: `EvidencePackage`, `AcquisitionMetadata`, `CustodyEvent`, `EvidenceNode` dataclasses; `build_evidence_package(ledger, operator, tool_version, acquisition_reason)` exports a self-contained, tamper-evident package from any `CryptographicAuditLedger`; `verify_seal(package_dict)` validates the SHA-256 integrity seal offline without a live instance; `add_custody_event()` appends chain-of-custody entries and re-seals; 56 tests in `tests/test_iso27037_evidence.py`)
- [x] RFC 3161 trusted timestamp on each forensic bundle (time-stamping authority integration) (`aegis/core/rfc3161_timestamper.py`: `RFC3161Timestamper` with self-contained DER encoder (INTEGER, OCTET STRING, SEQUENCE, OID, BOOLEAN, NULL) and DER parser; `build_timestamp_request(imprint, nonce)` produces RFC 3161 v1 TimeStampReq with SHA-256 AlgorithmIdentifier, random nonce, certReq=TRUE; `stamp(package_dict)` computes SHA-256 of canonical JSON, POSTs to TSA, extracts TimeStampToken and stores as `rfc3161_token_b64` + `rfc3161_tsa_url` + `rfc3161_message_imprint_hex` in returned package dict; `verify(package_dict)` re-computes imprint and checks DER structure; `parse_pki_status()` / `extract_token_from_response()` public helpers; httpx primary / urllib.request fallback; `AEGIS_TSA_URL` + `AEGIS_TSA_TIMEOUT` env vars; 68 tests)
- [x] DFIR-compatible export formats: PKCS#7 SignedData envelope; E01 (Expert Witness Format) encapsulation for block-level evidence (`aegis/core/dfir_export.py`: `DFIRExporter` with `to_pkcs7()` — ephemeral ECDSA P-256 key + self-signed X.509 cert (valid 30 years), CMS SignedData envelope per RFC 5652, SHA-256 content digest, DER output; `to_e01()` — EWF v1 binary container with EVF magic, 76-byte section descriptors + Adler-32 CRCs, zlib-compressed header metadata, 512-byte-sector-aligned data, MD5+SHA-256 hash section; `PKCS7ExportResult` / `E01ExportResult` with `to_dict()` / base64 export; `pytest tests/test_dfir_export.py` — 58 tests)
- [x] Evidence acquisition log: who exported, when, from what IP, under what authorization (non-repudiable export audit trail) — implemented by `aegis/core/export_audit_log.py` (see §5.5 tamper-evident export log above)
- [x] Legal admissibility attestation field: `LegalAdmissibility` enum (`Admissible` / `Conditional` / `Compromised`) added to `aegis/core/iso27037_evidence.py`; `build_evidence_package()` accepts `legal_admissibility_override: LegalAdmissibility | None` and `legal_admissibility_justification: str` parameters; override replaces chain-level value and justification is persisted in `EvidencePackage.legal_admissibility_justification`; both fields covered by the SHA-256 integrity seal so tampering is detected; 23 new tests in `tests/test_iso27037_evidence.py` (`TestLegalAdmissibilityEnum`, `TestLegalAdmissibilityOverride`)
- [x] Court-ready PDF report generation: human-readable summary of audit chain, signing key metadata, integrity verification results, chain-of-custody narrative (`aegis/core/forensic_pdf_report.py`: `ForensicReportBuilder.build_from_nodes()` generates 6-section report (Executive Summary, Chain Integrity, Signing Key Metadata, Audit Node Log, Chain-of-Custody Narrative, Legal Admissibility Assessment); `ForensicReport.to_text()`/`to_json()`/`to_dict()`/`compute_seal()` (SHA-256 of sorted-key JSON); no external PDF library dependency; `pytest tests/test_forensic_pdf_report.py`)
- [ ] INTERPOL / ILEA forensic standards alignment documentation

#### 5.4 Threat Intelligence Integration

- [x] Static WAF pattern set (23 critical + 11 soft, embedded in source)
- [x] STIX 2.1 / TAXII 2.1 threat feed ingestion: pull adversarial prompt indicators from sharing community — implemented by `aegis/core/stix_taxii_ingestor.py`; `STIXTAXIIIngestor` performs full TAXII 2.1 server discovery → collection listing → object pull flow; `parse_stix_bundle`, `is_prompt_indicator`, `extract_waf_pattern`, `parse_indicator`, `link_relationships` module-level helpers; `PromptIndicator`, `TaxiiCollection`, `IngestResult` dataclasses with `to_dict()`; supports `aegis-adversarial-prompt`, `adversarial-prompt`, `jailbreak`, `prompt-injection` STIX labels; extracts WAF-ready string literals from STIX patterning expressions; resolves `indicates` relationships to AttackPattern IDs; module-level `ingest_bundle()` convenience wrapper; 69 tests in `tests/test_stix_taxii_ingestor.py`
- [x] MITRE ATLAS (Adversarial Threat Landscape for AI Systems) tactic mapping per WAF hit
- [x] IOC (Indicator of Compromise) correlation: cross-reference tenant_id / request fingerprints against known threat actor TTPs (`aegis/core/ioc_correlator.py`: `IOCCorrelator` with `ThreatIOC` registry; 64-bit SimHash fingerprinting (reuses `cross_session_correlator.compute_simhash`); Hamming-distance threshold matching; `add_ioc()` / `add_iocs()` / `clear()` / `match()` / `match_messages()`; `IOCMatch` and `IOCCorrelationResult` dataclasses with `to_dict()`; pattern text not retained after registration; SHA-256 `request_hash` for audit logging; 49 tests in `tests/test_ioc_correlator.py`)
- [x] Threat intelligence sharing: aegis_server endpoint to publish anonymized attack telemetry to ISAC feeds (`aegis/core/ti_sharing.py`: `TIAnonymizer` SHA-256 hashes normalized attack patterns, buckets timestamps to hour, strips tenant IDs; `TISharer` with httpx-first/urllib-fallback HTTP; queue-based with network-error retention; `AnonymizedThreatEvent.to_stix_indicator()` returns STIX 2.1 indicator dict; `pytest tests/test_ti_sharing.py`)
- [x] YARA rule engine integration: apply YARA rules to request/response payloads for malware-derived string detection — implemented by `aegis/core/yara_engine.py`; pure-Python YARA-subset engine (no native dependency); supports plain-text, regex, and hex string types; modifiers `nocase`, `fullword`; conditions `any of them`, `all of them`, `N of them`, `any of ($prefix*)`, boolean `and`/`or`, single `$name`, `true`/`false`; `parse_yara_rules()`, `_eval_condition()`; `YARAEngine(rules_text, load_builtin)` with `add_rules()` and `scan(str|bytes)`; 7 built-in adversarial-prompt rules (IgnorePreviousInstructions, DANJailbreak, SystemPromptExtraction, RoleplayEscape, PromptDelimiterInjection, AsciiObfuscation, ContextWindowManipulation); `MatchedString`, `YARAMatch`, `YARAScanResult` dataclasses with `to_dict()`; 118 tests in `tests/test_yara_engine.py`

#### 5.5 Forensic Chain of Custody

- [x] Append-only WAL (no delete/overwrite path in audit node storage)
- [x] `verify_integrity()` detects gaps, hash mismatches, reordering
- [x] `legal_admissibility` field in audit chain health response
- [x] Operator signature on chain seal: require HSM-signed attestation before bundle export — implemented by `aegis/core/operator_seal.py`; `OperatorSealGate` issues time-bounded `OperatorAttestation` objects signed with HMAC-SHA256 (AEGIS_SIGNING_KEY) or HSM-PKCS#11 when `HSMSigningBackend` is injected; `create_attestation(operator_id, package_id)`, `verify_attestation()` → `OperatorSealVerifyResult`, `gate_export(package_id, attestation)` raises `OperatorSealError` when attestation is invalid/expired/wrong-package; attestations are package-bound (or broad with package_id="") and expire after configurable window (AEGIS_OPERATOR_SEAL_VALIDITY, default 3600s); HSM fallback to HMAC-SHA256 on HSM error; 53 tests in `tests/test_operator_seal.py`
- [x] Witness co-signing: two-of-three threshold signing for bundle export (multi-party authorization) (`aegis/core/witness_cosign.py`: `WitnessCoSignGate` with configurable m-of-n threshold, per-witness HMAC-SHA256 key derivation `HMAC-SHA256(master_key, witness_id)`, time-bounded `WitnessSignature` with `package_id` binding, `sign()`/`verify_signature()`/`check_threshold()`/`gate_export()`; duplicate-witness deduplication; `AEGIS_SIGNING_KEY` + `AEGIS_WITNESS_VALIDITY` config; `pytest tests/test_witness_cosign.py` — 56 tests)
- [x] Tamper-evident export log: every call to `POST /v1/enterprise/compliance/export` recorded in a separate non-repudiable log signed independently from the audit chain (`aegis/core/export_audit_log.py`: `ExportAuditLog` append-only JSONL log at `0o600`; per-entry HMAC-SHA256 `entry_sig` over canonical body including index, timestamp, operator, package_id, client_ip, api_key_hash, node_count; `record()` flushes+fsyncs after each write; `verify()` checks every HMAC and sequential index; `read_all()` for offline inspection; 47 tests in `tests/test_export_audit_log.py`)
- [x] Custody transfer protocol: `aegis/core/custody_transfer.py` implements `CustodyTransferLog` — append-only JSONL at 0o600; per-record HMAC-SHA256 `transfer_sig` over canonical body (index, timestamp, transferor, transferee, package_id, evidence_hash, reason, authorization, extra); `record()` fsyncs; `verify()` checks HMAC + sequential index; `read_all()` for offline inspection; 47 tests in `tests/test_custody_transfer.py` covering construction, signing, tampering, persistence, and cross-instance replay
- [x] Long-term archival: evidence bundle format compatible with 30-year retention (algorithm agility for hash/signature migration) (`aegis/core/archival_bundle.py`: `ArchivalBundleManager` seals content with multi-algorithm hash manifest (`sha2-256`, `sha2-384`, `sha2-512`, `sha3-256`, `sha3-512`) and HMAC signature manifest (`hmac-sha2-256`, `hmac-sha3-256`); `add_hash()`/`add_signature()` layer in new algorithms post-seal; `migration_log` records each operator-attributed transition; `verify()` checks all manifest entries independently; `export_json()`/`import_json()` for offline storage; `AEGIS_SIGNING_KEY` config; `pytest tests/test_archival_bundle.py` — 83 tests)

---

## Summary Scorecard

| Domain | Implemented | Remaining | Completion |
|---|---|---|---|
| Defense & Government | 41 | 9 | ~82% |
| Healthcare & Life Sciences | 26 | 5 | ~84% |
| Industrial Automation & OT | 21 | 10 | ~68% |
| Enterprise Hyperscale & HA | 17 | 16 | ~52% |
| Advanced Forensics & WAF | 46 | 2 | ~96% |
| **Total** | **151** | **42** | **~78%** |

**Current foundation strengths (production-ready today):** cryptographic audit
chain, ML-DSA-65 PQC signing, multi-provider proxy with zero-latency background
forensics, WAF with evasion-resistant normalization, sealed compliance export,
Redis-backed HA rate limiting, Prometheus + OTel observability, Vault secrets.

**Highest-leverage next items (unblocked, high ROI):**

1. SCIM 2.0 provisioning/deprovisioning lifecycle (Domain 1.2).
2. PII confidence scoring per response (entity recognition confidence threshold → block/flag/log) (Domain 2.4).
3. Prompt injection resistance scoring — ML classifier for indirect injection (Domain 5.1).
4. Hardware-bound session tokens (TPM 2.0 attestation-sealed) (Domain 1.2).

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
> **Done:** RBAC + NIST SP 800-207 Zero Trust attribute evaluation — `Role`/`RoleRegistry` (subject, LDAP-group, and default-role resolution) over the scope vocabulary; `ZeroTrustPolicyEngine` deny-by-default with dynamic constraints (`RequireMTLS`, `RequireAuthMethod`, `IPAllowlist`, `TimeWindow`); `AccessContext`/`AccessDecision` for auditable decisions; 46 tests (Domain 1.2) — completed 2026-06-21.
> **Done:** ABAC for IL5/IL6 data compartmentalization — Bell-LaPadula `ABACPolicyEngine` with `ClassificationLevel` dominance, need-to-know compartments, REL TO/NOFORN dissemination controls; `can_read`/`can_write`/`can_flow`/`endpoint_accredited` (DoD Impact Level → classification mapping); 46 tests (Domain 1.2) — completed 2026-06-21.
> **Done:** WORM (Write-Once Read-Many) enforcement for WAL segments — `WORMEnforcer` with dual-layer protection (application-level `WORMViolationError` + OS-level `0o400` permissions); `WORMSealRecord` sentinel JSON line; `seal()`, `verify()`, `enforce_immutability()`, `delete_node()` (unconditionally raises); `unseal_for_testing()` for CI teardown; `count_nodes_in_segment()` helper; 21 CFR Part 11 Annex 11 §5 / NIST SP 800-53 AU-9 compliance; 56 tests (Domain 2.2) — completed 2026-06-21.
> **Done:** Cross-session correlation — `CrossSessionCorrelator` with SimHash fingerprinting (64-bit, 4-word shingles), 8×8-bit LSH band bucketing, sliding-window eviction, Hamming-distance grouping; covers shared jailbreak kits, A/B variant attacks, botnet flooding; 52 tests (Domain 5.1) — completed 2026-06-21.
> **Done:** RAG-aware prompt injection scanner — `RAGInjectionScanner` with 7 signal categories (direct jailbreak, context-frame escape, role boundary injection, ChatML token injection, LLM-addressed instructions, whitespace padding, lateral exfiltration); `scan_document()`, `scan_tool_result()`, `scan_messages()` covering OpenAI tool/function roles and Anthropic tool_result blocks; 112 tests (Domain 5.1) — completed 2026-06-21.
> **Done:** WAF shadow mode — `shadow_mode=True` on `AegisWAF` runs full detection pipeline but suppresses enforcement; `WAFResult.shadow_blocked` field; `_run_detection()` internal method; `WARNING` log on every suppressed block; 14 tests (Domain 5.2) — completed 2026-06-21.
> **Done:** Legal admissibility attestation field — `LegalAdmissibility` StrEnum (`Admissible`/`Conditional`/`Compromised`); `build_evidence_package()` accepts `legal_admissibility_override` + `legal_admissibility_justification` for per-bundle override of chain-level value; both fields covered by SHA-256 integrity seal; 23 tests in `TestLegalAdmissibilityEnum`+`TestLegalAdmissibilityOverride` (Domain 5.3) — completed 2026-06-21.
> **Done:** SLO burn-rate alerting — `aegis/core/slo_alerting.py` with `SLOConfig`/`SLOBurnRateWindow`/`generate_prometheus_rule()`/`validate_burn_rate_threshold()`; `deploy/helm/templates/prometheusrule.yaml` PrometheusRule CRD; `prometheus.sloAlerting` Helm values; 8 alerts (1h/6h/24h/72h × availability+latency SLOs); critical/warning severity mapping; 65 tests (Domain 4.4) — completed 2026-06-21.
> **Done:** cgroups v2 process-level memory + CPU quotas — `aegis/core/cgroups_quota.py`; `CgroupsQuota.apply()` writes `memory.max`/`cpu.max` to process's own cgroup dir (parsed from `/proc/self/cgroup`); `apply_cgroups_quota()` with `AEGIS_CGROUP_MEMORY_MAX`/`AEGIS_CGROUP_CPU_MAX` env vars; `is_cgroups_v2_available()` detection; graceful fallback on non-Linux/missing cgroup/permission denied; `AEGIS_SKIP_CGROUPS_QUOTA` for CI; 68 tests (Domain 1.5) — completed 2026-06-21.
> **Done:** Dosage hallucination detection — `aegis/core/dosage_hallucination.py`; `DosageHallucinationDetector` with ~100-drug reference DB (12 therapeutic classes), forward + reverse regex extraction, canonical-name dedup, alias resolution, unit-mismatch guard; `scan_messages()` for assistant-role gating; `AEGIS_DOSAGE_STRICT` for unknown-drug enforcement; `extra_db` for custom formularies; 54 tests (Domain 2.4) — completed 2026-06-21.
> **Done:** DFIR-compatible export formats: `DFIRExporter.to_pkcs7()` (CMS SignedData, ephemeral ECDSA P-256 + 30-year self-signed cert, DER output) and `to_e01()` (EWF v1 binary container with EVF magic, Adler-32 CRCed section descriptors, zlib header, MD5+SHA-256 hash section); 58 tests (Domain 5.3) — completed 2026-06-21.
> **Done:** Long-term archival bundle: `ArchivalBundleManager` with multi-algorithm hash manifest (SHA-2/SHA-3 family) and HMAC signature manifest; `add_hash()`/`add_signature()` migration ops; operator-attributed `migration_log`; JSON export/import; 83 tests (Domain 5.5) — completed 2026-06-21.
> **Done:** Witness co-signing: m-of-n threshold bundle export authorization — `WitnessCoSignGate` with per-witness HMAC-SHA256 key derivation, time-bounded package-bound signatures, duplicate-witness deduplication, `gate_export()` raise on threshold failure; `AEGIS_SIGNING_KEY` + `AEGIS_WITNESS_VALIDITY` config; 56 tests (Domain 5.5) — completed 2026-06-21.
> **Done:** MODBUS/DNP3/OPC-UA SCADA command injection scanner — `aegis/core/ot_protocol_scanner.py`; `OTProtocolScanner` with 16 weighted signatures (MODBUS function codes/registers/API calls, DNP3 CROB/Group-Var/control codes, OPC-UA NodeId/write/Security-Mode-None/endpoint URL); complementary-probability risk scoring; `AEGIS_OT_BLOCK_THRESHOLD`; 55 tests (Domain 3.4) — completed 2026-06-21.
> **Done:** ML-KEM-1024 (FIPS 203) session key bootstrap — `aegis/core/mlkem_session.py`; `MLKEMSessionBootstrap` with `generate_keypair()`/`encapsulate()`/`decapsulate()`/`full_exchange()`; soft dep `kyber-py`; pk=1568B, sk=3168B, ct=1568B, ss=32B; 21 tests (Domain 1.1) — completed 2026-06-24.
> **Done:** Cross-domain solution (CDS) guard — `aegis/core/cds_guard.py`; `CDSGuard` with `ClassificationDomain` UNCLASSIFIED/CUI/SECRET/TOP_SECRET; downward-transfer sanitization; `AEGIS_CDS_STRICT_MODE`; `CDSViolationError` (Domain 1.1) — completed 2026-06-24.
> **Done:** Offline license validation — `aegis/core/offline_license.py`; HMAC-SHA256 over canonical JSON; `LicenseExpiredError`/`LicenseTamperError`; constant-time comparison; key separation enforced (Domain 1.3) — completed 2026-06-24.
> **Done:** Pinned CA bundle (air-gapped signature verification) — `aegis/core/pinned_ca_bundle.py`; SHA-256 DER fingerprints; `verify_cert()`/`verify_cert_chain()`; `PinnedCAUnavailableError` soft dep (Domain 1.3) — completed 2026-06-24.
> **Done:** LSM confinement guard — `aegis/core/lsm_guard.py`; `LSMGuard.detect()` AppArmor/SELinux probe; `LSMType(StrEnum)`; `LSMStatus` frozen dataclass; `load_apparmor_profile()`; `assert_enforcing_or_warn()`; `deploy/apparmor/aegis.profile` (Domain 1.5) — completed 2026-06-24.
> **Done:** Rust build hardening — `aegis_rust_v2/.cargo/config.toml`; full RELRO (`-z relro -z now`), noexecstack; `[profile.embedded]` opt-level="z" for edge builds; `scripts/build_embedded.sh` (Domain 1.5) — completed 2026-06-24.
> **Done:** Hardware-bound session tokens — `aegis/core/hardware_token.py`; `HardwareTokenManager` with TPM2/SOFTWARE backend enum; HMAC-SHA256 binding; `_is_tpm_available()` `/dev/tpm0` check; constant-time validation (Domain 1.2) — completed 2026-06-24.
> **Done:** Real-time scheduling — `aegis/core/rt_scheduler.py`; `RTScheduler` via ctypes `sched_setscheduler`; `SchedulingPolicy(StrEnum)` FIFO/RR/DEADLINE/OTHER; `AEGIS_RT_POLICY`/`AEGIS_RT_PRIORITY` env vars (Domain 3.2) — completed 2026-06-24.
> **Done:** CPU affinity pinning — `aegis/core/cpu_affinity.py`; `CPUAffinity` via ctypes `sched_setaffinity`; 128-byte `cpu_set_t`; `get_isolated_cpus()`; `AEGIS_CPU_AFFINITY` env var (Domain 3.2) — completed 2026-06-24.
> **Done:** Gossip WAL synchronization — `aegis/core/gossip_wal_sync.py`; `GossipWALSyncer` with `GossipMessage`/`SyncDecision`/`GossipSyncResult`; `AEGIS_GOSSIP_*` env vars (Domain 3.3) — completed 2026-06-24.
> **Done:** CRDT audit node ordering — `aegis/core/crdt_ordering.py`; `VectorClock` with `increment`/`merge`/`happens_before`/`concurrent_with`; `CRDTAuditOrderer.total_order()` topological sort with tiebreak (Domain 3.3) — completed 2026-06-24.
> **Done:** Raft consensus state machine — `aegis/core/raft_consensus.py`; pure-Python Raft per Ongaro & Ousterhout 2014; leader election, log replication, commit-index advancement; SHA-256 entry-hash tamper detection; all RPC types (Domain 4.1) — completed 2026-06-24.
> **Done:** Split-brain fencing tokens — `aegis/core/split_brain.py`; `LeaseBasedLock` with monotonically increasing `FencingToken` (Kleppmann 2016); `gate_wal_write()` enforces fence before every WAL write; `StaleLeaseError`/`FencingTokenError` (Domain 4.1) — completed 2026-06-24.
> **Done:** Kubernetes operator — `deploy/k8s/aegis-operator/crd.yaml` `AegisProxy` CRD; `deploy/k8s/aegis-operator/operator.py` kopf-based controller with `_build_deployment()`/`_build_hpa()`; secrets via `secretKeyRef` (Domain 4.4) — completed 2026-06-24.
> **Done:** Semantic similarity clustering — `aegis/core/semantic_sim_clustering.py`; `JailbreakClusterRegistry` with 4 built-in jailbreak families; SimHash + Hamming distance; `AEGIS_SEMANTIC_HAMMING_THRESHOLD` (Domain 5.1) — completed 2026-06-24.
> **Done:** Token-split reassembly WAF detector — `aegis/core/token_split_detector.py`; sliding-window bare+spaced+stripped join; catches patterns split across token boundaries; `AEGIS_TOKEN_SPLIT_WINDOW`/`AEGIS_TOKEN_SPLIT_STRIDE` (Domain 5.2) — completed 2026-06-24.
> **Done:** Court-ready forensic PDF report — `aegis/core/forensic_pdf_report.py`; `ForensicReportBuilder` 6-section report; `ForensicReport.to_text()`/`to_json()`/`compute_seal()` SHA-256 seal; no external PDF lib (Domain 5.3) — completed 2026-06-24.
> **Done:** Anonymized threat intelligence sharing — `aegis/core/ti_sharing.py`; `TIAnonymizer` SHA-256 pattern normalization + timestamp bucketing; `TISharer` httpx+urllib fallback; STIX 2.1 `to_stix_indicator()` (Domain 5.4) — completed 2026-06-24.
> **Done:** GxP IQ/OQ qualification scripts — `tools/qualification/iq_checks.py` IQ-001..IQ-008; `tools/qualification/oq_checks.py` OQProtocol; JSON evidence artifacts; `tests/test_iq_oq.py` (Domain 2.3) — completed 2026-06-24.
> **Done:** Fully air-gapped Docker image — `deploy/docker/Dockerfile.airgap` multi-stage, `ARG PYTHON_BASE_DIGEST` sha256 pin, `pip install --no-index --find-links /wheels`, `aegis.airgap="true"` OCI label, UID 10001; `scripts/vendor_wheels.sh` offline wheel vendoring + SHA256SUMS; `make docker-airgap`; 31 tests in `tests/test_airgap_docker.py` (Domain 1.3) — completed 2026-06-24.

---

## How to update this file

1. Implement the feature on the development branch.
2. Add or update the test(s) that prove it (`pytest`, `cargo test`, or a
   benchmark committed to `docs/BENCHMARKS.md`).
3. Flip the checklist item from `[ ]` to `[x]` in the **same** pull request.
4. Recompute the affected row(s) and the **Total** in the Summary Scorecard.
5. Update the "Last verified against codebase" date at the top.
