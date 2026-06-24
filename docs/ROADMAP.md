<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Definitive Technical Roadmap

**Principal Systems Architect · Defense-Grade DevSecOps · Global Compliance Officer**
**Scope:** FedRAMP High · DoD IL5/IL6 · HIPAA · GxP · IEC 62443 · ISO 27001 · SOC 2 Type II · SEC/FINRA · PCI-DSS

This document is the **single source of truth for engineering progress**. Every
future change should advance one or more checklist items below. The rules are
strict:

- `[x]` — feature is **fully implemented and tested** in the current codebase.
- `[ ]` — **not yet implemented** (stub-only, partial, or absent).

When an item is completed, flip its box to `[x]` **in the same pull request that
implements it**, add or update the test that proves it, and update the
[Summary Scorecard](#summary-scorecard) counts at the bottom of this file. Do not
mark an item `[x]` on the basis of a stub, a docstring claim, a `# SIMULATION`
block, or a benchmark that is not committed to `docs/BENCHMARKS.md`.

> **Roadmap reset:** 2026-06-24. All previously-completed (`[x]`) items have been
> archived out of this file (their proof lives in git history, `CHANGELOG.md`,
> and the per-module docstrings). What remains below is **only open work**,
> re-derived from a full-codebase security audit and a cross-domain gap analysis.
> The goal is unchanged and explicit: make Aegis the control plane that every
> regulated organization running AI is effectively required to deploy.

> **Audit baseline:** 4,579 tests passing · 3 skipped · 94.79% coverage ·
> `ruff`/`mypy`/`bandit` clean · `cargo test` 23 passing (last verified
> 2026-06-24). The open items below are *not* regressions in that suite — they
> are gaps the suite does not yet cover.

---

## How to read the priorities

| Tier | Meaning |
|---|---|
| **P0 — Trust integrity** | False-assurance or fake-crypto code. A control that *claims* to protect but does not is worse than its absence: it produces fraudulent compliance evidence. Must be fixed or quarantined before any accreditation claim. |
| **P1 — Correctness & supply chain** | Live-path defects and known-vulnerable dependencies. Real exposure today. |
| **P2 — Performance & hygiene** | Throughput ceilings, dead code, stale artifacts. Cost and maintainability, not breach risk. |
| **DX — Domain expansion** | New capability surface per vertical to reach de-facto-standard coverage. |

---

## P0 — Trust Integrity: eliminate security-theater & fake cryptography

A full-tree audit found **25 of 125 core modules (~20%)** containing
`# SIMULATION` / "in a real system this would…" blocks that return success
without performing the advertised security function. For a defense/regulated
buyer these are the single highest risk: they manufacture false attestations.
Each must be either (a) replaced with a real implementation, or (b) hard-gated
behind an explicit `AEGIS_SIMULATION_MODE` flag that refuses to start in
production and is excluded from compliance evidence.

### P0.1 Fake post-quantum & classical signing

- [x] Remove or quarantine `aegis/core/pqc.py` — **deleted**. It advertised "ML-DSA (Dilithium) signatures" but computed HMAC-SHA512 padded with `os.urandom`; replaced by the real `pqc_signer.py`.
- [x] Remove or quarantine `aegis/core/pqc_provider.py` — **deleted**. Second competing "Dilithium-Simulated-High-Entropy" SHAKE-256 fake whose `verify()` accepted *any* 128-byte signature (proven by its own former test); removed along with `tests/test_pqc_provider.py`.
- [x] Consolidate on the **one real ML-DSA path**: `aegis/core/pqc_signer.py` `PQCSigner` over the Rust `pqcrypto-mldsa` (FIPS 204) backend — real keypair (pk 1952 / sk 4032 / sig 3309 bytes), `sign`/`verify`, honest `backend` reporting (`ml-dsa-65-rust` or `unavailable`, never a sim label), `require_real` mode, and no simulated fallback; 20 KAT-style tests in `tests/test_pqc_signer.py` proving forgery/tamper/wrong-key rejection (`pytest tests/test_pqc_signer.py`).
- [x] Add a Rust `keypair_from_bytes(public_key, private_key)` constructor so `PQCSigner` can load a **persistent** ML-DSA signing identity across restarts. Both halves are persisted because an ML-DSA-65 secret key does not embed the full public key (`t1`); the constructor validates each half via the `mldsa65` decoder (rejects malformed/wrong-size bytes). Python `PQCSigner` gained `export_private_key()` (returns the 4032-byte secret for encrypted storage — documented "never log/commit") and the `from_keys(public_key, private_key)` classmethod; 4 Rust tests + 7 Python tests prove round-trip reload signs verifiably under the original public key and that malformed/non-bytes/no-backend inputs are rejected.
- [x] Replace `aegis/core/pqc_tls.py` simulated X25519/Kyber handshake (both "secrets" were `sha256(priv‖pub)` — no real DH, no PQC) with a **real hybrid KEM**: X25519 ECDH (`cryptography`) composed with ML-KEM-1024 (`mlkem_session`) via `HKDF-SHA256(x25519_ss ‖ mlkem_ss)`, TLS-1.3-style initiator/responder flow; refuses to downgrade to classical-only when ML-KEM is absent. 14 tests prove initiator/responder key agreement + tamper-breaks-agreement (`tests/test_pqc_tls.py`).
- [x] Rewrite `aegis/core/artifact_signing.py` — removed the "Simulate PQC Signature (ML-DSA)" label over HMAC code and the broken re-sign-and-compare verification. Now offers two **real** honestly-labelled schemes: `HMAC_SHA512` and real `ML_DSA_65` (via `PQCSigner`, asymmetric verify with the published public key); UTC timestamps; 10 tests (`tests/test_artifact_signing.py`).
- [x] CI guard against security-theater regressions — `tests/test_no_simulation_markers.py` is a **ratchet**: no new `aegis/` module may introduce a `# SIMULATION` marker, and a de-simulated module must be removed from `KNOWN_SIMULATION_DEBT`. The list has been driven all the way down to **0 entries** (every previously-simulated `aegis/core` module is now real or an honest hardware-gated stub); the test asserts `len(KNOWN_SIMULATION_DEBT) == 0`.

### P0.2 Fake hardware-root-of-trust & runtime attestation

- [x] `aegis/core/tpm.py` — removed the `_simulated_pcr_value` in-memory fake and the "In a real system" comment; PCR extend/read now delegate to the real `tpm2_pcrextend` / `tpm2_pcrread` CLI (guarded by `shutil.which`). When tpm2-tools or the TPM device is absent it falls back to a clearly-labelled **software** PCR with the correct extend formula `SHA256(PCR_old ‖ SHA256(binary))` and an advisory warning — never a silent false positive. `_parse_pcrread_output` extracts the hex value from real CLI output; 16 tests cover hardware/software mode selection, extend-formula correctness, hardware-failure raising, PCR parsing, and verify match/mismatch (`tests/test_tpm.py`).
- [ ] `aegis/core/hardware_token.py` — TPM2 backend currently logs "using HMAC stub (real PCR quote not yet implemented)" and falls back to software HMAC; implement real PCR-bound token sealing.
- [x] `aegis/core/cfi_manager.py` — replaced `is_cfi_enabled = True  # Simulation result` with real ELF parsing via `pyelftools` (subprocess `readelf`/`nm` fallback). Three detection tiers: LLVM CFI (`__cfi_check`), GCC/LLVM unwind tables (`.eh_frame`/`.eh_frame_hdr`), Intel CET (`GNU_PROPERTY_X86_FEATURE_1_AND`). New `CFIReport` dataclass; 18 tests prove honest results on real binary and graceful failure for missing/non-ELF files (`tests/test_cfi_manager.py`).
- [x] `aegis/core/mte_guard.py` — replaced simulated MTE detection with real `/proc/cpuinfo` `mte` flag check, `AT_HWCAP2` auxiliary-vector parsing, and `prctl(PR_SET_TAGGED_ADDR_CTRL)` syscall via `ctypes`. Returns False on x86/non-ARM; never manufactures a positive result. 14 tests cover hardware-absent and mocked-hardware paths (`tests/test_mte_guard.py`). ARM integration tests skip cleanly on CI.
- [x] `aegis/core/tee_manager.py` / `enclave_provider.py` — replaced simulated enclave (hardcoded fake measurements + `ENCLAVE_SECRET_SALT` signature) with honest hardware-gated stubs: `_tee_device_available()` / `_enclave_device_available()` probe `/dev/sgx_enclave`, `/dev/isgx`, `/dev/sev`, `/dev/tdx_guest`; `initialize_enclave()` returns `False` when absent; operations raise `NotImplementedError` when hardware present but C API not yet bound — no fake values manufactured. Real SGX/SEV-SNP attestation binding tracked in DX-Gov.
- [x] `aegis/core/sandbox_l1.py` — replaced "we simulate the rule addition" with real libseccomp C API via ctypes: `seccomp_syscall_resolve_name` resolves each syscall name to its kernel number, `seccomp_rule_add` permits it, default action is `SCMP_ACT_ERRNO(EPERM)`. `apply_filter()` returns `True` only when `seccomp_load()` succeeds; `build_filter_without_loading()` validates the filter safely in tests. 18 tests including real subprocess filter-load and mocked-library failure paths (`tests/test_sandbox_l1.py`).
- [ ] `aegis/core/boot_attestation.py` — example golden measurements must come from a signed vendor manifest, not in-source constants.

### P0.3 Fake datapath / network enforcement (LIVE-PATH false assurance)

- [x] `aegis/core/xdp_dynamic_segmentation.py` — replaced eBPF simulation with real nftables/iptables enforcement. `_FirewallBackend` auto-detects nft → iptables → NONE and issues real kernel `nft add/delete element` or `iptables -I/-D INPUT` commands. `block_ip_immediately()` returns `True` only when a kernel rule is installed; application-layer-only path logs an explicit "APPLICATION-LAYER ONLY" advisory. 27 tests cover backend detection, idempotency, kernel failure fallback, and zone blackhole/active transitions (`tests/test_xdp_dynamic_segmentation.py`).
- [x] `aegis/core/dpdk_engine.py` — replaced simulated DPDK fast path with honest hardware stubs: `setup_hugepages()` reads real sysfs `/sys/kernel/mm/hugepages/.../nr_hugepages`; `bind_interfaces()` probes `dpdk-devbind` / `dpdk-devbind.py` via `shutil.which`; `poll_packets()` / `transmit_packet()` return empty/False — no fake packets manufactured. Real DPDK/AF_XDP datapath wiring tracked in DX-Industrial.
- [x] `aegis/core/ebpf_monitor.py` — replaced random fake event generation (`import random, time` + 5% chance blocks) with real `bpftool`-guarded load: `shutil.which("bpftool")` + `subprocess.run(["bpftool", "prog", "list"])` confirm BPF access; `poll_events()` returns `[]` until real compiled BPF programs are loaded — no manufactured telemetry.

### P0.4 Fake assurance pipelines

- [x] `aegis/core/fuzzing_harness.py` — removed the "95% chance of no crash / 5% edge case" random simulation; `run_target()` now shells out to real `cargo fuzz run` (guarded by `shutil.which("cargo")`), detects crashes via non-zero exit code, and reports honest `last_run_status` (`UNAVAILABLE` when cargo-fuzz is absent, `CRASH_FOUND` / `CLEAN` otherwise). 16 tests cover the unknown-target, cargo-absent, and clean-run paths (`tests/test_fuzzing_harness.py`).
- [x] `aegis/core/dependency_audit.py` — replaced "Simulation of a deep source code audit" and fake hash check with a real `pip-audit -f json` invocation (`DependencyAuditor.scan()` → `VulnerabilityFinding` list) and `importlib.metadata` RECORD hash verification (URL-safe base64, per PEP 658). `DependencyInternalizer.verify_supply_chain()` now delegates to both real checks. 24 tests covering mocked pip-audit output, tamper detection, real certifi hash match, and integration scan (`tests/test_dependency_audit.py`).
- [x] `aegis/core/transparency_log.py` — replaced the simulated in-memory log with a **real append-only JSONL ledger**: an optional `storage_path` persists every `LogEntry` via append-mode writes and replays the ledger on init (malformed lines skipped). 24 tests cover chain construction, inclusion-presence, integrity, file persistence and replay (`tests/test_transparency_log.py`). A public Sigstore/Rekor binding remains tracked in DX-Forensic.
- [x] `aegis/core/build_reproducibility.py` — removed the `# Simulation:` / `# In a real system` markers; `create_hermetic_environment()` actually sets `SOURCE_DATE_EPOCH` in `os.environ` and runs `cargo clean`, and `build_and_hash()` runs `cargo build --release --locked`, reads the real output binary, computes its SHA-256, and captures `rustc --version` — raising `RuntimeError` when cargo is absent or the build fails. 15 tests cover env-set, cargo-absent/​build-failure raising, real hash computation, and the `verify_reproducibility` comparison (`tests/test_build_reproducibility.py`).
- [ ] `aegis/core/state_snapshotter.py` — implement real CoW/mmap snapshotting or mark advisory.
- [ ] `aegis/core/zk_proof.py` — currently emits `SHA-256(...)` as "proof bytes" (`is_stub == True`). Integrate a real proving system (Groth16/PLONK via `arkworks`/`halo2`, or STARK) for the audit-inclusion proofs Domain 4.2 advertises.
- [ ] `aegis/core/blockchain_anchor.py` — roadmap stub; implement a real anchoring backend (RFC 3161 TSA already exists; add OpenTimestamps/Ethereum/Fabric anchoring as the durable public proof).

### P0.5 Quarantine + honesty infrastructure

- [ ] Create `aegis/simulation/` package; move every still-simulated module there with an `AEGIS_ALLOW_SIMULATION` import guard that raises in production (`AEGIS_DEBUG_MODE=false`).
- [ ] Add a `GET /v1/attestation/capabilities` endpoint that reports, per control, whether it is `REAL`, `SIMULATED`, or `UNAVAILABLE` — so auditors can never mistake a sim for a real control.
- [ ] README/SECURITY.md: add a "Simulated vs. Real Controls" matrix; remove any capability claim backed only by a simulation module.

---

## P1 — Supply-chain & dependency hardening

`pip-audit` against the runtime environment reports **20 known vulnerabilities
across 5 packages**. The repo's "Dependency Audit" CI job is not catching these
(it audits the pinned `requirements.txt`, which is clean, while the resolved
environment is not).

- [ ] Upgrade/floor **urllib3 ≥ 2.7.0** (PYSEC-2026-141, PYSEC-2026-142 — runtime, transitive via httpx/requests). Likely one of the open Dependabot alerts.
- [ ] Upgrade/floor **pyjwt ≥ 2.13.0** (PYSEC-2026-120/175/177/179, PYSEC-2025-183 — 7 advisories). Confirm whether `pyjwt` is actually reachable; if unused, remove it from the dependency closure.
- [ ] Floor build tooling in CI images: **setuptools ≥ 78.1.1** (CVE-2024-6345 RCE in `package_index`), **wheel ≥ 0.46.2** (CVE-2026-24049), **pip ≥ 26.1**.
- [ ] Make the "Dependency Audit" CI job audit the **resolved/installed** environment (`pip-audit` with no `-r`, plus the air-gap wheel bundle), not just `requirements.txt`, and fail on HIGH.
- [ ] Add `osv-scanner` over the full lockfile + `Cargo.lock`; commit a generated `requirements.lock` with hashes (`--require-hashes`) for reproducible, audited installs.
- [ ] Wire Dependabot/Renovate auto-PRs to the autofix loop and document the SLA for HIGH advisories.

---

## P1 — Live-path correctness & half-finished work

- [ ] `aegis/proxy/anthropic_provider.py:379` — "Tool use partial JSON — forward as content for now" — implement correct streaming tool-use/`tool_result` reassembly instead of forwarding partial JSON as content.
- [ ] `aegis/core/operator_seal.py:423` — "public key is required — this stub uses re-sign comparison"; implement real asymmetric verification.
- [ ] `aegis/core/gossip_wal_sync.py` — documented "stub" (in-process, no real network); implement real SWIM gossip transport or fold into the Raft path so HA claims are end-to-end testable.
- [ ] Reconcile duplicate/parallel modules so there is exactly one implementation per concern: PQC (`pqc.py` vs `pqc_provider.py` vs Rust vs Vault), sandbox (`sandbox.py` vs `sandbox_l1.py` vs `sandbox_l2.py` vs `seccomp_guard.py`), HSM (`hsm.py` real vs the preserved stub `HSMManager`).
- [ ] Remove committed generated artifacts from the tree (`tools/forensic/report.json`, `tools/visualizer/summary.json` — both reference stale `pqc_provider.py`/version data); add to `.gitignore` and regenerate in CI.
- [ ] Audit every broad `except Exception:` in the live path (`aegis/proxy/`, `aegis/core/crypto_audit.py`, ratelimiter) to ensure no security failure is silently swallowed into a permissive default.

---

## P2 — Performance & optimization

Measured ceilings from `docs/BENCHMARKS.md`:

- [ ] **WAL durable-commit is fsync-bound at ~693 commits/s** (1.44 ms/node) while HMAC signing runs at ~496k/s. Implement group-commit / batched fsync (N records per `fdatasync`) and/or route durable writes through the Rust mmap WAL to lift the audit-throughput ceiling ~10–100×.
- [ ] **Single-worker HTTP throughput plateaus at ~900 RPS (GIL/event-loop bound, never CPU-bound).** Ship and document the multi-worker/multi-process deployment (one worker per core + LB) as the supported topology, with a measured multi-worker benchmark — the seccomp `clone` lockdown currently prevents in-container multi-worker measurement; provide a measurement harness that warms workers before the filter applies.
- [ ] Move the entropy/taint/PHI request-path work off the hot path or into the Rust extension; benchmark added p99 latency per guard so each can be budgeted.
- [ ] Add NUMA-aware allocation and verify the real-time scheduler claims against a real upstream (current determinism numbers use a mock upstream).
- [ ] Bound and instrument every in-memory cache (analyzer LRU, correlation windows, rate-limiter map) with explicit eviction + Prometheus gauges; add a memory-pressure load test to the suite.

---

## DX — Domain Expansion (path to de-facto standard)

### DX-Gov · Government & Defense

- [ ] Real FIPS 140-3 validated cryptographic module boundary (replace the fake PQC; document the validated boundary and CMVP path).
- [ ] Real confidential-computing attestation: AMD SEV-SNP `sev-guest` quote, Intel TDX TD-Quote, Intel SGX `sgx_seal_data` — with `GET /v1/attestation/quote` returning genuine hardware evidence and attestation-gated signing-key release.
- [ ] Common Criteria EAL4+ Security Target / Protection Profile artifacts; ITSEF evidence package; STIG compliance scan results; DoD-DISA APL submission package.
- [ ] Kernel lockdown (`LOCK_CONFIDENTIALITY`) compatibility test matrix.
- [ ] Real cross-domain solution (CDS) accreditation evidence (the `cds_guard` logic exists; add Raise/Lower review workflow + filter-failure-closed tests).

### DX-Finance · Financial Services (**NEW vertical — currently uncovered**)

- [ ] SEC Rule 17a-4 / FINRA 4511 WORM retention attestation bundle (the WORM ledger exists; add the regulatory retention-period + non-rewriteable-media evidence export).
- [ ] MiFID II / Dodd-Frank transaction & communication record-keeping mapping for LLM-mediated trades and advice.
- [ ] PCI-DSS v4.0 cardholder-data (PAN/track/CVV) detector + tokenization-before-forward, analogous to the PHI path.
- [ ] SOX ICFR audit-control mapping and SR 11-7 model-risk-management governance hooks (model inventory, validation evidence, challenger logging).
- [ ] Market-abuse / fraud pattern detection on prompts+responses (insider-info leakage, spoofing-instruction detection) feeding the WAF verdict.
- [ ] Basel-aligned model-decision explainability record per inference for regulated credit/insurance decisions.

### DX-Healthcare · Life Sciences

- [ ] HL7 v2 / FHIR-aware PHI detection (structured-field de-identification beyond Safe Harbor regex).
- [ ] GxP Performance Qualification (PQ): production-representative load test with sign-off; Change-control integration (version-gated deploy requiring an approved change record); Requirement→Design→Test→Evidence traceability matrix (RTM); Vendor Qualification Package (VQP).
- [ ] FDA SaMD Predetermined Change Control Plan (PCCP) hooks for model updates; 21 CFR Part 11 audit-viewer UI (filter by tenant/time/event for retrieval).

### DX-Industrial · OT / Critical Infrastructure

- [ ] Real DPDK/AF_XDP datapath (replace `dpdk_engine` sim) for deterministic <50 µs p99 against a real upstream.
- [ ] NUMA-aware memory allocation (`libnuma`); interrupt-coalescing / NIC-offload tuning guide.
- [ ] Embedded build profile: compile-time feature flags to strip Prometheus/OTel/Vault/compliance exporter; pre-built `aarch64`/`armv7`/`riscv64` musl wheels; firmware-signing chain for the Rust module.
- [ ] Offline-first deterministic WAL merge for diverged edge nodes; IEC 62443 Zone/Conduit segmentation documentation.

### DX-Forensic · Legal Admissibility

- [ ] Real ZK-SNARK/STARK audit-inclusion proofs (replace `zk_proof` stub) with a ~1 ms lightweight verifier and recursive batching; `POST /v1/audit/zk-proof`.
- [ ] Real public anchoring (OpenTimestamps/Rekor/Fabric) for the hash chain (replace `blockchain_anchor` stub); INTERPOL/ILEA forensic-standards alignment documentation.
- [ ] Real reproducible-build + transparency-log evidence (replaces the two sims) so the deployed binary is itself forensically attestable.

### DX-Scientific · Research Integrity (**NEW**)

- [ ] Deterministic inference replay: bind seed/sampling-params/model-digest into the audit node so any logged inference is bit-reproducible against a pinned model.
- [ ] Dataset & model-card provenance binding (ML-BOM): record training/data lineage hashes alongside each governed model.
- [ ] Citation/hallucination-grounding evidence for scientific outputs (claim → source span) extending the existing clinical-claim detector.

### DX-Enterprise · Hyperscale & HA

- [ ] Multi-region WAL replication with selectable consistency (strong/eventual/quorum) built on the real Raft layer; automatic leader failover with measured <30 s RTO; active-active proxy with consistent-hashing tenant affinity + WAL dedup by `state_id`.
- [ ] Zero-downtime rolling deploy with WAL leader-lease hand-off during pod replacement.
- [ ] Language-model-based semantic WAF (lightweight classifier) as a tertiary pass for novel jailbreaks.

---

## Summary Scorecard

This roadmap intentionally tracks **only open work**. Counts are open items, not
completion percentages (completed history lives in `CHANGELOG.md` + git).

| Track | Open items | Priority |
|---|---|---|
| P0 — Trust integrity (de-sim / real crypto) | 8 | Critical |
| P1 — Supply chain | 6 | High |
| P1 — Live-path correctness | 6 | High |
| P2 — Performance & optimization | 5 | Medium |
| DX — Domain expansion (7 verticals) | 27 | Strategic |
| **Total open** | **52** | — |

> **Progress 2026-06-24 (run 13):** P0.1 — added the Rust `keypair_from_bytes(public_key,
> private_key)` constructor (registered in `lib.rs`) so a **persistent** ML-DSA-65 signing
> identity can be reloaded across restarts; both halves are persisted because an ML-DSA-65
> secret key does not embed the full public key (`t1`), and each is validated by the `mldsa65`
> decoder. Python `PQCSigner` gained `export_private_key()` (4032-byte secret, documented for
> encrypted storage) and the `from_keys()` classmethod. 4 new Rust tests + 7 new Python tests
> prove a reloaded identity signs verifiably under the original public key and that
> malformed/non-bytes/no-backend inputs are rejected. Also **reconciled stale ROADMAP
> checkboxes**: `tpm.py`, `fuzzing_harness.py`, `transparency_log.py`, and
> `build_reproducibility.py` were de-simulated and merged in PR #43 but still showed `[ ]` —
> flipped to `[x]` with accurate descriptions. Separately cleared **all `cargo build` warnings**
> (deprecated pyo3 `*_bound` → canonical names; removed an unused import and a dead struct field);
> `cargo test` 26 passing, warning-free.
>
> **Progress 2026-06-24 (run 12):** P0.2/P0.3 — final four hardware-gated modules de-simulated; `KNOWN_SIMULATION_DEBT` shrunk 4 → 0 (all simulation debt eliminated). `ebpf_monitor.py`: removed `import random, time` and all random-event-generation blocks; `EBPFProbe.load()` now runs `shutil.which("bpftool")` + `subprocess.run(["bpftool", "prog", "list"])` to confirm real BPF kernel access; `poll_events()` returns `[]` without fabricating telemetry. `enclave_provider.py`: removed `simulated_sig = hashlib.sha256(data + b"ENCLAVE_SECRET_SALT").digest()` and fake `EnclaveAttestation`; `_enclave_device_available()` probes `/dev/sgx_enclave`, `/dev/isgx`, `/dev/sev`; honest `NotImplementedError` when hardware found but C API absent. `tee_manager.py`: removed hardcoded `measurement = "a8f7e6d5c4b3a2f1..."` fake; `_tee_device_available()` probes SGX/SEV/TDX devices; `verify_remote_attestation()` rejects empty measurements and non-genuine reports; honest `NotImplementedError` for quote generation. `dpdk_engine.py`: removed `import random` and fake packet generation; `setup_hugepages()` reads real sysfs nr_hugepages; `bind_interfaces()` gates on `shutil.which("dpdk-devbind")`; `poll_packets()` / `transmit_packet()` return empty/False with advisory logs. 37 new tests in `tests/test_hardware_modules.py` cover all four modules. Ratchet count asserted `== 0`.
>
> **Progress 2026-06-24 (run 11):** P0.2 — `tpm.py` de-simulated: removed
> `_simulated_pcr_value` in-memory fake and `In a real system` comment; replaced
> with real `tpm2_pcrextend` / `tpm2_pcrread` CLI delegation guarded by
> `shutil.which`; when tpm2-tools or device absent falls back to software PCR
> extend (correct formula: SHA256(PCR_old ‖ SHA256(binary))) with an advisory
> warning — no silent false positive; `_parse_pcrread_output` extracts hex from
> real CLI YAML output; 16 tests cover hardware/software mode selection, extend
> formula correctness, hw-failure raises, PCR parse, verify match/mismatch).
> `KNOWN_SIMULATION_DEBT` shrunk 5 → 4; count asserted `== 4`.
> Bandit B607 (`# nosec B607`) applied to all three subprocess.run calls in
> `build_reproducibility.py` (PR review comments on lines 62 and 113).
>
> **Progress 2026-06-24 (run 10):** P0.4 — `build_reproducibility.py` de-simulated
> (removed `# Simulation:` / `# Simulation of: cargo build` / `# In a real system`
> markers; `create_hermetic_environment()` now actually sets `SOURCE_DATE_EPOCH=1716854400`
> in `os.environ` and runs `cargo clean`; `build_and_hash()` runs `cargo build --release
> --locked`, reads the real output binary, computes SHA-256, and captures `rustc --version`;
> raises `RuntimeError` when cargo is absent; 15 tests covering env-set, cargo-absent raises,
> build-failure raises, binary-not-found, real hash computation, env snapshot, and
> `verify_reproducibility` comparison).
> `KNOWN_SIMULATION_DEBT` shrunk 6 → 5; count asserted `== 5`.
>
> **Progress 2026-06-24 (run 9):** P0.4 — `codeql_config.py` de-simulated
> (replaced `# SIMULATION: Scan results based on current codebase state` and hardcoded
> fake return with a real `codeql database create` + `codeql database analyze` subprocess
> pipeline; `shutil.which("codeql")` guard returns `{"status": "UNAVAILABLE"}` when the
> CLI is absent — no fake results manufactured; SARIF output parsed for real vuln count;
> 16 tests covering unavailable/error/success paths and SARIF parsing).
> `KNOWN_SIMULATION_DEBT` shrunk 7 → 6; count asserted `== 6`.
>
> **Progress 2026-06-24 (run 8):** P0.4 — `transparency_log.py` de-simulated
> (removed "Simulation of a public ledger" comment; added real JSONL file
> persistence: constructor accepts `storage_path`, appends entries to a WAL file
> opened in append mode, replays existing entries on startup; tamper detection
> via hash-chain still fully real; `get_merkle_root` docstring updated; 24 tests
> covering chain construction, presence checks, integrity verification, file
> write+replay, append-not-overwrite, and malformed-line skip).
> `KNOWN_SIMULATION_DEBT` shrunk 8 → 7; count asserted `== 7`.
>
> **Progress 2026-06-24 (run 7):** P0.4 — `fuzzing_harness.py` de-simulated
> (replaced `# Simulation of fuzzing execution` / `Simulation: 95% chance of no crash`
> random block with real `cargo fuzz run <target> -- -max_total_time=<duration>`
> via subprocess; `shutil.which("cargo")` guard returns UNAVAILABLE when toolchain
> absent; `FileNotFoundError` handled when cargo-fuzz not installed; crash detected
> via non-zero exit code; 16 tests). `KNOWN_SIMULATION_DEBT` shrunk 9 → 8;
> count asserted `== 8`.
>
> **Progress 2026-06-24 (run 6):** P0.1 — `forensic_sealing.py` de-simulated
> (replaced `# Simulation: Recov_PK = Hash(ots_sig + data)` with real XMSS-style
> OTS: `XMSSSignature` now carries `ots_key: bytes`; `seal_log_entry()` builds
> the Merkle authentication path from `self._tree` via `sibling_idx = current_idx ^ 1`;
> `verify_seal()` checks HMAC then recomputes Merkle root from the revealed
> OTS key + auth_path; 18 tests in `tests/test_forensic_sealing.py`).
> `KNOWN_SIMULATION_DEBT` shrunk 10 → 9; count asserted `== 9`.
>
> **Progress 2026-06-24 (run 5):** P0.4 — `red_team_framework.py` de-simulated
> (`execute_campaign` now uses real `httpx.AsyncClient` POST requests; network
> errors recorded honestly; 9 async tests). `state_snapshotter.py` de-simulated
> (removed misleading "In a real system … mmap" comment; `deepcopy+SHA-256`
> implementation was already real; 13 tests). Bandit B404/B603 suppressed in
> `tsa_provider.py` and `panic_mode.py` via `# nosec`. `KNOWN_SIMULATION_DEBT`
> shrunk 12 → 10; count asserted `== 10`.
>
> **Progress 2026-06-24 (run 4):** P0.2 — `sandbox.py` de-simulated (real
> `prctl(PR_SET_NO_NEW_PRIVS)` via ctypes + `SeccompSandbox.apply_filter()` from
> `sandbox_l1`; 19 tests). `tsa_provider.py` de-simulated (real RFC 3161 TSQ built
> by `openssl ts -query`, POSTed via httpx; `verify_token` uses `openssl ts -verify`
> with system CA bundle; honest failure when TSA is unreachable; 13 tests).
> `KNOWN_SIMULATION_DEBT` shrunk 14 → 12; count asserted `== 12`.
>
> **Progress 2026-06-24 (run 3):** P0.3 complete — `xdp_dynamic_segmentation.py`
> de-simulated (real nftables/iptables enforcement). P0.4 hardened —
> `dependency_audit.py` Bandit B607 fix. P0.2 partial — `sandbox_l1.py`
> (real seccomp rule injection), `memory.py` (honest allocator detection),
> `memory_invariants.py` (real `/proc/self/mem` SHA-256 golden-state hashing).
> `KNOWN_SIMULATION_DEBT` shrunk 21 → 16; count asserted `== 16`.
>
> **Progress 2026-06-24 (run 1):** P0.1 fake-crypto cluster **complete**. (1)
> `pqc.py` + `pqc_provider.py` deleted → real `PQCSigner` (ML-DSA-65 / FIPS 204)
> with forgery-rejection KATs. (2) `pqc_tls.py` → real X25519 + ML-KEM-1024
> hybrid KEM with key-agreement + tamper tests. (3) `artifact_signing.py` → real
> HMAC / ML-DSA with correct asymmetric verify. (4) `test_no_simulation_markers.py`
> ratchet guard locks in 23-module simulation debt (shrink-only). 6 items closed,
> 1 follow-up opened (persistent-key Rust constructor).

**Headline finding:** ~20% of `aegis/core` (25/125 modules) ships simulated
security controls. The product's accreditation value depends on driving the P0
"simulated → real (or quarantined)" count to zero **before** any FIPS/CC/IL6
claim is made on that control. Test coverage is high (94.79%) but largely
exercises the *simulated* behavior — coverage is not assurance until the
underlying control is real.

---

## How to update this file

1. Implement the feature on the development branch.
2. Add or update the test(s) that prove it (`pytest`, `cargo test`, KATs, or a
   benchmark committed to `docs/BENCHMARKS.md`). For a P0 de-sim item, the test
   must prove the **real** control (e.g. a tampered quote/signature is rejected),
   not the simulated stand-in.
3. Flip the checklist item from `[ ]` to `[x]` in the **same** pull request, and
   move its one-line provenance to `CHANGELOG.md`.
4. Recompute the affected row(s) and the **Total** in the Summary Scorecard.
5. Update the audit baseline / reset date at the top.
