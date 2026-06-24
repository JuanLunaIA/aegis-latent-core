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

> **Audit baseline:** 4,575 tests passing · 94.79% coverage · `ruff`/`mypy`/
> `bandit` clean · `cargo test` 23 passing. The open items below are *not*
> regressions in that suite — they are gaps the suite does not yet cover.

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

- [ ] Remove or quarantine `aegis/core/pqc.py` — it advertises "ML-DSA (Dilithium) signatures" but computes **HMAC-SHA512** (a *symmetric* MAC) padded with `os.urandom` to fake a 3293-byte signature; `verify()` needs the private key, so it is forgeable by any verifier and only checks the first 64 of 3293 bytes.
- [ ] Remove or quarantine `aegis/core/pqc_provider.py` — second competing "Dilithium-Simulated-High-Entropy" module using SHAKE-256; duplicate fake PQC surface.
- [ ] Consolidate on the **one real ML-DSA path**: Rust `pqcrypto-mldsa` (FIPS 204) and/or `oqs-python` and/or Vault Transit `ml-dsa-65`, exposed through a single `PQCSigner` interface with real keypair/sign/verify and KATs (known-answer tests) from the FIPS 204 vectors.
- [ ] Remove `aegis/core/pqc_tls.py` simulated X25519/Kyber hybrid handshake; replace with real hybrid KEM (`cryptography` X25519 + `ml-kem-1024`) or delete and rely on TLS-stack PQC.
- [ ] Remove `aegis/core/artifact_signing.py` "Simulate PQC Signature" path; route artifact signing through the real signer + HSM.
- [ ] Add a CI guard that fails the build if any module under `aegis/` (excluding an allow-listed `simulation/` quarantine package) contains `# SIMULATION` / `simulate a … signature` markers.

### P0.2 Fake hardware-root-of-trust & runtime attestation

- [ ] `aegis/core/tpm.py` — replace simulated PCR extend/quote (`_simulated_pcr_value`) with a real TPM 2.0 binding via `tpm2-pytss`; `golden_hash` comparison must use a real quote signature, not a string compare.
- [ ] `aegis/core/hardware_token.py` — TPM2 backend currently logs "using HMAC stub (real PCR quote not yet implemented)" and falls back to software HMAC; implement real PCR-bound token sealing.
- [ ] `aegis/core/cfi_manager.py` — currently hardcodes `is_cfi_enabled = True  # Simulation result`; either parse the real ELF for CFI sections (`readelf`/`pyelftools`) or remove the control so it cannot emit a false "CFI enforced" attestation.
- [ ] `aegis/core/mte_guard.py` — replace simulated `/proc/cpuinfo` MTE detection and "Simulated success of hardware fault detection" with a real check (or quarantine).
- [ ] `aegis/core/tee_manager.py` / `enclave_provider.py` — replace simulated enclave with real SEV-SNP/TDX/SGX attestation (see DX-Gov) or quarantine and stop advertising TEE.
- [ ] `aegis/core/sandbox_l1.py` — replace "we simulate the rule addition" seccomp logic with real `seccomp_syscall_resolve_name`/libseccomp binding (the live `seccomp_guard.py` is real; `sandbox_l1` is a parallel sim that should be reconciled or deleted).
- [ ] `aegis/core/boot_attestation.py` — example golden measurements must come from a signed vendor manifest, not in-source constants.

### P0.3 Fake datapath / network enforcement (LIVE-PATH false assurance)

- [ ] `aegis/core/xdp_dynamic_segmentation.py` is imported by the **live proxy** (`aegis/proxy/app.py:431`). Its `block_ip_immediately()` only adds to an in-memory Python `set` and logs `# Simulation: eBPF_map_update(...DROP)` — **no packet is ever dropped**, and the in-memory blacklist is never consulted on subsequent requests. Either implement a real XDP/eBPF map update (or nftables/ipset fallback) **and** enforce the blacklist on ingress, or rename the control so operators do not believe IPs are kernel-blackholed.
- [ ] `aegis/core/dpdk_engine.py` — simulated DPDK fast path; wire to a real DPDK/AF_XDP datapath or quarantine (see DX-Industrial).
- [ ] `aegis/core/ebpf_monitor.py` — verify the eBPF monitor performs real `bpf()` syscalls or mark advisory.

### P0.4 Fake assurance pipelines

- [ ] `aegis/core/fuzzing_harness.py` — replace "95% chance of no crash, 5% edge case" random simulation with a real fuzzing harness (libFuzzer/`cargo-fuzz`/`atheris`) producing reproducible corpora.
- [ ] `aegis/core/dependency_audit.py` — replace "Simulation of a deep source code audit" / simulated hash check with a real `pip-audit`/`osv-scanner` + hash-pinning verification.
- [ ] `aegis/core/transparency_log.py` — replace simulated transparency log with a real Sigstore/Rekor append-only log binding (see DX-Forensic).
- [ ] `aegis/core/build_reproducibility.py` — replace simulated cache purge / repro check with a real bit-for-bit reproducible build verification.
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
| P0 — Trust integrity (de-sim / real crypto) | 26 | Critical |
| P1 — Supply chain | 6 | High |
| P1 — Live-path correctness | 6 | High |
| P2 — Performance & optimization | 5 | Medium |
| DX — Domain expansion (7 verticals) | 27 | Strategic |
| **Total open** | **70** | — |

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
