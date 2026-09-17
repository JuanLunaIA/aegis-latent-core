<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Master Defect and Debt Registry

**Audience:** the maintainer, and any agent or engineer continuing this work.
**Scope:** every known defect, debt item and open decision, with a stable id and a terminal state.
**Boundary:** a row records a classification and its evidence pointer. It does not license a public claim — [Claims Matrix](CLAIMS_MATRIX.md) does, and [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md) blocks what neither permits.

**This registry is the continuation point.** A future session resumes from this file, not from a conversation. Seeded from MISSION ORDER XIV on 2026-09-17 and extended by the autodiscovery scans in §3.

---

## 1. Status vocabulary

Five terminal states. `SEED` is **not** terminal — it means the row has been recorded but not yet worked.

| Status | Requires |
|---|---|
| `FIXED` | (a) diff, (b) regression test name, (c) executed command output |
| `VERIFIED` | Already correct in current source; re-run output recorded |
| `DOCUMENTED` | Accepted limitation, boundary written into `UNSUPPORTED_CLAIMS.md` or `BOUNDARIES.md` |
| `BLOCKED` | Exact failing command + error + owner + unblock path |
| `WONT-FIX` | Decision + rationale + claim updated |
| `SEED` | **Not terminal.** Recorded, not yet worked |

**No row is ever deleted.** Status transitions only.

---

## 2. Session log

| Date | Session | What was done |
|---|---|---|
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | Registry created. Autodiscovery scans 1–5, 10 executed. W1 verification batch run. 13 rows brought to terminal state; the remainder stay `SEED`. |
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | **REG-010 FIXED** — retrieved-content injection scanning wired at admission (`CLM-097`). A probe run while writing the test found the first payload was caught by the WAF anyway, so the test proved nothing; it was re-based on a payload the WAF allows and the scanner catches. |
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | **REG-012 FIXED** — keyed payload digests under shredding (`CLM-098`). Judged **not** an invariant relaxation under `PD-R5`: no fail-closed path becomes fail-open and `verify_integrity` is unaffected, so no owner decision was required. `UC-037` corrected: it stated the weakness as a standing limitation. |

**Current seal state: NOT SEALED** — rows remain in `SEED`. See §6.

---

## 3. Autodiscovery results (2026-09-17)

Executed against `e96dc30`. Each scan's actual output, not a summary of intent.

| # | Scan | Command | Result |
|---|---|---|---|
| 1 | Source markers | `grep -rn "TODO\|FIXME\|HACK\|NOT_WIRED\|UNWIRED"` over `aegis/ aegis_rust_v2/src/ aegis_server/ scripts/ tools/` | **0 real markers.** All 9 hits are the tooling that *detects* markers (`verify_docs.py`, `forensic_checks.py`, `verify_documentation.py`, `audit_documentation_corpus.py`). No new REG |
| 2 | Claims register status mix | `grep` over `CLAIMS_MATRIX.md` | 71 `IMPLEMENTED`, 11 `ROADMAP`, 10 `CONFIGURATION-DEPENDENT`, 7 `MEASURED`, 2 `LEGAL-REVIEW-REQUIRED`. The 23 non-`IMPLEMENTED` rows are already tracked by seeded REGs or by `ROADMAP.md` |
| 4 | Reachability allowlist | `wc -l scripts/import_reachability_allowlist.txt` | 97 lines; gate reports 223 discovered / 111 reached / 34 roadmap / 78 allowlisted. **The seed's "99 orphan modules" is stale** — see REG-025 |
| 5a | `pip-audit` | executed | 14 advisories, **all on `pip` 24.0 and `setuptools` 79.0.1**. Neither is in `requirements.lock` — they are venv bootstrap tooling, not shipped runtime. New: **REG-D01** |
| 5b | `cargo audit` | executed | **0 vulnerabilities.** 2 allowed warnings: `bincode` 1.3.3 unmaintained (`RUSTSEC-2025-0141`), `chacha20` 0.10.1 yanked. New: **REG-D02**, **REG-D03**. Note: the `pqcrypto` advisories named in REG-040 **no longer appear** |
| 5c | `npm audit` | executed | **0 vulnerabilities** |
| 10 | Stale branches | `git ls-remote --heads origin` | Only `main` and the working branch exist. `docs/comprehensive-corpus-synchronization` is **gone** — REG-033 resolves on inspection |

**Discovery total: 3 new REG ids (`REG-D01`–`REG-D03`), 2 seeded rows resolved by inspection (REG-033, and REG-032 below).**

Scans 3, 6, 7, 8, 9 were **not executed this session** and are recorded as outstanding in §6 rather than reported as clean.

---

## 4. Registry

### 4.1 Wave 1 — security-critical code

| REG | Brands | Class | Sev | Mechanism | Status | Evidence |
|---|---|---|---|---|---|---|
| REG-001 | `[AEG2:ACT-01][BLIND-06][CLM-093][PR:180]` | CODE | P0 | Layer-2 WAF received unnormalized text (homoglyph bypass) | **VERIFIED** | `_guard_variants` present in `aegis/proxy/waf.py`; `tests/test_waf_layer2_normalization.py` green in the 143-test batch → `evidence/registry/w1_verify_batch_2026-09-17.txt` |
| REG-002 | `[AEG2:ACT-02][BLIND-03][CLM-095][PR:180]` | CODE | P0 | Forensic manifest unsigned (co-tampering) | **VERIFIED** | `manifest_signing_key` / `manifest.json.sig` in `aegis/core/forensic_bundle.py` (12 refs); `tests/test_forensic_bundle_manifest_signature.py` green |
| REG-003 | `[AEG2:ACT-06][BLIND-07][CLM-096][PR:180]` | CODE | P0 | RFC 3161 verify lacked CMS/X.509 | **VERIFIED** | `aegis/core/rfc3161_cms.py` present; `tests/test_rfc3161_cms_verification.py` green. Residual revocation → REG-021 |
| REG-004 | `[CLM-094][PR:180][AEG1:OOM]` | CODE | P0 | Unbounded concurrent streams (OOM) | **VERIFIED** | `StreamAdmissionGate` wired in `aegis/proxy/app.py` (3 refs); `tests/test_stream_admission_gate.py` green. Per-process-only limit is stated in `INTEGRITY_SEAL.md` §5 and `POSITIONING.md` §5 |
| REG-005 | `[CLM-092][AEG2:7.4]` | CODE | P0 | `forwarded_allow_ips="*"` | **VERIFIED** | `aegis_server/main.py:1081` binds it to `settings.get_trusted_proxy_cidrs()`, not `"*"` |
| REG-006 | `[CLM-090][LBP-02]` | CODE | P0 | `legal_admissibility` deception | **VERIFIED** | `signature_assurance` present in `aegis/core/crypto_audit.py` (10 refs); weakest-link lattice + construction-time warning observed firing during this session's ledger runs |
| REG-007 | `[AEG1:7.1#2]` | CODE | P0 | Deque rollover false-corruption | **VERIFIED** | `_window_anchor_hash` present in `aegis/core/crypto_audit.py` (4 refs) |
| REG-008 | `[CLM-064][AEG2:4.1]` | CODE | P0 | MMR v1 type-confusion | **VERIFIED** | `aegis-mmr-inclusion-v2` is the default for new chains; a live ledger commit this session produced `scheme=aegis-mmr-inclusion-v2`. Legacy chains → REG-024 |
| REG-010 | `[AEG2:ACT-04][BLIND-02][AML.T0051.001][CLM-097]` | CODE | P0 | `RAGInjectionScanner` unwired | **FIXED** | `_guard_retrieved_content` in `aegis/proxy/app.py` runs the scanner at all three governed admission sites, after the WAF and before the forwarder; refusal is committed to the signed chain first. Test `tests/test_rag_injection_admission.py` (10). Before: 6 failed / 4 passed (`evidence/registry/reg-010_before.txt`). After: 10 passed (`reg-010_after.txt`). Full suite 6,946 passed / 26 skipped. Residual: finite pattern set, `UC-042` ceiling unchanged |
| REG-011 | `[AEG2:ACT-03][BLIND-08]` | CODE | P0 | DB append races drop nodes | `SEED` | Needs testcontainers Postgres/Dynamo harness; likely `BLOCKED` if this environment lacks Docker |
| REG-012 | `[AEG2:ACT-05][BLIND-05][GDPR-17][CLM-098]` | CODE | P0 | Shredded nodes keep dictionary-attackable plaintext hashes | **FIXED** | `CryptoShredder.digest` keys request/response digests with a salt **derived** from the subject key, so the one row `shred` deletes destroys both; scheme `v2-aesgcm256-hmacsha256`. Probe on pre-fix source: `GUESS CONFIRMED AGAINST ERASED RECORD: True`; after: `False` (`evidence/registry/reg-012_before.txt`, `reg-012_after.txt`). Test `tests/test_shredded_digest_confirmability.py` (7). Chain still verifies with the key gone. `UC-037` corrected — it asserted the weakness this removes. Residual: media-sanitisation limits untouched; a keyed digest hides content, not existence, timestamp, tenant or chain position |
| REG-013 | `[AEG2:ACT-07][BLIND-09]` | CODE | P2 | OTel `traceparent` not propagated | `SEED` | |
| REG-014 | `[AEG2:ACT-08]` | CODE | P2 | `/metrics` dark by default | `SEED` | DECIDE: core dep vs documented extra |
| REG-015 | `[AEG2:ACT-09]` | CODE | P1 | ZK preview cap blowup | `SEED` | |
| REG-016 | `[AEG1:P0#3][CLM-082]` | CODE | P1 | Group-commit memory inversion | `SEED` | PR #180 pinned the invariant rather than building a staging buffer; the chosen semantics need writing down |
| REG-017 | `[STRAT:P0#1]` | CODE | P1 | JSONL torn-tail recovery | `SEED` | Fix = `wal_repair` tool under an explicit flag; fail-closed stays the default |
| REG-018 | `[STRAT:P0#3][AEG1:3.2]` | CODE | P1 | Cancellation orphans | `SEED` | |
| REG-019 | `[STRAT:P1#3]` | CODE | P2 | Ledger compaction + cold tiering | `SEED` | |
| REG-020 | `[AEG1:2.2][STRAT:P1#2]` | CODE | P1 | RFC 8785 `ensure_ascii`/float deviation | `SEED` | |
| REG-021 | `[REG-003 residual]` | CODE | P2 | RFC 3161 revocation (OCSP/CRL) | **DOCUMENTED** | `CMSVerificationResult.revocation_checked` is always `False` and asserted so in `tests/test_rfc3161_cms_verification.py`. Stated in `PROVE_IT.md` §5, `INTEGRITY_SEAL.md` §6, `POSITIONING.md` §5 |
| REG-022 | `[AEG2:8.2]` | CODE | P2 | Shredder vault backup/hardware retention hazard | `SEED` | |
| REG-023 | `[AEG1:P1#1][HIPAA]` | CODE | P0 | Pre-forward ePHI scrub | `SEED` | DECIDE — touches the "redaction protects the record, not your provider" boundary |
| REG-024 | `[CLM-064 residual][PR:180]` | CODE | P1 | v1 legacy chains | **VERIFIED** | `tools/anchor_v1_chain_into_v2.py` present; `tests/test_chain_anchor_tool.py` 6 passed |
| REG-025 | `[MO-XII:P6]` | CODE | P2 | Orphan modules | `SEED` | **Seed premise corrected:** not 99. Gate reports 78 allowlisted + 34 declared roadmap of 223 discovered |
| REG-045 | `[CLM-067][PR:153]` | CODE | P1 | `GrammarFrontierAutomaton` wiring | **VERIFIED** | Wired in `aegis/core/stream_redactor.py:136-137`, instantiated when `enable_phi or enable_pci`. **Not** in `streaming.py` — a naive grep there returns 0 and misreads as unwired |
| REG-046 | `[CLM-068][PR:164]` | CODE | P1 | `CryptoShredder` wiring + `shredding_version` | **VERIFIED** | 5 refs in `aegis/core/crypto_audit.py`; opt-in behind `AEGIS_ENABLE_CRYPTOGRAPHIC_SHREDDING`, off by default (`UC-037`) |
| REG-047 | `[CLM-011]` | CODE | P2 | Windows lock degrade on FAT32/network | `SEED` | |
| REG-048 | `[AEG1:1.3]` | DOC | P2 | NFS/EFS stale `flock` | **VERIFIED** | Already documented in `docs/operations/STORAGE_REQUIREMENTS.md` per PR #183 |
| REG-049 | `[BLIND-10]` | CODE | P1 | Disk-full deadlock | `SEED` | |
| REG-050 | `[STRAT:1.3]` | CODE | P2 | SSE slow-drip FD exhaustion | `SEED` | Partially mitigated by REG-004's admission gate; FD budget metric not present |

### 4.2 Wave 2 — supply chain / release / ops

| REG | Brands | Class | Sev | Mechanism | Status | Evidence |
|---|---|---|---|---|---|---|
| REG-026 | `[TRACK-C]` | CODE | P2 | mypy `--strict` errors | **SEED — premise corrected** | Seed says 73. Actual: `mypy --strict aegis` is **clean over 206 files**. 25 errors remain in `aegis_server/` only |
| REG-027 | `[PR:180 note]` | CODE | P0 | PyPI `aegis-latent-core` `5.0.0` unpublished | `SEED` | Confirmed still true. `publish_pypi.yml` builds `sdk/python` only |
| REG-028 | `[TRACK-A1]` | CODE | P0 | Release readback automation | `SEED` | |
| REG-029 | `[TRACK-A2]` | CODE | P1 | Consumer provenance one-liner | `SEED` | |
| REG-030 | `[TRACK-A3]` | CODE | P1 | PyPI byte-difference | `SEED` | |
| REG-031 | `[TRACK-A4]` | BLOCKED-ENV | P1 | `syft`/`cosign`/`cargo-fuzz` absent | `SEED` | |
| REG-032 | `[TRACK-A5]` | CODE | P3 | Untracked coverage/WAL artifacts | **VERIFIED** | `git ls-files` finds no `.coverage`, `coverage.json` or `.wal`. One `.jsonl` under `evidence/` is a deliberate evidence artifact |
| REG-033 | `[TRACK-A5]` | CODE | P3 | Stale branch `docs/comprehensive-corpus-synchronization` | **VERIFIED** | `git ls-remote --heads origin` returns only `main` and the working branch. Branch no longer exists |
| REG-034 | `[AEG2:1.4]` | CODE | P1 | `cosign verify` + `gh attestation verify` + `SHA256SUMS` sweep | `SEED` | Expected `BLOCKED` — tooling absent here |
| REG-035 | `[TRACK-C1]` | CODE | P1 | Reference deployment profile acceptance | `SEED` | |
| REG-037 | `[TRACK-C3]` | CODE | P2 | Memory/disk/rotation recovery tests | `SEED` | |
| REG-038 | `[TRACK-C4]` | CODE | P2 | Retire/migrate `aegis_server` dual surface | `SEED` | Interacts with REG-026's residual 25 errors |
| REG-039 | `[TRACK-ops]` | CODE | P2 | K8s operator placeholder image | `SEED` | |
| REG-040 | `[RUSTSEC-…][TRACK-B2]` | CODE | P0 | `pqcrypto` unmaintained | **SEED — premise likely resolved** | `cargo audit` no longer reports any `pqcrypto` advisory. Needs confirmation that the ml-dsa migration (task B1) removed the dependency rather than the advisory being withdrawn |
| REG-041 | `[CLM-040]` | CODE | P1 | ML-DSA verify timing `p=0.0` | `SEED` | |
| REG-051 | `[AEG2:13.2]` | CODE | P1 | Missing harnesses | `SEED` | Homoglyph parity harness now exists (REG-001); postgres-race and OOM-saturation do not |
| REG-053 | `[P2-7]` | CODE | P3 | Coverage badge stale | **VERIFIED** | Badge removed from `README.md` in PR #184 |
| REG-054 | `[P2-2]` | DOC | P3 | `mmr.py:71` stale docstring | `SEED` | |
| REG-055 | `[P2-4]` | CODE | P3 | Dual `httpx`+`requests`, numpy `isfinite` | `SEED` | |
| REG-056 | `[P2-5]` | CODE | P3 | Checked-in protobuf codegen | `SEED` | |
| REG-058 | `[P3-1]` | CODE | P3 | Samples/HTML + snapshots in repo | `SEED` | |
| REG-059 | `[P3-2]` | DOC | P3 | Buyer-guide duplication | `SEED` | |
| REG-060 | `[P3-5]` | DOC | P3 | `.aegis_ai_context` purpose note | `SEED` | |

### 4.3 Wave 3 — architecture decisions

| REG | Brands | Class | Sev | Mechanism | Status | Evidence |
|---|---|---|---|---|---|---|
| REG-042 | `[BLIND-01][CLM-012]` | ARCH | FATAL | Multi-pod total order absent | `SEED` | DECIDE: centralized writer / compare-and-append / Raft. ADR required either way |
| REG-043 | `[CLM-019][TRACK-B5]` | ARCH | P1 | `zk_proof` public surface | `SEED` | |
| REG-044 | `[TRACK-B3]` | ARCH | P2 | `CausalMmr` wiring | `SEED` | `GossipDaemon` exists (task C1) — `UC-038`'s "not wired" text may now be stale; verify before deciding |
| REG-A01 | `[BLIND-01]` | ARCH | FATAL | Single-node contract | **DOCUMENTED** | `UC-005`, `UC-038`, `CLM-064`; `README.md` §Boundaries; `POSITIONING.md` §5 |
| REG-A02 | `[AEG1:2.3][LBP-02]` | ARCH | HIGH | Host-root / HMAC forgery | **DOCUMENTED** | `UC-041`; construction-time warning; `PROVE_IT.md` §5; `OBJECTION_HANDLING.md` §6 |
| REG-A03 | `[LBP-04]` | ARCH | MEDIUM | Formal non-refinement | **VERIFIED** | `README.md` §Formal verification states the refinement gap and the Kani exception |
| REG-A04 | `[AEG2:8.1][GDPR]` | ARCH | HIGH | Hash pseudonymity | `SEED` | Depends on REG-012. `UC-037` carries `LEGAL-REVIEW-REQUIRED` |
| REG-A05 | `[LBP-01]` | ARCH | MEDIUM | fsync PLP dependency | `SEED` | `STORAGE_REQUIREMENTS.md` exists; currency not re-verified this session |
| REG-A06 | `[STRAT:6]` | ARCH | HIGH | Valuation overclaim ($35–50M) | **VERIFIED** | `UC-032` blocks it; PR #184's claim ledger recorded zero valuation figures corpus-wide |

### 4.4 Autodiscovery additions

| REG | Brands | Class | Sev | Mechanism | Status | Evidence |
|---|---|---|---|---|---|---|
| REG-D01 | `[DISC]` | CODE | P3 | `pip` 24.0 and `setuptools` 79.0.1 in the dev venv carry 14 advisories | **DOCUMENTED** | Neither is in `requirements.lock`; they are venv bootstrap tooling and **not shipped runtime**. The locked runtime is clean. Refresh on venv rebuild |
| REG-D02 | `[DISC][RUSTSEC-2025-0141]` | CODE | P2 | `bincode` 1.3.3 unmaintained | `SEED` | `cargo audit` allowed-warning. Not a vulnerability; an unmaintained-crate warning |
| REG-D03 | `[DISC]` | CODE | P2 | `chacha20` 0.10.1 yanked | `SEED` | `cargo audit` allowed-warning |

### 4.5 Human class — never agent-executed

`REG-H01`…`REG-H09` are recorded in [Registry Human Pack](REGISTRY_HUMAN_PACK.md). They are reproduced there rather than here because **no code REG substitutes for any of them**, and mixing them into the worklist produces a roadmap that looks closeable and is not.

Their status is tracked in [Commercial Readiness](commercial/COMMERCIAL_READINESS.md) as `CR-01`…`CR-07`. All `NOT STARTED`.

---

## 5. Burn-down

| Wave | Total | FIXED | VERIFIED | DOCUMENTED | BLOCKED | WONT-FIX | open (`SEED`) |
|---|---|---|---|---|---|---|---|
| W1 | 30 | 2 | 12 | 1 | 0 | 0 | **15** |
| W2 | 23 | 0 | 2 | 0 | 0 | 0 | **21** |
| W3 | 9 | 0 | 2 | 2 | 0 | 0 | **5** |
| `[DISC]` | 3 | 0 | 0 | 1 | 0 | 0 | **2** |
| **Total** | **65** | **2** | **16** | **4** | **0** | **0** | **43** |

Human class (9) is excluded from the burn-down by design.

---

## 6. What this session did not do

Recorded because a registry that omits its own coverage gaps asserts a completeness it did not earn.

**Autodiscovery scans not run:** 3 (`UNSUPPORTED_CLAIMS`/`ROADMAP` open-item extraction), 6 (CI logs, last 30 runs, for flaky/skipped suites), 7 (`evidence/` `NOT_EXECUTED` and `BLOCKED` sections), 8 (full battery failure/skip triage — the suite is green at 6,936 passed / 26 skipped, but the **26 skips were not individually triaged**), 9 (doc-gate findings — all four gates pass, so there are no findings to convert).

**43 rows remain `SEED`**, including genuinely confirmed P0 work: REG-011 (DB append races), REG-023 (pre-forward ePHI), REG-027 (gateway not on PyPI), REG-028 (release readback automation), and REG-042 (multi-pod total order, FATAL).

**Per `PD-R2` and the `R4` gate, this registry is `NOT SEALED`.** No closure attestation is emitted, and none should be written until the `SEED` count reaches zero.

**Seed premises corrected by verification** — three seeded rows carried figures that current source contradicts, which is why `PD-R1` requires re-verifying a seed before working it:

- REG-025: "99 orphan modules" → 78 allowlisted + 34 declared roadmap, of 223 discovered.
- REG-026: "73 mypy `--strict` errors" → `aegis` is clean over 206 files; 25 remain in `aegis_server/` alone.
- REG-040: `pqcrypto` advisories → no longer reported by `cargo audit`; two different warnings appear instead.

---

**Related:** [Registry Human Pack](REGISTRY_HUMAN_PACK.md) · [Claims Matrix](CLAIMS_MATRIX.md) · [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md) · [Commercial Readiness](commercial/COMMERCIAL_READINESS.md) · [Roadmap](../ROADMAP.md)
