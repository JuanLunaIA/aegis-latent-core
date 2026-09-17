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
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | **REG-017 FIXED** — `tools/wal_repair.py` (`CLM-099`). The tool is mostly refusals: a mid-file bad line is declined rather than truncated, because doing otherwise would discard every valid record after it. |
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | **REG-049 FIXED — premise corrected.** The seeded "disk-full deadlock" is not reproducible: `ENOSPC` injected at both real failure points raises and latches `wal_persist_failed`, no deadlock (`reg-049_probe.txt`). Built the real residual instead — an ingress preflight (`CLM-100`) that refuses before the upstream provider is billed, default off. Full re-anchor of W1's prior `FIXED` rows: fresh `pytest` run via the repo's own `.venv` (the bare `pytest` binary is not the venv's and fails all collection with `ModuleNotFoundError: No module named 'aegis'` — an environment artifact, not a regression) shows 6,966 passed / 26 skipped, exactly 30 more than the last recorded 6,936, matching REG-010 (10) + REG-012 (7) + REG-017 (8) + REG-049 (5). |
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | **REG-025 VERIFIED.** The reachability gate that the row asked for already exists and already runs (`scripts/verify_import_reachability.py`, PASS: 223 discovered, 112 reached, 34 roadmap, 77 allowlisted, no undeclared orphans). No code change — the control was already in force; the row needed closing, not building. |
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | **REG-013 FIXED.** Not a premise correction this time: the concern was real. `aegis/telemetry/otel.py` had a complete, independently tested W3C propagation facade with zero production callers — the gap was wiring, not missing capability, so no new propagation logic was written. Wired it into all five governed dispatch call sites via the forwarder's pre-existing, pre-unused `extra_headers` parameter. Found and recorded the one real residual honestly: the Rust fast path for non-streaming OpenAI requests bypasses `extra_headers` entirely and carries no trace context regardless. Fixed a real regression the wiring exposed in an existing test's rigid mock signature. |
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | **REG-011 VERIFIED — premise corrected (Docker was assumed unavailable; it was not).** Started `dockerd`, pulled real `postgres:16-alpine` and `amazon/dynamodb-local` images, and wrote real concurrency tests against both — the compare-and-append guard held under 20-way and repeated 8-way races on both backends, every run. Along the way, fixed a real defect in `tests/conftest.py` (its optional-backend stub shadowed a genuine `asyncpg`/`aioboto3` install because it only checked `sys.modules` membership, contradicting the module's own documented intent), which surfaced and required fixing 7 real regressions in `tests/test_dynamodb_provider_new.py` that depended on the stub's simplified `ClientError` constructor. `CLM-081` updated to drop the "neither was executed" caveat. |
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | **REG-026 VERIFIED, REG-040 VERIFIED — both re-checked from source, not from the prior report.** REG-026's 25-error `aegis_server` figure reproduced exactly under plain `mypy aegis_server`; a near-miss avoided — `mypy-ci.ini` reports 0 for that package only because it sets `ignore_errors = True`, which is not the same claim. REG-040's premise was corrected a **second** time: the intervening autodiscovery note claiming `cargo audit` "no longer reports" `pqcrypto` advisories was itself wrong — three are reported (`RUSTSEC-2026-0162/0163/0166`), on a default-enabled feature, already allowlisted with a written rationale in `.cargo/audit.toml`. Severity corrected P0→P1: unmaintained, not a CVE, already accepted in source. **Reported here as a demonstration of `PD-R1`, not a criticism of the prior session** — the rule exists because a scan's finding can itself be stale, and this round's evidence is what caught it. |
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | **CI-only regression on REG-011's own evidence, found via PR #187 and fixed** — not a new REG, a correction to the previous REG-011 row. `pytest.importorskip("aioboto3"/"asyncpg", ...)` in the two new real-server test files cannot detect "genuinely absent" once `tests/conftest.py` has already cached a `MagicMock` stub into `sys.modules` at collection time, so in CI (which never installs these optional extras) the tests ran against the stub instead of skipping. Reproduced locally by temporarily removing the real packages from `.venv`'s site-packages, matching CI's failure signature exactly (`RuntimeError: ... TestOperation` ×2, `AttributeError: 'coroutine' object has no attribute 'wait'` ×3). Fixed with an explicit `isinstance(module, MagicMock)` guard in both race-test files (skips honestly instead of by accident) and a corrected `_client_error()` in `tests/test_dynamodb_provider_new.py` (its TypeError-only fallback missed the stub silently misbinding two positional args). Full detail and before/after reproduction in `evidence/registry/reg-011_ci_fix.txt`; full suite re-confirmed green both with the packages hidden (35 passed, 2 modules skipped) and restored (`6979 passed, 26 skipped`). |
| 2026-09-17 | `session_01HXm9uxZjTkDFnaV6U8R9oa` | **REG-020 DOCUMENTED.** Reproduced the deviation from source rather than trusting the seed title: `rfc3161_timestamper.py`, `forensic_pdf_report.py`, `iso27037_evidence.py`, and `dfir_export.py` all compute their integrity seal over plain `json.dumps(sort_keys=True, separators=(",", ":"))` — `ensure_ascii` at Python's default `True` and Python's `repr`-based float formatting, neither of which is RFC 8785 JCS. Checked `CLAIMS_MATRIX.md` first: nothing claims RFC 8785 conformance for these four, so no false claim needed retracting, and the seal stays valid same-process tamper-evidence regardless. `forensic_bundle.py`'s `canonical_jcs_bytes` is confirmed genuinely RFC 8785-conformant — it excludes floats from its domain rather than reimplementing ECMAScript formatting. `docs/institutional/DOC-02...md` already disclosed this in prose, but the registry's own bar for `DOCUMENTED` requires the boundary in `UNSUPPORTED_CLAIMS.md` or `BOUNDARIES.md` specifically, so added it to `BOUNDARIES.md`'s Evidence boundaries table. No code change: confirmed neither `sdk/typescript` nor `dashboard` recomputes any of these four seals, so a hand-rolled ECMAScript-compatible encoder would be hardening against a verifier that does not exist. All four doc gates and the reachability gate pass; full suite 6,973 passed / 32 skipped (the 6 extra skips vs. the prior commit are REG-011's live-server tests, expected with no Postgres/DynamoDB containers running this session). |

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
| REG-011 | `[AEG2:ACT-03][BLIND-08]` | CODE | P0 | DB append races drop nodes | **VERIFIED** | **Seed premise corrected: Docker was assumed unavailable and was not** — `dockerd` started successfully in this environment. The guard mechanism (`write_node_atomic`, compare-and-append) already existed for both PostgreSQL (`FOR UPDATE` tip read + unique `prev_hash` index) and DynamoDB (`TransactWriteItems` against a tip item); the gap was that neither had ever been exercised against a real server — every existing test mocked `asyncpg`/`aioboto3` entirely (`CLM-081`'s own forbidden-phrase list already named this). Built real integration coverage instead of assuming a defect: `tests/test_postgres_concurrent_append_race.py` (3 tests) against a live `postgres:16-alpine` container, `tests/test_dynamodb_concurrent_append_race.py` (3 tests) against a live `amazon/dynamodb-local` container — each races 20 (genesis) or 8×3-rounds concurrent writers for one tip and asserts exactly one winner, N-1 `ConcurrentChainMutationError`s, and confirms row/item state independently rather than trusting the callers' own bookkeeping. Both guards held on every run, repeated 4x with no flake. Required fixing `tests/conftest.py`'s optional-backend stub: it stubbed `asyncpg`/`aioboto3`/`botocore` unconditionally by checking only `sys.modules` membership, which shadowed a genuine install that simply hadn't been imported yet — contrary to the module's own stated intent ("a real installation is never shadowed once imported"). The fix surfaced 7 real regressions in `tests/test_dynamodb_provider_new.py`, which constructed `ClientError` with the stub's simplified `code=`/`msg=` kwargs; fixed with a small `_client_error()` helper that builds correctly against either the stub or the real botocore constructor, independent of collection order (this suite uses `pytest-randomly`, so order cannot be relied on). Before: mocked suite alone, `69 passed`, proving nothing about real-server behaviour (`evidence/registry/reg-011_before.txt`). After: 6 real-server tests pass, 169 mocked tests still pass, full suite `6972 passed, 26 skipped` (`reg-011_after.txt`). `CLM-081` updated to drop the "PostgreSQL and DynamoDB... neither was executed" caveat and add the honest one: DynamoDB Local and a containerized PostgreSQL are not a managed service. **Post-closure addendum:** CI (which never installs these optional extras) exposed that `pytest.importorskip` cannot detect conftest's already-cached stub, so the two real-server files ran against a `MagicMock` instead of skipping in that environment; fixed with an explicit stub-detection guard and a corrected `_client_error()` — see the CI-fix session-log entry and `evidence/registry/reg-011_ci_fix.txt`. Residual: not tested under adversarial network partition, only process-level concurrency on one host |
| REG-012 | `[AEG2:ACT-05][BLIND-05][GDPR-17][CLM-098]` | CODE | P0 | Shredded nodes keep dictionary-attackable plaintext hashes | **FIXED** | `CryptoShredder.digest` keys request/response digests with a salt **derived** from the subject key, so the one row `shred` deletes destroys both; scheme `v2-aesgcm256-hmacsha256`. Probe on pre-fix source: `GUESS CONFIRMED AGAINST ERASED RECORD: True`; after: `False` (`evidence/registry/reg-012_before.txt`, `reg-012_after.txt`). Test `tests/test_shredded_digest_confirmability.py` (7). Chain still verifies with the key gone. `UC-037` corrected — it asserted the weakness this removes. Residual: media-sanitisation limits untouched; a keyed digest hides content, not existence, timestamp, tenant or chain position |
| REG-013 | `[AEG2:ACT-07][BLIND-09]` | CODE | P2 | OTel `traceparent` not propagated | **FIXED** | `aegis/telemetry/otel.py` already had a complete, independently tested W3C `traceparent`/`tracestate` parser and injector with **zero callers outside its own test file** — confirmed by grep before touching anything: only `aegis/telemetry/__init__.py`'s re-export and `tests/telemetry/test_otel_siem.py` imported it. The gap was wiring, not missing capability. `_outbound_trace_headers` (`aegis/proxy/app.py`) now parses the inbound header, mints a fresh `span_id` for this hop per W3C (reusing the caller's span_id would make Aegis indistinguishable from its caller), and injects the result via the forwarder's existing `extra_headers` parameter — which every one of the five dispatch call sites already accepted and none used. `CLM-101` added. Test `tests/test_trace_propagation.py` (7). Before: `ImportError` — `_outbound_trace_headers` did not exist (`evidence/registry/reg-013_before.txt`); a probe against the pre-fix commit confirms all five call sites omitted `extra_headers` (`reg-013_probe.txt`). After: 7 passed, full suite unaffected (`reg-013_after.txt`). Along the way, fixed a real regression the wiring exposed in `tests/test_app_coverage.py::test_sse_commit_on_client_disconnect`, whose `fake_stream` mock had a fixed two-positional-argument signature. Residual, found and recorded rather than glossed over: the Rust fast path (`LLMForwarder.forward_json`'s `HAS_RUST` branch — non-streaming OpenAI requests through the built Rust extension) calls `RustForwarder.forward_json_sync(path, body)` directly, which has no headers parameter at all, so that one path carries no trace context regardless of what the caller sent. Every streaming path and every native-Anthropic path is unaffected. This is header propagation only — no span is created or exported (`TraceProvider` remains unwired, no concrete `SpanExporter` exists in production), and the traceparent is not correlated into any evidence node |
| REG-014 | `[AEG2:ACT-08]` | CODE | P2 | `/metrics` dark by default | `SEED` | DECIDE: core dep vs documented extra |
| REG-015 | `[AEG2:ACT-09]` | CODE | P1 | ZK preview cap blowup | `SEED` | |
| REG-016 | `[AEG1:P0#3][CLM-082]` | CODE | P1 | Group-commit memory inversion | `SEED` | PR #180 pinned the invariant rather than building a staging buffer; the chosen semantics need writing down |
| REG-017 | `[STRAT:P0#1][CLM-099]` | CODE | P1 | JSONL torn-tail recovery | **FIXED** | `tools/wal_repair.py`: removes the final line only when it is the only unparseable one; refuses (exit 2) a mid-file fault; dry run by default and exits non-zero; byte-for-byte backup before truncation; re-scans after. `wal_corrupt` fail-closed default unchanged. Test `tests/test_wal_repair.py` (8), including that a repaired WAL reopens without faulting and passes `verify_integrity`. `evidence/registry/reg-017_before.txt`, `reg-017_after.txt`. Residual: does not establish the removed record never happened |
| REG-018 | `[STRAT:P0#3][AEG1:3.2]` | CODE | P1 | Cancellation orphans | `SEED` | |
| REG-019 | `[STRAT:P1#3]` | CODE | P2 | Ledger compaction + cold tiering | `SEED` | |
| REG-020 | `[AEG1:2.2][STRAT:P1#2]` | CODE | P1 | RFC 8785 `ensure_ascii`/float deviation | **DOCUMENTED** | Real, reproduced-from-source deviation, not a premise correction: `aegis/core/rfc3161_timestamper.py:497`, `forensic_pdf_report.py:119`, `iso27037_evidence.py:310`, and `dfir_export.py:479` compute their SHA-256 integrity seal over `json.dumps(obj, sort_keys=True, separators=(",", ":"))` with `ensure_ascii` at Python's default `True` (non-ASCII escaped as `\uXXXX`) and Python's shortest-round-trip float `repr` — neither matches RFC 8785 JCS, which requires raw UTF-8 and the ECMAScript `Number.prototype.toString()` float algorithm. Checked `docs/CLAIMS_MATRIX.md` first: no row claims RFC 8785 conformance for these four functions, so this is not a false public claim to correct. The seal remains valid same-process tamper-evidence (write and verify use the identical Python serializer); the risk is only that an independent, non-Python RFC 8785 implementation would not always reproduce the same bytes. `aegis/core/forensic_bundle.py`'s `canonical_jcs_bytes` is the one genuinely RFC 8785-conformant function in the codebase, and it earns that by excluding floats from its canonical domain entirely (its `normalize()` has no float branch and raises on one) rather than reimplementing ECMAScript float formatting — confirmed by reading the function, not assumed. `docs/institutional/DOC-02_CRYPTOGRAPHIC_FORENSIC_BLUEPRINT.md` already carried this disclosure in prose (§5, line 113) and in its `DOC02-SER-001` evidence-table row (`IMPLEMENTED`, "not RFC 8785 JCS"), but the registry's own terminal-state table requires a `DOCUMENTED` row's boundary to live in `UNSUPPORTED_CLAIMS.md` or `BOUNDARIES.md` specifically — DOC-02 alone did not satisfy that bar. Added the boundary to `docs/BOUNDARIES.md`'s Evidence boundaries table ("Non-JCS integrity seals" row) citing all four call sites and the DOC-02 cross-reference. No code change: rewriting these four serializers to a hand-rolled ECMAScript-compatible RFC 8785 encoder would be speculative hardening against a cross-language verifier that does not exist in this repository (checked `sdk/typescript` and `dashboard` — neither recomputes these specific seals), which is exactly the kind of unrequested validation `AGENTS.md` rule 2 says not to add |
| REG-021 | `[REG-003 residual]` | CODE | P2 | RFC 3161 revocation (OCSP/CRL) | **DOCUMENTED** | `CMSVerificationResult.revocation_checked` is always `False` and asserted so in `tests/test_rfc3161_cms_verification.py`. Stated in `PROVE_IT.md` §5, `INTEGRITY_SEAL.md` §6, `POSITIONING.md` §5 |
| REG-022 | `[AEG2:8.2]` | CODE | P2 | Shredder vault backup/hardware retention hazard | `SEED` | |
| REG-023 | `[AEG1:P1#1][HIPAA]` | CODE | P0 | Pre-forward ePHI scrub | `SEED` | DECIDE — touches the "redaction protects the record, not your provider" boundary |
| REG-024 | `[CLM-064 residual][PR:180]` | CODE | P1 | v1 legacy chains | **VERIFIED** | `tools/anchor_v1_chain_into_v2.py` present; `tests/test_chain_anchor_tool.py` 6 passed |
| REG-025 | `[MO-XII:P6]` | CODE | P2 | Orphan modules | **VERIFIED** | **Seed premise corrected:** not 99. Re-run this session: `python scripts/verify_import_reachability.py` → `modules discovered: 223  reached: 112  declared roadmap: 34  allowlisted: 77` — `PASS: no undeclared orphans, no stale roadmap entries`. The concern this row raised (undeclared orphan modules accumulating unnoticed) is exactly what this gate exists to catch, and it is wired into CI (`REG-D01`-adjacent gates run in `Makefile`'s `security`/`lint` targets); a module reachable neither via an import chain nor a declared roadmap/allowlist entry fails the gate rather than sitting quietly. No code change needed — the control already existed and is exercised. This is not a claim that the 77 allowlisted or 34 roadmap modules are individually justified; each entry's own reason is `scripts/import_reachability_allowlist.txt`'s job, not this row's |
| REG-045 | `[CLM-067][PR:153]` | CODE | P1 | `GrammarFrontierAutomaton` wiring | **VERIFIED** | Wired in `aegis/core/stream_redactor.py:136-137`, instantiated when `enable_phi or enable_pci`. **Not** in `streaming.py` — a naive grep there returns 0 and misreads as unwired |
| REG-046 | `[CLM-068][PR:164]` | CODE | P1 | `CryptoShredder` wiring + `shredding_version` | **VERIFIED** | 5 refs in `aegis/core/crypto_audit.py`; opt-in behind `AEGIS_ENABLE_CRYPTOGRAPHIC_SHREDDING`, off by default (`UC-037`) |
| REG-047 | `[CLM-011]` | CODE | P2 | Windows lock degrade on FAT32/network | `SEED` | |
| REG-048 | `[AEG1:1.3]` | DOC | P2 | NFS/EFS stale `flock` | **VERIFIED** | Already documented in `docs/operations/STORAGE_REQUIREMENTS.md` per PR #183 |
| REG-049 | `[BLIND-10]` | CODE | P1 | Disk-full deadlock | **FIXED — premise corrected** | **Seed premise falsified:** injecting `ENOSPC` at both real failure points (buffered WAL write, `fsync`) produces a raise and a latched `wal_persist_failed` in each case, ledger still responsive afterward, no deadlock — `evidence/registry/reg-049_probe.txt`. Real residual: the failure surfaces only at commit time, after the upstream provider was already called and billed. Fix: `_require_wal_headroom` (`aegis/proxy/app.py`), an ingress preflight gated by `AEGIS_WAL_MIN_FREE_BYTES` (default `0` = off — a false refusal on a nearly-full but working volume is a worse outage than the late detection it replaces), 5s TTL-cached `disk_usage` read, refuses 503 before the forwarder is awaited. A failed `disk_usage` does not refuse (`CLM-100`). Test `tests/test_wal_headroom_preflight.py` (5). Before: 5 failed (`reg-049_before.txt`). After: 5 passed (`reg-049_after.txt`). Full suite 6,966 passed / 26 skipped |
| REG-050 | `[STRAT:1.3]` | CODE | P2 | SSE slow-drip FD exhaustion | `SEED` | Partially mitigated by REG-004's admission gate; FD budget metric not present |

### 4.2 Wave 2 — supply chain / release / ops

| REG | Brands | Class | Sev | Mechanism | Status | Evidence |
|---|---|---|---|---|---|---|
| REG-026 | `[TRACK-C]` | CODE | P2 | mypy `--strict` errors | **VERIFIED — premise reconfirmed** | Seed says 73; the earlier session already corrected that to "`aegis` clean, 25 in `aegis_server`". Re-run this session, both halves independently: `mypy --strict aegis` — clean, 206 files. `mypy aegis_server` (plain, no `--strict`) — exactly **25 errors in 4 files** (checked 14), matching the cited figure exactly: `sqlite_provider.py` (4, `Iterable[Row]` indexing/len), `main.py` (21, missing return annotations, untyped-call, `Any` return, `set` vs `frozenset` argument, `sorted` key type). Note for future re-verification: `mypy --config-file mypy-ci.ini aegis_server` reports **0** errors because that config carries `[mypy-aegis_server.*] ignore_errors = True` — it excludes the package rather than passing it; do not cite that invocation as evidence this row is closed. Tracked for remediation by REG-038 (retire/migrate the dual surface) |
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
| REG-040 | `[RUSTSEC-…][TRACK-B2]` | CODE | P1 | `pqcrypto` unmaintained | **VERIFIED — premise corrected twice** | Seed implied a P0 vulnerability; the intervening autodiscovery note ("no longer reports any `pqcrypto` advisory") was **also wrong**. Re-run this session: `cargo audit --file aegis_rust_v2/Cargo.lock` reports **three** `pqcrypto` advisories — `RUSTSEC-2026-0162` (`pqcrypto-traits`), `-0163` (`pqcrypto-internals`), `-0166` (`pqcrypto-mldsa`), all dated 2026-06-04, all "unmaintained: upstream PQClean project being archived" — **not CVEs**. `pqclean-pqc` is `aegis_rust_v2/Cargo.toml`'s `default` feature (line 25), so these are default-build dependencies, not incidental. All three are **already deliberately allowlisted** in `aegis_rust_v2/.cargo/audit.toml` with a written rationale ("unmaintained upstream advisories; no replacement available yet"), which is why `cargo audit` exits 0 reporting "6 allowed warnings found" rather than failing. The pure-Rust `ml-dsa` backend from task B1 (`CLM-084`) exists as an **opt-in** build flag precisely because it measured 1.43x slower to verify and 4.80x slower to sign — switching the default is a real trade-off, not a bug fix, and is out of this row's scope. Severity corrected P0→P1: an unmaintained-crate warning with no CVE and an already-documented, already-allowlisted acceptance is not a P0. Re-verify against `.cargo/audit.toml`'s ignore list before ever again reporting this class of advisory as "resolved" or "no longer appears" — allowlisted is not absent |
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
| W1 | 30 | 5 | 14 | 2 | 0 | 0 | **9** |
| W2 | 23 | 0 | 4 | 0 | 0 | 0 | **19** |
| W3 | 9 | 0 | 2 | 2 | 0 | 0 | **5** |
| `[DISC]` | 3 | 0 | 0 | 1 | 0 | 0 | **2** |
| **Total** | **65** | **5** | **20** | **5** | **0** | **0** | **35** |

Human class (9) is excluded from the burn-down by design.

---

## 6. What this session did not do

Recorded because a registry that omits its own coverage gaps asserts a completeness it did not earn.

**Autodiscovery scans not run:** 3 (`UNSUPPORTED_CLAIMS`/`ROADMAP` open-item extraction), 6 (CI logs, last 30 runs, for flaky/skipped suites), 7 (`evidence/` `NOT_EXECUTED` and `BLOCKED` sections), 8 (full battery failure/skip triage — the suite is green at 6,936 passed / 26 skipped, but the **26 skips were not individually triaged**), 9 (doc-gate findings — all four gates pass, so there are no findings to convert).

**35 rows remain `SEED`**, including genuinely confirmed P0 work: REG-023 (pre-forward ePHI), REG-027 (gateway not on PyPI), REG-028 (release readback automation), and REG-042 (multi-pod total order, FATAL).

**Per `PD-R2` and the `R4` gate, this registry is `NOT SEALED`.** No closure attestation is emitted, and none should be written until the `SEED` count reaches zero.

**Seed premises corrected by verification** — several seeded rows carried figures that current source contradicts, which is why `PD-R1` requires re-verifying a seed before working it. Two of these were corrected **twice**, by different sessions, which is itself evidence for the rule rather than an embarrassment: re-verification caught re-verification's own mistakes.

- REG-025: "99 orphan modules" → 78 allowlisted + 34 declared roadmap, of 223 discovered (now 112 reached / 77 allowlisted / 34 roadmap of 223, per the gate's live count — the exact split drifts commit to commit and should be re-read from `verify_import_reachability.py`'s own output, never copied from a prior report).
- REG-026: "73 mypy `--strict` errors" → `aegis` is clean over 206 files; 25 remain in `aegis_server/` — **reconfirmed this session** with the exact figure reproduced (4 files, 25 errors) under plain `mypy aegis_server`. A same-session near-miss is recorded honestly: `mypy --config-file mypy-ci.ini aegis_server` reports 0, but only because that config sets `ignore_errors = True` for the package — it is not evidence the errors are fixed, and citing it would have been a false closure.
- REG-040: `pqcrypto` advisories → an intervening autodiscovery note claimed `cargo audit` "no longer reports" them; **that note was itself wrong**. Re-verified this session: three `pqcrypto` advisories are reported (`RUSTSEC-2026-0162/0163/0166`, all "unmaintained", none a CVE), on a default-enabled feature, and all three are already allowlisted in `aegis_rust_v2/.cargo/audit.toml` with a written rationale. Allowlisted is not absent, and "no longer reported" was a misreading of `cargo audit`'s exit code rather than its findings.

---

**Related:** [Registry Human Pack](REGISTRY_HUMAN_PACK.md) · [Claims Matrix](CLAIMS_MATRIX.md) · [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md) · [Commercial Readiness](commercial/COMMERCIAL_READINESS.md) · [Roadmap](../ROADMAP.md)
