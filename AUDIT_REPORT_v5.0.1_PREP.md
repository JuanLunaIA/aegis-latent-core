# AUDIT_REPORT_v5.0.1_PREP

**Mission:** deep forensic audit, gap analysis and registry consolidation toward `v5.0.1`.
**Target:** `JuanLunaIA/aegis-latent-core`, branch `registry-closure-2026-09-21`, HEAD `289e4ea` (tree clean at audit start).
**Date:** 2026-09-21 (UTC). **Performed by:** the agent, with six independent read-only delegated scans; every finding in this report carries a parent verification verdict below.
**Regulatory frame:** Regulation (EU) 2024/1689 (EU AI Act, Arts. 6, 9, 12, 13, 14, 17), Directive 2014/65/EU (MiFID II, Arts. 16, 16(6), 16(7), 25(1), 24) and Regulation (EU) No 596/2014 (MAR, Art. 12), verified against EUR-Lex / the EC AI Act Service Desk / ESMA sources as cited in §5. The repository's own authorities (`docs/CLAIMS_MATRIX.md`, `docs/institutional/UNSUPPORTED_CLAIMS.md`, `docs/BOUNDARIES.md`, `docs/institutional/DOC-05_REGULATORY_DOSSIER.md`) govern; this audit adds evidence, it does not widen any claim.

**Corrections to the mission brief (established first-hand before acting):**
1. There is no `docs/UNSUPPORTED_CLAIMS.md`; the register lives at `docs/institutional/UNSUPPORTED_CLAIMS.md`. This report uses the real path and adds entries there.
2. `docs/REGISTRY.md` is a defect/debt registry (its own scope line: "every known defect, debt item and open decision"), **not** a module inventory — the brief's premise for that file is corrected in §5.5 and no module inventory exists anywhere in the tree (that gap is itself finding AF-025/UC-057).
3. "Fence-on-cancel" is not a term used anywhere in this repository (0 grep hits). The property the brief describes is verified under its real name — cancellation/teardown ownership in `aegis/proxy/streaming.py` — and **fails** on the teardown style the ASGI stack actually delivers; see AF-003.
4. The suite/gate figures in `INTEGRITY_SEAL.md` and `README.md` no longer reproduce (see AF-019); this audit's own measurements are stated with the exact command beside them.

---

## 1. Executive summary — critical blockers

**16 findings are P1.** None of them is a fabricated claim, and two compliance-class P1s are register contradictions rather than unbacked assertions. The P1 set, in one line each:

| ID | Area | One-line blocker |
|---|---|---|
| AF-001 | Docs | `docs/architecture/DEEP_DIVE.md:288` advertises a `chain-of-custody` capability that the project's own ISO/IEC 27037 boundary says does not exist (no custody record is created — UC-024). |
| AF-002 | Docs | `docs/architecture/DEEP_DIVE.md:289` uses the blocked phrase "trusted timestamp" without naming the two gaps (no revocation checking; no RFC 5280 name-constraint/policy/EKU evaluation) — CLM-014/CLM-096. |
| AF-003 | Docs | `docs/compliance/EU_AI_ACT_TECHNICAL_INPUTS.md:67` still carries the superseded "the record holds the scrubbed form" text that REG-023/UC-045 corrected. |
| AF-004 | Docs | `docs/compliance/HIPAA_TECHNICAL_INPUTS.md:67` still presents "PHI reaches the provider unscrubbed" / "redaction changes the evidence record only" — contradicted by the amended boundary and UC-045. |
| AF-005 | Python | Rewriting only the self-declared `signature_scheme` label makes `verify_integrity()` return `(True, None)` and `signature_assurance` report `ASYMMETRIC_HARDWARE_ATTESTED` with every signature `unverified` — reproduced first-hand. |
| AF-006 | Python | `GET /v1/audit/nodes/{hash}/evidence` returns **HTTP 500 for every node** (the JCS canonicalizer rejects the always-present float fields) — reproduced first-hand. |
| AF-007 | Docs | `docs/BENCHMARKS.md:37` still lists the retracted 10,000-request distribution (p99 1,189.891 ms) as the retained measurement. |
| AF-008 | Docs | `docs/BOUNDARIES.md:30` publishes ZK cost numbers that `CLM-089` forbids ("none is claimed… not a reproducible artifact"). |
| AF-009 | Docs | `docs/PRODUCT_BRIEF_US.md:43` repeats the retracted 10,000 records / p99 1,189.89 ms pair in a buyer brief. |
| AF-010 | Docs | `docs/PROSPECTUS.md:58` presents the retracted v3.1.0 backpressure figures as the product's measured evidence. |
| AF-011 | Docs | `docs/benchmarks/BENCHMARK_RESULTS.md:15` still carries the retracted row while admitting its raw JSON is not committed. |
| AF-012 | Docs | The register's own `UC-018` retraction is contradicted by twelve documents that still cite the retracted run (verified count — see AF-007/009/010/011 and AUD-06). |
| AF-013 | Python | On the teardown styles the ASGI stack delivers (anyio cancellation, `aclose()`/`GeneratorExit`), **no terminal evidence node is written** while the response advertises `pending-terminal` — reproduced first-hand. |
| AF-014 | Rust | `AuditRingBuffer(capacity)` is unvalidated: `0` panics; `2**40` aborts the interpreter — reproduced first-hand. |
| AF-015 | Rust | Tokio runtime init uses `.expect()`, aborting the process on thread-creation failure instead of raising a Python exception. |
| AF-016 | Rust | A second `RustWal` handle on one path **silently overwrites committed frames**; the `SAFETY` invariant is unenforced — reproduced first-hand. |

Top P2 themes: the retracted-figure sweep beyond the buyer heads above (AUD-06); gate-scope drift between the Makefile and CI, with `scripts/*.py` outside every gate (AF-095, AUD-18); stale baselines and counts across navigation and seal artifacts (AF-026 for `llms.txt`, AF-059 for the unwired reachability control, AUD-19); MiFID II/MAR register silence plus two overclaiming, unwired compliance modules (AF-028, AF-029, AUD-20); the missing module inventory and per-module ownership (AF-024, AF-027, AUD-25); registry-rule boundary gaps for three already-terminal rows (AF-023, AUD-21); and unbounded enterprise buffering plus unlocked audit reads (AF-037, AF-038, AUD-08/AUD-09).

**What is *not* in this report, deliberately:** no fabricated certification claim was found (§4), no hardcoded secrets were found, no weak-RNG/md5/shell-injection defect survived verification (each candidate was checked and disproved — §4), and no evidence was manufactured: every measured figure below was produced by a command run by the parent on this host, quoted beside the finding.

---

## 2. Method, coverage and verification protocol

**File universe at HEAD (tracked files, excluding `.venv/`, `target/`, caches):** 565 `.py`, 19 `.rs`, 253 `.md`, 62 `.txt`, 33 `.yml/.yaml`, 7 `.toml`, 20 `.sh`. Markdown/text split: `docs/` 109, `evidence/` 85, `.claude/` 77, root 21, `.aegis_ai_context/` 7, remainder in `sdk/`, `benchmarks/`, `tools/`, `Samples/`.

**Layers, and what "exhaustive" means here (stated plainly):** the brief asks for a line-by-line reading of every file. That is not what was done, and pretending otherwise would be fabrication. What was done:

1. **Mechanical scans over 100% of tracked source files** (the parent): secrets/credential patterns; `eval`/`exec`/`pickle`/`yaml.load`/`os.system`/`shell=True`; weak hashes; non-constant-time comparisons; unbounded reads (`read()`, `readlines()`); unbounded loops; silent exception swallowing; traceback/exception text in responses; workflow `permissions` and action pinning. Every candidate hit was then opened and adjudicated — the verified-clean outcomes are recorded in §4 so they are not re-flagged.
2. **Six independent read-only delegated deep scans** (final cause), which read in full or in relevant part the modules they name and left reproducible probes in `/home/luna/.hermes/cache/scratch/`: Python concurrency/memory/error-handling; cryptographic and durability paths; the Rust crate; performance/quantitative claims across all `.md`/`.txt`; compliance/regulatory statements across every `.md`; governance coverage (inventory, maps, roadmap, registry rule).
3. **Parent verification of every claim before it entered this report.** Verdict vocabulary used in §3: **REPRODUCED FIRST-HAND** (the parent re-ran the probe or command and got the same result), **LINE-VERIFIED** (the parent printed the cited line/region from disk and it matches), or a named exception (e.g. a refined claim, or a corrected citation). Children's measurement-only results that the parent did not re-execute are labelled as such.
4. **Boundaries of this audit** are in §8. Notably: the Rust probes ran against a locally built `libaegis_rust.so`; the ZK feature stays unexecuted on this pre-ADX host (`REG-D04` boundary, not re-reported); no live TPM/HSM/PKCS#11 hardware was exercised; `docker`/`gh`/`cosign`/`syft`/`protoc` are absent on this host.

**Gate truth at HEAD (parent-run, this session):** `pytest` at the same tip: 6,868 passed / 120 skipped. `mypy --strict aegis sdk/python/src`: 5 errors in `sdk/python/src` (optional SDK deps absent in this venv); `mypy --strict aegis` alone is clean. `ruff check` (CI path list): clean; `ruff format --check .`: **exit 1, 11 files** (AF-018). Doc gates (`verify_documentation --strict`, `verify_claims` 102 claims/0 findings, `verify_links`) pass at HEAD before this report; this report re-runs them after the register edits.

---

## 3.1 A. Runtime defects — shipped Python (concurrency, crypto, durability)

#### AF-005 · P1 · [CRITICAL_SECURITY] · `aegis/core/crypto_audit.py:1442`

**Defect.** P1 CONFIRMED-BY-PARENT-RERUN. verify_integrity() dispatches signature checking on the node's own self-declared, hash-unbound field signature_scheme: HMAC is verified only when scheme == 'hmac-sha256' and no other scheme is ever verified (ed25519-fallback, pqc-ml-dsa, pkcs11-*). signature_scheme is not an input to node_hash nor to the signed payload, so a single-field edit of the WAL disables verification for that node with no other change; the same unauthenticated field is read by node_signature_assurance()/_SCHEME_ASSURANCE to report the strongest tier. Parent rerun: after rewriting only signature_scheme -> 'pkcs11-rsa-pss-sha256' on all 3 WAL lines, verify_integrity() returned (True, None), signature_assurance reported ASYMMETRIC_HARDWARE_ATTESTED, and every per-node signature_status was 'unverified' while prev-hash linkage still held.

**Evidence.** crypto_audit.py:1442 'if self._signing_key and node.signature_scheme == "hmac-sha256":'; :432 'return _SCHEME_ASSURANCE.get(node.signature_scheme, SignatureAssurance.UNSIGNED)'; node_hash fields (:562-574) = [prev_hash, state_id, timestamp, entropy, tenant_id, merkle_root, signature, request_hash, response_hash]; parent probe (probe_scheme.py): 'WAL lines tampered: 3/3; verify_integrity: (True, None); reported signature_assurance: ASYMMETRIC_HARDWARE_ATTESTED; per-node signature_status: [unverified, unverified, unverified]'.

**Verification.** REPRODUCED FIRST-HAND (parent probe_scheme.py: tampered 3/3 lines; verify_integrity=(True,None); assurance=ASYMMETRIC_HARDWARE_ATTESTED; all statuses 'unverified')

**Disposition.** Roadmap AUD-02; boundary UC-054; registry REG-D06.
#### AF-006 · P1 · [CRITICAL_SECURITY] · `aegis/proxy/audit_api.py:234`

**Defect.** P1 CONFIRMED-BY-PARENT-RERUN. GET /v1/audit/nodes/{node_hash}/evidence (documented as 'Return byte-exact JCS and DAG-CBOR projections') calls canonical_jcs_bytes(record) on record = node.to_dict() + node_hash. Every AuditNode.to_dict() contains float fields (timestamp, entropy, and sampling_params['elapsed_seconds']), and canonical_jcs_bytes rejects floats by design ('unsupported JCS manifest type: float'). The ForensicBundleError (a ValueError) is raised inside the handler, is not caught anywhere in the router, and no exception handler is registered in aegis/, so the endpoint returns HTTP 500 for every node that exists; the DAG-CBOR branch works. Parent rerun against a real ledger: GET /v1/audit/nodes/{hash} -> 200; GET /v1/audit/nodes/{hash}/evidence -> 500 'Internal Server Error'; float fields present: timestamp=1789971522.1993172, entropy=0.0.

**Evidence.** audit_api.py:233-234 'record, dag_cbor = _canonical_node(node); jcs = canonical_jcs_bytes(record)'; audit_api.py:76-79 handler; parent probe (probe_jcs.py, real ledger + TestClient): '/nodes/{hash} -> 200' and '/nodes/{hash}/evidence -> 500 | body: Internal Server Error'; canonicalizer: 'unsupported JCS manifest type: float'. Not covered by REG-020 (which concerns the four non-JCS seals).

**Verification.** REPRODUCED FIRST-HAND (parent probe_jcs.py: /evidence -> 500 on a real node)

**Disposition.** Roadmap AUD-01; boundary UC-053; registry REG-D05.
#### AF-013 · P1 · [COMPLIANCE_GAP] · `aegis/proxy/streaming.py:357`

**Defect.** P1 CONFIRMED-BY-PARENT-RERUN. On the client-disconnect teardown this app actually runs, no terminal evidence is committed: the first await inside the CancelledError handler (line 358) re-raises CancelledError from Starlette's already-cancelled anyio task group (uvicorn advertises ASGI spec_version 2.3, so StreamingResponse uses create_collapsing_task_group), so asyncio.shield(self._finalize(...)) at lines 360-362 is never reached and no client_disconnected node is written. The response advertises X-Aegis-Evidence-Status: pending-terminal plus a Link to an inclusion proof that never lands, so a mid-stream disconnect is silently unrecorded. Narrows the caller's previously verified account: cancellation does await the producer and commit under the shield for a bare asyncio task.cancel(), but not for the anyio-scope cancellation the ASGI stack delivers, and not for aclose()/GeneratorExit either (parent control run: T1_aclose commits=0, T2_cancel commits=1, T3_complete commits=1; real-app send-failure run: wal_terminal_nodes=0 while teardown shows cancel_producer:raised:CancelledError and no finalize:enter).

**Evidence.** streaming.py:357-365 'except asyncio.CancelledError: await self._cancel_producer(); try: await asyncio.shield(self._finalize("client_disconnected", final_marker_included=False))'; parent rerun of probe_v4.py: 'v4_send_fails_after_2: outcome=raised ClientGone sends=2 wal_terminal_nodes=0' with teardown_events=['cancel_producer:enter','cancel_producer:raised:CancelledError','aclose:enter','cancel_producer:enter','cancel_producer:returned','aclose:returned']; controls (probe_aclose_evidence.py): 'T1_aclose: terminal_commits=0 | T2_cancel: terminal_commits=1 outcomes=[client_disconnected] | T3_complete: terminal_commits=1'.

**Verification.** REPRODUCED FIRST-HAND (parent reran probe_v4.py + probe_aclose_evidence.py)

**Disposition.** Roadmap AUD-03; boundary UC-052; registry REG-D07.
#### AF-035 · P2 · [DOCUMENTATION_DRIFT] · `aegis/config.py:295`

**Defect.** phi_master_key's operator-facing description promises that setting it encrypts audit node payload bytes at rest under a per-tenant HKDF-SHA256 DEK before the WAL write, and calls it required for HIPAA-regulated deployments; the setting is never read and neither PHIPayloadEncryptor nor AuditNodeEncryptor is ever constructed in production code, so the promised encryption never happens. Per the repository's own REG-023 record the WAL holds digests rather than payload bytes, so this is a false control claim rather than a plaintext-at-rest leak - but an operator sizing a HIPAA deployment on this text is misled. Parent re-verified: 0 non-config references.

**Evidence.** aegis/config.py:295-304 field + description; grep for 'phi_master_key' returns only that declaration; encryptor constructors appear only in docstrings (phi_encryption.py:33, audit_node_encryptor.py:42).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-14; registry REG-D18.
#### AF-036 · P2 · [COMPLIANCE_GAP] · `aegis/config.py:306`

**Defect.** cac_piv_required is documented as a required-certificate control but is read by no code path: the identifier occurs only at its own declaration, and CACPIVAuth (the only implementation of the promised check) is never instantiated anywhere outside its own class definition. A deployment that sets AEGIS_CAC_PIV_REQUIRED=true therefore enforces nothing, and nothing warns that the control is inert. Parent re-verified: 0 non-config references.

**Evidence.** aegis/config.py:306-313 declares cac_piv_required with a description promising DoD CAC/GSA PIV enforcement; whole-repo grep returns only the declaration; 'CACPIVAuth' appears only at aegis/proxy/mtls.py:81 (class def) + docstrings; app.py builds only MTLSVerifier (:1033).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-14; registry REG-D18.
#### AF-020 · P2 · [COMPLIANCE_GAP] · `aegis/core/crypto_audit.py:1516`

**Defect.** The Part 11 §11.50 electronic-signature annotation fields signer_name and signature_meaning, and the outcome field status ('committed'/'rejected'), are bound by nothing: they are absent from node_hash's field list, absent from _build_signed_payload, and absent from the MMR leaf. export_part11_signatures() nevertheless presents node_hash/signature as 'cryptographic binding fields that link the annotation to the node'. An attacker with WAL write access can rewrite who signed a record and what the signature meant, and can relabel a rejected record as committed, on ANY node without breaking chain linkage, without invalidating the HMAC, and without changing node_hash. The codebase deliberately fixed exactly this class of gap for waf_verdict but left the signer annotation unbound.

**Evidence.** crypto_audit.py:1524-1528 docstring 'Plus cryptographic binding fields that link the annotation to the node: node_hash - SHA-256 chain accumulator (tamper-evident binding)'; node_hash content list has no signer_name/signature_meaning/status; _build_signed_payload = [prev_hash, merkle_root, request_hash, response_hash] (+waf_verdict). Parent statically re-verified both field lists.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-10; boundary UC-055; registry REG-D14.
#### AF-028 · P2 · [COMPLIANCE_GAP] · `aegis/core/mifid_record_keeper.py:6-7,21-23`

**Defect.** Docstring states the module 'satisfying' MiFID II Art. 16(6)/25(1) and that hash-only retention 'satisfies the record-keeping obligation'. This contradicts the repo's own claims discipline (docs/compliance/MIFID_II_TECHNICAL_INPUTS.md: 'Not a MiFID II compliance statement'; DOC-05 5.7 LEGAL-REVIEW-REQUIRED; RTS 24 requires prescribed order fields the module does not model).

**Evidence.** L6 'satisfying:'; L21-23 'Full message text is not stored - only a SHA-256 content hash. This satisfies the record-keeping obligation (the hash is immutable evidence ...)'

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Trivial-fix (citation/docstring) + Roadmap AUD-20; boundary UC-056.
#### AF-021 · P2 · [ARCHITECTURAL_DEBT] · `aegis/core/transparency_log.py:129`

**Defect.** TransparencyLogManager.verify_ledger_integrity() only compares each entry's prev_hash against the previous entry's stored entry_hash; it never recomputes entry_hash = SHA-256(index||binary_hash||version||timestamp||prev_hash) from the entry's own fields. Editing binary_hash (or version/timestamp) in place on any entry - including a non-tail entry - leaves the linkage graph intact, so verification still returns True and verify_binary_presence() then approves the substituted binary. The class docstring claims the chain 'guarantees tamper evidence'. The recomputation is simply missing.

**Evidence.** transparency_log.py:134-140 'for i in range(1, len(self._ledger)): ... if curr_entry.prev_hash != prev_entry.entry_hash: return False'; :90 'data_to_hash = f"{index}{binary_hash}{version}{timestamp}{prev_hash}".encode()'. Parent statically re-verified; child probe: integrity True both before and after tamper.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-11; registry REG-D15.
#### AF-037 · P2 · [ARCHITECTURAL_DEBT] · `aegis/proxy/audit_api.py:254`

**Defect.** Audit read endpoints iterate the live ledger deque without taking the ledger lock, while commits append to that same deque from asyncio worker threads; a mutation landing between two __next__ calls raises RuntimeError('deque mutated during iteration'), which escapes the handler as a 500 and returns no audit data. Iteration sites confirmed at lines 133, 148, 153, 177, 215, 230, 254, 288, 297, 324 (parent re-grep). The ledger's own accessors (signature_assurance, verify_integrity, archived_segments) all snapshot under self._lock, so this is an inconsistency rather than a deliberate design.

**Evidence.** audit_api.py:254 'for node in reversed(ledger.chain):'; audit_api.py:288 'return sorted({node.tenant_id for node in ledger.chain})'; writer side app.py:1382 'node = await asyncio.to_thread(state.ledger.commit_forensic,'; deque at crypto_audit.py:806 'self.chain: deque[AuditNode] = deque(maxlen=max_memory_nodes)'; child probe on CPython 3.11.11: 'reversed(deque) fresh iterator: RuntimeError: deque mutated during iteration'.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-08; registry REG-D12.
#### AF-038 · P2 · [PERFORMANCE_BOTTLENECK] · `aegis_server/main.py:894`

**Defect.** The enterprise app buffers unbounded request and response bodies: request_bytes = await request.body() reads the whole body with no limit, and line 976 response_bytes = await resp.aread() buffers the entire upstream response even when the client is relaying a chat completion. create_app registers no body-limit middleware (only CORS), whereas the gateway app installs RequestBodyLimitMiddleware with max_request_body_bytes, so the enterprise surface is the weaker of the two.

**Evidence.** aegis_server/main.py:894 'request_bytes = await request.body()'; :976 'response_bytes = await resp.aread()'; only middleware at :253-262 is CORSMiddleware; contrast aegis/proxy/app.py:1323 'app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=cfg.max_request_body_bytes)'.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-09 (enterprise surface); trivial-fix follow-up.
#### AF-029 · P2 · [COMPLIANCE_GAP] · `docs/CLAIMS_MATRIX.md / docs/ROADMAP.md / docs/institutional/UNSUPPORTED_CLAIMS.md:n/a`

**Defect.** MiFID II / MAR / market-abuse have ZERO occurrences in the three registers the audit brief names, despite two unwired compliance modules (market_abuse_detector, mifid_record_keeper), one compliance doc (docs/compliance/MIFID_II_TECHNICAL_INPUTS.md, indexed in docs/INDEX.md) and a dossier section (DOC-05 5.7). A claims-matrix guardian or gate cannot catch a MiFID overclaim today.

**Evidence.** grep -ni 'mifid|RTS|market abuse|MAR art' docs/CLAIMS_MATRIX.md docs/ROADMAP.md docs/institutional/UNSUPPORTED_CLAIMS.md -> 0 hits (each).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-20 (MiFID/MAR register coverage).
#### AF-075 · P3 · [DOCUMENTATION_DRIFT] · `aegis/config.py:191`

**Defect.** The whole LDAP/Active Directory settings family (ldap_url, ldap_base_dn, ldap_bind_dn, ldap_bind_password, ldap_user_search_base, ldap_timeout_seconds, ldap_ca_certs_file, ...) is presented as a configurable authentication mechanism, but no code reads any ldap_* attribute from settings and no authenticator is wired: LDAPAuthenticator(cfg) exists only inside the module docstring of aegis/auth/ldap_auth.py. LDAP identity assertion therefore cannot be enabled by configuration at all, while the field text tells operators to set AEGIS_LDAP_BIND_PASSWORD. Parent re-verified: no .ldap_* settings reads outside config/tests.

**Evidence.** aegis/config.py:191-199 ldap_url field text; importers of ldap_auth outside itself: rbac.py:20 (docstring) and tests/test_ldap_auth.py only; 'LDAPAuthenticator' construction only inside its own docstring at ldap_auth.py:49.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-14; registry REG-D18.
#### AF-076 · P3 · [PERFORMANCE_BOTTLENECK] · `aegis/core/crypto_audit.py:2373`

**Defect.** Startup replay accumulates one tuple per committed node across the entire WAL history - every rotated segment plus the active file - in an unbounded list before the MMR is rebuilt, so peak startup memory grows without limit on a long-lived ledger even though the chain being reconstructed is capped. max_memory_nodes bounds self.chain (deque(maxlen=...)) but nothing bounds portable_suffix, and with the default max_wal_bytes=0 there is not even rotation to split the file.

**Evidence.** crypto_audit.py:2373 'portable_suffix: list[tuple[str, str, str]] = []'; :2388-2393 append per node with mmr_leaf_hash; :2374 'for path in files:' over _segment_paths() + persistence_path; contrast :806 deque(maxlen=max_memory_nodes); config.py:326-335 max_wal_bytes default 0 disables rotation.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-23.
#### AF-051 · P3 · [COMPLIANCE_GAP] · `aegis/core/crypto_audit.py:978`

**Defect.** commit_forensic copies caller sampling_params into the node with no type/float validation (params = {**(sampling_params or {})}), the proxy parses request JSON with plain json.loads (which accepts the non-standard NaN/Infinity literals), and _persist_node serialises the node with json.dumps(..., allow_nan default True). Result: a request carrying {'temperature': NaN, 'top_p': Infinity} is admitted and the WAL line, and any digest taken over a json.dumps(sort_keys=True) seal of that record, contain the bare tokens NaN/Infinity, which are not valid RFC 8259 JSON. The WAL still reloads in Python, so the ledger is self-consistent, but the sealed bytes cannot be parsed by an independent verifier (jq/Go/Node/TypeScript) and therefore cannot be verified cross-language. Adjacent to, but not identical with, the REG-020 boundary row.

**Evidence.** crypto_audit.py:978 'params = {**(sampling_params or {})}'; :2035 json.dumps(node.to_dict(), separators=(",", ":")); parent probe (probe_nan_tokens.py): 'WAL contains bare NaN token: True | bare Infinity token: True'; excerpt '"sampling_params":{"temperature":NaN,"top_p":Infinity}'; 'strict RFC-8259 parse: REJECTED -> non-standard JSON constant NaN'; python json.loads round-trips leniently.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-23; registry REG-D28.
#### AF-060 · P3 · [ARCHITECTURAL_DEBT] · `aegis/core/export_audit_log.py:325`

**Defect.** Malformed export-log lines are silently discarded (except JSONDecodeError/KeyError: pass) with no counter or warning; a reader cannot tell how many entries were dropped.

**Evidence.** try: entries.append(ExportLogEntry.from_dict(json.loads(raw))) except (json.JSONDecodeError, KeyError): pass

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Trivial-fix (note the detection path) ; report-only otherwise.
#### AF-052 · P3 · [CRITICAL_SECURITY] · `aegis/core/hardware_token.py:403`

**Defect.** _canonical_fields() serialises the five bound token fields as token_id + 0x00 + subject + 0x00 + tenant_id + 0x00 + struct.pack('>dd', ...) with no length prefix and no validation that subject/tenant_id are delimiter-free. Two distinct field tuples serialise to identical bytes whenever an identifier contains a NUL, so the keyed attestation tag is identical for both splits. PARENT REFINEMENT of the child's claim: token_hash is NOT delimiter-free equal (child's claim), and merely swapping subject/tenant on a legit token FAILS validation ('token_hash mismatch') - but the token_hash is UNKEYED, so an attacker who recomputes it for the forged split changes nothing else: parent probe shows a token issued for ('a\x00b','c') then validates as valid=True with reported identity ('a','b\x00c') and the original attestation tag unchanged. Precondition: a NUL must be present in subject and/or tenant_id, which nothing in this module (or AuditNode, which only rejects NUL in state_id) rejects.

**Evidence.** hardware_token.py:403-411 'return (token_id.encode() + b"\x00" + subject.encode() + b"\x00" + tenant_id.encode() + b"\x00" + struct.pack(">dd", issued_at, expires_at))'; parent probes: 'canonical fields identical across the two splits: True'; 'token_hash equal across splits: False'; 'forged (hash copied) validates: False | reason: token_hash mismatch'; 'forged (hash recomputed) validates: True | reason: valid | reported identity: a / b\x00c'.

**Verification.** REPRODUCED FIRST-HAND + REFINED (parent probe_token_reason.py)

**Disposition.** Roadmap AUD-23; registry REG-D28.
#### AF-061 · P3 · [DOCUMENTATION_DRIFT] · `aegis/core/market_abuse_detector.py:27`

**Defect.** Spoofing is cited as a 'MiFID II Art. 12(1)(a)(ii)' violation. MiFID II (2014/65/EU) Art. 12 is 'Assessment period' (qualifying-holdings approval); market manipulation/spoofing is MAR (Regulation (EU) 596/2014) Art. 12(1)(a)(ii). The module's own header cites MAR correctly, so line 27 is an instrument mislabel - the exact conflation DOC-05 5.7 warns about.

**Evidence.** # - **MiFID II Art. 16**: ... L27: 'Dodd-Frank 747 / MiFID II Art. 12(1)(a)(ii) violation.' ESMA rulebook: MiFID II Art. 12 = Assessment period; MAR Art. 12 = market manipulation.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Trivial-fix (citation/docstring) + Roadmap AUD-20; boundary UC-056.
#### AF-062 · P3 · [DOCUMENTATION_DRIFT] · `aegis/core/market_abuse_detector.py:4-8`

**Defect.** Module docstring says verdicts 'feed directly into the proxy WAF verdict pipeline', but nothing in aegis/proxy imports it and the module is in the reachability allowlist (unwired). Original intent documented; wiring absent.

**Evidence.** grep for market_abuse in aegis/proxy/* = 0 hits; scripts/import_reachability_allowlist.txt:64 lists aegis.core.market_abuse_detector.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Trivial-fix (citation/docstring) + Roadmap AUD-20; boundary UC-056.
#### AF-063 · P3 · [DOCUMENTATION_DRIFT] · `aegis/core/mmr.py:57-62,105-107,165-180`

**Defect.** Phase-1 property 3 partial: v2 domain separation verified present (leaf 0x00/node 0x01/root 0x02 constants + v2_leaf_hash/v2_node_hash/v2_bagged_root), but 'v1 is completely deprecated' is FALSE by design - auto reopens existing chains under their recorded scheme and v1 proofs verify forever (CLM-064). The v1 residual weakness (verify_portable_inclusion accepts caller-supplied leaf bytes) is disclosed in CLM-064 but has no entry in UNSUPPORTED_CLAIMS.md and no BOUNDARIES.md row.

**Evidence.** mmr.py:105-107 _DOMAIN_LEAF=b'\x00', _DOMAIN_NODE=b'\x01', _DOMAIN_ROOT=b'\x02'; CLM-064 boundary text; grep UC register for mmr/domain -> none.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-20 (MiFID/MAR register coverage).
#### AF-053 · P3 · [ARCHITECTURAL_DEBT] · `aegis/core/transparency_log.py:75`

**Defect.** _append_to_disk() writes the JSON line with a plain open('a')/write and no flush() and no fsync(), and publish_binary_hash() returns the entry hash (a success value consumed by callers as the published commitment) immediately after that buffered write. A power loss or host crash can drop the just-published entry while the caller holds a returned entry_hash for a record that is not on stable storage. Sibling evidence logs in the same package do the opposite: export_audit_log.py:200-204 and custody_transfer.record() both flush+os.fsync per append, and worm_ledger.seal() fsyncs its sentinel, so this module is the outlier.

**Evidence.** transparency_log.py:75-79 'with self._storage_path.open("a", encoding="utf-8") as fh: fh.write(json.dumps(asdict(entry)) + "\n")'; :102-109 returns entry_hash after the write; contrast export_audit_log.py:200-204 'fh.flush(); os.fsync(fh.fileno())'. Parent statically re-verified.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-11; registry REG-D15.
#### AF-054 · P3 · [ARCHITECTURAL_DEBT] · `aegis/core/wal_backup.py:85`

**Defect.** restore() documents 'Copies backup files to the target path atomically' (line 85 and the class docstring), but the implementation copies each file straight over the live target directory with shutil.copy2 (followed by chmod) - no temporary file, no os.replace, no fsync, no directory fsync. A crash or a full disk during the copy leaves the live authoritative WAL truncated or partially overwritten; the only safety net is the optional pre_restore_backup_dir, which the caller must pass (default ''), and post-restore verification then fails closed on a path that is already destroyed. The real atomic pattern exists elsewhere in-tree (crypto_audit.py:2181-2192).

**Evidence.** wal_backup.py:84-85 docstring; :254-262 'for filename in manifest.get("files", []): ... shutil.copy2(src, dest); os.chmod(dest, 0o600)'; contrast crypto_audit.py:2181-2190 (temp file + fsync + os.replace + dir fsync). Parent statically re-verified.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-23; registry REG-D28.
#### AF-064 · P3 · [DOCUMENTATION_DRIFT] · `aegis/core/worm_ledger.py:1-30`

**Defect.** worm_ledger.py implements application-level sealed-segment enforcement and cites ISO/IEC 27037 and SEC 17a-4 in its docstring, but no document in docs/ names the module (grep -rln worm_ledger docs/ = 0 files), while mifid_record_keeper claims 17a-4 is 'already addressed by worm_ledger.py'.

**Evidence.** grep -rln 'worm_ledger' docs/ -> empty.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-23 (latent; module is allowlisted/unwired - noted, not urgent).
#### AF-065 · P3 · [PERFORMANCE_BOTTLENECK] · `aegis/core/worm_ledger.py:545-560,565-580,586-600`

**Defect.** Seal-detection helpers read the ENTIRE ledger file into memory (readlines) to inspect its last/selected line; cost is O(file size) per call. Module is allowlisted/unwired today, so the risk is latent, but a WORM ledger grows without bound by design.

**Evidence.** aegis/core/worm_ledger.py:549 lines = fh.readlines() inside _has_seal_record; same pattern at :569 and :590.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-23 (latent; module is allowlisted/unwired - noted, not urgent).
#### AF-077 · P3 · [PERFORMANCE_BOTTLENECK] · `aegis/proxy/app.py:1997`

**Defect.** The non-streaming path has no bound on the upstream body: forward_json uses a buffered httpx .post(), so the whole provider response is materialised in memory (unlike the SSE path, which is bounded by max_stream_response_bytes), and when a PHI/PCI scrubber is enabled the parsed body is re-serialised into a second full-size copy that is both returned to the caller and committed as the evidence payload. Memory per in-flight request therefore scales with the provider's own response size, with the largest copy held across the mandatory durable-evidence gate.

**Evidence.** aegis/proxy/app.py:1997-2008 'resp_json = upstream.json() ... resp_content = (json.dumps(resp_json).encode() if (state._phi_scrubber or state._pci_scrubber) else upstream.content)'; forwarder.py:285-289 buffered 'await self._client.post(...)'; only stream path bound is config.py:377 max_stream_response_bytes.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-23.
#### AF-078 · P3 · [CRITICAL_SECURITY] · `aegis/proxy/mtls.py:126`

**Defect.** A caller-visible HTTP 403 body interpolates internal exception text from certificate parsing/verification, exposing parser and verifier internals to an unauthenticated client on a pre-auth code path. Severity P3 - information disclosure, not an authentication bypass - and the sibling branches in the same file correctly return fixed strings.

**Evidence.** mtls.py:122-127 'except CACPIVCertError as exc: logger.warning(...); raise HTTPException(status_code=403, detail=f"CAC/PIV certificate rejected: {exc}")'; contrast :77 and :132 which return fixed strings.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Trivial-fix (Prompt 2) + Roadmap AUD-23.
#### AF-066 · P3 · [CRITICAL_SECURITY] · `aegis_server/main.py:736,817,844`

**Defect.** HTTP 500/400 handlers return detail=str(exc), echoing raw exception text to API clients (storage/export internals). 500s at :736 and :844; 400 at :817. aegis_server is deprecated in place (REG-038/UC-046), which bounds severity.

**Evidence.** except RuntimeError as exc: logger.error(...); raise HTTPException(status_code=500, detail=str(exc)) from exc

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-09 + trivial reword.

## 3.2 B. Rust extension (`aegis_rust_v2`)

#### AF-014 · P1 · [CRITICAL_SECURITY] · `aegis_rust_v2/src/audit.rs:44`

**Defect.** AuditRingBuffer.capacity is a Python-supplied usize that is neither lower- nor upper-bounded before it reaches crossbeam's ArrayQueue::new, and both failure modes kill the interpreter instead of raising. (a) capacity 0: crossbeam asserts and panics; (b) huge capacity: the allocation failure aborts. DEFAULT_CAPACITY = 65536 is only a default, never a ceiling, so 'allocation from a caller-controlled length without a cap' applies to the constructor itself. Because the shipped wheel is built from the release profile (panic = "abort"), neither case produces a Python exception that a caller could catch - the process (the audit gateway) dies. Input source: any Python caller or config path that constructs the buffer; value can come from configuration or a request-driven code path, so it is caller-influenced rather than remote-attacker-influenced.

**Evidence.** audit.rs:42-48 `pub fn new(capacity: usize) -> Self { ... queue: Arc::new(ArrayQueue::new(capacity)), ... }` -- measured subprocesses: (1) `R.AuditRingBuffer(0)` -> `thread '<unnamed>' panicked at crossbeam-queue-0.3.12/src/array_queue.rs:98:9:\ncapacity must be non-zero` / `/usr/bin/bash: line 15: 32696 Aborted` EXIT_CODE=134 (2) `R.AuditRingBuffer(1 << 40)` -> `memory allocation of 35184372088832 bytes failed` / `Aborted` EXIT_CODE=134 (control flow never reaches Python: `print('constructed', ...)` is never printed)

**Verification.** REPRODUCED FIRST-HAND (parent reran p_rb.py: AuditRingBuffer(2**40) aborts on allocation failure)

**Disposition.** Roadmap AUD-05; boundary UC-050; registry REG-D09.
#### AF-015 · P1 · [CRITICAL_SECURITY] · `aegis_rust_v2/src/forwarder.rs:55`

**Defect.** Tokio runtime construction is a fallible OS resource acquisition whose failure is handled with .expect(), so a transient thread-creation failure aborts the process instead of raising a Python exception. This is the same failure class the module's own documentation warns about: warmup_runtime() and RustForwarder::new() both initialise the global runtime, and the docs require warmup before a seccomp filter forbids clone()/clone3() - a host that warms up after the filter is applied, or that merely runs out of thread headroom, gets SIGABRT rather than a diagnosable error. Every other fallible init in this crate maps to PyErr (RustWaf::new, Client::builder, RustWal::open, hasher key length), so this is an inconsistency as well as an abort site. Triggered by process/OS resource state (attacker-influenceable via thread exhaustion), not by request content.

**Evidence.** forwarder.rs:49-55 `tokio::runtime::Builder::new_multi_thread() ... .build() .expect("aegis-rust: Tokio runtime init failed")` -- measured with RLIMIT_NPROC tightened to the current thread count, then `R.warmup_runtime()`: `thread '<unnamed>' panicked at tokio-1.52.3/src/runtime/scheduler/multi_thread/worker.rs:503:13:\nOS can't spawn worker thread: Resource temporarily unavailable (os error 11)` / `python: Aborted` EXIT=134 (SIGABRT)

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-05; boundary UC-050; registry REG-D09.
#### AF-016 · P1 · [CRITICAL_SECURITY] · `aegis_rust_v2/src/wal.rs:150`

**Defect.** The mmap unsafe block asserts an exclusivity invariant that no code enforces, and committed frames are silently destroyed when two RustWal handles share one path.  Each handle owns its own parking_lot Mutex and its own AtomicU64 write_pos (struct WalInner, wal.rs:78-83), so "one in-process mutex serializes frame placement" (docs/architecture/DEEP_DIVE.md §4.1) holds only per instance. A second RustWal opener rescans the same file, gets its own offset counter, and both then write the same byte range through the same MAP_SHARED mapping: every flushed, CRC-framed frame written by the first handle is overwritten in place by the second. memmap2 marks file-backed map constructors unsafe for exactly this reason (risk of UB if the file is modified in or out of process), so the unenforced SAFETY comment is a soundness claim, not just a data-loss one. Reachable with no misuse of the public Python API (RustWal.open / rust_integration.new_rust_wal); no flock/O_EXCL, no single-instance guard. Same-process trigger measured; the cross-process variant additionally risks SIGBUS if the other writer calls set_len.

**Evidence.** wal.rs:149-150: `// SAFETY: we own the file and no other process writes to the region.` / `let mut mmap = unsafe { MmapMut::map_mut(&file) }` -- measured (two handles on one path, alternating appends of 4+4 frames): append offsets: [('a', 0, 23), ('b', 0, 23), ('a', 23, 46), ('b', 23, 46), ('a', 46, 69), ('b', 46, 69), ('a', 69, 92), ('b', 69, 92)] a.write_pos 92 b.write_pos 92 a.read_all -> ['{"w":"b","i":0}', '{"w":"b","i":1}', '{"w":"b","i":2}', '{"w":"b","i":3}'] fresh open read_all -> ['{"w":"b","i":0}', '{"w":"b","i":1}', '{"w":"b","i":2}', '{"w":"b","i":3}'] -- memmap2-0.9.11/src/lib.rs (type-level Safety): `All file-backed memory map constructors are marked unsafe because of the potential for *Undefined Behavior* (UB) using the map if the underlying file is subsequently modified, in or out of process.`

**Verification.** REPRODUCED FIRST-HAND (parent reran probe_wal.py: second handle overwrote all 4 committed frames)

**Disposition.** Roadmap AUD-04; boundary UC-051; registry REG-D08.
#### AF-039 · P2 · [CRITICAL_SECURITY] · `aegis_rust_v2/src/forwarder.rs:169`

**Defect.** The upstream response body is read into memory in full with no size cap, no Content-Length check and no streaming bound (resp.bytes() collects everything), and the result is then copied a second time into a Python bytes object by HttpResponse.content (lib.rs:72-74). A hostile, compromised or merely misconfigured upstream - or an upstream that is allowed to echo unbounded data - can therefore drive the gateway's RSS to the size of its response, twice over, with no in-crate limit to breach. The upstream is operator-configured rather than attacker-chosen, which is why this is P2 and not P1, but the crate's own WAF/rate-limit subsystems are carefully bounded and this path is not.

**Evidence.** forwarder.rs:169-173 `let content = resp.bytes().await.map_err(|e| format!("body read failed: {e}"))?.to_vec();` combined with lib.rs:72-74 `fn content<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> { PyBytes::new(py, &self.content) }` -- note that status/headers/content are accumulated into a tuple and returned as HttpResponse with no length validation anywhere in between.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-12; registry REG-D16.
#### AF-040 · P2 · [CRITICAL_SECURITY] · `aegis_rust_v2/src/pqc_trait.rs:252`

**Defect.** In the pure-Rust backend (feature pure-rust-pqc, NOT the default), key generation unwraps the OS RNG with .expect(). RNG unavailability (e.g. a seccomp filter that blocks getrandom(2), an exhausted entropy source, or a sandboxed/edge deployment of the kind the embedded profile targets) therefore aborts the process on the key-generation path that Python reaches through generate_pqc_keypair(). The default PQClean backend has the same shape one level down, in its dependency: pqcrypto-internals-0.2.11/src/lib.rs:21 is `getrandom::fill(buf).expect("RNG Failed");`. Not executed in this audit: pure-rust-pqc is not in default features and I did not build or run that configuration, so the abort consequence is inferred from the code path plus Cargo.toml:193 (panic = "abort") rather than measured.

**Evidence.** pqc_trait.rs:250-252 `let mut seed = ml_dsa::B32::default(); getrandom::fill(&mut seed) .expect("system RNG must be available for key generation");` -- reached from pqc.rs:73 `let (public_key, private_key) = ActiveBackend::keypair();` in `generate_pqc_keypair()`. Dependency equivalent: `getrandom::fill(buf).expect("RNG Failed");` (pqcrypto-internals-0.2.11/src/lib.rs:21).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-05; boundary UC-050; registry REG-D09.
#### AF-041 · P2 · [CRITICAL_SECURITY] · `aegis_rust_v2/src/rate_limit.rs:144`

**Defect.** `max_age_secs * 1_000` is an unchecked multiply on a Python-supplied u64. With the release profile's overflow-checks = true the overflow panics; with panic = "abort" that is a whole-process abort, not a Python exception. A single call with max_age_secs > u64::MAX/1000 (e.g. a misconfigured or hostile config value, or a caller passing a sentinel like 2**63) terminates the gateway. Contrast session.rs:104, which uses the saturating form for the identical arithmetic - the two sibling call sites disagree, which is what makes this a defect rather than a design choice.

**Evidence.** rate_limit.rs:144 `let cutoff = now_millis().saturating_sub(max_age_secs * 1_000);` (the saturating_sub is applied to the right-hand product, which is evaluated first) -- measured `R.RustRateLimiter(5, 1).evict_stale(2**63)`: `thread '<unnamed>' panicked at src/rate_limit.rs:144:50:\nattempt to multiply with overflow` / `Aborted` EXIT=134

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-05; boundary UC-050; registry REG-D09.
#### AF-042 · P2 · [CRITICAL_SECURITY] · `aegis_rust_v2/src/session.rs:52`

**Defect.** RustSessionStore's max_sessions (Python-supplied, default 4096) is passed straight into DashMap::with_capacity_and_shard_amount, so the process attempts to pre-reserve capacity/shard_amount entries per shard with no ceiling and no clamp against any documented limit. An out-of-range value aborts the interpreter (allocation failure) rather than raising ValueError. Same defect class as audit.rs:44: an allocation sized by a caller-controlled length, performed before any validation, in a build whose release profile cannot convert the failure into an exception.

**Evidence.** session.rs:50-52 `pub fn new(max_sessions: usize, evict_after_secs: u64) -> Self { RustSessionStore { sessions: Arc::new(DashMap::with_capacity_and_shard_amount(max_sessions, 64)), ...` -- measured `R.RustSessionStore(1 << 40, 60)`: `memory allocation of 1408749273104 bytes failed` / `Aborted` EXIT=134 (the line after the constructor, `print("constructed", ...)`, never runs)

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-05; boundary UC-050; registry REG-D09.
#### AF-043 · P2 · [DOCUMENTATION_DRIFT] · `aegis_rust_v2/src/waf.rs:19`

**Defect.** The module documents NFKC normalisation before scanning, but no NFKC (or any Unicode normalisation) exists anywhere in the crate: scan() calls strip_zero_width() only, which maps seven zero-width code points to a space, and the crate declares no unicode-normalization dependency. Consequence measured: compatibility variants of a critical pattern are not blocked (fullwidth and mathematical-bold spellings of "ignore previous instructions" both return blocked=False, soft_score=0.0), while the NFKC-normalised spelling of the same string is blocked. Impact scope: the gateway path is mitigated because aegis/proxy/waf.py:383 applies NFKC and its layer is authoritative (waf.py:1-10), so this is a false negative for any direct RustWaf consumer and a false statement of behaviour in the crate's public API docs - not a demonstrated gateway bypass. The engine also builds both automata with ascii_case_insensitive(true), so non-ASCII case folding is absent for the same reason.

**Evidence.** waf.rs:19 `/// NFKC normalisation applied before scan to collapse Unicode lookalikes.` vs waf.rs:128-130 `pub fn scan(&self, text: &str) -> WafResult { let normalised = strip_zero_width(text);` (strip_zero_width, waf.rs:195-214, only replaces 0x200B/0x200C/0x200D/0xFEFF/0x00AD/0x2060/0x180E with ' ') -- measured: waf_ascii = (True, 0.0, 'critical pattern matched: "ignore previous instructions') waf_fullwidth = (False, 0.0, '') waf_math_bold = (False, 0.0, '') waf_fullwidth_nfkc_normalised = (True, 0.0, 'critical pattern matched: "ignore previous instructions')

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-13; registry REG-D17.
#### AF-079 · P3 · [DOCUMENTATION_DRIFT] · `aegis_rust_v2/src/audit.rs:68`

**Defect.** The overflow path documents ring-buffer semantics ('the oldest event is evicted to make room for the new one') and returns false to signal the eviction, but under concurrent producers it also pops whatever is at the head at that instant and then re-pushes best-effort, so the eviction is not the oldest and, if the re-push fails, the *incoming* event is the one lost while the caller is told only that 'an event was dropped'. The counter is incremented in both cases. The last-enqueued payload is not guaranteed to survive, which is what a caller reading the documented contract would assume. Low impact (best-effort telemetry buffering, the Python side is the replay authority) and not separately measured.

**Evidence.** audit.rs:52-68 `/// On overflow the **oldest** event is evicted to make room for the new one,` `/// matching ring-buffer semantics (always retain the most recent N events).` ... `let _ = self.queue.pop(); // may be a no-op if another thread drained first` `self.drop_count.fetch_add(1, Ordering::Relaxed);` `// Best-effort re-push; may still fail under extreme concurrent producer load.` `let _ = self.queue.push(json.to_string());`

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-080 · P3 · [ARCHITECTURAL_DEBT] · `aegis_rust_v2/src/crdt_mmr.rs:336`

**Defect.** MAX_CLOCK_ENTRIES is enforced on decode only, never on encode or append, so a replica can build a leaf its own decoder refuses. The ceiling is documented as the bound that makes the format safe to accept from a peer, but nothing stops a local replica from exceeding it: merge more than 4096 peers, append once, and encode_state() emits a leaf clock above the ceiling. Measured: the accumulator's own encoded state is rejected by its own decoder, i.e. the state cannot round-trip and every peer will refuse it (merge_encoded fails closed with ValueError). A replica in a large deployment therefore loses gossip capability at the moment it creates the offending leaf, with no local error. Not memory-unsafe; the decoder remains bounded.

**Evidence.** crdt_mmr.rs:335-336 `/// Ceiling on clock entries in one leaf, i.e. on distinct replicas.` / `const MAX_CLOCK_ENTRIES: u32 = 4_096;` enforced only at crdt_mmr.rs:494-496 `if entries > MAX_CLOCK_ENTRIES { return Err(StateDecodeError::TooManyClockEntries(entries)); }` while encode_state (crdt_mmr.rs:447-463) writes `(leaf.clock.clock.len() as u32)` with no check -- measured: merged clock entries: 4098 leaves: 4099 encoded bytes: 262328 round-trip REFUSED: ValueError peer state rejected: leaf clock declares 4098 entries; the ceiling is 4096

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-081 · P3 · [DOCUMENTATION_DRIFT] · `aegis_rust_v2/src/forwarder.rs:19`

**Defect.** The crate ships performance numbers in public doc comments that appear in no measurement record: a speedup table in lib.rs (12x, 25x, 100x, 15x, '<1 us enqueue'), '>100k RPS on a 32-core host vs ~8k RPS' in the forwarder, '~4 GB/s ... vs ~150 MB/s' in the WAF, '~50 ns per check on x86-64 (vs ~5 us ...)' in the rate limiter, and '<1 us (no syscall, no lock)' in the ring buffer. Grepping the whole docs/ tree for these figures returns nothing - they carry no environment, no date and no citation - while the repository's own rule (AGENTS.md: 'Do not assert ... production readiness/capacity ... without direct evidence') and docs/CLAIMS_MATRIX.md govern exactly this kind of claim, and tests/zk_mmr_cost.rs:14-16 shows the crate knows the rule ('Numbers printed here are attributable to the host that printed them and to nothing else. They are not a performance claim'). The numbers are unverifiable as written and are the kind of text that gets quoted downstream as capability evidence.

**Evidence.** lib.rs:7-16 `//! | Class / Function | Replaces | Speedup |` ... `//! | `RustForwarder` | reqwest::blocking + Python httpx | ~12x |` ... `//! | `AuditRingBuffer` | Python asyncio.create_task | <1 us enqueue|`; forwarder.rs:19-20 `//! Throughput: a single async reqwest client can sustain >100k RPS on a` `//! 32-core host vs ~8k RPS for reqwest::blocking with the same thread count.`; waf.rs:11-13 `//! Throughput: Aho-Corasick processes ~4 GB/s on x86-64 vs ~150 MB/s for`; rate_limit.rs:15 `//! Latency: ~50 ns per check on x86-64 (vs ~5 us for Python asyncio.Lock).`; grep -rn "4 GB/s|25x|100k RPS|8k RPS|<1 us|12x" docs/ -> no matches

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Trivial-fix (doc numbers) + Roadmap AUD-24.
#### AF-082 · P3 · [CRITICAL_SECURITY] · `aegis_rust_v2/src/forwarder.rs:83`

**Defect.** The bearer API key is stored as an Arc<String> in Rust for the lifetime of the forwarder and is never zeroized, while the crate zeroizes ML-DSA secret keys on drop (pqc.rs:64-68, zeroize crate declared at Cargo.toml:174). A credential that the same codebase treats as secret therefore persists in freed heap memory after the forwarder is dropped, and is copied on every request (`self.api_key.clone()` into the detached closure, forwarder.rs:139/151). Secret-handling hygiene is inconsistent across the FFI surface; no exploit is demonstrated and the value originates on the Python side, which also holds a copy.

**Evidence.** forwarder.rs:80-86 `pub struct RustForwarder { base_url: Arc<String>, api_key: Arc<String>, client: Arc<Client>, timeout: Duration, }` (no Drop impl anywhere in the file) vs pqc.rs:64-68 `impl Drop for PqcKeypair { fn drop(&mut self) { self.private_key.zeroize(); } }`; forwarder.rs:139 `let api_key = self.api_key.clone();` and forwarder.rs:150-152 `if !api_key.is_empty() { req = req.header(AUTHORIZATION, format!("Bearer {api_key}")); }`

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-083 · P3 · [DOCUMENTATION_DRIFT] · `aegis_rust_v2/src/hasher.rs:57`

**Defect.** hash_audit_payload's doc comment justifies its separator incorrectly: 'The null separator prevents length-extension attacks on the concatenation'. BLAKE3 is not vulnerable to length extension (that property belongs to Merkle-Damgard constructions such as SHA-256 with secret-prefix MACs), and the separator's actual job here is to make field boundaries unambiguous - which is exactly what tests/hasher.rs's own test (audit_payload_field_order_matters, hasher.rs:107-111) demonstrates. The construction and the code are correct (the separator is applied after every field, hasher.rs:76-78); only the reason recorded for it is wrong, and a reviewer who trusted the stated mechanism could remove the separator believing the concatenation to be safe. The same 'HMAC alternative' framing of blake3::keyed_hash (a PRF, not HMAC) is looser than the primitive it wraps.

**Evidence.** hasher.rs:52-57 `/// Canonical audit-payload hash: BLAKE3 over null-separated chain fields.` ... `/// The null separator prevents length-extension attacks on the concatenation.` vs hasher.rs:76-78 `for field in &[...] { h.update(field.as_bytes()); h.update(b"\x00"); }`

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Trivial-fix (doc rationale) + Roadmap AUD-24.
#### AF-084 · P3 · [ARCHITECTURAL_DEBT] · `aegis_rust_v2/src/mmr.rs:213`

**Defect.** An empty MmrAccumulator returns the sixty-four-character string "0000...0" as its root under both schemes - a sentinel outside the digest space that is nonetheless a well-formed hex string, so any verifier that compares roots without also checking leaf_count cannot distinguish 'no leaves' from a root. The sibling module argues against exactly this design in its own documentation (crdt_mmr.rs:255-260: an empty range hashes the tag alone 'rather than returning zeroes, so "no leaves" is a value in the digest space rather than a sentinel any payload could also produce'), and the Python side already treats "0"*64 as a magic value (aegis/proxy/audit_api.py:130-138 uses it as 'full_history_retained'), which is precisely the overloading that makes a sentinel risky. Measured: both v1 and v2 empty accumulators return the all-zero root, and the same constant is the chain's previous-hash genesis (aegis/core/crypto_audit.py:1000).

**Evidence.** mmr.rs:212-215 `pub fn root_hash(&self) -> String { if self.peaks.is_empty() { return "0".repeat(64); }` -- measured: mmr_v2_empty_root = 0000000000000000000000000000000000000000000000000000000000000000 mmr_v1_empty_root = 0000000000000000000000000000000000000000000000000000000000000000

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-085 · P3 · [ARCHITECTURAL_DEBT] · `aegis_rust_v2/src/mmr.rs:88`

**Defect.** digest_bytes decodes a hex digest with two expect() calls in a non-test path reachable from the Python API (add_leaf -> combine_hashes, and get_root_hash -> root_hash under v2). The invariant the comment relies on does hold today - every digest in the accumulator is produced by hex::encode over a SHA-256 output, and MmrAccumulator has no decoder or from_bytes entry point, so no caller can inject a foreign hex string - which is why I rate this P3 and do not claim exploitability. It is listed because of the interaction with panic = "abort": the comment argues that panicking is 'the honest response' to memory corruption, but in a shipped wheel the honest response is process termination with no traceback, and there is no test asserting the invariant (no test calls digest_bytes with foreign input, and there is no reconstruction path to fuzz).

**Evidence.** mmr.rs:84-89 `/// Every digest in this accumulator is produced by `hex::encode` over a` `/// SHA-256 output, so a decode failure means memory corruption or a caller` `/// that reached past the public API, not bad input. Panicking is the honest` `/// response: continuing would silently fold a wrong digest into the root.` `fn digest_bytes(hex_digest: &str) -> [u8; 32] { let raw = hex::decode(hex_digest).expect("accumulator digest is not valid hex"); <[u8; 32]>::try_from(raw.as_slice()).expect("accumulator digest is not 32 bytes") }` -- call sites: mmr.rs:98-99 (combine_hashes) and mmr.rs:227 (root_hash, v2).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-086 · P3 · [ARCHITECTURAL_DEBT] · `aegis_rust_v2/src/pqc.rs:113`

**Defect.** subtle is declared as a direct dependency and resolves in Cargo.lock, but no file under src/ or tests/ references it, and the only comparison of key material in the crate - the derived-versus-stored public key check in keypair_from_bytes - uses short-circuiting PartialEq. Both operands are public values (a derived public key and a supplied public key), so no secret leaks and I do not claim a timing vulnerability; the defect is that the dependency's presence reads as a constant-time control that does not exist. The crate is otherwise careful here: it documents the ML-DSA verification timing status as NOT ESTABLISHED (pqc.rs:127-198), so the drift is the unused import surface rather than an over-claim.

**Evidence.** Cargo.toml:173 `subtle = "2"` (Cargo.lock:2377 subtle 2.6.1) vs grep over src/ + tests/ for `subtle|ct_eq|ConstantTimeEq` -> only zeroize/getrandom hits (src/pqc.rs:17,66; src/pqc_trait.rs:251-324). Comparison site pqc.rs:112-117 `if let Ok(derived) = ActiveBackend::public_from_secret(private_key) { if derived != public_key { return Err(value_error("public and secret key do not belong to the same ML-DSA-65 identity".to_string())); } }`

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-087 · P3 · [PERFORMANCE_BOTTLENECK] · `aegis_rust_v2/src/pqc.rs:47`

**Defect.** PqcKeypair.sign and verify_pqc_signature hold the GIL for the whole ML-DSA operation, while the crate's own measurements put signing at ~135 us and verification at ~73 us per call (pqc_trait.rs:44-49, pqc.rs:144-148). Because signing is per-commit work on the evidence path, every commit serialises all Python threads for that window even though the operation is pure CPU inside Rust; the forwarder releases the GIL for I/O (forwarder.rs:143 `py.detach`), so the omission is an inconsistency in the same crate rather than a uniform policy. verify_pqc_signature additionally re-decodes the public key on every call while its own doc comment (pqc.rs:193-198) instructs callers to cache decoded keys - a caller-side requirement the crate offers no decoded-key handle for.

**Evidence.** pqc.rs:46-50 `fn sign<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> { let signature = ActiveBackend::sign_detached(data, &self.private_key).map_err(|e| value_error(e.to_string()))?; Ok(PyBytes::new(py, &signature)) }` and pqc.rs:200-208 `pub fn verify_pqc_signature(data: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> { ... ActiveBackend::verify_detached(data, signature, public_key) }` - neither takes/releases the GIL, vs forwarder.rs:143 `let result = py.detach(move || {`

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-088 · P3 · [ARCHITECTURAL_DEBT] · `aegis_rust_v2/src/rate_limit.rs:69`

**Defect.** The refill CAS computes `(cur + gain)` with an unchecked add where gain is the result of an earlier saturating_mul and can therefore legitimately be i64::MAX (elapsed ms is capped only by u64->i64 saturation on a clock jump, and refill_per_ms is u32-derived). Consequences differ by build profile, and the two profiles disagree: under the shipped release profile (overflow-checks = true) the add panics and, with panic = "abort", aborts the process on a bucket that has been idle for roughly three weeks with an extreme refill rate; under [profile.embedded] (Cargo.toml:208, overflow-checks = false) the same add wraps, and because the wrapped value is stored in tokens_milli the tenant's bucket can go permanently negative, i.e. a silent, unrecoverable lockout instead of an abort. The clamp to capacity_milli happens after the add, so it cannot prevent either outcome. Not reproduced: the precondition (elapsed x refill_per_ms > i64::MAX, ~24 days of idleness at refill_rate near u32::MAX) needs either a very long wait or a forward clock step, and I did not induce it - reported as a code-reading finding.

**Evidence.** rate_limit.rs:64-70 `let gain = elapsed.saturating_mul(refill_per_ms);` `// Add gain and clamp to capacity.` `let mut cur = self.tokens_milli.load(Ordering::Acquire);` `loop { let next = (cur + gain).min(capacity_milli);` with rate_limit.rs:56 `let elapsed = now_ms.saturating_sub(last) as i64;` and rate_limit.rs:125 `refill_per_ms: (refill_rate as i64).max(0),`; Cargo.toml:193-194 `panic = "abort"` / `overflow-checks = true`, Cargo.toml:208 `overflow-checks = false # Disable for size (safety still via seccomp)`

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-05; boundary UC-050; registry REG-D09.
#### AF-089 · P3 · [ARCHITECTURAL_DEBT] · `aegis_rust_v2/src/wal.rs:102`

**Defect.** capacity_bytes has a documented default (256 MiB, wal.rs:39) but no documented or enforced maximum, and it is applied with set_len before any validation (wal.rs:145), so a caller or config value sizes both the file and the mapping. Measured: a 1 TiB capacity is accepted, the file is extended to 1 TiB (sparse - 4.0K actually allocated) and appends succeed, so the failure is deferred to write time and shows up as address-space/disk commitment rather than as an error at open. This is the 'hardcoded default that is not enforced as a bound' pattern: the ceiling exists in the docs ("optional capacity ceiling", wal.rs:98) but the code never refuses a value above it.

**Evidence.** wal.rs:101-102 `pub fn open(path: &str, capacity_bytes: Option<usize>) -> PyResult<Self> { let capacity = capacity_bytes.unwrap_or(DEFAULT_SEGMENT_BYTES);` -- measured `R.RustWal.open(p, 1 << 40)`: capacity_bytes = 1099511627776 == 2^40: True ls -l size: 1099511627776 du -h (allocated): 4.0K append ok: 0 read_all: ['{"x":1}']

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-090 · P3 · [DOCUMENTATION_DRIFT] · `aegis_rust_v2/src/wal.rs:47`

**Defect.** The doc comment states that every frame-walk slice in the module is bounded through header_range/payload_range "rather than through open-coded pos + FRAME_HEADER + len comparisons", so that the arithmetic "exists in exactly one place and can be model-checked". Three sites still do open-coded, unchecked adds on the same quantities (open: write_pos + FRAME_HEADER twice; append: end + FRAME_HEADER twice, plus `flush_end - offset`). They are not exploitable today - write_pos <= capacity and end <= capacity are established upstream and overflow-checks = true would turn a wrap into an abort rather than a silent bad slice - but the claim that the model-checked helpers are the only place this arithmetic exists is false, and CLM-054's scope ('covers header_range and payload_range only') is the accurate statement, not this comment.

**Evidence.** wal.rs:46-50 `/// Every frame walk in this module bounds its slicing through this function and` `/// [`payload_range`] rather than through open-coded `pos + FRAME_HEADER + len`` `/// comparisons, so the arithmetic that decides whether a slice is in bounds` `/// exists in exactly one place and can be model-checked.` vs wal.rs:155-156 `if write_pos + FRAME_HEADER <= capacity { mmap[write_pos..write_pos + FRAME_HEADER].fill(0);` and wal.rs:213-214 `let flush_end = if end + FRAME_HEADER <= self.inner.capacity { mmap[end..end + FRAME_HEADER].fill(0);` and wal.rs:222 `if let Err(e) = mmap.flush_range(offset, flush_end - offset) {`

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-091 · P3 · [ARCHITECTURAL_DEBT] · `aegis_rust_v2/src/wal.rs:87`

**Defect.** Two unsafe impls (Send and Sync) for WalInner are unnecessary and remove the compiler's auto-trait checking for that struct. Every field is already Send + Sync - memmap2 documents MmapMut as Sync and Send, Mutex<T: Send> is Sync, AtomicU64 and usize are Send + Sync - so the struct would satisfy both traits without the unsafe blocks. Their presence means a future edit that adds a non-Send/non-Sync field (Rc, a raw pointer, a Cell) to WalInner still compiles, silently turning the hand-written claim into a real data-race/UB invitation. A crate with three unsafe sites has no unsafe policy either (no `unsafe_code` lint, Cargo.toml [lints.rust] declares only unexpected_cfgs).

**Evidence.** wal.rs:85-88 `// SAFETY: MmapMut is Send (the OS mapping is not thread-local).` / `// Mutex<MmapMut> makes it Sync.` / `unsafe impl Send for WalInner {}` / `unsafe impl Sync for WalInner {}`; fields at wal.rs:78-83 are `mmap: Mutex<MmapMut>, write_pos: AtomicU64, capacity: usize`; memmap2-0.9.11/src/lib.rs:1216 `/// `MmapMut` is [`Sync`] and [`Send`].`

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-092 · P3 · [ARCHITECTURAL_DEBT] · `aegis_rust_v2/src/zk_bindings.rs:144`

**Defect.** generate_zk_proof unwraps committed_root() on a circuit that was constructed one line earlier by WafPassInclusionCircuit::new, whose only success path sets committed_root = Some(native_root(&witness)) - so the expect is provably dead today, but it is an unwrap in a Python-reachable path (zk-spartan builds) whose failure mode under panic = "abort" is a process kill rather than a Python exception. The neighbouring zk_mmr.rs ships a second release-active panic in the same call chain: pack_bits asserts on the bit length before allocating, and pack_bits is called from synthesize() with 128-bit chunks, so that assert is unreachable as written but is not debug-gated. Both are 'assert the invariant in a build that cannot unwind' sites rather than live bugs. Not executed in this audit: zk-spartan is off in the default build and its test legs SIGILL on this CPU (REG-D04), so this is a source-reading finding.

**Evidence.** zk_bindings.rs:141-144 `let circuit = zk_mmr::WafPassInclusionCircuit::new(shape, witness).map_err(zk_error)?; let root = circuit .committed_root() .expect("a circuit built from a witness always has a root");` produced by zk_mmr.rs:224-229 `let committed_root = Some(native_root(&witness)); Ok(Self { shape, committed_root, witness: Some(witness), })`; second site zk_mmr.rs:373 `assert!(bits.len() as u32 <= Fr::CAPACITY, "chunk exceeds field capacity");`

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-093 · P3 · [ARCHITECTURAL_DEBT] · `aegis_rust_v2/src/zk_mmr.rs:663`

**Defect.** verify_zk_proof takes proof and verifier_key bytes straight from Python and hands them to bincode::deserialize with no size limit configured, so an over-large or deeply nested blob is parsed with attacker-chosen field counts rather than refused on a declared bound. This is a hardening item, not a demonstrated bug: bincode fails when input is exhausted and serde's Vec visitor caps its initial reservation, so I could not establish amplification, and the whole path is feature-gated. Listed because the brief asks about allocation driven by an untrusted length prefix and because every other parser in this crate (crdt_mmr::decode_state) explicitly refuses before allocating ('Counts are checked against explicit ceilings before anything is allocated'). Not executed: zk-spartan is off by default and SIGILLs on this host (REG-D04).

**Evidence.** zk_mmr.rs:661-664 `/// Decode a proof. Malformed bytes are refused rather than partially accepted.` `pub fn decode_proof(bytes: &[u8]) -> Result<Snark, ZkError> { bincode::deserialize(bytes).map_err(|e| ZkError::Decoding(e.to_string())) }` (same shape at zk_mmr.rs:675-677 for the verifier key), reached from zk_bindings.rs:178-179 `let proof = zk_mmr::decode_proof(&proof).map_err(zk_error)?; let key = zk_mmr::decode_verifier_key(&verifier_key).map_err(zk_error)?;`

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-24 (Rust P3 batch).
#### AF-094 · P3 · [DOCUMENTATION_DRIFT] · `docs/benchmarks/BENCHMARK_METHOD.md:175`

**Defect.** The benchmark method document gives the Rust reproduction command as `cd aegis_rust_v2 && cargo bench`, but the crate defines no benchmark target at all: there is no benches/ directory and no [[bench]] section in Cargo.toml, and cargo bench would therefore run only the test harness in bench mode (no measurements, no output). Anyone following the documented method to substantiate the doc-comment speedups above gets silence, which is how un-attributed performance figures survive. Scanned as part of the crate because it is the crate's only documented reproduction path for performance claims.

**Evidence.** BENCHMARK_METHOD.md:174-175 `# Rust benchmarks` / `cd aegis_rust_v2 && cargo bench` vs `ls aegis_rust_v2/benches` -> `ls: cannot access 'aegis_rust_v2/benches': No such file or directory` and `grep -n bench aegis_rust_v2/Cargo.toml` -> no matches (only [dev-dependencies] test-only crates and no [[bench]] target); `cargo test --release` output confirms four targets, all `test result: ok` with no bench target listed.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Trivial-fix + Roadmap AUD-24 (no cargo bench target exists).

## 3.3 C. Claims, benchmarks and performance records

#### AF-007 · P1 · [COMPLIANCE_GAP] · `docs/BENCHMARKS.md:37`

**Defect.** The public benchmark record lists the 10,000-request latency distribution (p50 202.136 ms, p95 614.083 ms, p99 1,189.891 ms, max 3,208.869 ms) as the retained v3.1.0 result, directly contradicting the claims register's UC-018 retraction. Line 107 of the same file separately states the current in-tree run (2,500 offered, p99 51.87 ms), so the file contains both the retracted and the current figures without reconciling them. Classification: UNSUPPORTED for the 1,189.89 ms pair; SUPPORTED for the 51.87 ms pair (matches evidence/execution_2026-09-16/).

**Evidence.** docs/BENCHMARKS.md:37 verbatim: '| Backpressure latency | Total runtime 32.36878035601694 s; p50 202.13615702232346 ms; p95 614.082946034614 ms; p99 1189.8909930023365 ms; max 3208.868669986259 ms. | The offered load produces substantial queueing while preserving evidence integrity. | Any claim that the gateway is low-latency or accepts 10k RPS in production. |'. Counter-evidence: docs/institutional/UNSUPPORTED_CLAIMS.md:38 (UC-018).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-06; registry REG-D10 (12-document sweep).
#### AF-008 · P1 · [COMPLIANCE_GAP] · `docs/BOUNDARIES.md:30`

**Defect.** BOUNDARIES.md states zero-knowledge proof costs as measured numbers ('setup 2.5 s, prove 1.3 s, verify 0.19 s for a depth-10, 4-peak shape at a 321-byte prefix'), but the claims matrix row that governs this feature (CLM-089) forbids exactly that class of number and states 'the cost harness is not a reproducible artifact'. Mechanical grep over all md/txt files finds these three values only in BOUNDARIES.md; no script, test, or artifact in the tree produces them. Classification: UNSUPPORTED (no producer) and a direct register contradiction.

**Evidence.** Claim text (docs/BOUNDARIES.md:30): '| Zero-knowledge inclusion proof feasibility | Circuit cost is linear in leaf length; a leaf built with a small or zero `max_forensic_bytes` proves and verifies - measured on one host at setup 2.5 s, prove 1.3 s, verify 0.19 s for a depth-10, 4-peak shape at a 321-byte prefix |'. Counter-evidence (docs/CLAIMS_MATRIX.md:122, CLM-089): 'Do not use: ... any setup, proving, verification or proof-size number - none is claimed, and the cost harness is not a reproducible artifact;'. `grep -rn '0\.19 s|1\.3 s|2\.5 s' --include='*.md' --include='*.txt'` returns only this line. | PARENT CORRECTION: the governing row is CLAIMS_MATRIX.md:115 (`CLM-089`), not :122 as originally cited; the quoted prohibition was re-read at :115 and is verbatim as shown.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-07; registry REG-D11.
#### AF-009 · P1 · [COMPLIANCE_GAP] · `docs/PRODUCT_BRIEF_US.md:43`

**Defect.** Same retracted figure repeated in a buyer-facing brief: 'The backpressure run preserved 10,000 durable records ... recorded p99 commit latency of 1,189.89 ms'. No producer artifact exists in-tree for the 10,000-record run, and the claims register (UC-018) says the figure is false. Classification: UNSUPPORTED.

**Evidence.** docs/PRODUCT_BRIEF_US.md:43: 'The published v3.1.0 release retained four market-hardening artifacts. The backpressure run preserved 10,000 durable records under a 2 ms injected `fsync` delay but recorded p99 commit latency of 1,189.89 ms.' Counter-evidence: docs/institutional/UNSUPPORTED_CLAIMS.md:38 and docs/PROSPECTUS_ES.md:52 (both state the 10,000/1,189.89 pair is false/retracted).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-06; registry REG-D10 (12-document sweep).
#### AF-010 · P1 · [COMPLIANCE_GAP] · `docs/PROSPECTUS.md:58`

**Defect.** Buyer-facing prospectus presents the retracted v3.1.0 backpressure figures as the product's measured evidence: 'offered 10,000 requests at 10,000 RPS ... observed 10,000 durable records ... p99 commit latency of 1,189.89 ms'. The only in-tree artifact for that harness contains 2,500 records and p99 836.3514210795984 ms (evidence/execution_2026-08-20/backpressure_stall_report.json) and UC-018 declares the 10,000/1,189.89 numbers false and retracted. Classification: UNSUPPORTED - no in-tree artifact produces the cited pair.

**Evidence.** docs/PROSPECTUS.md:58: 'The v3.1.0 backpressure run offered 10,000 requests at 10,000 RPS with a 2 ms injected `fsync` delay and observed 10,000 durable records, zero failures, zero missing IDs, zero duplicate IDs and valid chain integrity. It observed p99 commit latency of 1,189.89 ms.' Counter-evidence: docs/institutional/UNSUPPORTED_CLAIMS.md:38 (UC-018, see P1 finding above) and evidence/execution_2026-08-20/backpressure_stall_report.json ('observed/accepted_and_durable = 2500', 'observed/commit_latency_ms/p99 = 836.3514210795984').

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-06; registry REG-D10 (12-document sweep).
#### AF-011 · P1 · [COMPLIANCE_GAP] · `docs/benchmarks/BENCHMARK_RESULTS.md:15`

**Defect.** The canonical benchmark-results record still carries the retracted latency row as the retained v3.1.0 result while its own text (line 64-67) admits the raw JSON is not committed, so neither the number nor its retraction is checkable in-repo. Classification: UNSUPPORTED (no producing artifact in tree; contradicted by UC-018).

**Evidence.** docs/benchmarks/BENCHMARK_RESULTS.md:15: '| Backpressure latency - same retained `v3.1.0` run | Same run | p50 202.136 ms; p95 614.083 ms; p99 1,189.891 ms; max 3,208.869 ms |'. docs/benchmarks/BENCHMARK_RESULTS.md:64-66: '**The raw JSON for this 10,000-request run is not committed to this tree.**'. Counter-evidence: docs/institutional/UNSUPPORTED_CLAIMS.md:38 (UC-018: 'The committed artifact contains 2,500 durable records and p99 836.3514210795984 ms').

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-06; registry REG-D10 (12-document sweep).
#### AF-012 · P1 · [COMPLIANCE_GAP] · `docs/institutional/UNSUPPORTED_CLAIMS.md:38`

**Defect.** UC-018 formally retracts the figures '10,000 durable records' and 'p99 1,189.89 ms' and states the committed backpressure artifact contains 2,500 records with p99 836.3514210795984 ms, but the canonical benchmark record and five further documents still present the 10,000-record / 1,189.89 ms run as the retained v3.1.0 measurement. Both cannot be true; the retraction and the citations contradict each other. Classification: STALE/UNSUPPORTED depending on which side is wrong - the raw JSON for the 10,000-request run is admitted not to be in this tree, so the 1,189.89 ms figure has no producer artifact in-repo.

**Evidence.** Claim under audit (docs/institutional/UNSUPPORTED_CLAIMS.md:38): '| `UC-018` | The retained backpressure artifact contains 10,000 durable records and p99 1,189.89 ms. | The committed artifact contains 2,500 durable records and p99 836.3514210795984 ms. | Canonical matrices corrected to the retained artifact. |'. Contradicting in-corpus statement (docs/PROSPECTUS_ES.md:52): '**Correccion registrada:** una version anterior de este documento afirmaba <<10.000 commits durables>> y <<p99 1.189,89 ms>>. Ambas cifras son falsas y estan formalmente retractadas en `UC-018`; el artefacto retenido siempre contuvo 2.500 registros.' Still-cited version (docs/BENCHMARKS.md:37): '| Backpressure latency | Total runtime 32.36878035601694 s; p50 202.13615702232346 ms; p95 614.082946034614 ms; p99 1189.8909930023365 ms; max 3208.868669986259 ms. |'.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Register: `UC-018` already retracts the pair; the execution sweep (12 documents) is Roadmap AUD-06.
#### AF-030 · P2 · [COMPLIANCE_GAP] · `INTEGRITY_SEAL.md:24`

**Defect.** The 5.0.0 integrity seal records gate 6b as '`ruff format --check .` | **PASS** - 550 files'. Re-running that command read-only on the checked-out tree gives 806 files already formatted and 11 files that would be reformatted (non-zero exit), and the tree holds 817 Python files under the same command, not 550. The sealed gate result is not reproducible from the tree it is presented with, and the file count has drifted by ~48%. Classification: STALE (producer = the ruff command itself; recorded output no longer holds).

**Evidence.** Claim (INTEGRITY_SEAL.md:24): '| 6b | Format | `ruff format --check .` | **PASS** - 550 files |'. Measured on this checkout: '.venv/bin/ruff format --check .' -> '11 files would be reformatted, 806 files already formatted' (exit status non-zero).

**Verification.** REPRODUCED FIRST-HAND (parent ran `ruff format --check .`: exits 1, '11 files would be reformatted, 806 files already formatted')

**Disposition.** Roadmap AUD-19 (currency & provenance sweep).
#### AF-031 · P2 · [DOCUMENTATION_DRIFT] · `INTEGRITY_SEAL.md:26`

**Defect.** Seal records the claims register as '96 claims, 0 findings' for the 5.0.0 baseline; the live verifier reports 102 claims, 0 findings. The register grew after the seal was written and the seal text was not superseded, so a reader comparing seal to matrix sees two different register sizes. Classification: STALE (producer = scripts/verify_claims.py, which I ran read-only).

**Evidence.** Claim (INTEGRITY_SEAL.md:26): '| 8 | Claims register | `python scripts/verify_claims.py --root .` | **PASS** - 96 claims, 0 findings |'. Measured: '.venv/bin/python scripts/verify_claims.py --root .' -> 'verify_claims: PASS (102 claims, 0 findings)'. PR_FINAL_ENTERPRISE_HARDENING.md:67 records a third value for an earlier baseline ('84 claims, 0 findings').

**Verification.** REPRODUCED FIRST-HAND (parent doc-gate battery: verify_claims PASS, 102 claims, 0 findings)

**Disposition.** Roadmap AUD-19 (currency & provenance sweep).
#### AF-032 · P2 · [DOCUMENTATION_DRIFT] · `README.md:329`

**Defect.** README claims 'mypy --strict 0 errors over 206 files'. The same command in the seal is quoted as 216 files, and running it on this checkout reports 'Found 5 errors in 2 files (checked 216 source files)' with exit status 1. The errors are in sdk/python/src (subclassing optional SDK bases that are absent here), so the failure is environment-dependent - but the '206 files' count is wrong under every observed run and the '0 errors' half is not reproducible on a host without the optional SDKs installed. Classification: STALE / environment-dependent (producer = mypy, executed read-only).

**Evidence.** Claim (README.md:329): '| Static analysis | `mypy --strict` 0 errors over 206 files; Bandit 0 findings at every severity | CI | Per run |'. Counter-evidence: INTEGRITY_SEAL.md:22: '| 5 | Types | `mypy --strict aegis sdk/python/src` | **PASS** - no issues in 216 source files |'; measured: 'Found 5 errors in 2 files (checked 216 source files)'; 'python -c "import openai"' and 'import anthropic' both raise ModuleNotFoundError in this .venv.

**Verification.** REPRODUCED FIRST-HAND (parent ran `mypy --strict aegis sdk/python/src`: 5 errors in 2 files, 216 source files)

**Disposition.** Roadmap AUD-19 (currency & provenance sweep).
#### AF-033 · P2 · [COMPLIANCE_GAP] · `docs/FAQ_PROCUREMENT.md:64`

**Defect.** Procurement FAQ repeats the retracted pair ('preserved 10,000 durable records ... p99 commit latency of 1,189.89 ms'). The same contradiction is repeated in docs/operations/BACKPRESSURE_RUNBOOK.md:53, docs/ROADMAP.md:79, docs/performance/SCALING_GUIDE.md:38, DEPLOYMENT_GUIDE.md:138 and CHANGELOG.md:2154 - nine md files in total carry the retracted figures, versus one retraction. Classification: UNSUPPORTED (no in-tree artifact), P2 because these are pre-contract procurement surfaces.

**Evidence.** docs/FAQ_PROCUREMENT.md:64: 'The backpressure artifact preserved 10,000 durable records under an injected seam but recorded p99 commit latency of 1,189.89 ms.' Counter-evidence: docs/institutional/UNSUPPORTED_CLAIMS.md:38 (UC-018: committed artifact contains 2,500 durable records and p99 836.3514210795984 ms); docs/PROSPECTUS_ES.md:52 calls both figures false and formally retracted.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-06; registry REG-D10 (12-document sweep).
#### AF-034 · P2 · [COMPLIANCE_GAP] · `docs/FAQ_TECHNICAL.md:118`

**Defect.** Technical FAQ repeats the retracted v3.1.0 figures ('10,000 durable commits ... p50 202.136 ms, p95 614.083 ms, p99 1,189.891 ms') as a quotable row, while the register says the artifact contains 2,500 records at p99 836.3514210795984 ms. Classification: UNSUPPORTED for the 10,000/1,189.89 pair.

**Evidence.** docs/FAQ_TECHNICAL.md:118: '| Backpressure under injected I/O stall - **retained `v3.1.0` historical observation** | 10,000 offered requests over 32.4 s, 2 ms injected `fsync` delay | 10,000 durable commits, 0 failures, 0 missing identifiers, 0 duplicates, valid chain; p50 `202.136 ms`, p95 `614.083 ms`, p99 `1,189.891 ms` |'. Counter-evidence: docs/institutional/UNSUPPORTED_CLAIMS.md:38 (UC-018).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-06; registry REG-D10 (12-document sweep).
#### AF-067 · P3 · [DOCUMENTATION_DRIFT] · `INTEGRITY_SEAL.md:18`

**Defect.** Seal records '6920 passed, 26 skipped' for the 5.0.0 tree, while README.md:327 records '6,936 passed, 26 skipped, 0 failed' for the same '5.0.0 source baseline / 2026-09-16'. Two in-tree figures for one baseline date. Classification: UNVERIFIABLE-HERE as to which is current (no retained pytest artifact; run-tests not executed to preserve read-only posture and time budget).

**Evidence.** INTEGRITY_SEAL.md:18: '| 1 | Python tests | `pytest -n auto -q` | **6920 passed, 26 skipped, 0 failed** |'. README.md:327: '| Python suite | **6,936 passed, 26 skipped, 0 failed** | `5.0.0` source baseline | 2026-09-16 |'. Component-level test count of the seal's own narrative ('The Python count rose from 6879 to 6920: 41 tests added', INTEGRITY_SEAL.md:33) is internally consistent with neither README row.

**Verification.** REPRODUCED FIRST-HAND (parent ran ruff/mypy/claims commands)

**Disposition.** Roadmap AUD-19 (currency & provenance sweep).
#### AF-068 · P3 · [DOCUMENTATION_DRIFT] · `PR_FINAL_ENTERPRISE_HARDENING.md:26`

**Defect.** The group-commit comparison ('1,065.1 -> 1,536.1 commits/second (1.44x)', p50 28.204 -> 19.021 ms, p99 55.456 -> 24.781 ms, fsync 400 -> 66) has a producer script (tools/benchmarks/run_group_commit.py, which requires --output) but no retained report JSON anywhere in evidence/ - the only group-commit artifact in the tree is the backpressure re-measurement, which covers a different harness. CHANGELOG.md:853-859 restates the same figures. Classification: UNSUPPORTED (no producing artifact committed; re-derivation possible only by re-running, which would produce new host-specific numbers).

**Evidence.** Claim (PR_FINAL_ENTERPRISE_HARDENING.md:26): '| commits/second | 1,065.1 | **1,536.1** (1.44x) |'; line 22: 'Reproduce with `python tools/benchmarks/run_group_commit.py --output <report>.json`.' Counter-evidence: `find . -name '*group_commit*'` returns aegis/core/group_commit.py, tools/benchmarks/run_group_commit.py, evidence/backpressure_group_commit_remeasurement_2026-09-16.md and one __pycache__ entry - no run_group_commit report JSON exists in evidence/.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-26 (evidence retention & claim-generating surfaces).
#### AF-069 · P3 · [DOCUMENTATION_DRIFT] · `Samples/README.md:6`

**Defect.** Static sample gallery is described as mock data for a 'busy production deployment (>1B audit nodes, multi-provider traffic, live WAF blocks, sealed compliance bundles)', and its file table advertises 'live throughput & latency' and 'live WAF blocks'. CLM-038 requires that static samples not represent live runtime, customer activity or production capacity; the framing is qualified as mock data in the same paragraph, which is why this is P3 rather than higher. Classification: DOCUMENTATION_DRIFT (claim vs CLM-038).

**Evidence.** Samples/README.md:6: 'so the project can be shown as if it were running against a busy production deployment (>1B audit nodes, multi-provider traffic, live WAF blocks, sealed compliance bundles)'; Samples/README.md:18-19: '| `01-overview.html` | Overview - KPIs, live throughput & latency |'. Counter-evidence (docs/CLAIMS_MATRIX.md:79, CLM-038): 'Static Samples dashboards represent live runtime, customer activity, cryptographic proof, or production capacity. | `ROADMAP` | ... Static dashboards are illustrative only; sample values must not be used as evidence.'

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-22 (wording sweep).
#### AF-070 · P3 · [DOCUMENTATION_DRIFT] · `benchmarks/bench_crypto_audit.py:203`

**Defect.** The harness that produces the widely-cited 808.565 us/op commit figure prints its result under a '[PROVEN]' tag as an absolute sustained-throughput statement ('sustains <N> commits/s (1916.9 us/commit) on this host'), which conflicts with the repository's own rule that no throughput/capacity figure is claimed. Re-running it here (read-only, temp-dir WAL) gave 521.7 commits/s / 1916.921 us per commit versus the cited 1.24k / 808.565 us - a 2.4x host spread on the same code path, exactly the host-dependence the docs declare. Classification: SUPPORTED as a producer (the harness exists and runs); the claim value is host-specific and the '[PROVEN]' label overstates it.

**Evidence.** benchmarks/bench_crypto_audit.py:203: 'f" [PROVEN] Full durable commit (fsync per node) sustains "'. Cited claim (evidence/evidence_path_measurements_2026-09-03.md:54): '| `commit_forensic` (HMAC + MMR + WAL fsync) | 1.24k | 808.565 |'. Measured rerun (this host): 'commit_forensic (HMAC+MMR+WAL) 521.7 1916.921' and '[PROVEN] Full durable commit (fsync per node) sustains 521.7 commits/s (1916.9 us/commit) on this host.' Repo rule: docs/BENCHMARKS.md:144 'Do not use ... "10k RPS capacity" ... without a matching artifact'; docs/benchmarks/BENCHMARK_METHOD.md:43 'No RPS figure is claimed for any environment.'

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-26 (evidence retention & claim-generating surfaces).
#### AF-071 · P3 · [DOCUMENTATION_DRIFT] · `benchmarks/bench_forwarding.py:2`

**Defect.** The benchmark docstring and its printed banner frame the harness as validating a 'zero forensic latency' claim - a phrasing the corpus prohibits ('zero latency'/'zero overhead'). The harness compares WITH_BG vs NO_BG arms with a Welch t-test, i.e. it measures a microsecond-scale scheduling delta, not zero latency. Not an md/txt file, but it is a claim-generating surface cited by the docs discipline. Classification: DOCUMENTATION_DRIFT (wording contradicts docs/BENCHMARKS.md:144 and docs/benchmarks/BENCHMARK_METHOD.md:189-195).

**Evidence.** benchmarks/bench_forwarding.py:2: 'Forwarding latency benchmark - validates "zero forensic latency" claim.'; line 269: 'print("FORWARDING LATENCY BENCHMARK - zero forensic latency validation")'. Prohibited-phrasing table (docs/benchmarks/BENCHMARK_METHOD.md:194): '| "Zero overhead" | State the measured microbenchmark and its scope |'.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-26 (evidence retention & claim-generating surfaces).
#### AF-072 · P3 · [COMPLIANCE_GAP] · `docs/institutional/UNSUPPORTED_CLAIMS.md:35`

**Defect.** UC-015 ('BLAKE3 runs at approximately 4.0 GB/s in Aegis') has no producer anywhere: no BLAKE3 benchmark exists, and the MMR/digest path is SHA-256 over ASCII-hex per the claims matrix and the MMR measurement boundary, so the claim is not merely unmeasured but describes an algorithm the evidence path does not use. Correctly registered as unsupported; listed here because the task requires every no-producer claim to be enumerated. Classification: UNSUPPORTED (no producing artifact; no BLAKE3 usage found on the evidence path).

**Evidence.** docs/institutional/UNSUPPORTED_CLAIMS.md:35: '| `UC-015` | BLAKE3 runs at approximately 4.0 GB/s in Aegis. | No retained current-environment benchmark supports this product claim, and helper reachability differs from the evidence path. | `ROADMAP` until measured ... |'. Counter-evidence: evidence/evidence_path_measurements_2026-09-03.md:38: '**Both implementations use SHA-256 over ASCII-hex concatenation**, not BLAKE3. The wire literal is `sha256-asciihex` and `verify_portable_inclusion_hash` rejects any other value.'

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-26 (producers or keep-retracted).
#### AF-073 · P3 · [COMPLIANCE_GAP] · `docs/institutional/UNSUPPORTED_CLAIMS.md:36`

**Defect.** UC-016 ('WAF takes about 250 ns and rate limiting about 50 ns with less than 0.5% LLM overhead') has no producer: no WAF or rate-limiter microbenchmark or artifact in the tree returns ns-scale figures, and no '.5%' overhead measurement exists. Registered as unsupported; enumerated here for completeness. Classification: UNSUPPORTED (no producing artifact; grep over all 314 md/txt files finds the numbers only in the register row that rejects them).

**Evidence.** docs/institutional/UNSUPPORTED_CLAIMS.md:36: '| `UC-016` | WAF takes about 250 ns and rate limiting about 50 ns with less than 0.5% LLM overhead. | No retained end-to-end or microbenchmark evidence establishes these values after the current changes. | `ROADMAP`; use only named measured artifacts. |'. Counter-evidence: mechanical extraction over the 314 in-tree md/txt files produced no other line containing '250 ns', '50 ns' or '0.5%' in a performance context.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-26 (producers or keep-retracted).
#### AF-074 · P3 · [DOCUMENTATION_DRIFT] · `docs/institutional/UNSUPPORTED_CLAIMS.md:37`

**Defect.** UC-017 describes 'the retained run' as offering 10k RPS for 0.25 s and processing 2,500 records at p99 836.35 ms - which is the in-tree 2026-08-20/2026-09-16 run, not the v3.1.0 run that BENCHMARKS.md calls 'retained'. The word 'retained' denotes two different runs in two registers, which is the mechanism by which the P1 contradiction above propagates. Classification: DOCUMENTATION_DRIFT (naming, not arithmetic).

**Evidence.** docs/institutional/UNSUPPORTED_CLAIMS.md:37: '| `UC-017` | 10k RPS offered load means 10k production capacity. | The retained run offered 10k RPS for 0.25 s and processed 2,500 local records with p99 836.3514210795984 ms. |'. Counter-evidence: docs/BENCHMARKS.md:100-108 uses 'retained' exclusively for the 10,000-request / 32.4 s run whose 'raw JSON is not committed to this tree'.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-26 (producers or keep-retracted).

## 3.4 D. Compliance and regulatory surfaces

#### AF-001 · P1 · [DOCUMENTATION_DRIFT] · `docs/architecture/DEEP_DIVE.md:288`

**Defect.** Capability table advertises a 'chain-of-custody' forensic capability that the project's own ISO/IEC 27037 boundary documents state does not exist (no custody record is created, maintained or attached; 'Chain of custody maintained' is forbidden wording).

**Evidence.** docs/architecture/DEEP_DIVE.md:288 '| ISO/IEC 27037 evidence package | `iso27037_evidence.py` | chain-of-custody + SHA-256 seal, offline-verifiable |'. Contradicted by docs/compliance/ISO_27037_TECHNICAL_INPUTS.md:33 '| **Chain of custody** | No custody record is created, maintained, or attached to any artifact. Custody documentation is entirely the practitioner's. |' and :87 '- "Chain of custody maintained" — none is created'; by docs/assurance/CONTROL_TO_EVIDENCE_MATRIX.md:116 '| Chain of custody | Not provided. |'; and by the blocked claim UC-024 in docs/institutional/UNSUPPORTED_CLAIMS.md:44. The module does expose CustodyEvent/add_custody_event structures, so the cell is not baseless — but no production path creates or maintains a custody record, and the cell carries no boundary, so it reads as an assurance claim the project explicitly forbids.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-17; registry REG-D21.
#### AF-002 · P1 · [DOCUMENTATION_DRIFT] · `docs/architecture/DEEP_DIVE.md:289`

**Defect.** Uses the exact blocked phrase 'trusted timestamp' for the RFC 3161 control, with no statement of the two named gaps (no revocation checking of any kind; no RFC 5280 name-constraint/policy/EKU evaluation).

**Evidence.** docs/architecture/DEEP_DIVE.md:289 '| RFC 3161 trusted timestamp | `rfc3161_timestamper.py` | TSA token bound to bundle imprint |'. Blocked wording: docs/CLAIMS_MATRIX.md:51 CLM-014 boundary 'An obtained response is not a trusted timestamp.'; docs/CLAIMS_MATRIX.md:121 CLM-096 'Do not use: "timestamps are fully verified", "PKI-validated" or "trusted timestamps" without naming the two gaps'; docs/CLAIMS_MATRIX.md:184 lists '"trusted timestamp"' among blocked terms for CLM-014–CLM-020. docs/security/SECURITY_CONTROLS.md:94 states the same prohibition, and docs/institutional/DOC-02_CRYPTOGRAPHIC_FORENSIC_BLUEPRINT.md:365 requires the result to be labelled up to 'structural consistency' only.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-17; registry REG-D21.
#### AF-003 · P1 · [DOCUMENTATION_DRIFT] · `docs/compliance/EU_AI_ACT_TECHNICAL_INPUTS.md:67`

**Defect.** Stale boundary text: 'the record holds the scrubbed form'. This is the precise defect REG-023 found and fixed in docs/privacy/PII_REDACTION_BOUNDARIES.md:48 and published as UC-045; the superseded wording survives verbatim in this compliance document.

**Evidence.** docs/compliance/EU_AI_ACT_TECHNICAL_INPUTS.md:67 '**Redaction interacts with record completeness.** Enabling PHI or PCI scrubbing means the record holds the scrubbed form. If your assessment requires the original input, redaction reduces record fidelity.' Superseded by docs/REGISTRY.md:126 (REG-023): 'Two documentation defects were found and fixed. `docs/privacy/PII_REDACTION_BOUNDARIES.md:48` claimed "the record holds the scrubbed form": false twice over — the record holds digests rather than content, and the request digest is taken over `raw_body` [...]'. Corrected boundary now in docs/privacy/PII_REDACTION_BOUNDARIES.md:48 'What the evidence record commits is **digests, not content** (`request_hash`, `response_hash`, `mmr_leaf_hash`)' and UC-045 in docs/institutional/UNSUPPORTED_CLAIMS.md:65 '...neither is the record "the scrubbed form", and enabling the flag does not change it.'

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-16; registry REG-D20.
#### AF-004 · P1 · [DOCUMENTATION_DRIFT] · `docs/compliance/HIPAA_TECHNICAL_INPUTS.md:67`

**Defect.** Stale boundary text that contradicts the amended PII Redaction Boundary and UC-045: it presents 'PHI reaches the provider unscrubbed' and 'redaction changes the evidence record only' as unconditional facts. The first is true only while both opt-ins are off (they are off by default, so it is misleading rather than false); the second is wrong either way — the record commits digests, and the flag changes the provider path, not the record.

**Evidence.** docs/compliance/HIPAA_TECHNICAL_INPUTS.md:67 '**PHI reaches the provider unscrubbed.** The request goes upstream as sent; redaction changes the evidence record only. If PHI must not reach your model provider, you need filtering before the gateway, plus a Business Associate Agreement with the provider.' Contradicted by UC-045 (docs/institutional/UNSUPPORTED_CLAIMS.md:65) '(1) **The provider path is protected only when the opt-in is set.** `AEGIS_PHI_DEIDENTIFY` / `AEGIS_PCI_SCRUB` are off by default; with them off the request reaches the upstream provider exactly as received [...] and with them on what crosses is text with matched patterns removed' and (2) 'A one-way digest is not a disclosure of the payload, but neither is the record "the scrubbed form"...'; and by docs/privacy/PII_REDACTION_BOUNDARIES.md:155 'One opt-in changes the provider path — it does not change the section above.' The same file also asserts at :25 '| Pattern-based scrubbing across seventeen Safe Harbor-associated categories | Reduces PHI written into the evidence record |'.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-16; registry REG-D20.
#### AF-017 · P2 · [DOCUMENTATION_DRIFT] · `docs/assurance/AUDIT_EVIDENCE_INDEX.md:123`

**Defect.** Evidence index names the same non-in-tree artifact as the source of the WAF corpus result, in a document whose purpose is artifact traceability.

**Evidence.** docs/assurance/AUDIT_EVIDENCE_INDEX.md:123 '| WAF corpus | Zero observed bypasses, zero false positives | `waf_corpus_report_v1_candidate.json` | Per corpus |'. Contradicts CLM-032 (docs/CLAIMS_MATRIX.md:69) 'a candidate-named artifact ... is **not in this tree** and is no longer cited as if it were' and docs/security/WAF_TESTING.md:13 '**Current artifact:** `evidence/market_hardening_v3_1/waf_corpus_report_v1_candidate.json` outside the source tree'.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-15; registry REG-D19.
#### AF-018 · P2 · [DOCUMENTATION_DRIFT] · `docs/compliance/COMPLIANCE_MAPPING.md:32`

**Defect.** Cites a non-in-tree artifact as repository evidence for the WAF control — the exact practice CLM-032 retired.

**Evidence.** docs/compliance/COMPLIANCE_MAPPING.md:32 '| WAF and normalization | Application-layer normalization and pinned local corpus regression | `aegis/proxy/waf.py`, `tests/data/waf_corpus_v1.json`, `tools/security/run_waf_corpus.py`, `waf_corpus_report_v1_candidate.json` | `MEASURED` / local corpus |'. CLM-032 (docs/CLAIMS_MATRIX.md:69) states: 'a candidate-named artifact (`waf_corpus_report_v1_candidate.json`) is **not in this tree** and is no longer cited as if it were.' docs/security/WAF_TESTING.md:13 locates the artifact 'outside the source tree'. CLM-032's in-tree evidence is `evidence/execution_2026-08-20/waf_corpus_report.json`.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-15; registry REG-D19.
#### AF-019 · P2 · [COMPLIANCE_GAP] · `examples/README.md:35`

**Defect.** Runnable-demo README frames a compliance outcome and names SOC 2 and HIPAA with no qualification, in a repository where no SOC 2 examination or HIPAA determination exists.

**Evidence.** examples/README.md:35 '| 5 | Compliance export is real and re-verifiable | seal a SOC2/HIPAA bundle, then `verify_bundle()` re-checks `chain_hash` + signature |'. The required treatment is applied elsewhere: docs/api/AUDIT_ENDPOINTS.md:98 '**The endpoint name refers to the shape of the projection, not to a compliance determination.**' and docs/STYLE_GUIDE.md:42 'certified, SOC 2 / ISO 27001 / HIPAA / FedRAMP / PCI compliant | No independent audit exists. | "contributes technical inputs that an assessor may evaluate"'. Absence of certification: docs/enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md:142 '**Q: Are you SOC 2 certified?** → **No.** No SOC 2 examination has been performed, and none is in progress.'

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-22; registry REG-D26 (compliance-wording sweep).
#### AF-044 · P3 · [DOCUMENTATION_DRIFT] · `README.md:18`

**Defect.** Groups EU AI Act Art. 12 with obligations the reader 'already owes'; the Art. 12 logging duty for high-risk systems is not yet applicable, and the repo's own mapping requires the date/applicability analysis that this framing omits.

**Evidence.** README.md:18 '**You already owe someone a record you can stand behind** — EU AI Act Art. 12, HIPAA audit controls, SEC 17a-4's audit-trail alternative, MiFID II.' The Art. 12 logging obligation for high-risk systems applies from 2 December 2027 (Annex III high-risk) and 2 August 2028 (Annex I high-risk) after the Digital Omnibus on AI amendments (sources: https://ai-act-service-desk.ec.europa.eu/en/ai-act/timeline/timeline-implementation-eu-ai-act ; https://artificialintelligenceact.eu/article/12/ ; https://www.whitecase.com/insight-alert/eu-ai-omnibus-enters-force-amending-ai-act). The repository itself requires the qualifier: docs/compliance/COMPLIANCE_MAPPING.md:110 '...applicability depends on system role, intended purpose, use, geography and relevant dates', and docs/institutional/DOC-05_REGULATORY_DOSSIER.md:114 lists 'effective dates' among required inputs. README.md:306 states the qualified form correctly ('as an input to a record-keeping assessment').

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-22; registry REG-D26 (compliance-wording sweep).
#### AF-045 · P3 · [COMPLIANCE_GAP] · `SECURITY_AUDIT_EXECUTION_LOG.md:130`

**Defect.** Internal execution log records a 'Compliance export SOC2/HIPAA' control as implemented with no boundary; the artifact is a compliance-named bundle generator, not a SOC 2 or HIPAA deliverable.

**Evidence.** SECURITY_AUDIT_EXECUTION_LOG.md:130 '| Compliance export SOC2/HIPAA | `aegis_server/compliance/exporter.py` | ✅ IMPLEMENTED | Enterprise layer only |'. Compare the qualified treatment in docs/api/AUDIT_ENDPOINTS.md:98 for the Part 11 endpoint, and the prohibition in docs/STYLE_GUIDE.md:42.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-22; registry REG-D26 (compliance-wording sweep).
#### AF-046 · P3 · [DOCUMENTATION_DRIFT] · `SECURITY_AUDIT_REPORT.md:72`

**Defect.** Admissibility framing ('For forensic and legal admissibility, record full chain of custody') without the style guide's required qualification that admissibility is a judicial determination — and in a repository that states no chain of custody is created.

**Evidence.** SECURITY_AUDIT_REPORT.md:72 '- For forensic and legal admissibility, record full chain of custody (timestamps, hashes, signer identity) and store signed SBOMs with release artifacts.' Required qualification: docs/STYLE_GUIDE.md:43 'legally admissible | Admissibility is a judicial determination. | "technical integrity evidence; admissibility requires qualified legal review"'. Contradicting status of custody: docs/assurance/CONTROL_TO_EVIDENCE_MATRIX.md:116 '| Chain of custody | Not provided. |'; docs/compliance/ISO_27037_TECHNICAL_INPUTS.md:33.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-22; registry REG-D26 (compliance-wording sweep).
#### AF-047 · P3 · [COMPLIANCE_GAP] · `Samples/README.md:26`

**Defect.** Sample index presents the same unqualified 'Compliance — SOC2 / HIPAA' page description.

**Evidence.** Samples/README.md:26 '| `10-compliance.html` | Compliance — SOC2 / HIPAA sealed bundles |'. No boundary or negative statement in the file; the repository's own rule requires 'contributes technical inputs that an assessor may evaluate' (docs/STYLE_GUIDE.md:42).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-22; registry REG-D26 (compliance-wording sweep).
#### AF-048 · P3 · [DOCUMENTATION_DRIFT] · `docs/compliance/EU_AI_ACT_TECHNICAL_INPUTS.md:38`

**Defect.** Describes RFC 3161 acceptance as resting on 'nonce and imprint checks' only, omitting the signature/trust-store verification that CLM-014 and the sibling MiFID II document state; the compliance docs describe the same control at different verification depths (understatement/consistency drift, not overclaim).

**Evidence.** docs/compliance/EU_AI_ACT_TECHNICAL_INPUTS.md:38 '| Optional timestamping | RFC 3161 exchanges persisted after nonce and imprint checks | `aegis/anchoring/rfc3161.py` |'. Correct full statement: docs/CLAIMS_MATRIX.md:51 (CLM-014) 'RFC 3161 exchanges can be persisted and accepted only after nonce/imprint checks and OpenSSL verification against an explicit trust store.'; docs/compliance/MIFID_II_TECHNICAL_INPUTS.md:66 'an obtained response is persisted after nonce and imprint checks and OpenSSL verification against an explicit trust store'. Implementation: aegis/anchoring/rfc3161.py OpenSSLRFC3161Verifier.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-16; registry REG-D20.
#### AF-049 · P3 · [COMPLIANCE_GAP] · `docs/enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md:148`

**Defect.** The GDPR answer omits the direct 'No' used for every neighbouring certification question and asserts a controller/processor characterisation, which the dossier treats as a legal determination for the controller and counsel.

**Evidence.** docs/enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md:148 '**Q: Are you GDPR compliant?** → Compliance is a determination about a controller or processor, not about a software component. The software is self-hosted, so the customer is the controller of data in their deployment.' Neighbours answer the same class of question with an explicit negative: :142 '**Q: Are you SOC 2 certified?** → **No.** No SOC 2 examination has been performed, and none is in progress.'; :144 '**Q: Are you ISO 27001 certified?** → **No.**'; :146 '**Q: Are you HIPAA compliant?** → **No.**'. docs/institutional/DOC-05_REGULATORY_DOSSIER.md:169 frames the equivalent question as 'A legal determination about the controller's processing, made by the controller with counsel and, where relevant, a supervisory authority.'

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-22; registry REG-D26 (compliance-wording sweep).
#### AF-050 · P3 · [COMPLIANCE_GAP] · `tools/visualizer/README.md:25`

**Defect.** User-facing dashboard README labels a product page 'SOC2 / HIPAA' with no compliance boundary.

**Evidence.** tools/visualizer/README.md:25 '| **Compliance** | SOC2 / HIPAA sealed export bundles with offline re-verification status |'. No adjacent qualifier (contrast docs/api/AUDIT_ENDPOINTS.md:98 and docs/STYLE_GUIDE.md:42). No SOC 2 examination and no HIPAA determination exist (docs/enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md:142, :146).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-22; registry REG-D26 (compliance-wording sweep).

## 3.5 E. Governance, registers and process

#### AF-022 · P2 · [DOCUMENTATION_DRIFT] · `docs/INDEX.md:4`

**Defect.** docs/INDEX.md declares '**Scope:** every maintained document, grouped by who needs it', but 35 of the 109 docs/**/*.md files are not linked from it (74 are). The unlisted set includes the registry itself and its companions (docs/REGISTRY.md, docs/REGISTRY_HUMAN_PACK.md, docs/ROADMAP.md, docs/PROVE_IT.md, docs/PLATFORM_COMPATIBILITY.md, docs/PLATFORM_OPERATOR_GUIDE.md, docs/UPGRADING.md, docs/PRODUCT_BRIEF_US.md, docs/PROSPECTUS.md, docs/PROSPECTUS_ES.md, docs/RELEASE_EPISTEMIC_STATEMENT.md, docs/SECURITY_ASSURANCE_ROADMAP.md), the whole docs/commercial/ tree (12 files incl. SALES_KIT/*, COMMERCIAL_READINESS.md, POSITIONING.md, ENTERPRISE_PRICING_GUIDE.md, SOFTWARE_ESCROW_POLICY.md, CLAIM_LEDGER.md, ARTIFACT_INVENTORY.md, CONNECTOR_ECOSYSTEM.md), docs/institutional/DOC-08_ZERO_KNOWLEDGE_INCLUSION.md (cited normatively by docs/BOUNDARIES.md:30), docs/compliance/LICENSE_AUDIT.md, and docs/security/{BUILD_SCRIPT_ATTESTATION,DEPENDENCY_RISK_REGISTER,DEPENDENCY_TRIAGE,WAL_HARDENING_2026-08-20}.md. The file was last changed 2026-09-03 (25878ee).

**Evidence.** Raw: script resolving every [..](..) target in docs/INDEX.md and diffing against 'find docs -name "*.md"': 'docs/**/*.md total: 109; linked from INDEX.md: 74; NOT linked: 35' with the 35 paths printed (reproducible via my scratch script part2_sample.py logic).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-19.
#### AF-023 · P2 · [COMPLIANCE_GAP] · `docs/REGISTRY.md:25`

**Defect.** Q4: the registry's own terminal-state rule (line 25: DOCUMENTED = 'Accepted limitation, boundary written into UNSUPPORTED_CLAIMS.md or BOUNDARIES.md') is violated by 3 of the 19 DOCUMENTED/WONT-FIX rows; the other 16 are represented. Not represented anywhere in either register: (1) REG-019 'Ledger compaction + cold tiering' (row at docs/REGISTRY.md:122) - its boundary lives only in docs/ROADMAP.md P2 and the summary ROADMAP.md; 'compaction'/'cold tier'/'retention window'/'headroom' return zero hits in both registers. (2) REG-021 'RFC 3161 revocation (OCSP/CRL)' (row at :124) - its boundary is stated only in PROVE_IT.md 5, INTEGRITY_SEAL.md 6, POSITIONING.md 5; 'revocation'/'OCSP'/'CRL' return zero hits in both registers. (3) REG-D01 'pip 24.0 and setuptools 79.0.1 in the dev venv carry 14 advisories' (row at :182) - no register entry ('setuptools'/'pip 24'/'bootstrap'/'requirements.lock'/'pip-audit' zero hits; UC-049 covers only the Rust advisories REG-D02/D03). Represented rows verified individually: REG-015 -> BOUNDARIES.md:30, REG-016 -> :29, REG-020 -> :28, REG-D04 -> :31, REG-023 -> UC-045 (UNSUPPORTED_CLAIMS.md:65), REG-027 -> UC-047 (:69), REG-038 -> UC-046 (:67), REG-043 -> UC-043 (:63), REG-044 -> UC-038 (:58), REG-051 -> UC-048 (:70), REG-A01 -> UC-005 (:25), REG-A02 -> UC-041 (:61), REG-A04 -> UC-044 (:64), REG-042 -> UC-005 (:25, AD-16 named) plus BOUNDARIES Deployment boundaries (:41), REG-D02/REG-D03 -> UC-049 (:71).

**Evidence.** Raw greps: 'grep -in -- compaction|cold tier|OCSP|CRL|revocation|setuptools|pip 24|bootstrap|requirements.lock|pip-audit docs/institutional/UNSUPPORTED_CLAIMS.md docs/BOUNDARIES.md' -> no output for all of these; row ids and terminal statuses extracted from docs/REGISTRY.md (19 terminal rows: 17 DOCUMENTED + 2 WONT-FIX); UC ids present in the register: UC-001..UC-049, none missing.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-21; registry REG-D25 (boundary entries for REG-019/021/D01).
#### AF-024 · P2 · [DOCUMENTATION_DRIFT] · `docs/REPOSITORY_MAP.md:10`

**Defect.** Q1 result. Of 298 cache-free files under the six roots (aegis 207, aegis_server 14, aegis_rust_v2/src 15, scripts 35, tools 24, integrations 3), 171 are named in NONE of the four sources (docs/REPOSITORY_MAP.md, .aegis_ai_context/README.md, llms.txt, reachability allowlist/roadmap) = the literal 'unreferenced' count; 138 of them are Python and 15 are Rust. Of those 171, 68 appear NOWHERE even including the gate's classification (no nav-doc mention, no allowlist/roadmap entry, no import-reachability verdict), and 103 are gate-'reached' live Python modules that no navigation doc names (e.g. the gate's own declared entrypoint modules aegis/engines/*, aegis/crypto/*, aegis/forensics/*, aegis_server/main.py, plus aegis/core/crypto_shredder.py, aegis/consensus/*, aegis/providers/*). Only 127 of 298 files (43%) are referenced by at least one of the four sources. First 40 of the 171 (path-sorted): aegis/anchoring/__init__.py, aegis/anchoring/rfc3161.py, aegis/auth/__init__.py, aegis/auth/apikey.py, aegis/auth/mtls.py, aegis/auth/oidc.py, aegis/auth/principal.py, aegis/auth/scopes.py, aegis/consensus/__init__.py, aegis/consensus/gossip.py, aegis/consensus/runtime.py, aegis/consensus/transport.py, aegis/core/__init__.py, aegis/core/a2a.py, aegis/core/adversarial_filter.py, aegis/core/attestation_capabilities.py, aegis/core/audit_node.proto, aegis/core/blockchain_anchor.py, aegis/core/circuit_breaker.py, aegis/core/crypto_shredder.py, aegis/core/entropy_analysis.py, aegis/core/forensic.py, aegis/core/fuzzing_harness.py, aegis/core/group_commit.py, aegis/core/homoglyph_normalizer.py, aegis/core/hsm.py, aegis/core/leak_detector.py, aegis/core/lsm_guard.py, aegis/core/math_utils.py, aegis/core/mlkem_session.py, aegis/core/normalization.py, aegis/core/observability.py, aegis/core/pci_detector.py, aegis/core/phi_deidentifier.py, aegis/core/pqc_signer.py, aegis/core/pqc_tls.py, aegis/core/rag_injection_scanner.py, aegis/core/ratelimiter.py, aegis/core/rfc3161_cms.py, aegis/core/rfc3161_timestamper.py. TOTAL 171 (per root: aegis 92, aegis_server 12, aegis_rust_v2/src 15, scripts 30, tools 22). The 'appears nowhere at all' set (68) is listed in the notes.

**Evidence.** Raw: 'find <root> -type f -not -path "*__pycache__*" -not -name "*.pyc" | wc -l' -> 207/14/15/35/24/3; per-file test = substring match of the exact relative path, unique basename, and dotted module name against the three docs, plus membership in the 77-entry allowlist and the 34-entry roadmap (pyproject omit); output written to /home/luna/.hermes/cache/scratch/inventory_result.json (counts: total_files 298, T0_unreferenced 171, T1_nowhere 68, T2_reached_but_unnamed 103). Spot check: 'grep -l crypto_shredder docs/REPOSITORY_MAP.md .aegis_ai_context/README.md llms.txt scripts/import_reachability_allowlist.txt' -> no output. Also note 71 of the 171 sit under a directory named at depth>=2 (aegis/core/ 44, aegis/proxy/ 11, aegis/auth/ 6, aegis/telemetry/ 4, aegis/storage/ 3, aegis_server/crypto/ 3) - a directory mention is not a file-level reference.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-25 (inventory & ownership); AUD-19 (navigation).
#### AF-025 · P2 · [COMPLIANCE_GAP] · `docs/ROADMAP.md:58`

**Defect.** Q3: docs/ROADMAP.md has exactly 31 open '- [ ]' items (matches the registry's scan-3 count at docs/REGISTRY.md:91). Only 12 of them map to a registry row or a Human Pack row; 19 map to no registry row and name no owner/unblock path. The registry's scan-3 disposition ('Code-shaped ones map to registry rows - REG-019, REG-037, REG-038, REG-043 - and the remainder are roadmap- or owner-level work with named unblock paths (external assurance, pricing validation, hiring - the Human Pack)') therefore holds for 12 items and not for the other 19. UNMAPPED (19): L58 (release-environment reviewers/trusted signer roots/immutable release settings/registry privileges/SBOM policy/trusted-root distribution - no REG row; REG-031/REG-034 cover only the cosign/gh verification subset), L80 (dm-delay block-device test - precondition stated, no owner, no REG), L81 (customer-target storage acceptance - no REG; nearest REG-035 is profile acceptance), L82 (revisit group commit/Rust WAL - no REG; REG-016 documents the closed decision), L89 (HTTP/2 fragmentation tests), L90 (nuclei-templates revision - only a scan-7 evidence mention, no row), L91 (WAF corpus expansion - adjacent UC-042/REG-001), L98 (three-replica deployment test), L99 (HSM/Vault rotation evidence - adjacent REG-H08 procurement), L104 (ML-DSA timing repeat - adjacent REG-041/UC-012), L105 (constant-time wording rule - no REG row; mirrored in UC-012), L106 (FIPS/conformance tracking - adjacent UC-013), L111 (transparency-log/timestamp anchoring backend), L113 (dependency/action exceptions bounded, owned, time-limited - no row owns or time-limits them), L142 (protected tags/environments/trusted publishers - adjacent REG-027), L143 (full gate completion before release), L148 (end-to-end latency measurement), L149 (multi-worker topology measurement), L152 (SLO publication - precondition named, no owner named, no REG row). MAPPED (12): L61->REG-042/UC-005/UC-038, L62->REG-H01, L110->REG-043, L112->REG-035, L114->REG-H01, L130->REG-038, L147->REG-019, L151->REG-037/REG-051, L159->REG-H06, L160->REG-H05, L161->REG-H04, L162->REG-H01.

**Evidence.** Raw: 'grep -n "^- \[ \]" docs/ROADMAP.md' -> 31 items (lines 58,61,62,80,81,82,89,90,91,98,99,104,105,106,110,111,112,113,114,130,142,143,147,148,149,151,152,159,160,161,162); REG-id regex over the item texts -> only L147 cites one (REG-019); keyword sweeps over docs/REGISTRY.md: dm-delay 0, loop-backed 0, HTTP/2 0, fragmentation 0, three-replica 0, HSM/Vault 0, transparency 0, multi-worker 0, immutable signed tags 0, trusted-publisher 0, customer-target 0, FIPS 0, block device 0; registry back-references to the roadmap exist only for ROADMAP.md:61, :110, :130 (grep -oE 'ROADMAP.md:[0-9]+' docs/REGISTRY.md | sort | uniq -c -> 1 each). Human Pack rows: docs/REGISTRY_HUMAN_PACK.md:34-175 (REG-H01..H09).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-25 (assign owners/unblock paths to the 19 unmapped open items).
#### AF-026 · P2 · [DOCUMENTATION_DRIFT] · `llms.txt:6`

**Defect.** llms.txt, one of the four navigation sources, states 'Checked-out source baseline/release target: 4.1.2' and 'The most recent published release is signed annotated tag v4.0.2' (line 7), contradicting the current state that AGENTS.md and .aegis_ai_context/README.md both assert (source baseline v5.0.0 with 14 synchronized anchors, published 2026-09-16 on every surface except PyPI aegis-latent-core; most recent release published on every surface is v4.1.2). The file was last changed 2026-09-03 (commit 25878ee), before the 5.0.0 publication, and was never refreshed; it also never mentions v4.1.2 or v5.0.0. Since llms.txt is the fallback navigation aid when .aegis_ai_context/ is unavailable, an agent reading it gets a baseline two releases behind.

**Evidence.** llms.txt:6-7 text as quoted; 'git log -1 --format=%ci -- llms.txt' -> 2026-09-03 23:35:28 -0300 25878ee; AGENTS.md baseline paragraph; .aegis_ai_context/README.md:7 ('current source baseline is v5.0.0 ... published 2026-09-16 on every surface except PyPI aegis-latent-core').

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-19; registry REG-D23.
#### AF-027 · P2 · [ARCHITECTURAL_DEBT] · `scripts/verify_import_reachability.py:72`

**Defect.** Q5: what actually plays the module-inventory role is SPLIT across three artifacts, none of which is a per-module inventory. (a) The reachability gate scripts/verify_import_reachability.py + scripts/import_reachability_allowlist.txt + pyproject [tool.coverage.run].omit is the closest thing: 'modules discovered: 223  reached: 112  declared roadmap: 34  allowlisted: 77 ... PASS', but PACKAGE_ROOTS = ('aegis','aegis_server','integrations') (line 72) and it walks only *.py (line 112), so scripts/ (35 files), tools/ (24), aegis_rust_v2/src/ (15 .rs) and every non-.py file are outside it. (b) docs/REPOSITORY_MAP.md is a hand-maintained map naming 44 paths (~10 source modules). (c) .aegis_ai_context/01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv (37 symbol rows, 10 distinct files) and 08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md are advisory. Missing to make a real inventory possible: any per-module record with purpose/status/test/owner; any coverage of scripts/, tools/, aegis_rust_v2/src/ or non-.py files; and any per-module maintainer field - .github/CODEOWNERS declares a SINGLE accountable owner for everything ('* @JuanLunaIA' plus 6 directory globs, comment 'A single accountable owner is declared until the project has a staffed review team'), and the word 'Owner:' exists in the registry only in the 3 BLOCKED rows (docs/REGISTRY.md:145,148,149), i.e. no maintainer field exists anywhere at module granularity. The allowlist itself states 'This is a disclosure, not a classification' (lines 6-12). docs/commercial/ARTIFACT_INVENTORY.md is a revenue/buyer-text inventory, not this role.

**Evidence.** Raw: 'python3 scripts/verify_import_reachability.py --root .' -> 'modules discovered: 223 reached: 112 declared roadmap: 34 allowlisted: 77 / verify_import_reachability: PASS - no undeclared orphans, no stale roadmap entries' (exit 0); script lines 29-45 (scope), 72 (PACKAGE_ROOTS), 112 (rglob *.py); allowlist 96 lines incl. comments, 77 entries; 'wc -l .aegis_ai_context/01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv' -> 38; 'grep -rc "Owner:" docs/REGISTRY.md' -> 3; cat .github/CODEOWNERS.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-25; boundary UC-057.
#### AF-055 · P3 · [DOCUMENTATION_DRIFT] · `.aegis_ai_context/01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv:5`

**Defect.** The AI-context pack's symbol/type index still describes the source release target as v4.1.2 ('Checked-out source release target v4.1.2 with 14 synchronized anchors', 'Agreement at 4.1.2 defines the source release target', lines 5-9), contradicting the pack's own README (:7, current source baseline v5.0.0 published 2026-09-16 except PyPI aegis-latent-core) and 02_OPERATIONAL_INVARIANTS_MATRIX.md:24, which both state v5.0.0. The pack is advisory and its manifest verifies integrity, not currency, so the stale baseline is not caught by tests/test_ai_context.py.

**Evidence.** Raw: 'grep -rn 4.1.2 .aegis_ai_context/*.tsv .aegis_ai_context/*.md' -> 01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv:5,6,7,8,9; contrast .aegis_ai_context/README.md:7 and 02_OPERATIONAL_INVARIANTS_MATRIX.md:24 (v5.0.0).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Trivial-fix + Roadmap AUD-19.
#### AF-056 · P3 · [DOCUMENTATION_DRIFT] · `docs/REGISTRY.md:10`

**Defect.** Q5: docs/REGISTRY.md is a DEFECT/DEBT registry, NOT a module inventory. Its own scope line (line 10) is 'every known defect, debt item and open decision, with a stable id and a terminal state'; all 66 rows are keyed by REG-<id> + Brands + Class + Sev + Mechanism + Status + Evidence. Module paths appear only as evidence locators. The audit brief that assumed it was a module inventory is wrong; the file itself makes no such claim and needs no correction (the burn-down in section 5 is arithmetically self-consistent: W1 30 + W2 23 + W3 9 + DISC 4 = 66 rows; 18 FIXED + 26 VERIFIED + 17 DOCUMENTED + 3 BLOCKED + 2 WONT-FIX = 66).

**Evidence.** Raw: 'grep -oE "| REG-[A-Z]?[0-9]+" docs/REGISTRY.md | sort -u | wc -l' -> 66 unique REG ids; 'grep -oE "aegis/[A-Za-z_/]+\.py" docs/REGISTRY.md | sort -u | wc -l' -> 15 (evidence locators only); 'grep -oE "***(FIXED|VERIFIED|DOCUMENTED|BLOCKED|WONT-FIX)[^*]***" docs/REGISTRY.md | sed s/**//g | cut -d" " -f1 | sort | uniq -c' -> 18 FIXED / 26 VERIFIED / 17 DOCUMENTED / 3 BLOCKED / 2 WONT-FIX; burn-down table at docs/REGISTRY.md:197-203, seal state at :213; scope line docs/REGISTRY.md:10; row schema docs/REGISTRY.md:103-185.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-21; registry REG-D25 (boundary entries for REG-019/021/D01).
#### AF-057 · P3 · [DOCUMENTATION_DRIFT] · `docs/REPOSITORY_MAP.md:3`

**Defect.** The 'Last verified' stamp in docs/REPOSITORY_MAP.md reads 2026-08-27 UTC while the same page describes the v5.0.0 source baseline published 2026-09-16 (line 5) and the file was last modified 2026-09-17 by commit dc20a2c (the REG-060 change that added the AI-context section, and the REG-025/040/011 closure). The verification date therefore predates the content it certifies by three weeks - a stale provenance stamp on the map that other artifacts point to as the maintained source map.

**Evidence.** docs/REPOSITORY_MAP.md:3 ('**Last verified:** 2026-08-27 UTC') vs :5; 'git log -1 --format=%ci -- docs/REPOSITORY_MAP.md' -> 2026-09-17 08:59:33 -0300 dc20a2c 'Registry closure, wave 2: REG-049, REG-025, REG-026, REG-040, REG-011 (#187)'.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-25 (inventory & ownership); AUD-19 (navigation).
#### AF-058 · P3 · [DOCUMENTATION_DRIFT] · `docs/institutional/UNSUPPORTED_CLAIMS.md:5`

**Defect.** Formatting/editorial defects in the register that BOUNDARIES.md and the registry treat as normative: (a) the 2026-09-21 amendment note (line 5) states the UC-046 and UC-047 additions twice ('UC-046 added for the aegis_server second-surface boundary ... UC-047 for the PyPI gateway gap ...' followed by 'UC-046 added for the second HTTP surface (aegis_server) ... UC-047 added for the PyPI distribution gap ...'); (b) the table is split by a blank line at line 66, so UC-046..UC-049 render as a second table; (c) rows UC-048 and UC-049 end with a stray pipe-and-quote artifact ('| "') at lines 70 and 71.

**Evidence.** docs/institutional/UNSUPPORTED_CLAIMS.md:5 (duplicated clauses), :66 (blank line splitting the table), :70-71 (trailing '| "'); the four doc gates do not flag it (docs/REGISTRY.md:221 records verify_docs PASS / verify_claims PASS 102 claims 0 findings).

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Trivial-fix (editorial) + Roadmap AUD-19.
#### AF-059 · P3 · [DOCUMENTATION_DRIFT] · `scripts/verify_import_reachability.py:74`

**Defect.** The reachability gate and its 77-entry allowlist - the only artifact that enumerates un-reached modules - are referenced in none of the three navigation artifacts (grep for 'reachab'/'import_reachability' over docs/REPOSITORY_MAP.md, .aegis_ai_context/README.md, llms.txt returns nothing), so a reader of the repository map cannot discover the module-coverage control. Relatedly, 4 of the gate's 6 declared ENTRYPOINT_MODULES are named in none of the four sources: aegis_server.main, aegis.engines, aegis.crypto, aegis.forensics (only 'aegis' and 'aegis.proxy.app' are named, via REPOSITORY_MAP.md:16,30 and llms.txt:21).

**Evidence.** Raw: 'grep -ln "reachab|import_reachability" docs/REPOSITORY_MAP.md .aegis_ai_context/README.md llms.txt' -> no output (exit 1); ENTRYPOINT_MODULES at scripts/verify_import_reachability.py:74-81; 'grep -l aegis.engines|aegis/crypto|aegis.forensics|aegis_server.main' over the three docs -> NONE for each.

**Verification.** LINE-VERIFIED (parent printed the cited line/region from disk; matches the finding's claim)

**Disposition.** Roadmap AUD-25; boundary UC-057.

#### AF-095 · P2 · [ARCHITECTURAL_DEBT] · `Makefile:34` vs `.github/workflows/ci.yml:144` (and `scripts/verify_docs.py`, `scripts/verify_release_readback.py`)

**Defect.** The repository's own `make lint` target runs `ruff format --check .` over the whole tree, while CI's Lint job runs the same command over a fixed nine-directory path list. With ruff 0.16.8 the two scopes disagree in both directions: (a) `scripts/verify_docs.py` and `scripts/verify_release_readback.py` are unformatted Python that exists in **no** CI gate, and (b) modern ruff also formats Python code fences inside Markdown, so nine `.md` files (README, docs/api/MMR_PROOF_V1.md, docs/DEVELOPER_*.md, docs/PROVE_IT.md, docs/USAGE_EXAMPLES.md, docs/commercial/CONNECTOR_ECOSYSTEM.md, .claude/agents/*.md) now fail the whole-tree check. Net effect at HEAD: `make lint` fails (exit 1) while CI is green — the two canonical commands give opposite verdicts, and `INTEGRITY_SEAL.md:24`'s "ruff format --check . → PASS — 550 files" is unreproducible (the same command now scans 817 files and fails).

**Evidence.** Parent-run at HEAD `289e4ea`: `.venv/bin/ruff format --check .` → exit 1, "11 files would be reformatted, 806 files already formatted"; the 11 files are the two scripts plus nine markdown files with code fences; CI's command (`.github/workflows/ci.yml:144-155`) names only `aegis aegis_server integrations tests tools/visualizer tools/forensic tools/benchmarks tools/security benchmarks`; `Makefile:32-34` runs `ruff check .` then `ruff format --check .`.

**Verification.** REPRODUCED FIRST-HAND (parent ran both forms and diffed the scopes).

**Disposition.** Roadmap AUD-18; boundary UC-058; registry REG-D22.

---

## 4. Verified-absent register (checked and disproved — do not re-flag)

These were found by the mechanical sweeps and the delegated scans, then adjudicated and **rejected as defects** with a reason. They are listed so the next audit starts from evidence instead of suspicion.

**Secrets and credentials (parent, whole tree):** no hardcoded credentials of any kind. The only hits for key-shaped literals are synthetic demo strings inside `Samples/*.html` (a WAF/threat-detection gallery), by design. No `.env`, token, or private key material is committed.

**Language-level hazards (parent, whole tree):** no `os.system`, no `yaml.load`, no `pickle.loads` on untrusted input, no Python `eval`/`exec` of non-constant input. The three `eval(` hits are Redis Lua `eval` (2 sites in rate limiters) and a regex pattern string inside a detection list; the two `shell=True` hits are docstring text describing why shell=True is *not* used (`cfi_manager.py`) and in triage tooling.

**Hash and comparison misuse (delegated, parent-spot-checked):** md5 appears only with `usedforsecurity=False` and a documented rationale (EWF/E01 format-mandated checksums in `dfir_export.py`; SimHash similarity bucketing in `cross_session_correlator.py`) and always beside SHA-256 where integrity is claimed. No sha1. Every secret/MAC/key/token comparison in the read set uses `hmac.compare_digest`; the non-constant-time comparisons found compare digests/roots (public values), not secrets.

**Randomness (delegated):** every `random.*` use is annotated non-security (`# nosec B311 - deterministic corpus replay, not a security decision`) or confined to benchmarks/tests. Security-relevant randomness is `os.urandom`/`secrets` throughout (96-bit GCM nonces, TSP nonces, token bytes, uuid4 identifiers). No `uuid1`.

**Canonicalization hardening that *is* present (delegated, verified):** `canonical_jcs_bytes` rejects floats — including NaN/Infinity — and lone surrogates; `canonical_dag_cbor_bytes` rejects NaN/Infinity; the `\x00`-joined `hash_audit_payload` and the `|`-joined `node_hash` were both attacked by construction and no collision was found given the co-fields' format constraints (timestamp `%.9f`, digests, validated vocabularies); `boot_attestation`'s lone-surrogate path does not raise (ensure_ascii escapes it). The one canonicalization defect that *did* survive is the hardware-token NUL ambiguity (AF-023 item 3).

**Durability paths that are sound (delegated, verified):** `crypto_audit` + `group_commit` write under the ledger lock, return a ticket, fsync only in `_sync_wal` outside the lock, latch `wal_persist_failed` on batch failure and raise to every waiter; MMR checkpoint writes are temp-file + fsync + `os.replace` + directory fsync. No path reports a governed commit durable before its fsync. No `mmap`/`msync` in ledger paths.

**Rust crate (delegated + parent line-verified):** MMR domain separation is exactly `0x00` leaf / `0x01` node / `0x02` root in `mmr.rs`, `crdt_mmr.rs` and `zk_mmr.rs`, with byte-for-byte root parity against the Python reference measured for n = 1, 2, 3, 5, 8, 37 leaves; no v2 path hashes un-prefixed data. `unsafe` inventory is exactly three sites (two of them the unnecessary `Send`/`Sync` impls — AF-024). No raw-pointer arithmetic, transmutes, unions, `repr(packed)`, or unchecked indexing found. Keyed hashing rejects wrong key lengths with `ValueError`; error paths otherwise map to `PyErr`; RNG is the OS CSPRNG; integer casts are guarded on the release matrix; the crate correctly documents constant-time status as NOT ESTABLISHED and scopes its Kani proofs to `header_range`/`payload_range`.

**Python concurrency (delegated, parent-spot-checked):** stream admission gate never leaked a slot under normal completion, disconnect race, or send-failure teardown; `_ByteBoundedQueue` is correctly bounded (no lost wakeup, no unbounded growth); `analysis_queue` bounded with `QueueFull` handling and clean shutdown; fire-and-forget commits keep strong references; group-commit ticket protocol monotonic; lock ordering `_lock -> _sync_lock` consistent; SSE line iteration caps both terminated and unterminated lines; WAF `inspect_payload` has no fail-open exception path.

**Supply chain / CI (parent):** every workflow carries a `permissions:` block (no `write-all`); **all** actions are pinned to full commit SHAs; no workflow disables a security gate.

**Compliance claims (delegated, parent-verified):** no file asserts certification, legal compliance, court admissibility or external assurance as established fact. `CLM-039`'s boundary ("Not a SOC 2 opinion, HIPAA determination, FedRAMP authorization, EU AI Act conformity assessment, GDPR legal basis, or legal advice") is respected everywhere it is restated; `VENDOR_SECURITY_QUESTIONNAIRE.md` says "**No.**" to SOC 2 / ISO 27001 / HIPAA; `docs/STYLE_GUIDE.md:42-44` prohibits exactly the wording that four sandbox surfaces then used (AF-022).

**Governance arithmetic (delegated, parent-reconciled):** the registry burn-down reconciles (66 = 30+23+9+4 = 18+26+17+3+2); all 125 distinct paths named in `REPOSITORY_MAP.md`/`INDEX.md` exist (0 missing); the reachability gate exits 0 with its four counts; UC ids form a gapless set (UC-001..UC-049).

---

## 5. Regulator and article verification (results)

Every article number cited anywhere in the `.md` corpus was checked against the instrument; the corpus itself is **accurate**. Verification sources: EUR-Lex (CELEX:32024R1689, 32014L0065, 32017R0565, 32017R0580, 32017R0574, 32016R0679), the EC AI Act Service Desk, artificialintelligenceact.eu, ESMA, sec.gov/eCFR, finra.org.

| Instrument | Article | What it is | Where cited | Verdict |
|---|---|---|---|---|
| EU AI Act (2024/1689) | 6 | high-risk classification rules | COMPLIANCE_MAPPING:110, DOC-05:114 | correct |
| EU AI Act | 9 | risk-management system | DOC-05 §5.5 | correct |
| EU AI Act | 12 | **record-keeping / automatic logging** for high-risk systems | README:306, INDEX:101, POSITIONING:35 | correct — but README:18 groups it with duties the reader "already owes" today; applicability dates (2 Dec 2027 / 2 Aug 2028 per the Digital Omnibus) and role conditions are the qualifier the repo's own COMPLIANCE_MAPPING:110 requires (AF-022) |
| EU AI Act | 13 | transparency / instructions for use | DOC-05 master matrix | correct |
| EU AI Act | 14 | human oversight | DOC-05 master matrix | correct |
| EU AI Act | 17 | quality management system | **not cited anywhere in the corpus** | nothing to check (the brief's Art. 12/17 pairing is accurate as to subject matter) |
| MiFID II (2014/65/EU) | 16 | organisational requirements | market_abuse_detector.py:14; DOC-05 §5.7 | correct |
| MiFID II | 16(6) | records of services/transactions, ≥5 years | mifid_record_keeper.py:6-7; DOC-05 | correct as to the 5-year floor; the **"7 years for SMCR-scope firms"** attribution in the module does not match the FCA-based retention we could verify (6 years), and the MiFID 7-year figure is the competent-authority extension, not a default — flagged for counsel (AF-020) |
| MiFID II | 16(7) + DelReg 2017/565 Art. 76 | recording of communications | DOC-05:130,:136 | correct |
| MiFID II | 25(1) | suitability records | mifid_record_keeper.py:6-7 | correct |
| MiFID II | 24 | general principles / information to clients | **not cited anywhere** | nothing to check |
| **MiFID II Art. 12** | — | **"Assessment period"** (qualifying-holdings approval) | `aegis/core/market_abuse_detector.py:27` cites "MiFID II Art. 12(1)(a)(ii)" for spoofing | **WRONG — the provision is MAR (Reg. 596/2014) Art. 12(1)(a)(ii); MiFID II Art. 12 is "Assessment period".** Fixed in AF-020 (trivial-fix) |
| RTS 24 / RTS 25 | — | DelReg 2017/580 (order records) / 2017/574 (clock sync) | DOC-05:128-130 | correct — the dossier explicitly corrects the common RTS 24/25 conflation |
| GDPR (2016/679) | 5(1)(c)/(e), 16, 17, 17(2), 25, 32 | minimisation, storage limitation, erasure, design, security | DATA_RETENTION:75, COMPLIANCE_MAPPING:112, DOC-05:151-172 | correct subject matter |
| SEC 17a-4(f) / FINRA 4511 | — | WORM + audit-trail alternative; ≥6 years where unspecified | DOC-05:40,:70 | correct |
| HIPAA | 45 CFR 164.514(b)(2); 164.312(b)/(c)/(e) | Safe Harbor 18 categories; audit controls/integrity/transmission | HIPAA_TECHNICAL_INPUTS:56, COMPLIANCE_MAPPING:98 | correct |

**Verdict for the brief's regulatory clause:** all article references in the Markdown corpus are technically accurate; the only wrong citation found in the repository is a *code docstring* (`market_abuse_detector.py:27`) and it is mapped to AF-020. Nothing in this repository asserts MiFID II or EU AI Act compliance as fact, and after this audit it must not: the correct form is already available in `docs/compliance/MIFID_II_TECHNICAL_INPUTS.md` ("Not a MiFID II compliance statement") and is now reinforced by `UC-056`.

---

## 6. Register updates made by this change

Everything below is appended to the registers in the same commit as this report; nothing existing was deleted. IDs: `AUD-nn` (roadmap backlog tickets, 26), `UC-050`…`UC-058` (unsupported-claims entries, 9), `REG-D05`…`REG-D30` (registry audit block, 26 rows, all OPEN by design with their roadmap ticket named as the mechanism).

**`docs/ROADMAP.md` — new section "Audit backlog — v5.0.1-prep (2026-09-21)"**: 26 tickets, each with ID / Severity / Affected files / Root cause / Proposed solution / Estimated effort:

- **AUD-01 [P1] Audit evidence endpoint returns HTTP 500 for every node (JCS projection).** Files: aegis/proxy/audit_api.py (handler at :233-234; canonicalizer in aegis/core/forensic_bundle.py). Root cause: AuditNode.to_dict() always carries float fields (timestamp, entropy, sampling_params.elapsed_seconds); canonical_jcs_bytes rejects floats by design, the ForensicBundleError is uncaught, and no exception handler is registered, so the documented byte-exact RFC 8785 projection 500s on 100% of nodes. Reproduced first-hand (parent probe: GET /nodes/{hash} -> 200; /evidence -> 500). Proposed solution: Either route the JCS projection through a float-safe form (project floats as strings per the register's own JCS scope) or catch ForensicBundleError and return a documented 4xx/501 with an explanatory body; add a regression test that exercises the endpoint against a real committed node (every existing test mocks the ledger). Estimated effort: S (0.5-1 day).
- **AUD-02 [P1] Signature verification is dispatched on a self-declared, hash-unbound field.** Files: aegis/core/crypto_audit.py (_verify dispatch :1442; node_hash :562-574; _build_signed_payload; node_signature_assurance :432). Root cause: signature_scheme is not an input to node_hash nor to the signed payload; verify_integrity() verifies HMAC only when the label says hmac-sha256, and node_signature_assurance maps the same unauthenticated label to an assurance tier. Reproduced first-hand: rewriting only the label on all WAL lines yields verify_integrity=(True,None) with signature_assurance=ASYMMETRIC_HARDWARE_ATTESTED and every per-node status 'unverified'. Proposed solution: Bind the scheme into the chain: add signature_scheme to the hashed material and the signed payload under a chain-version bump, verify each declared scheme against an allowlist with a real verifier (or mark 'unverified' explicitly in verify_integrity's result), and add a tamper test (edit label -> integrity fails or status is 'unverified' and assurance is floored). Estimated effort: M (2-4 days, touches node_hash compatibility + migration note).
- **AUD-03 [P1] Terminal evidence is not committed on the teardown styles the ASGI stack actually delivers.** Files: aegis/proxy/streaming.py (_iterate CancelledError handler :357-365; _cancel_producer :567-570; aclose). Root cause: Under anyio-delivered cancellation (the real Starlette/uvicorn path) the first await inside the CancelledError handler re-raises, so the shielded _finalize never runs; aclose()/GeneratorExit cannot await at all. Reproduced first-hand: real-app send-failure run -> wal_terminal_nodes=0; controls T1_aclose=0, T2_cancel=1, T3_complete=1. Response headers advertise pending-terminal with no landing proof. Proposed solution: Commit terminal evidence on every teardown style: wrap the finalize in a shielded, cancellation-proof task created before the generator is abandoned (e.g. spawn the terminal commit as a task the response object owns, committed in the server-side task group), and add teardown tests for all three styles (cancel, aclose/GeneratorExit, send failure) counting terminal nodes. Estimated effort: M (1-3 days + tests).
- **AUD-04 [P1] RustWal: two handles on one path silently destroy committed frames (unexercised SAFETY invariant).** Files: aegis_rust_v2/src/wal.rs (SAFETY comment :149-150; WalInner :78-83; open :101-102). Root cause: Each handle owns its own Mutex and AtomicU64 write_pos; nothing enforces single-writer exclusivity, so a second opener rescans, computes the same offsets, and overwrites flushed frames through its own MAP_SHARED mapping. Reproduced first-hand: alternating appends -> b's frames overwrote a's; a.read_all returned only b's records; both handles reported write_pos 92. Proposed solution: Add a single-writer guard (flock or O_EXCL lock file) in RustWal::open and fail closed with a clear PyErr; document concurrent multi-handle use as unsupported (UC-051) until then; add a test that opening a second handle either fails or is safe. Estimated effort: S-M (1-2 days + test).
- **AUD-05 [P1] Release-profile aborts instead of exceptions for caller-controlled sizes and resource failures.** Files: aegis_rust_v2/src/audit.rs :44; session.rs :52; rate_limit.rs :144 and :69; forwarder.rs :55; pqc_trait.rs :252; Cargo.toml panic=abort. Root cause: Caller-supplied usize capacities reach crossbeam ArrayQueue and DashMap constructors unvalidated (capacity 0 panics; 2**40 aborts on allocation failure - reproduced first-hand), an unchecked multiply can panic on overflow, a fallible Tokio build uses .expect(), and the pure-Rust PQ backend expects the OS RNG. With panic="abort" in the release profile none of these become Python exceptions - the gateway process dies. Proposed solution: Validate and clamp all caller-supplied sizes (reject 0 and > documented ceilings with ValueError), replace overflow-prone arithmetic with saturating ops or checked_mul+error, map runtime/RNG failures to PyErr, and add a regression suite that exercises each invalid input path. Estimated effort: M (2-3 days + tests).
- **AUD-06 [P1] Retracted backpressure figures (10,000 records / p99 1,189.89 ms) still presented as measured evidence in 12 documents.** Files: docs/PROSPECTUS.md:58; docs/PRODUCT_BRIEF_US.md:43; docs/BENCHMARKS.md:37; docs/benchmarks/BENCHMARK_RESULTS.md:15; docs/benchmarks/BENCHMARK_METHOD.md; docs/benchmarks/README.md; docs/FAQ_TECHNICAL.md:118; docs/FAQ_PROCUREMENT.md:64; docs/operations/BACKPRESSURE_RUNBOOK.md:53; docs/performance/SCALING_GUIDE.md:38; docs/ROADMAP.md:79; DEPLOYMENT_GUIDE.md:138 (plus CHANGELOG history). Root cause: UC-018 declares the 10,000-record / p99 1,189.89 ms pair false and retracted (the committed artifact contains 2,500 records at p99 836.3514210795984 ms), but the sweep stopped at the canonical matrices; buyer-facing docs still carry the pair as the retained v3.1.0 measurement. Parent verified 13 files carry the pair (14 with CHANGELOG history); UC-017 also uses 'retained' for a different run, which is the naming mechanism that keeps the error propagating. Proposed solution: Run a scripted sweep: replace every occurrence with the artifact-backed pair (2,500 / 836.3514210795984 ms) or an explicit retraction note, standardise the word 'retained' to name one run (the 2026-09-16 execution evidence), and add the sweep to the docs gate (a grep-based check that no md file cites the retracted pair outside the retraction rows themselves). Estimated effort: S (1 day for the sweep; +0.5 day for a gate check).
- **AUD-07 [P1] BOUNDARIES.md publishes ZK cost numbers that CLM-089 forbids.** Files: docs/BOUNDARIES.md:30 vs docs/CLAIMS_MATRIX.md:115 (CLM-089). Root cause: The ZK row states 'measured on one host at setup 2.5 s, prove 1.3 s, verify 0.19 s', while CLM-089 prohibits 'any setup, proving, verification or proof-size number' because the cost harness is #[ignore]d and not a reproducible artifact. Proposed solution: Either remove the numbers from BOUNDARIES.md and restate the CLM-089 boundary, or promote the cost harness to a reproducible artifact (a committed, runnable command + output file) and update CLM-089 to name it. The two registers must not contradict. Estimated effort: S (2-4 h either way).
- **AUD-08 [P2] Audit read endpoints iterate the live ledger deque without a lock/snapshot.** Files: aegis/proxy/audit_api.py :133,:148,:153,:177,:215,:230,:254,:288,:297,:324; writer aegis/proxy/app.py:1382,1845; deque aegis/core/crypto_audit.py:806. Root cause: Commits append to the deque from asyncio worker threads while handlers iterate it; a landing mutation raises RuntimeError('deque mutated during iteration') -> 500 with no data. Ledger accessors elsewhere snapshot under self._lock, so this is an inconsistency. Proposed solution: Take a snapshot (list(ledger.chain) or a locked accessor) at every read site, matching signature_assurance/verify_integrity; add a test that commits concurrently with each endpoint. Estimated effort: S (0.5-1 day).
- **AUD-09 [P2] Enterprise surface buffers request and response bodies without limits.** Files: aegis_server/main.py :894, :976 (middleware :253-262); contrast aegis/proxy/app.py:1323. Root cause: await request.body() and await resp.aread() buffer full bodies; no RequestBodyLimitMiddleware is installed on the enterprise app, so it is weaker than the gateway it fronts. Proposed solution: Install the gateway's body-limit middleware with max_request_body_bytes and add a response-side cap/streaming path; test oversized request and oversized upstream response. Estimated effort: S-M (1-2 days).
- **AUD-10 [P2] 21 CFR Part 11 signer annotation fields are not cryptographically bound.** Files: aegis/core/crypto_audit.py (node_hash fields :562-574; _build_signed_payload; export_part11_signatures :1520-1545). Root cause: signer_name/signature_meaning/status are absent from node_hash, the signed payload and the MMR leaf, yet the export docstring calls node_hash a 'tamper-evident binding' for the annotation; a WAL-write attacker can rewrite signer identity and relabel rejected as committed with no verification change. Proposed solution: Include the annotation in the hashed material (chain-versioned) or, if that is not wanted, rewrite the export to state plainly which fields are unbound; add a tamper test. Estimated effort: M (1-2 days + migration note).
- **AUD-11 [P2] Transparency log: verify does not recompute entry hashes; append is not fsynced.** Files: aegis/core/transparency_log.py :75-79 (append), :129-140 (verify); contrast export_audit_log.py:200-204. Root cause: verify_ledger_integrity only compares prev_hash linkage against stored entry_hash, so in-place edits of binary_hash/version/timestamp verify clean; publish_binary_hash returns a success hash after a buffered write with no flush/fsync. Proposed solution: Recompute entry_hash from fields inside verify_ledger_integrity; flush+fsync (or document the weaker durability contract) on append; test tamper detection on a non-tail entry. Estimated effort: S (0.5 day + tests).
- **AUD-12 [P2] Rust forwarder buffers upstream responses with no cap.** Files: aegis_rust_v2/src/forwarder.rs :169-173; lib.rs:72-74. Root cause: resp.bytes().await collects the whole body, then it is copied again into a Python bytes object; a hostile or misconfigured upstream drives gateway RSS to 2x response size. Proposed solution: Stream with a bounded reader and enforce a configurable maximum (mirroring the Python stream bound); return a PyErr on breach. Estimated effort: S-M (1-2 days + tests).
- **AUD-13 [P2] RustWaf documents NFKC normalisation that does not exist.** Files: aegis_rust_v2/src/waf.rs :19 (claim) vs :128-131 (only strip_zero_width). Root cause: No Unicode normalisation exists in the crate (no unicode-normalization dependency); compatibility variants (fullwidth/mathematical-bold) of a critical pattern are not blocked by a direct RustWaf consumer. The Python gateway layer applies NFKC and is authoritative, so this is a library-level false negative and a false API statement, not a demonstrated gateway bypass. Proposed solution: Implement NFKC via unicode-normalization (and non-ASCII case folding via the same path) or correct the module documentation and add the fullwidth control to the crate's tests. Estimated effort: S-M (1-2 days).
- **AUD-14 [P2] Inert configuration controls presented as enforceable (CAC/PIV, PHI at-rest key, LDAP family).** Files: aegis/config.py :306 (cac_piv_required), :295 (phi_master_key), :191-199 (ldap_*). Root cause: cac_piv_required and phi_master_key are read nowhere (0 references outside the declaration); no ldap_* setting is read and no LDAP authenticator is wired; each field's description promises enforcement or encryption that never happens. Operators sizing HIPAA/DoD deployments on this text are misled. Proposed solution: Choose per control: wire it (instantiate CACPIVAuth; construct the payload encryptor; wire LDAPAuthenticator) or reword the description to say the control is not yet wired and delete the knob if it cannot ever work; add a config-surface test that fails when a settings field has no reader (a small grep-based gate). Estimated effort: M (wire-up path is larger; reword path is S).
- **AUD-15 [P2] WAF corpus cited from a non-in-tree artifact, the practice CLM-032 retired.** Files: docs/compliance/COMPLIANCE_MAPPING.md:32; docs/assurance/AUDIT_EVIDENCE_INDEX.md:123. Root cause: Both still name waf_corpus_report_v1_candidate.json, which is not in the tree; CLM-032's correct in-tree evidence is evidence/execution_2026-08-20/waf_corpus_report.json. Proposed solution: Point both rows at the in-tree artifact (or the 2026-09-16 evidence) and add a link check that artifacts named as evidence exist in-tree. Estimated effort: S (2 h).
- **AUD-16 [P2] Two compliance technical-input docs carry boundary text that REG-023/UC-045 superseded.** Files: docs/compliance/EU_AI_ACT_TECHNICAL_INPUTS.md:67; docs/compliance/HIPAA_TECHNICAL_INPUTS.md:67 (also :25,:38 for the RFC 3161 depth). Root cause: Both still say 'the record holds the scrubbed form' / 'redaction changes the evidence record only' and 'PHI reaches the provider unscrubbed' unconditionally - text corrected in docs/privacy/PII_REDACTION_BOUNDARIES.md:48 and UC-045 but not propagated. Proposed solution: Apply the corrected wording verbatim from PII_REDACTION_BOUNDARIES.md and UC-045 to both files; align the RFC 3161 row with CLM-014's full statement. Estimated effort: S (3-4 h).
- **AUD-17 [P2] Capability table uses blocked wording: 'chain-of-custody' and 'trusted timestamp'.** Files: docs/architecture/DEEP_DIVE.md :288, :289. Root cause: The ISO 27037 row claims 'chain-of-custody' (the project's own boundary: no custody record is created - UC-024) and the RFC 3161 row says 'trusted timestamp' (blocked by CLM-014/CLM-096; the gaps - no revocation checking, no RFC 5280 name-constraint evaluation - are not named). Proposed solution: Replace with the register's own words: evidence-package seal, offline-verifiable, and 'TSA token bound to bundle imprint - not a trusted timestamp; no revocation checking'. Estimated effort: S (2 h).
- **AUD-18 [P2] Gate-scope drift: the Makefile formatter gate is broader than CI's and fails at HEAD.** Files: Makefile:34 (`ruff format --check .`) vs .github/workflows/ci.yml:144 (fixed path list); unformatted: scripts/verify_docs.py, scripts/verify_release_readback.py; newly covered: 9 markdown code fences. Root cause: Modern ruff (0.16.8) formats Python fences inside Markdown and includes .md under `.`, so `make lint` fails on 11 files while CI (narrower path list, same unpinned ruff) passes. The two Python files are outside every gate. Reproduced first-hand: exit 1, '11 files would be reformatted, 806 files already formatted'. Proposed solution: Decide the canonical scope once: either align the Makefile with CI's path list (and add scripts/ to both), or extend CI to the whole tree and format/exclude markdown fences; then fix the two scripts and add the chosen form to CI. Estimated effort: S (0.5-1 day incl. policy decision).
- **AUD-19 [P2] Documentation currency & provenance sweep (stale baselines and counts).** Files: llms.txt:6 (baseline 4.1.2); .aegis_ai_context/01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv:5 (v4.1.2); docs/REPOSITORY_MAP.md:3 (Last verified 2026-08-27); docs/INDEX.md (35 of 109 docs unlinked); INTEGRITY_SEAL.md:18/:24/:26 (6920/550 files/96 claims); README.md:327,:329 (6,936 tests / mypy 206 files). Root cause: These artifacts were written for earlier baselines and never refreshed; two in-tree counts disagree with each other and with today's measurements (ruff now scans 817 files; claims register is 102; parent's suite run at HEAD: 6,868 passed / 120 skipped). Proposed solution: Refresh each with the current measured values (or mark historical with an explicit baseline tag); regenerate the AI-context tsv; add the 35 unlinked docs to INDEX.md (or narrow its scope statement); and add a check that llms.txt/tsv baselines match AGENTS.md's baseline line. Estimated effort: S-M (1 day; the baseline-consistency check is the force multiplier).
- **AUD-20 [P2] MiFID II / MAR: modules unwired, citations partly wrong, registers silent.** Files: aegis/core/market_abuse_detector.py :27 (mis-cites MiFID II Art. 12(1)(a)(ii); the provision is MAR Art. 12(1)(a)(ii)), :4-8 ('feeds directly into the proxy WAF verdict pipeline' - no proxy import exists); aegis/core/mifid_record_keeper.py :6-7,:21-23 ('satisfying...' / '7 years for SMCR-scope firms'); docs/CLAIMS_MATRIX.md, docs/ROADMAP.md, docs/institutional/UNSUPPORTED_CLAIMS.md (no MiFID/MAR entries). Root cause: Two compliance modules are allowlist-classified (built, not wired) and their docstrings overclaim wiring/legal satisfaction; MiFID II has a buyer doc and a dossier section but no claims-matrix row, no UC entry and no roadmap ticket; the SMCR 7-year attribution does not match the FCA-based retention we could verify (6 years) and the MiFID 7-year figure is the competent-authority extension, not a default. Proposed solution: Correct the citations and docstrings (MAR not MiFID for Art. 12; 'contributes technical inputs' not 'satisfying'); add CLM rows for both modules with explicit 'not wired' boundaries; add UC-056; open the roadmap items (wire or retire the modules). Counsel review for the SMCR reference. Estimated effort: S for wording + M for wiring decision.
- **AUD-21 [P2] Registry rule not met for three terminal rows: boundary missing from UC/BOUNDARIES.** Files: docs/REGISTRY.md:122 (REG-019 compaction/cold tiering), :124 (REG-021 RFC 3161 revocation), :182 (REG-D01 dev-venv advisories); docs/institutional/UNSUPPORTED_CLAIMS.md; docs/BOUNDARIES.md. Root cause: The registry's own rule says a DOCUMENTED row's boundary must live in UNSUPPORTED_CLAIMS.md or BOUNDARIES.md; greps for 'compaction', 'cold tier', 'OCSP', 'revocation', 'setuptools', 'pip-audit' return zero hits in both registers, so three terminal rows are terminal without their boundary published where the rule says it lives. Same class: the MMR v1 residual (caller-supplied leaf bytes in verify_portable_inclusion, CLM-064) has no UC/BOUNDARIES entry. Proposed solution: Add the three boundary entries (and the MMR v1 note) to the register that owns each class - ROADMAP-only for REG-019, BOUNDARIES for REG-021's revocation gap, UC for the dev-venv advisories and MMR v1 - or amend the rule to accept the current homes. Estimated effort: S (3-4 h).
- **AUD-22 [P2] Compliance-wording sweep: unqualified SOC2/HIPAA/GDPR/admissibility language in sample and tooling surfaces.** Files: examples/README.md:35; tools/visualizer/README.md:25; Samples/README.md:26 (and :6); SECURITY_AUDIT_EXECUTION_LOG.md:130; docs/enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md:148; SECURITY_AUDIT_REPORT.md:72; README.md:18. Root cause: These surfaces name SOC 2/HIPAA/GDPR/admissibility without the repository's required qualifier ('contributes technical inputs that an assessor may evaluate'; 'admissibility is a judicial determination'), while neighbouring files apply it correctly. No file asserts certification as fact, so this is drift, not fabrication. Proposed solution: Apply the style-guide wording to each; add the deltas to the wording gate if one exists; give VENDOR_SECURITY_QUESTIONNAIRE's GDPR answer the same explicit 'No' shape as its neighbours. Estimated effort: S (3-4 h).
- **AUD-23 [P3] Residual robustness batch: durability, ingest validation, delimiters, bounds.** Files: aegis/core/wal_backup.py:85,:254-262; aegis/core/crypto_audit.py:978,:2373; aegis/core/hardware_token.py:403; aegis/proxy/app.py:1997; aegis/proxy/mtls.py:126; aegis/core/worm_ledger.py:549 (latent; module allowlisted). Root cause: (1) restore() copies over the live WAL without temp+replace while documenting 'atomically'; (2) NaN/Infinity admitted into sealed bytes via sampling_params (non-RFC-8259 tokens; cross-language verifiers cannot parse); (3) hardware_token canonical fields are NUL-joined without validation, so a token can be re-split and (with the unkeyed hash recomputed) validate under a different subject/tenant; (4) non-streaming path buffers provider responses and re-serialises a second copy; (5) mtls 403 echoes internal exception text; (6) worm_ledger seal helpers read whole files (latent, no caller). Proposed solution: Batch fix each with its own test: temp-file+replace+fsync restore; reject non-finite floats at ingest (or serialise them as strings); delimiter-free/length-prefixed token canonicalisation (and reject NUL in identifiers); bound the non-streaming body; fixed-string 403. Estimated effort: M (2-3 days all-in).
- **AUD-24 [P3] Rust P3 batch: doc claims, guards, and latent edges.** Files: aegis_rust_v2/src/wal.rs :47,:87,:102; crdt_mmr.rs :336 (encode-side ceiling); mmr.rs :88,:213; zk_bindings.rs :144; zk_mmr.rs :663 (unbounded bincode input); pqc.rs :47,:113; rate_limit.rs :69; forwarder.rs :19,:83; audit.rs :68; hasher.rs :57; docs/benchmarks/BENCHMARK_METHOD.md:175. Root cause: Assorted: unnecessary unsafe Send/Sync impls remove compiler checking; documented capacity ceiling never enforced (1 TiB accepted); a doc comment claims all slicing goes through model-checked helpers while three sites do not; a replica can encode a clock above its own decode ceiling; two expects in non-test paths; unbounded deserialize; GIL held across ML-DSA sign/verify; unused subtle dependency; doc-comment performance numbers with no measurement record; the benchmark method doc cites a cargo bench target that does not exist; hasher doc rationale is wrong (separator suffix vs length extension). Proposed solution: One small PR per item in the batch: add lint for unsafe_code; enforce the capacity ceiling; fix or scope the doc comments; add the encode-side ceiling check; convert expects to PyErr; cap bincode input; document the GIL behaviour; drop or use subtle; remove unmeasured numbers; correct the bench command; fix the rationale. Estimated effort: M (2-3 days across the batch).
- **AUD-25 [P2] Module inventory & ownership do not exist; navigation covers 43% of files.** Files: docs/REPOSITORY_MAP.md; scripts/verify_import_reachability.py:72,:74; llms.txt; .github/CODEOWNERS; docs/ROADMAP.md (19 unmapped open items). Root cause: No artifact is a per-module inventory (purpose/status/tests/owner); the reachability gate covers only .py under three roots and its 77-entry allowlist is referenced by no navigation doc; 171 of 298 files under the six roots are named in no navigation source (68 appear nowhere at all, including all 15 Rust sources); CODEOWNERS declares a single owner for everything, so no per-module maintainer field can exist; 19 roadmap open items name no owner or unblock path. Proposed solution: Generate a module inventory (path, purpose, status, tests, owner) from the reachability gate + allowlist + pyproject omit list, extend the gate to scripts/, tools/ and the Rust crate, reference it from the navigation docs, and name owners for the 19 unmapped roadmap items. Estimated effort: L (3-5 days; the generator can be incremental).
- **AUD-26 [P3] Evidence retention & claim-generating surfaces.** Files: PR_FINAL_ENTERPRISE_HARDENING.md:26 (producer exists, report JSON absent); benchmarks/bench_crypto_audit.py:203 ('[PROVEN]' label on a host-specific number); benchmarks/bench_forwarding.py:2 ('zero forensic latency' framing); UC-015:35, UC-016:36 (no producers). Root cause: Harness output is labelled as absolute when host-specific; one comparison's report JSON was never committed; two UC rows have no producer at all. The docs' own rules (BENCHMARK_METHOD: 'No RPS figure is claimed for any environment') are contradicted by the harness banners. Proposed solution: Re-label harness output as host-specific observations; commit a retained report or mark the figures historical; remove/replace '[PROVEN]' and 'zero latency' phrasings; decide the fate of UC-015/UC-016 (produce or keep retracted). Estimated effort: S-M (1-2 days).

**`docs/institutional/UNSUPPORTED_CLAIMS.md` — new entries (appended, with the register's 4-column shape):**

- **UC-050** — *Archived claim:* Malformed or out-of-range inputs to the released Rust extension surface as Python exceptions. *What holds instead:* Caller-controlled capacities and resource failures abort the process instead: `AuditRingBuffer(0)` panics and `AuditRingBuffer(2**40)` (also `RustSessionStore(2**40)`) dies with an allocation failure under the release profile's panic=abort — reproduced first-hand, exit 134. `rate_limit.rs` can panic on an unchecked multiply; Tokio runtime init and (non-default pure-rust-pqc) RNG use `.expect()`. Python cannot catch any of these. *(tracked as AUD-05)*
- **UC-051** — *Archived claim:* RustWal supports concurrent handles / multiple writers on one path. *What holds instead:* There is no single-instance guard. A second handle rescans, computes the same offsets and silently overwrites already-committed frames through its own MAP_SHARED mapping — reproduced first-hand (four committed frames of handle A replaced by handle B's; both report the same write_pos). The `SAFETY` comment asserts an exclusivity invariant no code enforces. *(tracked as AUD-04)*
- **UC-052** — *Archived claim:* A mid-stream client disconnect always produces a terminal evidence node (the 'fence' property). *What holds instead:* Under anyio-delivered cancellation — the path the real Starlette/uvicorn stack uses — the first await inside the `CancelledError` handler re-raises, so the shielded `_finalize` never runs; `aclose()`/`GeneratorExit` cannot await at all. Reproduced first-hand: real-app send-failure run wrote 0 terminal nodes; controls: bare `task.cancel()` = 1 commit, `aclose()` = 0, normal completion = 1. A client may therefore see `X-Aegis-Evidence-Status: pending-terminal` with no landing terminal record. *(tracked as AUD-03)*
- **UC-053** — *Archived claim:* `GET /v1/audit/nodes/{hash}/evidence` returns the byte-exact RFC 8785 (JCS) projection. *What holds instead:* In 5.0.0 it returns HTTP 500 for every node that exists: `AuditNode.to_dict()` always carries float fields and `canonical_jcs_bytes` rejects floats by design, with the error uncaught — reproduced first-hand against a real ledger. The DAG-CBOR projection on the same handler works; use it until AUD-01 lands. *(tracked as AUD-01)*
- **UC-054** — *Archived claim:* `verify_integrity()` verifies signatures, and `signature_assurance` reflects that verification. *What holds instead:* Verification is dispatched on the node's own self-declared `signature_scheme`, which is bound by no hash and no signature. Rewriting only that label on stored WAL lines yields `verify_integrity() = (True, None)` and `signature_assurance = ASYMMETRIC_HARDWARE_ATTESTED` while every per-node status is `unverified` — reproduced first-hand. Until AUD-02 lands, treat any assurance tier above the configured signing mode's floor as a label, not a verification result. *(tracked as AUD-02)*
- **UC-055** — *Archived claim:* The 21 CFR Part 11 export cryptographically binds the signer annotation to the node. *What holds instead:* `signer_name`, `signature_meaning` and `status` are absent from `node_hash`, from the signed payload and from the MMR leaf, so they can be rewritten on any node without changing verification results; the export docstring nevertheless calls `node_hash` the 'tamper-evident binding' for the annotation. Static verification (field lists re-read by the parent). *(tracked as AUD-10)*
- **UC-056** — *Archived claim:* MiFID II / EU market-abuse (MAR) compliance capability. *What holds instead:* `aegis/core/mifid_record_keeper.py` and `aegis/core/market_abuse_detector.py` are built but wired to no request path (both sit in the reachability allowlist, whose own header calls the list 'a worklist, not a verdict'); neither module establishes any legal obligation, and the record keeper's 'satisfying…' docstring overclaims. The detector's spoofing citation must read MAR Art. 12(1)(a)(ii), not MiFID II. They contribute technical inputs only — the repository's own MiFID II document says 'Not a MiFID II compliance statement'. *(tracked as AUD-20)*
- **UC-057** — *Archived claim:* The repository maintains a module inventory with status and owners. *What holds instead:* No artifact is a per-module inventory and no per-module owner field exists: the reachability gate classifies 223 discovered / 112 reached / 34 roadmap / 77 allowlisted modules for `.py` under three roots only; `CODEOWNERS` declares a single accountable owner for everything; 171 of 298 files under the six primary roots are named in no navigation source and 68 appear nowhere at all (including all 15 Rust sources). *(tracked as AUD-25)*
- **UC-058** — *Archived claim:* The format gate covers the repository. *What holds instead:* CI formats a fixed path list (9 directories) with an unpinned ruff; `scripts/*.py` is outside every gate and currently has 2 unformatted files, and modern ruff also formats Python code fences inside Markdown. The Makefile's broader `ruff format --check .` therefore fails at HEAD (11 files: 2 scripts, 9 markdown) while CI passes — reproduced first-hand. *(tracked as AUD-18)*

**`docs/REGISTRY.md` — new block "§4.6 v5.0.1-prep audit additions (2026-09-21)"**: 26 rows (`REG-D05`…`REG-D30`), one per AUD ticket, all `OPEN` with the ticket named as the mechanism; a matching burn-down row keeps §5 arithmetic honest. The original 66-row closure block is untouched and its seal statement in §2/§6 is amended only to record that this new, deliberately non-terminal block exists — the audit did not fix these items, so they must not read as terminal.

---

## 7. Trivial fixes to execute in Prompt 2 (bounded, mechanical)

1. `aegis/core/market_abuse_detector.py:27` — change "MiFID II Art. 12(1)(a)(ii)" to "MAR Art. 12(1)(a)(ii)" (Reg. (EU) No 596/2014).
2. `aegis/core/market_abuse_detector.py:4-8` — reword the "feeds directly into the proxy WAF verdict pipeline" claim (no proxy import exists; the module is allowlisted).
3. `aegis/core/mifid_record_keeper.py:6-7,:21-23` — replace "satisfying:" / "satisfies the record-keeping obligation" with "contributes technical inputs"; drop or counsel-review the "7 years for SMCR-scope firms" attribution.
4. `docs/architecture/DEEP_DIVE.md:288-289` — replace "chain-of-custody" (UC-024 forbids) and "trusted timestamp" (CLM-014/096 forbid) with the registers' own wording.
5. `docs/compliance/EU_AI_ACT_TECHNICAL_INPUTS.md:67` and `docs/compliance/HIPAA_TECHNICAL_INPUTS.md:67` — paste the corrected boundary text from `docs/privacy/PII_REDACTION_BOUNDARIES.md:48` / UC-045.
6. `docs/compliance/COMPLIANCE_MAPPING.md:32` and `docs/assurance/AUDIT_EVIDENCE_INDEX.md:123` — repoint to the in-tree artifact `evidence/execution_2026-08-20/waf_corpus_report.json` (CLM-032).
7. `examples/README.md:35`, `tools/visualizer/README.md:25`, `Samples/README.md:26` (+`:6`), `SECURITY_AUDIT_EXECUTION_LOG.md:130`, `docs/enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md:148`, `SECURITY_AUDIT_REPORT.md:72`, `README.md:18` — apply the style-guide qualifiers (§5 of this report lists the exact required phrasing for each).
8. `docs/BOUNDARIES.md:30` — remove the three ZK cost numbers or promote the cost harness to a reproducible artifact (then update CLM-089).
9. `llms.txt:6` and `.aegis_ai_context/01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv:5` — set both baselines to the current `5.0.0` line (matching `AGENTS.md`), or mark them explicitly historical.
10. `docs/REPOSITORY_MAP.md:3` — update "Last verified" to the date of the last content change, or replace the bare stamp with a provenance line naming the commit.
11. `aegis_rust_v2/src/wal.rs:47` — correct the doc comment (three sites do open-coded arithmetic); `hasher.rs:57` — correct the separator rationale (NUL is a suffix separator, not a length-extension defence); `forwarder.rs:19` — remove or source the ">100k RPS" numbers; `docs/benchmarks/BENCHMARK_METHOD.md:175` — replace `cargo bench` with the real command.
12. `aegis/proxy/mtls.py:126` — return a fixed string for the CAC/PIV rejection detail (siblings already do).
13. `docs/institutional/UNSUPPORTED_CLAIMS.md:37` — reword UC-017 so "the retained run" names one run unambiguously (AUD-06's naming fix).
14. `INTEGRITY_SEAL.md:18,:24,:26` and `README.md:327,:329` — re-run or supersede the stale numbers (tests count, ruff file count, claims count, mypy file count) with the commands beside them; AF-019 owns the sweep.
15. `aegis/core/export_audit_log.py` — add one docstring line noting that `read_all` skips malformed lines and that `verify()` is the detection path.

---

## 8. Residual unverified scope (what this audit did not establish)

1. **No live-hardware cryptography was executed**: `hsm.py` beyond its header, `tpm.py`, `tee_manager.py`, `cac_piv.py`, `enclave_provider.py`, `pinned_ca_bundle.py` were read partially and not exercised (no TPM/HSM/PKCS#11 in this environment).
2. **The ZK feature stays unexecuted** on this pre-ADX host (REG-D04 boundary taken as given, not re-reported); the `pure-rust-pqc` feature was not built, so AF-005's RNG item is inference from code + release profile, not a measurement.
3. **Rust probes ran against a locally built `libaegis_rust.so`** (release profile, this host); non-x86_64 targets and the 32-bit `usize` paths were reasoned from source only.
4. **No fuzzing, Miri or Kani run**; the WAL's mmap/flush semantics remain outside any proof (as CLM-054 and DEEP_DIVE §4.3 state).
5. **Storage backends beyond their headers** (sqlite/postgres/dynamodb providers), `sdk/` (Python + TypeScript), `connectors/`, `integrations/`, `deploy/`, `dashboard/`, `tools/` were covered at grep level except where a finding names them.
6. **The disconnect-teardown trigger frequency in the wild is unmeasured** (the mechanism and the missing commit are measured; a real TCP RST path was emulated through the real ASGI app rather than a production network).
7. **Registry/PyPI/npm/OCI lifecycle state was not re-read** in this audit (out of scope; the 5.0.0 readback record stands).
8. **This audit's own figures are single-host**: the benchmarks re-run for the claims scan produced host-specific values (e.g. commits/s 521.7 vs the released 1.24k) — consistent with the repo's own host-dependence declarations, and the reason AF-026 exists.

---

*End of report. Every P1 in §1 was reproduced first-hand on this host; every cited line in §3 was re-printed from disk during the audit; the two places where the delegated scans were imprecise (a `CLAIMS_MATRIX` line number, and the hardware-token token_hash mechanism) are corrected inline and marked.*

---

## 9. Re-verification at `9df5fd3` (2026-09-24)

This mission order was re-issued on 2026-09-24. It was executed as a **verification pass at current `main` (`9df5fd3`)** rather than a second from-scratch audit: this report is the first pass's product, and re-running the same scans over an equivalent tree would produce a second copy of it, not new evidence. Every line below is an executed output on the stated host; the raw captures are in [`evidence/registry/reanchor_2026-09-24.txt`](evidence/registry/reanchor_2026-09-24.txt).

**Registry state read first.** §4.6's `[AUDIT]` block: 30 rows, all terminal (`REG-D05`–`REG-D34`; the last three `FIXED` 2026-09-22). At `9df5fd3`: `OPEN` = 0, `SEED` = 0. Audit backlog: `AUD-01`–`AUD-30` `[x]`; open: `AUD-35` [P2] inert settings, `AUD-36` [P2] MiFID/MAR wire-or-retire, `AUD-37` [P3] date-bound documents, each with owner and its own quoted unblock path in `docs/MODULE_INVENTORY.md`.

**Battery (all exit 0; extension built with CI's `maturin build --release --features extension-module`).**

| Check | Result |
|---|---|
| `ruff check` / `format --check` | pass; 601 files formatted |
| `bandit -lll` | 0 issues; 54,905 LOC scanned |
| `mypy --strict aegis` / `scripts tools` | 208 + 41 files clean |
| `verify_docs` / `verify_claims` / `verify_links` | 0 findings / 106 claims 0 findings / 1,405 links and anchors |
| `verify_documentation --strict` | PASS, 27 required files, 0 errors, 0 warnings |
| reachability / release contract / AI-context / action pins | PASS (225/114/34/77) / READY, fourteen anchors at 5.0.1 / 83 files / PASS 123 |
| corpus audit | PASS — 1,267 files, 0 institutional placeholders, 0 NFC/CRLF/UTF-8 issues |
| module inventory | current — 301 files, owner `@JuanLunaIA` for all 301 |
| full suite (`HERMES_SANDBOX=true`, `-n auto`, extension installed) | **7,425 passed, 32 skipped, 0 failed** (229.4 s) |
| targeted Phase-1 selection (12 files) | **246 passed** |
| streaming/teardown explicit | `test_streaming_teardown.py` 8 passed; `test_proxy_streaming.py` 26 passed |
| sdk/python (CI steps, isolated venv) | ruff, mypy, mypy `--strict` clean; **20 passed** |
| sdk/typescript (CI steps) | **26 passed** (6 files); audit 0 vulnerabilities; pack OK |
| dashboard (CI steps, canary envs) | **6 passed** (3 files); next build OK; audit 0 vulnerabilities; bundle-secrets 52 files searched, 0 findings |
| `cargo test --release` / `--lib` (debug) | 90 + 3 passed / 90 passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | exit 0 |
| `tools/forensic/forensic_checks.py` | exit 0; `python_syntax_errors` 0 |

**Phase-1 properties, by the brief's own items.** Concurrency and mmap: the native WAL's writer-exclusion and frame-arithmetic tests pass in release and debug (`second_handle_is_refused_while_a_writer_holds_the_segment`, `header_end_is_bounded_and_never_wraps`, `concurrent_appends_publish_only_complete_frames`); the mapping itself stays outside Miri and Kani by design (`docs/formal/FORMAL_VERIFICATION_LIMITS.md`). Unbounded allocations: admission gate and bound tests pass, including `test_large_logical_stream_retained_memory_is_bounded`. Fence-on-cancel: not a term in this tree; the property is `TerminalCommitHandoff` (`aegis/proxy/streaming.py:83`) plus `test_cancellation_closes_upstream_and_commits_once` and the eight teardown tests — all pass. Non-finite floats: refused, not sanitised (`aegis/core/forensic_bundle.py:92-93,145-146`). fsync/msync ordering: as recorded (`docs/operations/STORAGE_REQUIREMENTS.md`; `wal.rs:222-228`), with `test_coalesced_commit.py`. Weak RNG: no finding — every key and nonce path uses `os.urandom`/`secrets`; the single `random` use is the red-team scenario picker under `nosec B311`. Hardcoded secrets: no live credential; all pattern hits are synthetic fixtures. Stack-trace hygiene: `test_error_response_hygiene.py` passes. MMR v1: "completely deprecated" is contrary to the record and must not be written; `UC-060` publishes the residual, `CLM-064` states the position.

**Corrections to the re-issued brief (re-checked; same as the first pass established).** `docs/UNSUPPORTED_CLAIMS.md` is `docs/institutional/UNSUPPORTED_CLAIMS.md`; `docs/REGISTRY.md` is the defect register, not the module inventory (`docs/MODULE_INVENTORY.md`, currency-tested); "v1 completely deprecated" contradicts the record; "MiFID II Art. 16/24" is not the repository's citation set (MAR Art. 12(1)(a)(ii); MiFID II Art. 16(6)/25(1)), and article-level compliance phrasings for these modules are register-forbidden (`CLM-103`–`CLM-105`). No regulatory wording was added anywhere by this pass.

**Findings of this pass.** No new code defect. One candidate nit, listed and deliberately not applied: `aegis/core/market_abuse_detector.py:8-9` cites `AUD-20` (closed) for its unwired state, while the live wire-or-retire ticket is `AUD-36`; AUD-20's closure names AUD-36, so the pointer traverses — a refresh, not a defect.

**Not run here, stated rather than implied.** The zk-spartan feature tests (pre-ADX SIGILL boundary, `REG-D04`); no fuzzing, Miri or Kani; no live-hardware cryptography (no HSM/TPM/PKCS#11 here); no CI read-back (nothing was pushed).

*Append-only: nothing above this section was modified by the re-verification; no finding of the first pass was re-opened and none was withdrawn.*
