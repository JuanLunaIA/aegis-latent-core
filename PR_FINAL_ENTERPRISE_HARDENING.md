# PR summary — enterprise hardening pass

**Branch:** `claude/aegis-v4-comprehensive-audit-m2qyka` · **Base:** `main` · **PR:** [#157](https://github.com/JuanLunaIA/aegis-latent-core/pull/157)
**Source baseline:** `4.3.0`, fourteen synchronized anchors, **unpublished** — no tag, GitHub Release, PyPI or npm artifact, or OCI image exists for it. The most recent published release is `v4.1.2`.
**Durable record:** this file summarises one pull request. [`CHANGELOG.md`](CHANGELOG.md) and [`docs/CLAIMS_MATRIX.md`](docs/CLAIMS_MATRIX.md) are the records that survive it.

## 1. What changed

| SHA | Change | Files |
| --- | --- | --- |
| `ccf4b03` | Coalesce concurrent WAL commits onto one `fsync` | `aegis/core/group_commit.py` (new), `aegis/core/crypto_audit.py`, `tests/test_coalesced_commit.py` (new), `tools/benchmarks/run_group_commit.py` (new), `docs/CLAIMS_MATRIX.md`, `CHANGELOG.md` |
| `2cdabdb` | Start the gossip mesh from the gateway; verify receipts across replicas | `aegis/consensus/runtime.py` (new), `aegis/proxy/app.py`, `aegis/config.py`, `aegis/core/a2a.py`, `deploy/helm/templates/statefulset.yaml`, `tests/consensus/test_gossip_runtime.py` (new), `tests/test_a2a_protocol.py`, `docs/CLAIMS_MATRIX.md`, `.aegis_ai_context/MANIFEST.json`, `CHANGELOG.md` |
| `3541cf0` | Put the ML-DSA backend behind a trait; measure what a swap costs | `aegis_rust_v2/src/pqc_trait.rs` (new), `aegis_rust_v2/src/pqc.rs`, `aegis_rust_v2/Cargo.toml`, `aegis_rust_v2/Cargo.lock`, `aegis_rust_v2/src/lib.rs`, `aegis_rust_v2/src/crdt_mmr.rs`, `docs/security/DEPENDENCY_RISK_REGISTER.md`, `docs/security/PQC_CONSTANT_TIME.md`, `docs/CLAIMS_MATRIX.md`, `.aegis_ai_context/MANIFEST.json`, `CHANGELOG.md` |
| (this commit) | Reconcile four documentation statements against the code | `README.md`, `docs/FAQ_TECHNICAL.md`, `docs/api/AUDIT_ENDPOINTS.md`, `docs/assurance/CONTROL_TO_EVIDENCE_MATRIX.md`, `docs/security/SECURITY_CONTROLS.md`, `docs/enterprise/SUPPORT_MODEL.md`, `docs/enterprise/PROCUREMENT_CHECKLIST.md`, `docs/institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md`, `CHANGELOG.md` |

## 2. Measurements

All figures below are `MEASURED` on the container this branch was developed in — one shared-CPU Linux machine, CPython 3.11.15. **None is a capacity, SLA or production-readiness figure**, and `fsync` cost in particular is a property of the device under the run rather than of this code.

### 2.1 Coalesced group commit

400 commits across 32 threads, real ledger, real filesystem, same process, both arms. Reproduce with `python tools/benchmarks/run_group_commit.py --output <report>.json`.

| | per-record `fsync` (before) | group commit (after) |
| --- | --- | --- |
| commits/second | 1,065.1 | **1,536.1** (1.44x) |
| p50 latency | 28.204 ms | 19.021 ms |
| p95 latency | 34.072 ms | 23.405 ms |
| p99 latency | 55.456 ms | **24.781 ms** |
| max latency | 79.422 ms | 25.473 ms |
| `fsync` calls | 400 | **66** |
| durable commits / chain intact | 400 / yes | 400 / yes |

The slower the device, the larger the win: the fixed per-call cost being shared is bigger.

### 2.2 ML-DSA-65 backends

Interleaved two-class timing, 40,000 samples (`verify`) and 20,000 (`sign`), both signing arms hedged. Sample sizes are well below the 1,000,000 that `docs/security/PQC_CONSTANT_TIME.md` requires for a release claim; these compare two implementations against each other, which is a different question from certifying either.

| operation | `pqcrypto-mldsa` (PQClean C) | `ml-dsa` (pure Rust) |
| --- | --- | --- |
| verify, mean | 45,961 ns | 65,805 ns (1.43x) |
| verify, class delta | −644 ns | −1,128 ns |
| verify, p | 0.0000 | 0.0000 |
| sign, mean | 135,443 ns | 650,361 ns (**4.80x**) |
| sign, class delta | +256 ns | +1,152 ns |
| sign, p | 0.8399 | 0.8828 |

**No constant-time claim is made or lifted for either backend.** The release gate stays closed.

### 2.3 Streaming holdback

Not re-measured in this pass. The composite holdback (`W_deid + 28` characters) and its per-chunk overhead were measured on 2026-09-10 and are recorded in `CLM-067` and `evidence/streaming-engine/`; nothing in this branch changes that path.

## 3. Claims register

Four rows added or changed, each with its "do not use" register entry:

| claim | subject |
| --- | --- |
| `CLM-082` | Coalesced WAL group commit — including the durability ordering that **changed** |
| `CLM-083` | `verify_cluster_receipt` — a match is one replica's word, not the cluster's |
| `CLM-084` | The ML-DSA backend seam — a proven-compatible alternative, **not** a migration |
| `CLM-080` | Updated: the mesh is started by the gateway, not merely importable |
| `CLM-059` | Widened: `wal_persist_failed` is now also reachable from a commit-time `fsync` failure |

`scripts/verify_claims.py` reports **84 claims, 0 findings**.

## 4. Verification pipeline

Every command below was executed on this branch. Results are reported as observed, including the three that could not run here.

| gate | result |
| --- | --- |
| `pytest tests/ -q` | **6,731 passed, 53 skipped** |
| `ruff check aegis aegis_server integrations tests tools benchmarks` | All checks passed |
| `ruff format --check …` | 494 files already formatted |
| `mypy --strict aegis sdk/python/src` | Success, 213 source files |
| `bandit -r aegis aegis_server -lll` | exit 0 — **0 High**; 9 Medium and 20 Low are below the `-lll` threshold |
| `cargo fmt --manifest-path aegis_rust_v2/Cargo.toml -- --check` | clean (**was failing on `main`**; four pre-existing diffs in `crdt_mmr.rs`, fixed here) |
| `cargo clippy --all-targets -- -D warnings` | clean in **three** configurations: default, `--no-default-features --features pure-rust-pqc`, `--features pqc-compat-tests` |
| `cargo test --release --locked` | 67 + 3 + 0 passed, 0 failed |
| `cargo test --features pqc-compat-tests` | 71 passed — includes the four cross-backend compatibility tests |
| `cargo kani` | **5 harnesses verified, 0 failures**; 16/16 checks SUCCESS |
| `z3 specs/aegis_invariants.smt2` | `unsat` — proved |
| `z3 specs/aegis_stream_buffer.smt2` | `unsat` — proved |
| `bash scripts/verify_formal_artifacts.sh` | **CANNOT RUN HERE** — see below |
| `(cd sdk/typescript && npm ci --ignore-scripts && npm run check && npm audit --audit-level=high)` | 6 test files, 26 tests passed; build clean; **0 vulnerabilities** |
| `(cd dashboard && npm ci --ignore-scripts && npm run typecheck && npm test && npm run build)` | typecheck clean; 3 files, 6 tests passed; production build succeeded; **0 vulnerabilities** |
| `python tools/docs/verify_documentation.py --root . --strict` | PASS, 0 errors, 0 warnings |
| `python scripts/verify_docs.py` | PASS, 0 findings |
| `python scripts/verify_claims.py` | PASS, 84 claims, 0 findings |
| `bash scripts/verify_links.sh` | PASS, 1,113 links and anchors resolved |
| `git diff --check` | clean |

### 4.1 What could not run, and why

`scripts/verify_formal_artifacts.sh` exits 127 before running anything: it requires the `lean` binary and `.tools/tla2tools.jar`, neither of which exists in this environment. Its **z3 half was run directly** and both SMT proofs discharge (`unsat`), which is the part that covers `specs/aegis_stream_buffer.smt2`. The Lean proof and the three TLC models — `aegis_invariants`, `aegis_ledger_immutability`, `aegis_session_manager` — were **not** executed, and this branch makes no claim about them.

This is reported rather than worked around. Suppressing the tool check to make the gate report success would be exactly the kind of fabricated evidence `AGENTS.md` forbids.

## 5. Mandates not implemented, with the evidence

Four items in the originating order rest on premises that do not hold. Each was checked against source before being set aside.

**ML-DSA verify timing, `p = 0.0 → p > 0.05` by hoisting the parse.** Not achievable, by three independent findings. (a) `pqc.rs` already recorded the measurement that refutes the mechanism: decoding is ~5.6% of the call (4.10 µs of 73 µs) while the valid-vs-tampered difference is 2.02 µs — larger than the whole decode step. (b) Caching unpacked polynomial coefficients is not implementable against `pqcrypto-mldsa`, a PQClean FFI binding whose `crypto_sign_verify` takes packed bytes and unpacks internally. (c) The remedy `pqc.rs` itself proposed — a different implementation — was measured this pass and shows the **same** `p = 0.0000` with a **larger** class delta. Two independent implementations of one specification agreeing points at the experiment: its classes are one repeated signature versus 1024 varying ones, **all valid**, and **ML-DSA verification consumes no secret** — public key, public message, public signature. Signing, which does touch the secret key, meets the non-detection threshold on both backends. Separately, the order's `--samples 100000` is below the harness's own enforced minimum of 1,000,000.

**MMR dual-scheme domain separation.** Already implemented — v1/v2 schemes, RFC 6962 §2.1 tags, and `verify_portable_inclusion_hash` already accepting both 64-char hex and unpadded base64url roots.

**`CompositeStreamRedactor`.** Already exists in `aegis/core/stream_redactor.py`, already composed after `StreamingDeidentifier`, already covered by `tests/test_streaming_safety_engine_integration.py`.

**"All fourteen anchors must agree on `4.4.0`".** They already agree — at **`4.3.0`**. No `4.4.0` exists at any surface. See §6.

## 6. Open question for the owner

**Fourteen documentation references say `4.4.0`; fourteen source anchors say `4.3.0`.** `docs/FAQ_TECHNICAL.md` says shredding is available "since `4.4.0`", `ARCHITECTURE.md` refers to restoring "the pre-`4.4.0` output", `MMR_PROOF_V1.md` and `ROADMAP.md` set the SDK wire boundary at "predating `4.4.0`", and `CLM-067` cites `evidence/streaming-engine/4.4.0/`. Meanwhile `pyproject.toml`, `Cargo.toml` and both `package.json` files read `4.3.0`, `AGENTS.md` states the baseline is `4.3.0`, and `RELEASE_STATUS.md` never mentions `4.4.0`.

A reader who checks out this tree finds the features present and the documentation saying they arrive in a version the tree is not. Two coherent resolutions exist — bump the anchors to `4.4.0`, or retarget the doc references to `4.3.0` — and choosing between them is a release-numbering decision, not a factual error resolvable from source. It is **not** changed here: guessing would rewrite fourteen version references and an evidence directory path on my own authority.

## 7. Boundaries

- Group commit changes **when** the `fsync` happens relative to other commits, not **whether** the caller waits for one. A node now enters the in-memory chain before its batch is synced; nothing observes it, because the commit has not returned. The prior invariant "each node is fsynced before the in-memory chain is updated" no longer holds and was corrected everywhere it was written down.
- `fsync` is a request to the operating system. Hardware that acknowledges before the write is persistent defeats this exactly as it defeated the per-record version.
- Gossip remains **off by default** and reconciles the CRDT accumulator, **not** the ledger. Enabling it changes nothing about what a WAL records or what a receipt proves.
- The ML-DSA default backend is **unchanged**. This branch ships a seam and a proven-compatible alternative; it does not migrate. The four RUSTSEC advisories are retired only in a build that takes the flag, and none of them is a defect.
- PostgreSQL and DynamoDB fork-prevention paths (`CLM-081`) remain unexecuted here; no backend for either exists in this environment.
