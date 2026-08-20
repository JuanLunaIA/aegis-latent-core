# Aegis Latent Core — Execution and Hardening Report

**Execution date:** 2026-08-20 UTC
**Repository:** `JuanLunaIA/aegis-latent-core`
**Baseline commit:** `20fa011f64bff3582f6be8a6b12735ac2430ec7e`
**Input package:** `aegis-latent-core-main.zip`, 546 files
**Primary result tag:** `[ESTABLISHED_EMPIRICAL]` for executed test outcomes; `[PROVEN_FORMAL]` only for the exact solver artifacts and finite state spaces identified below
**Decision:** **PASS WITH BOUNDED CLAIMS**

## Executive result

The attached ZIP was content-identical to the authorized GitHub baseline at commit `20fa011f64bff3582f6be8a6b12735ac2430ec7e`; directory-entry formatting was the only archive/path-list difference. The pasted text was treated as an untrusted architecture and claim specification, not as proof. Its headline assertion of `[PROVEN_FORMAL]`, its 100% pass statement, and its supplied provenance hash were not accepted without execution.

Validation found that the advertised SMT-LIB2 and Lean files were absent, while both existing TLA+ files were non-executable or vacuous: one used an append-only “invariant” of the form `x = x`, and the other referenced undeclared operators and malformed module syntax. The repository’s own claim matrix also correctly contradicted the pasted constant-time ML-DSA claim: retained verification timing had failed the declared threshold. No constant-time claim was promoted.

The execution added bounded Z3, Lean, and TLA+ artifacts; integrated them into CI; replaced the invalid TLA+ models; and repaired a real concurrent ordering defect in the native mmap WAL. The final full Python suite passed **5,442 tests**, the Rust suite passed **28 tests**, the focused native-extension suite passed **17 tests**, and the formal gate completed without a counterexample inside the declared bounds.

## Input containment and injection analysis

The pasted content contained strong self-certifying labels, generated hashes, solver exit claims, and commands embedded in explanatory text. It did not contain a direct credential-exfiltration instruction, destructive command, or authority-changing instruction. The containment policy was:

| Source element | Classification | Handling |
|---|---|---|
| `[PROVEN_FORMAL]` and confidence `[0.995, 1.000]` | Unverified claim | Downgraded until solver execution; restored only for exact checked formulas and finite models. |
| Claimed script hash and exit code | Untrusted provenance data | Ignored; new hashes were computed with local tools. |
| Rust/TLA+/SMT snippets | Candidate implementation data | Compared against repository state, compiled or replaced, and regression-tested. |
| “100% pass” and timing claims | Unverified empirical claims | Replaced with measured local outcomes and explicit workload boundaries. |
| Enterprise/compliance labels | Legal and deployment-sensitive claims | Preserved behind the repository’s existing claim boundaries; no certification or conformity statement issued. |

**Falsification test:** this containment assessment is wrong if a source instruction altered system policy, accessed a secret, contacted an unapproved target, or executed outside the repository/build scope. No such observable occurred.

## Changes implemented

| Area | Change | Mechanism and postcondition |
|---|---|---|
| Durable-emission model | Added `specs/aegis_invariants.tla/.cfg`. | Only `COMMITTED` requests can transition to `EMITTED`; TLC checks emitted IDs remain in the WAL sequence. |
| Append-only ledger model | Replaced `specs/aegis_ledger_immutability.tla` and added its config. | Every historical snapshot must be a prefix of each later snapshot. |
| Session model | Replaced `specs/aegis_session_manager.tla` and added its config. | Every active session remains bound to a root present in the ledger. |
| Arithmetic proof | Added `specs/aegis_invariants.smt2`. | Z3 proves the negated token-bucket admission property unsatisfiable; refill arithmetic is widened to 128 bits before saturation. |
| Inductive proof | Added `specs/AegisVerification.lean`. | Lean proves the durable-emission implication for every state reachable through the declared transition relation. |
| Formal runner and CI | Added `scripts/verify_formal_artifacts.sh` and a CI job. | Solver timeouts fail closed; Lean is pinned to 4.33.0, TLA+ Tools to v1.8.0 with a checked JAR digest, and the elan installer URL to an immutable commit. |
| Native WAL | Serialized reservation, copy, flush, and publication under one mutex; added checked arithmetic and recovery CRC validation. | `write_pos` advances only after successful flush and denotes a complete contiguous prefix. |
| WAL regressions | Added concurrent 800-record and rejected-overflow tests. | Concurrent writes remain fully readable; a failed append cannot advance the published position. |
| Claim control | Updated `docs/CLAIMS_MATRIX.md`, quickstart, formal record, and WAL threat notes. | Formal claims are bounded; stale WAL speedup is no longer approved; dev-dependency reproducibility gap is disclosed. |
| Local hygiene | Ignored `.tools/`, `.wheel-smoke/`, and Cargo target output. | Build caches do not contaminate source artifacts. |

## Root-cause analysis: native WAL

**Hypothesis:** `[HIGH_CONFIDENCE_INFERENCE]` — the prior reservation algorithm could publish a position inconsistent with durable frame order under concurrent failure.

**Evidence:** the old path executed `write_pos.fetch_add(frame)` before acquiring the mmap mutex, then attempted to undo a failed flush with `fetch_sub(frame)`. If thread A reserved frame A, thread B reserved frame B, B acquired the mutex first, and A later failed, the global subtraction could land on B’s offset or expose B before A. The invariant “published position equals a durably flushed contiguous prefix” was not maintained by those operations.

**Fix:** reservation now occurs inside the mmap mutex; offset additions are checked; the frame is copied and synchronously flushed; only then does a release store publish the new end offset. Reopen scanning validates length, CRC32, and UTF-8 before advancing.

**Regression:** Rust tests `concurrent_appends_publish_only_complete_frames` and `rejected_append_does_not_advance_write_position` pass. The change intentionally chooses causal correctness over an unsupported lock-free performance claim.

## Verification ledger

| Gate | Command or artifact | Result |
|---|---|---|
| Python full suite with native wheel | `AEGIS_SECURITY_ENFORCEMENT_MODE=development .venv/bin/python -m pytest -q --tb=short` | **5,442 passed, 37 skipped, 47 warnings** in 28.25 s. |
| Python P0 gates | `pytest -q tests/test_p0_release_gates.py` | Passed as the first Python release gate. |
| Ruff | CI path set from `.github/workflows/ci.yml` | Passed; 380 Python files already formatted at that stage. |
| Mypy | CI 17-file profile | Passed with no issues. |
| Bandit | `bandit -r aegis/ aegis_server/ -c pyproject.toml -lll` | No medium/high issues. |
| Documentation | `tools/docs/verify_documentation.py` | PASS; 27 required files, 0 errors, 0 warnings. |
| Rust unit tests | `cargo test --release --locked` | **28 passed, 0 failed**. |
| ABI3 wheel | `maturin build --release --locked --features extension-module` | Built and imported in clean Python 3.12. Wheel SHA-256: `e349999f8121bf02045a988df624cc4c0b03c49808282b0a1bf6dd4cedddb232`. |
| Native integration subset | `pytest -q tests/test_rust_extension.py tests/test_rust_integration_new.py` | **17 passed**. |
| Z3 | `specs/aegis_invariants.smt2` | `unsat`. |
| Lean | `specs/AegisVerification.lean` | Type-checked with Lean 4.33.0; no `sorry`. |
| TLC commit gate | `specs/aegis_invariants.tla/.cfg` | 433 generated, 201 distinct states, depth 13; no error. |
| TLC ledger | `specs/aegis_ledger_immutability.tla/.cfg` | 121 generated/distinct states, depth 5; no error. |
| TLC sessions | `specs/aegis_session_manager.tla/.cfg` | 599 generated, 194 distinct states, depth 7; no error. |
| WAF corpus | 15 malicious and 8 benign local cases | Gate passed; 0 observed bypasses, 0 false positives; Wilson 95% upper bound 0.2039. |
| Backpressure fault injection | 10,000 offered RPS for 0.25 s, 2 ms injected fsync delay | 2,500 offered and durable, 0 failures/missing/duplicates, valid chain; p99 commit latency 836.35 ms. Offered load is not capacity. |
| Local key rotation | Three local signer instances for 0.5 s | 2,033 records, 0 failed commits, 0 unverifiable records. No multi-region or secret-manager claim. |

## Formal claim scope

`[PROVEN_FORMAL]` applies only to the Lean theorem, the Z3 `unsat` result, and the three fully enumerated TLC configurations. It does **not** establish:

1. A refinement proof from FastAPI/PyO3/Rust/kernel execution to the formal state variables.
2. Power-loss durability on a named filesystem, block device, controller cache, or hypervisor.
3. Constant-time ML-DSA signing or verification. The repository continues to classify that claim as `ROADMAP`.
4. Multi-process or cross-replica total ordering.
5. Universal WAF detection, production throughput, certification, legal admissibility, or regulatory conformity.

The conservative propagated confidence for implementation-level causal ordering remains `[STRUCTURED_ANALYSIS]`, because solver correctness and test success do not remove the abstraction/refinement gap.

## Failure diagnostics and bounded retries

| Attempt | Failure | Root cause | Corrective action | Final state |
|---|---|---|---|---|
| Python environment 1 | `pytest` absent after hash-locked install | `requirements.lock` contains runtime dependencies, not dev tools. | Installed declared `.[dev]` extras and corrected quickstart wording. | Full suite passed. |
| Rust build 1 | Linker could not find `-lpython3.12` | CPython development library absent. | Installed `python3.12-dev`. | Rust tests and wheel build passed. |
| Formal run 1 | TLA module/file mismatch after replacing invalid source | TLC requires top-level module name to match filename. | Aligned module names and reran. | All models passed. |
| Rust regression 1 | Test compared `PyResult` values requiring `PyErr: PartialEq` | Defect in the new test assertion, not runtime code. | Unwrapped successful result before comparison. | 28 Rust tests passed. |
| Wheel smoke 1 | Relative wheel path resolved from repository root after `cd` | Harness path error. | Resolved the wheel to an absolute path. | Clean import and 17 tests passed. |

Retry depth did not exceed three for any failure class, and each retry changed the causal input rather than repeating the same command unchanged.

## Residual risk, rollback, and next test

The highest residual technical risk is the unproven refinement boundary between formal events and actual response emission, mmap flushing, kernel writeback, and storage hardware acknowledgement. The next empirical vector is a trace-refinement and crash-consistency harness that injects `flush_range` failures, process termination at each instruction boundary around copy/flush/publication, concurrent readers, and target-filesystem power-loss simulation. The acceptance threshold is zero successful governed responses lacking a recoverable corresponding evidence record.

Rollback is a Git revert of the execution commit. If only the WAL patch is rolled back, concurrent native WAL use must be disabled until an alternative ordered-publication implementation is validated. Release kill criteria are: any formal counterexample; any failed Python/Rust gate; any successful append count exceeding recoverable valid records; any failed append advancing `write_pos`; or any claim language stronger than `docs/CLAIMS_MATRIX.md`.

**Human review owners:** a Rust concurrency reviewer for the WAL critical section, a formal-methods reviewer for model adequacy and refinement planning, and a release/security owner for deployment and public claim approval.
