# Aegis Latent Core — Bounded Formal Verification Record

**Verification date:** 2026-09-30 UTC
**Source baseline:** `8b0dd18` (`main` after PR #224) plus the changes documented in this record
**Primary epistemic tag:** `[PROVEN_FORMAL]` for the stated Lean theorems, Z3 obligations, and enumerated TLC state spaces only
**Implementation-level tag:** `[STRUCTURED_ANALYSIS]`; no refinement proof connects these abstractions to every Python, Rust, operating-system, or storage transition

## Objective and claim boundary

The formal gate checks narrow safety properties of abstractions written separately from the code, plus bit-precise properties of a few Rust functions. It does not certify the product, prove target-filesystem durability, establish constant-time cryptography, or prove that the implementation refines the models. The lifecycle models do not represent incremental SSE event emission: their abstract emission corresponds only to an outcome whose modelled commit has completed and must not be read as proof that all SSE events are withheld.

The executable entry point is `scripts/verify_formal_artifacts.sh`. CI installs the declared toolchains, builds TLA+ Tools from an exact Git object, verifies the JAR source revision, and fails closed on a non-zero solver exit, a timeout, an unexpected counterexample, a type-check failure, or any Z3 output that differs from the file's declared expectation.

## Why this record was rewritten

The previous gate could pass without checking anything, and three of its artifacts did:

| Artifact | Defect in the previous version | Observable that exposed it |
|---|---|---|
| `specs/aegis_invariants.smt2` | Asserted a predicate together with its negation, so Z3 returned `unsat` whatever the arithmetic was. | Replacing the refill with a subtraction still produced `unsat`. |
| `specs/aegis_stream_buffer.smt2` | Defined `retained_bytes` as `R_max` and then asserted `retained_bytes > R_max`, which is `unsat` for any expression. | Replacing `4W` with `0W` still produced `unsat`. |
| `specs/aegis_invariants.tla` | A straight line from `RECEIVED` to `EMITTED` with no failure, so the invariant held because no alternative existed. | No configuration could violate any invariant. |
| `specs/aegis_ledger_immutability.tla` | One action, `Append`, and an invariant that the ledger only grows: true by construction, with no adversary. | Same. |
| `specs/aegis_session_manager.tla` | Described sessions bound to ledger roots and a network status that the code does not have; its `ZeroTrustEnforced` invariant read a variable no action changed. | Same. |
| `specs/AegisVerification.lean` | Four straight-line transitions and no failure path, so its theorem could not fail for want of a counterexample. | No reachability theorem showed the failure paths exist. |

The rewrite makes every check falsifiable. Each SMT file declares the result it expects from every `(check-sat)` and contains at least one `sat` check, so contradictory assumptions fail instead of passing. Each TLA+ model has a witness configuration whose invariants must be violated (the behaviours are reachable) and a counterexample configuration showing which design decision each safety invariant depends on. The Lean file must prove nine named theorems, three of which are reachability theorems for the failure paths.

## Artifacts and properties

| Artifact | Property | Bound or logical scope | Falsification observable |
|---|---|---|---|
| `specs/aegis_invariants.smt2` | The token-bucket refill and consume steps of `aegis_rust_v2/src/rate_limit.rs` preserve `0 <= tokens <= capacity`, never overflow `i64`, and saturation never changes the result (T0–T4). Both saturations are load-bearing (W1, W2). | Quantifier-free integer arithmetic over the declared `u32`/`i64` ranges; one CAS step at a time. | Z3 output differs from `; expect: sat unsat unsat unsat unsat unsat sat sat`. |
| `specs/aegis_stream_buffer.smt2` | An observed per-stream retention within its component budgets never exceeds `R_max = 4W + Q + E + P` (S1); the declared-domain ceiling is exactly 33,636,352 bytes (S2, S3); the factor 4 is load-bearing (W1). | Integer arithmetic over the ranges declared in `aegis/core/stream_bounds.py`. | Z3 output differs from `; expect: sat unsat unsat sat unsat sat`. |
| `specs/AegisVerification.lean` | Every reachable state satisfies the durability invariant; failed and refused requests emit nothing; admission requires a healthy ledger; durability requires a healthy commit; a fault clears only by repair; emission, commit failure, refusal and recovery are all reachable. | Inductive theorems over the exact `Step` and `Reachable` definitions in the file. | Lean rejects the file, reports a warning, omits one of the nine theorems, or reports an axiom other than `propext`, `Quot.sound` or `Classical.choice`. |
| `specs/aegis_invariants.tla` | Every commit that returned success is replayable (`CommittedReplayable`), emission implies a durable record (`SafetyInvariant`), and committed records are on disk (`CommittedOnDisk`), across write and fsync failures, torn tails, crashes, replay and offline repair. | Two requests, three records, two crashes; complete reachable-state exploration. | TLC reports a violation, type error, deadlock or incomplete run on the main configuration. |
| `specs/aegis_ledger_immutability.tla` | With pinned keys and an uncompromised signing key, any file that verifies is a prefix of the true history (`ChainEvidence`); with an external anchor for the length, the first `n` records are exactly the true ones (`AnchoredEvidence`). | Two leaf values, length three, an adversary with write access to the file; perfect hashing and signatures. | Same. |
| `specs/aegis_session_manager.tla` | `SessionLifecycleManager` is bounded, never shares a monitor between live sessions, never carries one session's monitor state into another (`MonitorOwnership`), returns stable monitors on re-access, and evicts only the least recently used session. | Three session IDs, two live sessions, five monitors. | Same. |

### Counterexamples the gate requires

Each counterexample configuration flips one design decision and TLC must find the violation. If a future change made the invariant hold without that decision, the model would no longer show the decision is needed, and the gate fails.

| Configuration | Design decision removed | Invariant that must fail |
|---|---|---|
| `aegis_invariants_ungated.cfg` | `CryptographicAuditLedger` refuses commits while its fault latch is not healthy (`LedgerGatesCommits = FALSE`). | `CommittedReplayable`: a request admitted before another request's write failure latched commits after the partial line, replay stops before it, and a commit that returned success does not replay. |
| `aegis_ledger_immutability_unpinned.cfg` | The verifier accepts only pinned keys (`KeysPinned = FALSE`: the signature is checked against the key recorded in the node). | `ChainEvidence`: the adversary rewrites the chain, re-signs it with its own key, and verification passes. |
| `aegis_ledger_immutability_compromised.cfg` | The signing key is not compromised (`AdversaryHasKey = TRUE`). | `ChainEvidence`. |
| `aegis_session_manager_pooled.cfg` | Each new session gets a newly allocated monitor (`PoolMonitors = TRUE` hands over the evicted one). | `MonitorOwnership`. |

The first two are the models of the two ledger defects fixed alongside this rewrite: the ledger now refuses commits while faulted, and it verifies `pqc-ml-dsa` signatures only against keys it pins. See [Failure Semantics](../architecture/FAILURE_SEMANTICS.md) and `CLM-061`, `CLM-114` and `CLM-115` in the [Claims Matrix](../CLAIMS_MATRIX.md). The closure record, with before-and-after output against `main`, is `evidence/registry/reg-d88_d93_closure.txt` (`REG-D88`, `REG-D89`, `REG-D92`).

## Executed result

CI runs the gate with Z3 4.8.12 (Ubuntu package), Lean 4.33.0, Java 21 and TLA+ Tools built from source revision `0894c3407f4717fec7cc18bde3bf3c857fa47333`, and verifies the checked-out Git object and the JAR manifest before model checking. The release-asset URL previously used for `v1.8.0` stays out of the trust path because the upstream lightweight tag and asset changed while keeping the same URL.

The results below were measured locally on 2026-09-30 with Z3 5.1.0, Lean 4.33.0 and a TLA+ Tools JAR built from revision `341472c7e9e46a310ab82369fca223c2e5234db0` (`TLA_SOURCE_REVISION` overridden for that JAR). The CI run on the pull request that carries this record is the observable for the pinned toolchain.

| Check | Result | Evidence |
|---|---|---|
| Z3 `aegis_invariants.smt2` | `sat unsat unsat unsat unsat unsat sat sat`, equal to the declared expectation | V0, T0–T4, W1, W2 |
| Z3 `aegis_stream_buffer.smt2` | `sat unsat unsat sat unsat sat`, equal to the declared expectation | V0, S1–S4, W1 |
| Lean `AegisVerification.lean` | Type-checked, no warning; nine required theorems reported | Axioms: `propext` or none; no `sorryAx` |
| TLC `aegis_invariants.cfg` | No error | 26,041 generated states, 10,973 distinct, depth 27 |
| TLC `aegis_invariants_ungated.cfg` | `CommittedReplayable` violated, as required | 228 distinct states when found |
| TLC `aegis_invariants_witness.cfg` | Four witnesses violated, as required | 87, 37, 71 and 1,270 distinct states |
| TLC `aegis_ledger_immutability.cfg` | No error | 4,452,703 generated states, 247,063 distinct, depth 17 |
| TLC `aegis_ledger_immutability_compromised.cfg` | `ChainEvidence` violated, as required | 30 distinct states |
| TLC `aegis_ledger_immutability_unpinned.cfg` | `ChainEvidence` violated, as required | 28 distinct states |
| TLC `aegis_ledger_immutability_witness.cfg` | Two witnesses violated, as required | 19 and 35 distinct states |
| TLC `aegis_session_manager.cfg` | No error, both temporal properties hold | 64,880 generated states, 11,167 distinct, depth 12 |
| TLC `aegis_session_manager_pooled.cfg` | `MonitorOwnership` violated, as required | 50 distinct states |
| TLC `aegis_session_manager_witness.cfg` | Three witnesses violated, as required | 11, 48 and 15 distinct states |

TLC runs with four workers, so the number of distinct states it has found when it reports an expected violation varies from run to run; the verdict does not. The counts of the configurations that must pass are exhaustive and do not vary.

## Links from the models to the code

A model says nothing about the code unless something ties them together. These ties are tests, not refinement proofs:

- `tests/test_stream_bounds.py` reads the declared ranges and the `R_max` expression out of `specs/aegis_stream_buffer.smt2` and checks them against `aegis/core/stream_bounds.py`, so the two cannot drift apart silently.
- `tests/test_session_manager_conformance.py` is a Hypothesis state machine that drives the real `SessionLifecycleManager` and checks the TLA+ model's invariants after every step.
- `tests/test_ledger_fault_gate.py` exercises the interleaving TLC found in `aegis_invariants_ungated.cfg` against the real ledger: a commit that follows another commit's torn write is refused, and every node the ledger returned still replays once the torn tail is repaired.
- `tests/test_signing_key_pinning.py` exercises the attack TLC found in `aegis_ledger_immutability_unpinned.cfg`: a chain rewritten and re-signed under an attacker's ML-DSA key reads `invalid` and fails `verify_integrity()`.

## Kani bit-level model checking

Kani 0.67.0 checks the real Rust functions, so the refinement gap does not apply to these harnesses. The exemption is exactly as narrow as the functions they cover. Every harness runs over the entire input domain, which is symbolic exploration, not sampling.

`aegis_rust_v2/src/wal.rs`, `mod verification`. Every slice taken during a frame walk in `read_all`, `scan_write_pos` and `open` is bounded through `header_range` and `payload_range`, so an out-of-bounds index during a walk would require one of these to fail:

| Harness | Property |
|---|---|
| `header_end_is_the_same_bound` | `header_end` and `header_range` agree on every input, so the two call sites cannot disagree about a frame's extent. |
| `header_range_is_in_bounds` | A returned range lies inside the supplied limit and is exactly one header long; a refusal means overflow or non-fit. |
| `payload_range_is_in_bounds` | A returned payload range lies inside the limit, starts immediately after the header, and is exactly `payload_len` bytes. |
| `zero_length_payload_is_never_a_frame` | The zero-length recovery terminator is refused at every position and every limit. |
| `a_frame_walk_strictly_advances` | The cursor advances strictly, which is what makes both walks terminate on arbitrary mapped bytes. |
| `header_and_payload_do_not_overlap` | A frame's length field can never be read out of its own payload. |

`aegis_rust_v2/src/rate_limit.rs`, `mod verification`. These check the same functions the limiter's compare-and-swap loops call, bit-precisely, where the SMT file states them over the integers:

| Harness | Property |
|---|---|
| `capacity_milli_is_exact_and_non_negative` | The constructor's millitoken capacity never overflows and is exactly `capacity × 1000`. |
| `refill_preserves_the_bounds` | The refill step preserves `0 <= tokens <= capacity` and never lowers the balance, for every non-negative gain. |
| `refill_equals_the_unbounded_result` | For every non-negative gain, the refill result equals `min(cur + gain, capacity)` computed in `i128`: saturation never loses or invents a token. |
| `refill_gain_is_positive` | For every elapsed time and rate that pass the guard, the gain is at least the elapsed time, so it is positive: a refill never debits a bucket and never stalls one. Together with the two harnesses above, this covers every gain the limiter can compute. |
| `consume_preserves_the_bounds` | The consume step preserves the invariant, debits exactly the cost when it admits, and rejects exactly when the balance is below the cost. |

That the gain equals the exact product below `i64::MAX` is not a harness: it is `saturating_mul`'s documented contract, checked at the overflow boundary by the unit test `a_long_idle_bucket_refills_to_capacity_without_overflow`. Two harness shapes that stated it were dropped because CBMC did not finish them: one over the multiplication and the refill together (no result in 30 minutes) and one comparing `saturating_mul` against a second 64-bit multiplication (no result in 10 minutes). Mutating `refill_gain` to `wrapping_mul` makes `refill_gain_is_positive` fail. All eleven harnesses verify in about 25 seconds on this host.

Kani models no `mmap`, no `flush_range`, no filesystem, no atomics, no memory ordering, no clock and no `DashMap`. Nothing here establishes durability, crash consistency, power-loss behaviour, or that `capacity` equals the mapped length. It does not make the WAL or the limiter "memory-safe" as a whole, and it is not a whole-system refinement proof. See [Formal Verification Limits](FORMAL_VERIFICATION_LIMITS.md).

Reproduce with `cd aegis_rust_v2 && cargo kani`. CI runs it as the `Kani Model Checking` job, pinned to Kani 0.67.0.

## Mechanistic trace

In the lifecycle model a request is admitted only while the ledger's latch is healthy (`_require_intact_ledger`). Its commit either appends and fsyncs a record, or fails and latches `wal_persist_failed`, possibly leaving a partial line. Process death may leave a torn tail. On restart, replay stops at the first unparseable line and latches `wal_corrupt`, and offline repair truncates only a torn last line. The ledger refuses every commit while latched. TLC enumerates every interleaving inside the constants and checks, in every state, that emitted requests have durable records and that every commit that returned success replays. Lean proves the phase-level implications by induction over the reachable-state derivation, and proves separately that each failure path is reachable, so none of those implications is vacuous. Z3 checks separate arithmetic properties and does not prove the request lifecycle.

## Residual risk and next falsification test

The dominant epistemic gap is still the absence of a machine-checked refinement mapping from FastAPI and Rust control flow to the TLA+ and Lean states. The conformance tests above narrow it for the session manager, the stream bound and two ledger interleavings; they do not close it. The next test is a trace-refinement harness that records implementation lifecycle events, rejects any trace the formal transition relation does not accept, and injects flush failures, process termination and concurrent appends. A qualified formal-methods reviewer owns approval of any broader claim. Rollback consists of reverting the formal gate and its claim-matrix row; this does not change runtime behaviour.
