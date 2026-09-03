# Aegis Latent Core — Bounded Formal Verification Record

**Verification date:** 2026-08-20 UTC
**Source baseline:** `20fa011f64bff3582f6be8a6b12735ac2430ec7e` plus the changes documented in this record
**Primary epistemic tag:** `[PROVEN_FORMAL]` for the stated Lean theorem, Z3 formula, and enumerated TLC state spaces only
**Implementation-level tag:** `[STRUCTURED_ANALYSIS]`; no refinement proof connects these abstractions to every Python, Rust, operating-system, or storage transition

## Objective and claim boundary

The formal gate checks four narrow safety claims. It does not certify the product, prove target-filesystem durability, establish constant-time cryptography, or prove that the implementation refines the models. In particular, the lifecycle models do not represent incremental SSE event emission; their abstract `EMITTED` transition corresponds only to an outcome whose modeled commit has completed and must not be read as proof that all SSE events are withheld. The executable entry point is `scripts/verify_formal_artifacts.sh`; CI installs the declared toolchains, builds TLA+ Tools from an exact Git object, verifies the JAR source revision, and fails closed on a non-zero solver exit, timeout, counterexample, type-check failure, or unexpected Z3 result.

| Artifact | Property | Bound or logical scope | Falsification observable |
|---|---|---|---|
| `specs/aegis_invariants.smt2` | An admission predicate cannot be true when the saturated post-refill token balance is below cost. | Quantifier-free 64-bit inputs with refill multiplication and addition widened to 128 bits. | Z3 returns any result other than `unsat`. |
| `specs/AegisVerification.lean` | Every state reachable through the declared phase transitions satisfies `responseEmitted = true → durable = true`. | Inductive theorem over the exact `Step` and `Reachable` definitions in the file. | Lean rejects the file or a new transition cannot discharge `step_preserves_invariant`. |
| `specs/aegis_invariants.tla` | Emitted request IDs are a subset of request IDs present in the WAL sequence. | Three request IDs; WAL capacity three; complete reachable-state exploration. | TLC emits a counterexample, type error, deadlock, or incomplete run. |
| `specs/aegis_ledger_immutability.tla` | Every older ledger snapshot is a prefix of every newer snapshot, and the last snapshot equals current state. | Three leaf values; maximum four appends; complete reachable-state exploration. | TLC emits a counterexample, type error, deadlock, or incomplete run. |
| `specs/aegis_session_manager.tla` | Every active session is bound to a root present in the ledger; insecure processing remains false. | Two session IDs, two roots, maximum three commits, secure/compromised network states. | TLC emits a counterexample, type error, deadlock, or incomplete run. |

## Executed result

The gate runs with Z3 4.8.12, Lean 4.33.0, Java 21, and TLA+ Tools built from source revision `0894c3407f4717fec7cc18bde3bf3c857fa47333`. CI verifies the checked-out Git object and the resulting JAR manifest before model checking. The release-asset URL previously used for `v1.8.0` was removed from the trust path because the upstream lightweight tag and asset changed while retaining the same URL; a mutable download cannot satisfy this gate's provenance contract.

| Check | Result | State-space evidence |
|---|---|---|
| Z3 token-bucket contradiction | `unsat` | Exact QF_BV formula in `specs/aegis_invariants.smt2`. |
| Lean durable-emission theorem | Type-checked | `reachable_states_satisfy_invariant` accepted without `sorry` or admitted axioms. |
| TLC commit-before-emission | No error | 433 generated states, 201 distinct states, depth 13. |
| TLC append-only ledger | No error | 121 generated and distinct states, depth 5. |
| TLC session binding | No error | 599 generated states, 194 distinct states, depth 7. |
| Kani WAL frame bounds | 5 harnesses verified, 0 failures | `mod verification` in `aegis_rust_v2/src/wal.rs`, Kani 0.67.0; re-executed 2026-09-03. |

## Kani bit-level model checking

Kani 0.67.0 checks the frame-bounds arithmetic of the memory-mapped WAL. Five
`#[kani::proof]` harnesses run over the entire `usize` domain — symbolic exploration, not
sampling — against `header_range` and `payload_range` in `aegis_rust_v2/src/wal.rs`. Every slice
taken during a frame walk in `read_all`, `scan_write_pos` and `open` is bounded through those two
functions, so an out-of-bounds index during a walk would require one of these properties to fail:

| Harness | Property |
|---|---|
| `header_range_is_in_bounds` | A returned range lies inside the supplied limit and is exactly one header long; a refusal means overflow or non-fit. |
| `payload_range_is_in_bounds` | A returned payload range lies inside the limit, starts immediately after the header, and is exactly `payload_len` bytes. |
| `zero_length_payload_is_never_a_frame` | The zero-length recovery terminator is refused at every position and every limit. |
| `a_frame_walk_strictly_advances` | The cursor advances strictly, which is what makes both walks terminate on arbitrary mapped bytes. |
| `header_and_payload_do_not_overlap` | A frame's length field can never be read out of its own payload. |

**These differ in kind from the artifacts above.** Z3, Lean and TLA+ check abstractions written
separately from the code; Kani checks the real functions, so the refinement gap does not apply to
them. The exemption is exactly as narrow as it sounds and is bounded in
[Formal Verification Limits](FORMAL_VERIFICATION_LIMITS.md): Kani models no `mmap`, no
`flush_range`, no filesystem and no concurrency, so nothing here establishes durability, crash
consistency, power-loss behaviour, or that `capacity` equals the mapped length. It does not make
the WAL "memory-safe" as a whole, and it is not a whole-system refinement proof.

Reproduce with `cd aegis_rust_v2 && cargo kani`. CI runs it as the `Kani Model Checking` job,
pinned to Kani 0.67.0.

## Mechanistic trace

In the abstract lifecycle, a request moves from `RECEIVED` to `CONTROLLED`, then `UPSTREAM`, `COMMITTED`, and finally `EMITTED`. The only modeled transition that inserts an identifier into `response_emitted` requires the source state `COMMITTED`; the commit transition appends that identifier to `wal_log`. TLC enumerates every reachable interleaving inside the finite constants and checks `response_emitted ⊆ SequenceRange(wal_log)` in each state. This abstraction fits complete non-streaming outcomes and the SSE terminal-marker transition, but it omits preceding incremental sanitized SSE events. Lean independently proves the corresponding phase-level implication by induction over the reachable-state derivation. Z3 checks separate arithmetic safety properties and does not prove the request lifecycle. The per-stream retained-memory arithmetic contract is separately encoded in `specs/aegis_stream_buffer.smt2`; it is not an implementation refinement proof.

## CHOKE perturbation record

| Perturbation | Executed check | Outcome |
|---|---|---|
| Operator inversion | Emission is not commuted ahead of commit; the model exposes no transition permitting that inversion. | The inverted operation is outside `Next` and therefore unreachable in the checked model. |
| Coordinate transformation | Request identities are uninterpreted model values; renaming them preserves transition and invariant structure. | Invariant is identity-equivariant within the finite set. |
| Boundary stress | Empty ledger, full capacity, compromised network state, and zero active sessions are reachable boundary states. | No checked invariant failed at those boundaries. |

## Residual risk and next falsification test

The dominant epistemic gap is the absence of a machine-checked refinement mapping from FastAPI and Rust control flow to the TLA+/Lean states. The next test is a trace-refinement harness that records implementation lifecycle events, rejects any trace not accepted by the formal transition relation, and injects flush failures, process termination, and concurrent appends. A qualified formal-methods reviewer owns approval of any broader claim. Rollback consists of reverting the formal gate and its claim-matrix row; this does not change runtime behavior.
