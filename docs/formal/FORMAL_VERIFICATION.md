# Aegis Latent Core — Bounded Formal Verification Record

**Verification date:** 2026-08-20 UTC
**Source baseline:** `20fa011f64bff3582f6be8a6b12735ac2430ec7e` plus the changes documented in this record
**Primary epistemic tag:** `[PROVEN_FORMAL]` for the stated Lean theorem, Z3 formula, and enumerated TLC state spaces only
**Implementation-level tag:** `[STRUCTURED_ANALYSIS]`; no refinement proof connects these abstractions to every Python, Rust, operating-system, or storage transition

## Objective and claim boundary

The formal gate checks four narrow safety claims. It does not certify the product, prove target-filesystem durability, establish constant-time cryptography, or prove that the implementation refines the models. In particular, the lifecycle models do not represent incremental SSE event emission; their abstract `EMITTED` transition corresponds only to an outcome whose modeled commit has completed and must not be read as proof that all SSE events are withheld. The executable entry point is `scripts/verify_formal_artifacts.sh`; CI installs the declared toolchains, verifies the TLA+ Tools JAR digest, and fails closed on a non-zero solver exit, timeout, counterexample, type-check failure, or unexpected Z3 result.

| Artifact | Property | Bound or logical scope | Falsification observable |
|---|---|---|---|
| `specs/aegis_invariants.smt2` | An admission predicate cannot be true when the saturated post-refill token balance is below cost. | Quantifier-free 64-bit inputs with refill multiplication and addition widened to 128 bits. | Z3 returns any result other than `unsat`. |
| `specs/AegisVerification.lean` | Every state reachable through the declared phase transitions satisfies `responseEmitted = true → durable = true`. | Inductive theorem over the exact `Step` and `Reachable` definitions in the file. | Lean rejects the file or a new transition cannot discharge `step_preserves_invariant`. |
| `specs/aegis_invariants.tla` | Emitted request IDs are a subset of request IDs present in the WAL sequence. | Three request IDs; WAL capacity three; complete reachable-state exploration. | TLC emits a counterexample, type error, deadlock, or incomplete run. |
| `specs/aegis_ledger_immutability.tla` | Every older ledger snapshot is a prefix of every newer snapshot, and the last snapshot equals current state. | Three leaf values; maximum four appends; complete reachable-state exploration. | TLC emits a counterexample, type error, deadlock, or incomplete run. |
| `specs/aegis_session_manager.tla` | Every active session is bound to a root present in the ledger; insecure processing remains false. | Two session IDs, two roots, maximum three commits, secure/compromised network states. | TLC emits a counterexample, type error, deadlock, or incomplete run. |

## Executed result

The gate ran with Z3 4.8.12, Lean 4.33.0, Java 21, and TLA+ Tools v1.8.0. The downloaded TLA+ Tools JAR had SHA-256 `ab323b79802aedc3203b3f9af37c6aca3ed43f4e0225b36f2aa77b26de46c05f`.

| Check | Result | State-space evidence |
|---|---|---|
| Z3 token-bucket contradiction | `unsat` | Exact QF_BV formula in `specs/aegis_invariants.smt2`. |
| Lean durable-emission theorem | Type-checked | `reachable_states_satisfy_invariant` accepted without `sorry` or admitted axioms. |
| TLC commit-before-emission | No error | 433 generated states, 201 distinct states, depth 13. |
| TLC append-only ledger | No error | 121 generated and distinct states, depth 5. |
| TLC session binding | No error | 599 generated states, 194 distinct states, depth 7. |

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
