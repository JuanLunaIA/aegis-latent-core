# Formal Verification — Limits

**Audience:** security reviewers, auditors, anyone about to cite the formal artifacts.
**Scope:** precisely what the Z3, Lean and TLA+/TLC artifacts establish, and what they do not.
**Boundary:** **these are bounded model checks over abstractions. They are not refinement proofs of the Python or Rust implementation, and they say nothing about any deployment.** Read this before citing any formal result.

---

## 1. Why this document is separate

"Formally verified" is among the most over-claimed phrases in security marketing. It is usually taken to mean "proven correct", and it almost never does.

Here it means: some invariants over some abstract models were checked within some bounds, and the checks passed. That is genuinely worth having — it catches design errors that testing misses — and it is far weaker than what a reader hears.

Separating the limits from the description makes it harder to cite the result without the boundary.

## 2. The artifacts

| Artifact | Tool | Subject |
| --- | --- | --- |
| `specs/aegis_invariants.tla` + `.cfg` | TLA+/TLC | Core invariants |
| `specs/aegis_ledger_immutability.tla` + `.cfg` | TLA+/TLC | Append-only ledger prefixes |
| `specs/aegis_session_manager.tla` + `.cfg` | TLA+/TLC | Session-to-ledger binding |
| `specs/AegisVerification.lean` | Lean 4 | Mechanised theorem |
| `specs/aegis_invariants.smt2` | Z3 | Invariant satisfiability |
| `specs/aegis_stream_buffer.smt2` | Z3 | Per-stream retained-byte arithmetic |
| `aegis_rust_v2/src/wal.rs` `mod verification` | Kani | WAL frame-bounds arithmetic |

CI gates: `scripts/verify_formal_artifacts.sh` (Z3, Lean, TLC) and the `Kani Model Checking` job (`cargo kani`). Toolchain: Lean 4.33.0, TLA+ built from a pinned revision, Z3 from the distribution package, Kani 0.67.0.

The Kani harnesses differ in kind from the others and the difference matters when citing them. They run against the **actual functions in `wal.rs`**, not against a separately written abstraction, so for those two functions the refinement gap described in [§ 4](#not-a-refinement-proof) does not apply. That is a narrow exemption: it covers the frame-bounds arithmetic and nothing else in the file.

## 3. What is established

Within the declared bounds, the models preserve:

- **Commit before emission** — no emission step is reachable from a state where the corresponding commit has not occurred.
- **Append-only ledger prefixes** — no transition rewrites or removes an existing prefix.
- **Session-to-ledger binding** — session state and ledger records stay associated as modelled.
- **Per-stream byte arithmetic** — retained bytes stay within the modelled bound `R_max = 4W + Q + E + P`.

Kani additionally establishes, over the whole `usize` domain rather than within a bound, that `header_range` and `payload_range` in `aegis_rust_v2/src/wal.rs`:

- return a byte range inside the supplied `limit` whenever they return one, and refuse otherwise;
- never overflow, so no arithmetic wraps into an apparently valid range;
- never treat a zero-length payload — the recovery terminator — as a frame;
- always advance the cursor strictly, which is what makes the `read_all` and `scan_write_pos` walks terminate on arbitrary mapped bytes;
- produce header and payload ranges that do not overlap.

Because every slice taken during a frame walk is bounded through those two functions, an out-of-bounds index during a walk would require one of these properties to fail.

**Falsification conditions:** a Z3 result other than `unsat`, a Lean type-check failure, a TLC counterexample within the configured bounds, or a Kani counterexample. Any of those falsifies the corresponding claim, and the CI gate fails.

## 4. What is not established

### Not a refinement proof

The TLA+, Lean and Z3 artifacts are abstractions written separately from the code. **Nothing mechanically connects those models to the Python or Rust that runs.**

A discrepancy between such a model and the implementation is invisible to those tools. The model can be correct and the implementation wrong, and every check still passes.

This is the single most important limitation. A reader who takes "formally verified" to mean the code was proven correct has misunderstood by a wide margin.

The Kani harnesses are the one exception, and they are exactly as narrow as they look: they check two real functions in `wal.rs` over all inputs. They establish nothing about `append`, `open`, `read_all` or `scan_write_pos` as wholes, and nothing about the mapping those functions produce ranges into.

### Bounded, not exhaustive

TLC explores a **finite** state space defined by each `.cfg`. A property holding within those bounds does not establish it for all executions, all message counts, all concurrency levels, or all data values.

Z3 checks satisfiability of encoded constraints — a statement about the encoding, not about runtime behaviour.

### Nothing about the environment

The models say nothing about:

| Excluded | Why it matters |
| --- | --- |
| Filesystem semantics | Whether `fsync` truly reached stable storage is a storage property |
| Operating system behaviour | Scheduling, signals, process death mid-write |
| Hardware | Power loss, cache behaviour, storage firmware |
| Network | Partitions, reordering, client disconnects |
| Concurrency in the real runtime | Python's actual threading and async behaviour |
| Cryptographic strength | The models treat primitives as abstract |
| The Rust extension | Only the two WAL frame-bounds functions are checked; nothing else in the crate is modelled |
| The memory mapping itself | Kani cannot model `mmap`, `flush_range`, or the filesystem, so durability, crash consistency, torn writes, and the invariant that `capacity` equals the mapped length are all outside it |
| Concurrent `append` | The mutex and `write_pos` ordering are argued in code comments and exercised by a unit test, not proven |
| Any deployment | Configuration, scale, operations |

### Nothing about security properties as a whole

The models cover specific ordering and arithmetic invariants. They do not model an adversary, and they establish nothing about authentication, authorization, injection resistance, or tampering by an operator.

## 5. Cite it like this

**Acceptable:**

> Bounded TLA+/TLC models check that commit-before-emission and append-only ledger prefixes hold within the configured state space, and a Z3 encoding checks per-stream retained-byte arithmetic. These are abstractions, not refinement proofs of the implementation.

And, for the Kani result specifically:

> Kani proves, over all `usize` inputs, that the two functions bounding every slice in the native WAL's frame walks return only in-bounds ranges, never overflow, and always advance. It does not model the memory mapping, durability, or concurrent appends.

**Not acceptable:**

| Do not say | Why |
| --- | --- |
| "Formally verified" | Implies the implementation was proven |
| "Mathematically proven correct" | The models are, the code is not |
| "Proven secure" | No adversary is modelled |
| "Verified implementation" | The implementation is not what was verified |
| "Exhaustively checked" | Bounded state space |
| "The WAL is memory-safe" | Two arithmetic functions are proven; the mapping, the flush path and the concurrency are not |
| "Proven crash-safe" | Kani models no filesystem and no power loss |

## 6. What would strengthen this

For a reviewer assessing how much weight to give these artifacts, the honest ranking of what is missing:

1. **A refinement relation** connecting a model to the implementation. This is the gap that matters most and is the hardest to close. The Kani harnesses sidestep it for two functions by checking the real code, which suggests the achievable direction: verify more real functions rather than write more abstractions.
2. **Adversary modelling**, so the results say something about security rather than only about ordering.
3. **Wider bounds**, with the state-space size recorded so a reader can judge coverage.
4. **Property-based testing** against the same invariants, executed on the real implementation — a weaker but achievable bridge between model and code.

Only the narrow Kani exemption in item 1 exists today; the rest is not in progress. See [Roadmap](../../ROADMAP.md).

---

**Related:** [Formal Verification](FORMAL_VERIFICATION.md) · [Failure Semantics](../architecture/FAILURE_SEMANTICS.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md) · [Audit Evidence Index](../assurance/AUDIT_EVIDENCE_INDEX.md)
