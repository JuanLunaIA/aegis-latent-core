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

CI gate: `scripts/verify_formal_artifacts.sh`. Toolchain: Lean 4.33.0, TLA+ built from a pinned revision, Z3 from the distribution package.

## 3. What is established

Within the declared bounds, the models preserve:

- **Commit before emission** — no emission step is reachable from a state where the corresponding commit has not occurred.
- **Append-only ledger prefixes** — no transition rewrites or removes an existing prefix.
- **Session-to-ledger binding** — session state and ledger records stay associated as modelled.
- **Per-stream byte arithmetic** — retained bytes stay within the modelled bound `R_max = 4W + Q + E + P`.

**Falsification conditions:** a Z3 result other than `unsat`, a Lean type-check failure, or a TLC counterexample within the configured bounds. Any of those falsifies the corresponding claim, and the CI gate fails.

## 4. What is not established

### Not a refinement proof

The models are abstractions written separately from the code. **Nothing mechanically connects a model to the Python or Rust that runs.**

A discrepancy between the model and the implementation is invisible to every tool here. The model can be correct and the implementation wrong, and every check still passes.

This is the single most important limitation. A reader who takes "formally verified" to mean the code was proven correct has misunderstood by a wide margin.

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
| The Rust extension | Not modelled |
| Any deployment | Configuration, scale, operations |

### Nothing about security properties as a whole

The models cover specific ordering and arithmetic invariants. They do not model an adversary, and they establish nothing about authentication, authorization, injection resistance, or tampering by an operator.

## 5. Cite it like this

**Acceptable:**

> Bounded TLA+/TLC models check that commit-before-emission and append-only ledger prefixes hold within the configured state space, and a Z3 encoding checks per-stream retained-byte arithmetic. These are abstractions, not refinement proofs of the implementation.

**Not acceptable:**

| Do not say | Why |
| --- | --- |
| "Formally verified" | Implies the implementation was proven |
| "Mathematically proven correct" | The models are, the code is not |
| "Proven secure" | No adversary is modelled |
| "Verified implementation" | The implementation is not what was verified |
| "Exhaustively checked" | Bounded state space |

## 6. What would strengthen this

For a reviewer assessing how much weight to give these artifacts, the honest ranking of what is missing:

1. **A refinement relation** connecting a model to the implementation. This is the gap that matters most and is the hardest to close.
2. **Adversary modelling**, so the results say something about security rather than only about ordering.
3. **Wider bounds**, with the state-space size recorded so a reader can judge coverage.
4. **Property-based testing** against the same invariants, executed on the real implementation — a weaker but achievable bridge between model and code.

None is in progress. See [Roadmap](../../ROADMAP.md).

---

**Related:** [Formal Verification](FORMAL_VERIFICATION.md) · [Failure Semantics](../architecture/FAILURE_SEMANTICS.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md) · [Audit Evidence Index](../assurance/AUDIT_EVIDENCE_INDEX.md)
