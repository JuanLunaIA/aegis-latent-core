# Formal Verification — Limits

**Audience:** security reviewers, auditors, anyone about to cite the formal artifacts.
**Scope:** precisely what the Z3, Lean, TLA+/TLC, Kani and Miri artifacts establish, and what they do not.
**Boundary:** **these are bounded model checks over abstractions. They are not refinement proofs of the Python or Rust implementation, and they say nothing about any deployment.** Read this before citing any formal result.

---

## 1. Why this document is separate

"Formally verified" is among the most over-claimed phrases in security marketing. It is usually taken to mean "proven correct", and it almost never does.

Here it means: some invariants over some abstract models were checked within some bounds, and the checks passed. That is genuinely worth having — it catches design errors that testing misses — and it is far weaker than what a reader hears.

Separating the limits from the description makes it harder to cite the result without the boundary.

## 2. The artifacts

| Artifact | Tool | Subject |
| --- | --- | --- |
| `specs/aegis_invariants.tla` + `.cfg` | TLA+/TLC | Request lifecycle: evidence before emission, and every returned commit replays |
| `specs/aegis_ledger_immutability.tla` + `.cfg` | TLA+/TLC | Tamper evidence of the signed chain against a WAL writer, given pinned keys |
| `specs/aegis_session_manager.tla` + `.cfg` | TLA+/TLC | Bounded, isolated per-session monitors |
| `specs/AegisVerification.lean` | Lean 4 | Nine theorems over the phase-level lifecycle, including reachability of each failure path |
| `specs/aegis_invariants.smt2` | Z3 | Token-bucket arithmetic over the integers |
| `specs/aegis_stream_buffer.smt2` | Z3 | Per-stream retained-byte arithmetic |
| `aegis_rust_v2/src/wal.rs` `mod verification` | Kani | WAL frame-bounds arithmetic |
| `aegis_rust_v2/src/rate_limit.rs` `mod verification` | Kani | Token-bucket refill and consume arithmetic |
| `aegis_rust_v2/tests/block_buffer_panic_safety.rs` | Miri | Digest-buffer cursor validity after a panic |

CI gates: `scripts/verify_formal_artifacts.sh` (Z3, Lean, TLC), the `Kani Model Checking` job (`cargo kani`) and the `Miri Undefined Behaviour` job (`cargo miri test`). Toolchain: Lean 4.33.0, TLA+ built from a pinned revision, Z3 from the distribution package, Kani 0.67.0, Miri on pinned `nightly-2026-09-09` — nightly because Miri ships only as a nightly component and `rustup component add miri` against stable fails outright, so there is no stable configuration to prefer.

The Kani harnesses differ in kind from the others and the difference matters when citing them. They run against the **actual functions in `wal.rs` and `rate_limit.rs`**, not against a separately written abstraction, so for those functions the refinement gap described in [§ 4](#not-a-refinement-proof) does not apply. That is a narrow exemption: it covers the frame-bounds arithmetic in `wal.rs` and the refill and consume arithmetic in `rate_limit.rs`, and nothing else in either file — not the compare-and-swap loops, the atomics, the clock or the map around them.

### Miri: a different kind of check, and a narrow one

Miri is not a prover. It is an interpreter that executes real Rust and reports
undefined behaviour along **the paths it actually runs** — out-of-bounds
arithmetic, invalid aliasing, uninitialised reads, invalid pointer use. So it
shares Kani's advantage of running the real code and none of its exhaustiveness:
Kani reasons over the whole `usize` domain, whereas Miri sees exactly the inputs
its test drives.

What it covers here is one target, `tests/block_buffer_panic_safety.rs`, which
exercises the `block-buffer` cursor under a panicking compression function. That
buffer sits beneath every SHA-256 and HMAC call on the evidence path, where a
torn cursor is not a crash but a *wrong digest* — the failure this repository
can least afford to discover downstream.

**Three things keep it from covering more, and all three are properties of Miri
rather than choices:**

- Miri cannot execute foreign functions, and the default build links PQClean's C
  implementation of ML-DSA-65. The `pure-rust-pqc` feature removes that C, but
  it does not remove the next constraint.
- Miri does not service `mmap`, which the WAL is built on, so the WAL's own code
  paths are unreachable under it. Their bounds arithmetic is what the Kani
  harnesses cover instead.
- Running `--lib` drags tokio, reqwest and vendored OpenSSL through Miri's own
  compilation. Measured locally, that had not finished after fifteen minutes. A
  job that times out establishes nothing, so the scope is the target Miri can
  actually reach.

A passing Miri run therefore says: *no undefined behaviour was observed on these
paths, under this interpreter, at this pinned toolchain.* It does not say the
crate is free of undefined behaviour, and it says nothing at all about the C
code, the memory-mapped WAL, or any path a test does not drive.

## 3. What is established

Within the declared bounds, the models preserve:

- **Commit before emission** — no emission step is reachable from a state where the corresponding commit has not occurred (`aegis_invariants.tla`).
- **Every returned commit replays** — across write failures, torn tails, crashes, replay and repair, a commit that returned success stays replayable, because the ledger refuses commits while its fault latch is set. `aegis_invariants_ungated.cfg` shows the invariant fails without that gate.
- **Tamper evidence against a WAL writer** — against an adversary who can modify, insert, delete, reorder and re-sign records but does not hold the signing key, any file the verifier accepts is a prefix of the true history, provided the verifier pins keys (`aegis_ledger_immutability.tla`). Truncating the tail is **not** detected unless the verifier also holds an external anchor for the length (`AnchoredEvidence`; the `WitnessTruncationUndetected` witness shows the gap). The `unpinned` and `compromised` configurations show the property fails without pinning and with the key.
- **Bounded, isolated session monitors** — the session table stays within its bound, evicts the least recently used session, and never hands one session's monitor to another (`aegis_session_manager.tla`). The `pooled` configuration shows the isolation fails if monitors are reused.
- **Per-stream byte arithmetic** — retained bytes stay within the modelled bound `R_max = 4W + Q + E + P`, and the factor 4 is needed (`aegis_stream_buffer.smt2`).
- **Token-bucket arithmetic** — over the integers, each compare-and-swap step preserves `0 <= tokens <= capacity`, and saturation never changes the answer (`aegis_invariants.smt2`).

Every one of these is falsifiable: each model also carries witness configurations whose invariants must be violated, which shows the states the property talks about are reachable, and the gate fails if TLC does not find those violations.

Kani additionally establishes, over the whole `usize` domain rather than within a bound, that `header_range` and `payload_range` in `aegis_rust_v2/src/wal.rs`:

- return a byte range inside the supplied `limit` whenever they return one, and refuse otherwise;
- never overflow, so no arithmetic wraps into an apparently valid range;
- never treat a zero-length payload — the recovery terminator — as a frame;
- always advance the cursor strictly, which is what makes the `read_all` and `scan_write_pos` walks terminate on arbitrary mapped bytes;
- produce header and payload ranges that do not overlap.

Because every slice taken during a frame walk is bounded through those two functions, an out-of-bounds index during a walk would require one of these properties to fail.

**Falsification conditions:** Z3 output that differs from the file's declared `; expect:` line (a `sat` where `unsat` is expected is a broken property, an `unsat` where `sat` is expected is a vacuous model); a Lean error, warning, missing required theorem or axiom beyond `propext`, `Quot.sound` and `Classical.choice`; a TLC counterexample on a main configuration, or an expected violation TLC does not find on a witness or counterexample configuration; or a Kani counterexample. Any of those falsifies the corresponding claim, and the CI gate fails.

## 4. What is not established

### Not a refinement proof

The TLA+, Lean and Z3 artifacts are abstractions written separately from the code. **Nothing mechanically connects those models to the Python or Rust that runs.**

A discrepancy between such a model and the implementation is invisible to those tools. The model can be correct and the implementation wrong, and every check still passes.

This is the single most important limitation. A reader who takes "formally verified" to mean the code was proven correct has misunderstood by a wide margin.

The Kani harnesses are the one exception, and they are exactly as narrow as they look: they check two real functions in `wal.rs` and four in `rate_limit.rs` over all inputs. They establish nothing about `append`, `open`, `read_all` or `scan_write_pos` as wholes, nothing about the mapping those functions produce ranges into, and nothing about how the limiter's compare-and-swap loops interleave.

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
| The Rust extension | Only the two WAL frame-bounds functions and the four token-bucket arithmetic functions are checked; nothing else in the crate is modelled |
| The memory mapping itself | Kani cannot model `mmap`, `flush_range`, or the filesystem, so durability, crash consistency, torn writes, and the invariant that `capacity` equals the mapped length are all outside it |
| Concurrent `append` | The mutex and `write_pos` ordering are argued in code comments and exercised by a unit test, not proven |
| Any deployment | Configuration, scale, operations |

### Nothing about security properties as a whole

The models cover specific ordering and arithmetic invariants. One adversary is modelled: in `aegis_ledger_immutability.tla`, a party with write access to the WAL who can modify, insert, delete, reorder and re-sign records under its own key. That model shows a verifying file is a prefix of the true history only while the verifier pins keys and the adversary does not hold the signing key, and that dropping the tail goes undetected without an external length anchor. No other adversary is modelled, and the models establish nothing about authentication, authorization, injection resistance, or an operator who holds the signing key.

## 5. Cite it like this

**Acceptable:**

> Within the configured state space, bounded TLA+/TLC models check that no outcome is emitted before its evidence commit and that every returned commit replays, and that a WAL writer without the signing key cannot make a verifier that pins keys accept anything but a prefix of the true history. Z3 checks the per-stream retained-byte bound and the token-bucket arithmetic. Each model also carries configurations that must fail, so none of these checks passes vacuously. These are abstractions, not refinement proofs of the implementation.

And, for the Kani result specifically:

> Kani proves, over all inputs, that the two functions bounding every slice in the native WAL's frame walks return only in-bounds ranges, never overflow, and always advance, and that the rate limiter's refill and consume arithmetic keeps a bucket's balance within `0..=capacity` without overflow. It does not model the memory mapping, durability, the limiter's atomics, or concurrent appends.

**Not acceptable:**

| Do not say | Why |
| --- | --- |
| "Formally verified" | Implies the implementation was proven |
| "Mathematically proven correct" | The models are, the code is not |
| "Proven secure" | One adversary, a WAL writer without the signing key, is modelled in one abstraction; nothing else is |
| "Verified implementation" | The implementation is not what was verified |
| "Exhaustively checked" | Bounded state space |
| "The WAL is memory-safe" | Two WAL arithmetic functions are proven; the mapping, the flush path and the concurrency are not |
| "Proven crash-safe" | Kani models no filesystem and no power loss |

## 6. What would strengthen this

For a reviewer assessing how much weight to give these artifacts, the honest ranking of what is missing:

1. **A refinement relation** connecting a model to the implementation. This is the gap that matters most and is the hardest to close. The Kani harnesses sidestep it for a handful of functions by checking the real code, which suggests the achievable direction: verify more real functions rather than write more abstractions.
2. **Wider adversary modelling.** Today only the WAL-writer adversary of `aegis_ledger_immutability.tla` is modelled; a network adversary, a malicious tenant and an operator holding the key are not.
3. **Wider bounds**, with the state-space size recorded so a reader can judge coverage.
4. **Property-based testing** against the same invariants, executed on the real implementation — a weaker but achievable bridge between model and code.

Only the narrow Kani exemption in item 1 exists today; the rest is not in progress. See [Roadmap](../../ROADMAP.md).

---

**Related:** [Formal Verification](FORMAL_VERIFICATION.md) · [Failure Semantics](../architecture/FAILURE_SEMANTICS.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md) · [Audit Evidence Index](../assurance/AUDIT_EVIDENCE_INDEX.md)
