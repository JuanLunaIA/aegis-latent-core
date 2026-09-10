# Architecture Decisions

**Audience:** contributors, architects, security reviewers.
**Scope:** the decisions that shaped this system, why they were made, and what each cost.
**Boundary:** these record reasoning, not claims. Capabilities they mention are governed by [Claims Matrix](../CLAIMS_MATRIX.md).

---

## How to read this

Each entry states the decision, the alternative that was rejected, and the **cost** — what the decision made worse. An architecture decision record with no cost column is advocacy, not a record.

The founding decision is [ADR-001](ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md): position the system as an AI governance and evidence gateway rather than a firewall or a compliance product. The entries below follow from it.

---

## AD-01 — Commit evidence before emitting the response

**Decision.** For an admitted non-streaming call, the evidence record is written, flushed and `fsync`-ed before the response is observable to the caller.

**Rejected.** Return first, commit asynchronously. Lower latency, and the industry-common pattern.

**Why.** An evidence record that may or may not exist is not evidence. Asynchronous commit means a caller can act on a response that was never recorded — a crash between emission and commit produces exactly the gap an auditor asks about. The property that makes the system worth deploying is that the record exists whenever the response was observed.

**Cost.** Added latency on every governed call, bounded by storage `fsync` performance. Under storage pressure the system slows and eventually refuses rather than degrading silently. The backpressure measurement records p99 commit latency of 836 ms under a 2 ms injected `fsync` delay — that is the cost, made visible.

---

## AD-02 — Stream incrementally, commit once at the terminal

**Decision.** SSE emits sanitized events as they arrive through a bounded byte-accounted queue, reports `pending-terminal` throughout, and withholds the terminal marker until the terminal summary commits.

**Rejected.** Buffer the whole stream and commit before emitting anything — which would preserve AD-01 exactly but destroy the reason to stream.

**Why.** Streaming exists for time-to-first-token. Buffering removes it. The reconciliation is that partial output carries no evidence claim, and the terminal marker is the point at which a durable record exists.

**Cost.** A client can receive substantial output for which no durable record yet exists. A client library that treats connection close as success will silently accept unevidenced streams. The gateway cannot prevent that — it is a client contract, and the burden is real.

---

## AD-03 — One writer per WAL path, enforced

**Decision.** The ledger takes a POSIX advisory lock before publishing the WAL handle; a second writer raises `WalWriterConflictError` at startup.

**Rejected.** (a) Document the constraint and rely on operators. (b) Build a distributed lock or centralized writer.

**Why.** (a) was the previous state and it failed: two writers forked the chain silently, discoverable only afterwards. (b) is real work with real complexity that has not been done. The lock converts a silent fork into a startup error, which is the largest safety improvement available for the smallest change.

**Cost.** POSIX-only; on a platform without `fcntl` the discipline is operator-enforced and the ledger only warns. `flock` is advisory and per-inode, so it does not constrain a writer reaching the same bytes by another path or over a network filesystem. It prevents a second writer; it does not serialize two, so multi-worker on one WAL remains unsupported rather than newly supported.

**Amended (Windows).** The POSIX-only cost above was subsequently narrowed rather than accepted: `_lock_wal_fd` now takes a `msvcrt.locking` byte-range lock on Windows. That primitive is *mandatory* rather than advisory — a locked range is denied to readers too — and the WAL is read while a writer holds it, so the lock is placed on a one-byte sentinel region at 1 TiB, past any WAL that can exist. Locking beyond end-of-file is well defined there and does not extend the file. **New cost:** a second platform-specific path to maintain, a magic offset that must stay inside the maximum file size of every deployed filesystem, and a third outcome to reason about — a sentinel that cannot be positioned degrades to the same warning as a platform with no primitive at all, because refusing there would reject the *first* writer as though it were the second. The rest of the original cost stands unchanged.

---

## AD-04 — StatefulSet with per-replica volumes

**Decision.** The Helm chart renders a `StatefulSet` with `volumeClaimTemplates`, pins `workers` to `"1"`, and constrains `accessMode` to `ReadWriteOnce`/`ReadWriteOncePod` in `values.schema.json`.

**Rejected.** Deployment with a shared PVC — the previous default, which placed four writers on one chain.

**Why.** Each replica needs its own WAL path. Schema pinning gives an install-time rejection rather than a `CrashLoopBackOff` from AD-03's lock.

**Cost.** Not upgrade-in-place compatible: the workload kind changes and claim names do not overlap, so migration is required and documented in [DOC-04 §6.4](../institutional/DOC-04_OPERATIONS_PLAYBOOK.md). A `StatefulSet` replaces pods in place, so rolling updates briefly reduce capacity where a Deployment would surge. And it removes an operator knob — `workers` cannot be raised, deliberately.

---

## AD-05 — MMR inclusion proofs over hexadecimal peak bagging

**Decision.** Proofs follow the `aegis-mmr-inclusion-v1` schema; peak bagging hashes over hexadecimal text rather than decoded digest bytes.

**Rejected.** Bagging over raw bytes, which is more conventional.

**Why.** The choice is arbitrary in isolation but must be identical across the core, the Python verifier and the TypeScript verifier. Fixing it in a published schema, with cross-implementation tests, is what makes proofs portable. Changing it now would invalidate every existing proof.

**Cost.** Divergence from convention, which surprises implementers. Documented explicitly in [MMR Proof v1](../api/MMR_PROOF_V1.md) precisely because it is surprising.

---

## AD-06 — Proofs require an independently obtained root

**Decision.** Verification takes a trusted root as an input the verifier supplies. The gateway does not assert its own root as authoritative.

**Rejected.** Return the root alongside the proof and verify against it.

**Why.** Verifying a proof against a root supplied by the same gateway that produced the proof establishes internal consistency and nothing else. The system would be attesting to itself.

**Cost.** Real friction. Every consumer must solve root distribution — a published root, a third-party anchor, or an out-of-band channel — and there is no built-in mechanism. This is the most common integration mistake, and the SDKs cannot detect it because a root is a root.

---

## AD-07 — Fail closed, including at startup

**Decision.** Strict mode refuses to bind when any required invariant is unmet: no signer, no distributed limiter, debug enabled, auth disabled, kernel controls absent, identity HMAC key too short.

**Rejected.** Start and log a warning.

**Why.** A warning in a log is not read. A process that will not start is read immediately. For a system whose value is evidence integrity, running degraded is worse than not running.

**Cost.** Operators encounter startup refusals, sometimes in a hurry, and the temptation is to relax the setting that produced the error rather than fix the environment. Documentation repeatedly says to read the error instead — which is a mitigation, not a fix.

---

## AD-08 — The native Rust WAL is auxiliary

**Decision.** The JSONL WAL is authoritative. The Rust streaming WAL is best-effort; its failures are counted and logged, and do not fail the call.

**Rejected.** Make the native WAL authoritative for streams.

**Why.** Two authoritative stores need a reconciliation story. There is not one, so there is one authoritative store.

**Cost.** The native path's performance benefit does not extend to the durability guarantee. `aegis_native_stream_wal_errors_total` is a degradation signal that is easy to misread as evidence loss, which is why the metric's help text says otherwise.

---

## AD-09 — Redaction protects the record, not the provider

**Decision.** Redaction runs on the payload before the evidence record is committed — after the request has been forwarded upstream.

**Rejected.** Redact before forwarding.

**Why.** Redacting before forwarding changes what the model receives, which changes the response. The gateway would be silently altering the caller's request, and the evidence record would no longer describe what the caller asked.

**Cost.** Significant and frequently misunderstood: personal data reaches the provider unredacted. Anyone whose privacy position depends on the provider not receiving it needs a control before the gateway. This is stated in [PII Redaction Boundaries §4](../privacy/PII_REDACTION_BOUNDARIES.md#4-the-limit-that-surprises-people) because assuming otherwise is the expensive error.

---

## AD-10 — Detect tampering; do not attempt to prevent it

**Decision.** Hash linkage and signatures make alteration detectable on read. No attempt is made to prevent an operator with filesystem access from altering records.

**Rejected.** Claim immutability, or attempt to enforce it in software.

**Why.** Software running as a process on a host cannot prevent the host's operator from modifying its files. A system claiming otherwise would be claiming something false.

**Cost.** Every integrity, custody and non-repudiation statement terminates at the operator-trust boundary. That limits what the system can claim, and it is the correct limit. External immutability requires an external control — an Object Lock bucket, an anchor, a third-party witness — each of which is configuration-dependent and none of which is guaranteed.

---

## AD-11 — Claims are governed and machine-checked

**Decision.** Every public claim carries a state, an evidence locator and a boundary in [Claims Matrix](../CLAIMS_MATRIX.md), checked in CI.

**Rejected.** Ordinary editorial review.

**Why.** The product is evidence integrity. A project that overstates its own claims has demonstrated the failure mode it exists to prevent. Automated gates make that structural rather than dependent on whoever is writing.

**Cost.** Friction on every documentation change, and a checker that must be carefully tuned — its denial detector was calibrated against real boundary statements it initially flagged as violations. A checker with false positives gets disabled, which would be worse than not having one.

---

## AD-12 — Add a domain-separated scheme rather than change the existing one

**Decision.** `aegis-mmr-inclusion-v2` hashes with one-byte domain tags over raw 32-byte digests. It is added alongside `aegis-mmr-inclusion-v1`, which remains the default and is what the ledger writes. Proof `version` and `algorithm` must agree, and a mismatch is rejected rather than resolved in the caller's favour.

**Rejected.** Changing v1 in place. This was the original instruction, paired with a requirement that existing proofs keep verifying; the two cannot both hold.

**Why.** AD-05 noted that changing the scheme "would invalidate every existing proof", and that remains true in a sharper form than portability: the scheme determines every root a chain has already recorded. Replacing it in place would make each deployed WAL replay to a different root, and the ledger's own integrity check would then declare an untampered chain corrupt. For a system whose purpose is holding evidence, that failure is unrecoverable — the operator cannot distinguish it from real tampering. An explicitly versioned second scheme makes the transition a recorded fact instead of a silent reinterpretation of history.

The weakness being addressed is real and was demonstrated before being fixed: v1 tags neither hash input, so a leaf payload equal to the concatenation of two child digests hashes to exactly the interior node over them (RFC 6962 §2.1). It is reachable through `verify_portable_inclusion`, which accepts caller-supplied leaf bytes.

**Cost.** Two schemes to maintain, test and explain, in three implementations. The weakness stays reachable in the default path until v2 is wired into the ledger, which is blocked on the `aegis_rust` accumulator implementing v1 only and on there being no recorded scheme transition for an existing chain. Both are tracked as open work in [docs/ROADMAP.md](../ROADMAP.md). Documented in [MMR Proof v1](../api/MMR_PROOF_V1.md) and governed by `CLM-064`.

---

## AD-13 — Converge without a leader, and sort by a total order rather than the causal one

**Decision.** `CausalMmr` (`aegis_rust_v2/src/crdt_mmr.rs`) is a join-semilattice over domain-separated MMRs. Replicas append locally with a vector clock, exchange leaf sets, and merge with a `join` that is idempotent, commutative and associative. Leaves are ordered by an explicit **total** order — scalar clock sum, then replica id, then that replica's own sequence, then the leaf digest.

**Rejected.** (a) A centralized writer or a consensus round to give one order. (b) Sorting directly by the vector clock's partial order, falling back to replica id when two events are incomparable.

**Why.** (a) is a real design with real operational weight — capacity, availability, failover, recovery, custody — none of which has been done, so shipping the accumulator first costs nothing and settles the algebra. (b) is the tempting implementation and it is **wrong**: the resulting comparator is not transitive, and a non-transitive comparator makes `sort_by` produce an order that depends on the input permutation. That destroys commutativity and associativity — precisely the two properties the construction exists to provide. The scalar clock sum fixes it because it *extends* causality: if `a` causally precedes `b` then `a`'s clock is componentwise ≤ `b`'s and differs somewhere, so `sum(a) < sum(b)` and causally ordered events never invert, while concurrent events are broken by keys identical on every replica.

**Cost.** It is a data structure, not a topology. It is not wired into the ledger, there is no transport, membership protocol or persistence, and a merged root commits to a *set* of leaves rather than re-linking the per-replica `prev_hash` chains — so it is a long way from a governed multi-pod chain, and `docs/ROADMAP.md` still carries cross-replica ordering as open work. The total order discards information: two genuinely concurrent events are separated by a tiebreak that means nothing causally, and a reader who mistakes the sequence for a happens-before relation will be wrong. `join` reconciles replicas that disagree about ordering, not replicas that lie. And there is no latency claim here at all — none can be measured until a transport exists. Governed by `CLM-066`; boundaries in [DOC-01 §8.8](../institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md).

---

## AD-14 — Erase the key, not the record

**Decision.** `CryptoShredder` (`aegis/core/crypto_shredder.py`) seals a payload under a per-subject AES-256-GCM key from the `cryptography` library and commits `SHA-256(0x00 || nonce || ciphertext)`. Erasure destroys the key and leaves every byte of the ledger where it was.

**Rejected.** (a) Deleting or rewriting the committed node. (b) A homomorphic trapdoor commitment over a pairing-friendly curve, which was the original proposal.

**Why.** (a) is the thing the whole system is built to make detectable: it breaks chain linkage, invalidates the root for every subsequent record, and makes the ledger's own integrity check report an untampered chain as corrupt — indistinguishable, afterwards, from real tampering. (b) would mean hand-rolling curve arithmetic and a bespoke commitment scheme. The rule that settled it is the standing one: **no hand-rolled cryptographic primitives.** An unaudited BLS12-381 implementation would be a much larger security claim resting on a much smaller evidence base than an audited AEAD does. Envelope encryption gets the same structural result — the tree does not move, previously issued proofs still verify — out of a primitive that is already reviewed.

**Cost.** The key vault becomes the only mutable component in an append-only design, and therefore a new single point of failure: lose it and every subject's plaintext is gone at once; compromise it and every erasure through it is undone. Its backup policy is in direct tension with the erasure it exists to perform. Erasure is bounded to *unrecoverable to a holder of the ciphertext* — it says nothing about key material on the physical medium, where allocator copies, the SQLite journal, page cache, swap, snapshots and SSD wear-levelling are all outside a CPython process's reach — and the node keeps its request and response digests, so a guessed plaintext is still confirmable. Because sealing changes what the MMR commits to, the option is **off by default and belongs to a chain rather than to a runtime**: `AEGIS_ENABLE_CRYPTOGRAPHIC_SHREDDING` cannot be turned on for a chain that already holds records, so adopting it means starting a new one, exactly as `AD-12` requires for the hash scheme. That is the second decision this one forces, and the reason it ships off: paying the WAL-growth and vault-custody costs should be a deliberate act, not the consequence of an upgrade. And it settles a structural conflict, not a legal one: **no regulatory conclusion follows.** Governed by `CLM-068`; boundaries in [DOC-02 §6.2](../institutional/DOC-02_CRYPTOGRAPHIC_FORENSIC_BLUEPRINT.md) and [DOC-05 §5.8.1](../institutional/DOC-05_REGULATORY_DOSSIER.md).

---

## AD-15 — Bound every quantifier so the streaming holdback is a bound

**Decision.** `GrammarFrontierAutomaton` (`aegis/core/streaming_safety_engine.py`) bounds every whitespace run in every pattern to `\s{1,4}`, declares a per-rule frontier at least as long as that rule's longest possible match, withholds the maximum of those frontiers, and redacts every match in the buffer **to fixpoint** before computing the frontier over what is left.

**Rejected.** (a) Unbounded `\s+` between words, which reads more natural and matches more strings. (b) The obvious streaming loop: redact the first match, conclude the buffer is settled, release everything.

**Why.** (a) makes the maximum match length infinite, so no fixed holdback settles a pattern and "frontier" becomes a heuristic wearing a proof's clothing. Bounding the quantifier is what turns a holdback into a bound that cannot be overrun. (b) is a **bypass**, and it was found by construction rather than in review: given `ignore all previous rules ... SSN: 123-45-6789`, the override is redacted, the frontier collapses to zero, the whole buffer is released, and the SSN leaves in the clear behind it. Redacting to fixpoint first, and only then measuring the residual text, is what closes it.

**Cost.** One-directional and asserted by test rather than left implicit: an evasion that pads whitespace past the bound is **not matched**. That is the same trade the `ADDRESS` bound makes in the wired de-identifier, and it is the price of a holdback that is provably sufficient rather than probably sufficient. Holding the global maximum instead of a per-rule frontier costs a few dozen characters of latency on every stream, chosen because tracking which rule is still viable at the tail would fail open when it got it wrong. The fixpoint loop needs a round cap, because an unbounded rewrite loop in the streaming path is worse than a missed redaction. The component is unwired — the gateway still uses `StreamingDeidentifier` — and it matches four declared patterns and nothing else. Governed by `CLM-067`; boundaries in [DOC-03 §5.4](../institutional/DOC-03_THREAT_MODEL.md).

---

## Revisiting a decision

A decision is revisited when its cost becomes unacceptable or its premise changes. Record the revision here with the new reasoning and the new cost. Do not edit a past entry to match a new position — the sequence of what was decided and why is the useful part.

---

**Related:** [ADR-001](ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md) · [Architecture](ARCHITECTURE.md) · [Failure Semantics](FAILURE_SEMANTICS.md) · [Security Architecture](../security/SECURITY_ARCHITECTURE.md) · [DOC-01](../institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md)
