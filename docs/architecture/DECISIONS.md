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

## Revisiting a decision

A decision is revisited when its cost becomes unacceptable or its premise changes. Record the revision here with the new reasoning and the new cost. Do not edit a past entry to match a new position — the sequence of what was decided and why is the useful part.

---

**Related:** [ADR-001](ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md) · [Architecture](ARCHITECTURE.md) · [Failure Semantics](FAILURE_SEMANTICS.md) · [Security Architecture](../security/SECURITY_ARCHITECTURE.md) · [DOC-01](../institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md)
