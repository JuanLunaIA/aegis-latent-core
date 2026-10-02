# Failure Semantics

**Audience:** developers, SRE, security reviewers.
**Scope:** what happens on every failure path, what the caller observes, and what evidence exists afterwards.
**Boundary:** describes the checked-out source. It does not establish that any deployment's storage, network or upstream behaves as assumed. See [Boundaries](../BOUNDARIES.md).

---

## Principle

The system prefers refusing to serving unevidenced traffic. Where a failure could produce either a response with no durable record or no response at all, the design chooses no response.

The one deliberate exception is optional enrichment, which may be dropped without affecting the governed call. That exception is explicit and bounded, not a general permission to degrade.

## Failure matrix

| # | Failure | Caller observes | Evidence afterwards | Fail-closed? |
| --- | --- | --- | --- | --- |
| 1 | Admission rejected by the WAF, the retrieved-content scan or the rate limit | `403` / `429` | A rejection record, unless the ledger is faulted or the commit fails (`X-Aegis-Evidence-Status` says which); **no governed evidence record** | Yes |
| 1a | Admission rejected by authentication, scope or the body-size bound | `401` / `403` / `413` | **No record of any kind** | Yes |
| 2 | Upstream failure | `502` / `504`, or a terminal error response | Durable record of the governed outcome | Yes |
| 3 | WAL append failure | `503`; the response is not returned | No record for this call | Yes |
| 4 | `fsync` failure | `503` | Not durable, but the bytes are already in the WAL and replay reads them back as committed; see §3 | Yes |
| 5 | Terminal commit failure mid-stream | Stream ends **without** the terminal marker | No terminal record | Yes |
| 6 | Proof retrieval failure | `404` or `503` from the proof endpoint | The record is unaffected | Yes |
| 7 | Rate-limit backend unavailable | `503` | No governed record | Yes |
| 8 | Auth backend unavailable (OIDC/JWKS) | `503` or `401` | No governed record | Yes |
| 9 | Analysis queue full | Governed call **succeeds normally** | Full governed record; enrichment skipped | No, by design |
| 10 | Native stream WAL append failure | Nothing | JSONL record intact; counter increments | No, by design |
| 11 | Second writer on a WAL path | Process fails to start | Existing chain untouched | Yes |
| 12 | WAL replay finds corruption | Startup completes; health reports `wal_corrupt`; governed requests are refused with `503` | Chain truncated at the bad line; no further nodes appended | **Yes — see §4** |
| 13 | MMR checkpoint absent, unreadable, stale or failing its checksum | Nothing; startup is slower | Full WAL replay reconstructs the same accumulator | Yes — see §7.1 |
| 14 | MMR checkpoint restores to a root the WAL does not attest | Nothing; startup is slower | The fast-path accumulator is discarded and every leaf replayed | Yes — see §7.1 |
| 15 | Request body unusable: invalid UTF-8 or JSON, an integer past Python's digit limit, not a JSON object, or nested more than 32 levels | `400` before the WAF; nothing forwarded | A rejection record for a depth refusal only; none for a body that does not parse or is not an object | Yes — see §1 |
| 16 | A feature that runs after the seccomp lockdown needs a syscall outside the profile | The kernel kills the process (`SIGSYS`); in-flight requests get no response | Every node committed before the kill replays; the call being served has no record | Yes — see §7.2 |

---

## 1. Admission rejection

A rejected request never reaches the upstream and never produces a governed evidence record. The WAF, the retrieved-content scan, the rate limit and the request-body depth bound also commit a rejection record (`CLM-060`, `CLM-118`). Authentication, scope and body-size refusals commit nothing, and neither does a body that does not parse: those happen before the gateway knows whose request it is or what it says. Earlier revisions of this document said every admission refusal produced a rejection record; that was never true of `401`, `413` or unparseable bodies.

**WAF Layer-2 evaluation is fail-closed**: if an unhandled scoring exception occurs during local layer-2 evaluation, the request is refused (`403` with reason `Layer-2 evaluation unavailable`, score 1.0) rather than allowed to pass through, preserving the fail-closed perimeter unless the operator has explicitly configured shadow mode.

**Unusable bodies are `400`, not `500`** (`REG-D98`). The three model endpoints parse with one helper: invalid UTF-8, an integer past Python's digit limit and a parser recursion failure answer `Invalid JSON`; valid JSON that is not an object answers `Request body must be a JSON object`; nesting past 32 levels, measured iteratively before canonicalisation, answers `JSON nesting exceeds 32 levels` and is recorded, as the WAF depth guard recorded it before the bound existed. Before this, all five classes escaped as `500`, which tells an attacker where the parser gives way and counts a client error as a server fault.

This distinction matters when reconciling counts: `aegis_requests_total` for `4xx` will exceed the number of governed evidence records, and that is correct rather than a gap. Do not build a reconciliation that expects one evidence record per received request.

## 2. Upstream failure

An upstream failure is a governed outcome, not an absence of one. The gateway commits a record describing the failure before returning it, so a `502` carries durable evidence in the same way a `200` does.

The circuit breaker may open under sustained failure, at which point requests are rejected at admission (row 1) rather than forwarded — so the evidence shape changes from "governed failure" to "rejected", which is worth knowing when reading a timeline.

## 3. Storage failure

`_persist_node` builds, signs, writes, and flushes a record under the ledger lock, then takes a group-commit ticket (`CLM-082`). The `fsync` itself is issued by `_await_durable` with the lock **released**, and covers every record written while it was in flight — one sync can retire several concurrent commits instead of charging each a separate device round trip inside the lock. A commit does not return until its own record is confirmed by a completed `fsync`; a failure there aborts the commit and the response, and fails every other commit waiting on the same batch together (`_await_durable` latches `wal_persist_failed`).

That ordering has a residue worth naming precisely: the refused batch's bytes were already written and flushed to the WAL file *before* the `fsync` that failed them. They are not durable — the write never reached stable storage — but they are still in the file, and replay on restart reads them back as ordinary committed records (`tests/test_coalesced_commit.py`). This is the safe direction: evidence exists for a call whose caller was told it failed, never the reverse (a caller told "durable" with nothing behind it — `_await_durable` raises before returning the node in that case).

**Durability barriers during WAL rotation.** When the active WAL rotates, the outgoing segment is flushed and `fsync`ed. If this barrier fails, rotation immediately aborts, the failure latches onto the commit engine (`_commit_engine.fail`), and pending commits fail closed rather than continuing on an unverified segment rename. On POSIX systems, a directory `fsync` is executed after creating or renaming the active segment to ensure filesystem namespace metadata is durable before group-commit tickets are acknowledged.

**Once a fault is latched, the ledger refuses every later commit.** `wal_persist_failed`, `signing_failed`, `wal_corrupt`, `mmr_scheme_mismatch` and `mmr_replay_mismatch` all make `commit_forensic`, `commit_state`, `commit_rejection` and `commit_forensic_summary` raise `LedgerFaultedError`, checked under the ledger lock before anything reaches the MMR or the WAL (`CLM-114`). The gateway maps it to `503` like any other commit failure. This closes a window that the admission check alone could not: a request admitted before another request's write tore part-way through a line could still commit, its record landed after the torn bytes, its caller was told it was durable, and replay then stopped at the torn line and never read it back. TLC finds that trace in `specs/aegis_invariants_ungated.cfg`, and `tests/test_ledger_fault_gate.py` drives it against the real class. The latch clears only when a new ledger replays a WAL that verifies, that is after repair and a restart.

**`fsync` returning successfully is not power-loss durability.** It means the filesystem reported the write reached stable storage. A device with a volatile write cache that acknowledges early can lose an `fsync`-ed record on power loss. The gateway cannot detect this. Power-loss protection is a storage procurement decision; see [Storage Requirements](../operations/STORAGE_REQUIREMENTS.md).

So row 4 is fail-closed with respect to *reported* failures and silent with respect to *unreported* ones. That gap is a property of the storage layer, not something the gateway can close.

## 4. WAL corruption

Startup replay stops at the first malformed line and marks the ledger `wal_corrupt`.

**Governed traffic is then refused.** `_require_intact_ledger` runs at the top of every governed endpoint — `/v1/chat/completions`, `/v1/messages`, `/v1/completions` — and returns `503` with `Evidence chain is not intact; governed requests are rejected`. Nothing is forwarded upstream and no node is appended.

This closes a gap that earlier revisions of this document described as the one place the system was not fully fail-closed. The old behaviour was worse than it sounds: each individual commit past the corruption point succeeded and verified, so a gateway that started on a corrupt WAL would keep accepting traffic and building a chain whose earlier segment could not be replayed at all — a divergence visible only to whoever eventually tried to replay it. `tests/test_app_wal_corrupt.py` pins the refusal, that it happens before the upstream call, and that the chain does not grow.

The in-process engine (`aegis.wrap`) applies the same rule at `guard_request`: any ledger state other than `healthy` raises `AegisEmbeddedError` before the provider is contacted, and nothing is committed (`tests/test_embedded_mode.py`). Both boundaries read the latch before admitting; the ledger class also refuses at commit (§3), which covers a call admitted just before the latch was set.

**`/health` and `/metrics` stay reachable on purpose.** They fail closed in the sense of reporting `503` and `fault_state: wal_corrupt`, but they keep answering. An observability surface that went dark alongside the data path would leave an operator watching traffic stop with no way to learn why from the process itself.

Recovery remains a human decision. The gateway will not repair, truncate, or roll over a corrupt WAL on your behalf; it stops so that the damage does not extend. Alert on `wal_corrupt`; see [Monitoring and Alerting](../operations/MONITORING_ALERTING.md).

## 5. Streaming failures

Streaming trades atomicity for latency, and the reconciliation is `pending-terminal`.

| Point of failure | Caller observes | Record |
| --- | --- | --- |
| Before first event | Error response | No stream record |
| Mid-stream, upstream drops | Stream ends without terminal marker | Terminal summary may still commit if the gateway can construct it |
| Mid-stream, terminal commit fails | Stream ends without terminal marker | No terminal record |
| Client disconnects early | Client sees nothing further | Gateway may still commit; the client has no proof |

**The terminal marker is the contract.** A caller that received it has a committed terminal summary. A caller that did not must not treat the stream as complete, however much output arrived. A client library that treats connection close as success will silently accept unevidenced streams; that is a client bug, and the gateway cannot prevent it.

Bounds that terminate a stream — queue bytes, event count, event size, cumulative output, duration — all take the same path: the stream ends, and the terminal marker appears only if the terminal summary committed.

## 6. Optional-path failures

Rows 9 and 10 are deliberate soft failures.

**Analysis queue full.** Enrichment is bounded and rejects rather than growing. `aegis_analysis_queue_rejections_total` increments; the governed call is unaffected. Sustained rejection means analysis coverage has gaps, which matters for detection but not for evidence.

**Native stream WAL failure.** The Rust WAL is auxiliary. The JSONL WAL already holds the authoritative record, so a failure is logged, counted, and otherwise ignored. Do not treat this counter as evidence loss.

## 7. Startup failures

Strict mode refuses to bind rather than starting degraded:

| Condition | Result |
| --- | --- |
| `debug_mode` enabled | Refuses |
| `auth_disabled` | Refuses |
| `require_durable_evidence` false | Refuses |
| Rate-limit backend not Redis | Refuses |
| No signing key and no PKCS#11 library | Refuses |
| API-key mode with no keys, or a key lacking a principal mapping | Refuses |
| `mtls_required` without `ssl_ca_certs` | Refuses |
| Identity HMAC key under 32 bytes | Refuses |
| Configured PKCS#11 backend unavailable | Refuses |
| WAL path already locked by another writer | Refuses with `WalWriterConflictError` |
| `tsa_url` set while the seccomp filter is about to load | Refuses: RFC 3161 verification runs the `openssl` binary, which the profile forbids (`REG-D105`) |

A refusal to start is the system working. The correct response is to read the error and fix the configuration, not to relax the setting that produced it.

### 7.1 The MMR checkpoint has no failure mode that costs correctness

`<wal>.mmr.state` is an optimisation, and it is built so that every way it can go wrong costs startup time rather than integrity. Writing it never raises — a ledger that could not write one replays on the next start and is fully correct. Reading it returns nothing for *every* failure mode (absent, unreadable, not an object, wrong version, failing its own checksum, malformed peaks, or describing more leaves than the WAL holds), because all of them have the same remedy: replay.

The part that makes it safe rather than merely tolerant is the acceptance test. After restoring the checkpointed prefix and replaying the leaves committed after it, the result is accepted **only if the final root equals the root the last committed node recorded in the WAL**. Any disagreement discards the fast-path accumulator entirely and replays every leaf. A tampered or stale checkpoint therefore cannot introduce a root the WAL does not already attest — it can only make startup slower.

The fast path is opt-in (`mmr_fast_restore=True`) because it trades away in-memory proofs for leaves it summarises; the file is written either way, so enabling it needs no migration. See [DOC-02 §6.1](../institutional/DOC-02_CRYPTOGRAPHIC_FORENSIC_BLUEPRINT.md).

### 7.2 Features that run after the seccomp lockdown

The seccomp filter's default action is `SCMP_ACT_KILL_PROCESS`. A syscall outside the profile does not return an error; the kernel kills the whole process. The profile was first measured on the request path, and three configured features that run only later were each killed the first time they ran (`REG-D103`–`REG-D105`, `CLM-119`):

| Feature | What killed it | Now |
|---|---|---|
| WAL rotation (`max_wal_bytes > 0`, required by S3 archival) | `chmod` on the segment path; `mkdir` on a directory that already existed | `fchmod` on the open descriptor (in the default profile); `mkdir` only when the directory is missing |
| S3 archival journal, cryptographic-shredding vault | SQLite's `pread64`, `pwrite64`, `ftruncate`, `geteuid`, and `fchown` when running as root | The lifespan loads `SQLITE_SYSCALLS` when archival, shredding or the SQLite HA sequence store is configured |
| Terminal outbox (`terminal_outbox_enabled = True`) | Spool rollback, compaction descriptor duplication, and mode setting | The lifespan loads `TERMINAL_OUTBOX_SYSCALLS` (`ftruncate`, `dup`, `dup3`, `chmod`, `fchmodat`) when the outbox is configured |
| RFC 3161 anchoring | `execve` of the `openssl` binary | Refused at startup (§7); not supported behind the filter |

A kill leaves the chain in the same state as any crash: every node whose `fsync` completed replays, and the call in flight has no record (row 16). The profile covers the flows that have been driven under the real filter; a path none of them reaches can still be outside it. `tests/test_seccomp_runtime_paths.py` runs each flow under the real filter in a child interpreter, because the filter is skipped inside pytest.

## 8. Recovery

| State | Recovery | Reference |
| --- | --- | --- |
| Corrupt WAL | Restore from backup, or accept truncation with the divergence recorded | [Backup and Restore](../operations/BACKUP_RESTORE.md) |
| Writer conflict | Fix topology: one worker, one volume per replica | [DOC-04 §6.4](../institutional/DOC-04_OPERATIONS_PLAYBOOK.md) |
| Storage full | Extend, or rotate and archive. Never delete segments | [Storage Requirements](../operations/STORAGE_REQUIREMENTS.md) |
| Redis loss | Restore; requests fail closed meanwhile | [Backpressure Runbook](../operations/BACKPRESSURE_RUNBOOK.md) |
| Key compromise | Rotate, **retaining the retired key** | [Key Rotation Runbook](../operations/KEY_ROTATION_RUNBOOK.md) |

## 9. What is not handled

- **Byzantine storage** that acknowledges writes it discards.
- **Operator tampering.** Detected on read, not prevented.
- **Cross-replica consistency beyond the HA modes.** Without `AEGIS_HA_MODE`, replicas share nothing. With `active_passive` or `active_active`, a writer lease and a global sequence order the chains (`CLM-108`), and **their Redis or PostgreSQL outage stops admission**; this is not consensus over content, and it is untested against real storage classes, partitions or backend failover.
- **Network partition between gateway and storage** beyond what the filesystem surfaces.
- **Upstream correctness.** The gateway records what the provider returned; it does not evaluate it.

---

**Related:** [Architecture](ARCHITECTURE.md) · [Security Architecture](../security/SECURITY_ARCHITECTURE.md) · [Storage Requirements](../operations/STORAGE_REQUIREMENTS.md) · [Incident Response](../security/INCIDENT_RESPONSE.md) · [Monitoring and Alerting](../operations/MONITORING_ALERTING.md)
