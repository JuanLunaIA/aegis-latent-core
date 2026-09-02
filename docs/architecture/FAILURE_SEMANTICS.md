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
| 1 | Admission rejected (auth, scope, bounds, WAF, rate limit) | `401` / `403` / `413` / `429` | A rejection record; **no governed evidence record** | Yes |
| 2 | Upstream failure | `502` / `504`, or a terminal error response | Durable record of the governed outcome | Yes |
| 3 | WAL append failure | `503`; the response is not returned | No record for this call | Yes |
| 4 | `fsync` failure | `503` | No durable record; see §3 | Yes |
| 5 | Terminal commit failure mid-stream | Stream ends **without** the terminal marker | No terminal record | Yes |
| 6 | Proof retrieval failure | `404` or `503` from the proof endpoint | The record is unaffected | Yes |
| 7 | Rate-limit backend unavailable | `503` | No governed record | Yes |
| 8 | Auth backend unavailable (OIDC/JWKS) | `503` or `401` | No governed record | Yes |
| 9 | Analysis queue full | Governed call **succeeds normally** | Full governed record; enrichment skipped | No, by design |
| 10 | Native stream WAL append failure | Nothing | JSONL record intact; counter increments | No, by design |
| 11 | Second writer on a WAL path | Process fails to start | Existing chain untouched | Yes |
| 12 | WAL replay finds corruption | Startup completes; health reports `wal_corrupt` | Chain truncated at the bad line | **Partially — see §4** |

---

## 1. Admission rejection

A rejected request never reaches the upstream and never produces a governed evidence record. It produces a rejection record.

This distinction matters when reconciling counts: `aegis_requests_total` for `4xx` will exceed the number of governed evidence records, and that is correct rather than a gap. Do not build a reconciliation that expects one evidence record per received request.

## 2. Upstream failure

An upstream failure is a governed outcome, not an absence of one. The gateway commits a record describing the failure before returning it, so a `502` carries durable evidence in the same way a `200` does.

The circuit breaker may open under sustained failure, at which point requests are rejected at admission (row 1) rather than forwarded — so the evidence shape changes from "governed failure" to "rejected", which is worth knowing when reading a timeline.

## 3. Storage failure

`_persist_node` writes under a lock in the order: build node → sign → write → `flush` → `fsync`. A failure at any step aborts the commit, and an aborted commit aborts the response.

**`fsync` returning successfully is not power-loss durability.** It means the filesystem reported the write reached stable storage. A device with a volatile write cache that acknowledges early can lose an `fsync`-ed record on power loss. The gateway cannot detect this. Power-loss protection is a storage procurement decision; see [Storage Requirements](../operations/STORAGE_REQUIREMENTS.md).

So row 4 is fail-closed with respect to *reported* failures and silent with respect to *unreported* ones. That gap is a property of the storage layer, not something the gateway can close.

## 4. WAL corruption — the honest exception

Row 12 is the one place the system is not fully fail-closed, and it should be understood rather than glossed.

Startup replay stops at the first malformed line and marks the ledger `wal_corrupt`. `/v1/audit/health` reports the degradation. **But subsequent commits remain permitted, and the request path does not check the fault state before committing.**

A gateway that started with a corrupt WAL will continue to accept governed traffic and append to the chain past the corruption point. The result is a chain whose earlier segment is unverifiable and whose later segment is fine.

Treat `wal_corrupt` in health as an incident signal requiring action, not as a state the system will manage on your behalf. Alert on it; see [Monitoring and Alerting](../operations/MONITORING_ALERTING.md).

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

A refusal to start is the system working. The correct response is to read the error and fix the configuration, not to relax the setting that produced it.

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
- **Cross-replica consistency.** No such guarantee exists.
- **Network partition between gateway and storage** beyond what the filesystem surfaces.
- **Upstream correctness.** The gateway records what the provider returned; it does not evaluate it.

---

**Related:** [Architecture](ARCHITECTURE.md) · [Security Architecture](../security/SECURITY_ARCHITECTURE.md) · [Storage Requirements](../operations/STORAGE_REQUIREMENTS.md) · [Incident Response](../security/INCIDENT_RESPONSE.md) · [Monitoring and Alerting](../operations/MONITORING_ALERTING.md)
