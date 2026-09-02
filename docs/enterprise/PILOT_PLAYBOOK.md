# Pilot Playbook

**Audience:** platform engineering and security teams running an evaluation.
**Scope:** how to run a pilot that produces a defensible go/no-go decision.
**Boundary:** **passing a pilot establishes that the software behaved as documented in your environment. It does not establish certification, compliance, a service level, production readiness, or legal admissibility.** A pilot result is evidence for your decision; it is not assurance from anyone else.

---

## 1. Objectives

A pilot should answer four questions and no more:

1. **Does it produce the evidence it claims to?** Every governed call yields a durable, verifiable record.
2. **Does it fail the way it says it fails?** Fail-closed behaviour is the security property; if it fails open under load, nothing else matters.
3. **Can we operate it?** Rotate keys, roll back, restore a backup, respond to an incident.
4. **What does it cost us to run?** Storage growth, latency added, operational attention.

A pilot that only exercises the happy path answers none of them. Most of the tests below are failure tests deliberately.

## 2. Scope

**In:** one workload, one environment, a bounded time window, synthetic or non-sensitive data.

**Out:** production traffic, real personal data, and any conclusion about scale beyond what you actually measured.

**Use synthetic data.** A pilot is an unaccepted deployment by definition. Putting real personal data through one is the mistake this document exists to prevent.

## 3. Environment

Run the [single-node hardened](../operations/DEPLOYMENT_PROFILES.md#2-single-node-hardened) or [Kubernetes](../operations/DEPLOYMENT_PROFILES.md#3-kubernetes) profile. **Do not pilot in development mode** — it disables the controls you are evaluating, and a pilot of an unenforced configuration tells you nothing.

Before starting, record: the exact commit or tag, the image digest, `aegis_security_enforcement_mode` per replica, storage device and whether it has power-loss protection, Redis topology, and the signer in use.

## 4. Acceptance criteria

Each test states what must be true. A test that "mostly worked" did not pass.

### T1 — Evidence completeness

Send N governed non-streaming calls.

- [ ] Exactly N durable evidence records exist.
- [ ] Every response carried a durable evidence status.
- [ ] `verify_integrity()` returns valid.
- [ ] Node count matches N, accounting for retained-window bounds.

**Fails if** any accepted response has no record.

### T2 — Commit before emission

- [ ] For non-streaming: the record exists before the response is observable to the client.
- [ ] For streaming: the terminal marker never appears without a committed terminal summary.

**Fails if** a client can observe a completed call with no durable record.

### T3 — Evidence replay

- [ ] Stop the gateway. Reopen the WAL in a separate process.
- [ ] The chain reconstructs and verifies.
- [ ] Node count matches what was written.

**Fails if** replay cannot reconstruct, or verification fails on an untampered file.

### T4 — Proof verification against an independent root

- [ ] Retrieve an inclusion proof for a known record.
- [ ] Obtain the trusted root through a channel that does not pass through the gateway.
- [ ] Verify with the Python SDK, and again with the TypeScript SDK.
- [ ] Both succeed.
- [ ] A proof for a record not in the tree fails to verify.

**Fails if** a forged or unrelated proof verifies. The negative case is the one that matters.

### T5 — Upstream failure

Point the gateway at an upstream that returns errors, then at one that hangs.

- [ ] Errors produce durable records of the governed failure.
- [ ] The circuit breaker opens under sustained failure.
- [ ] No unevidenced success is returned.

**Fails if** any upstream failure yields a success response, or a governed outcome with no record.

### T6 — Rate-limit backend failure

Stop Redis mid-run.

- [ ] Requests fail closed with 503.
- [ ] `aegis_ratelimit_backend_errors_total` increments.
- [ ] No request is served unlimited.
- [ ] Recovery is clean when Redis returns.

**Fails if** the gateway serves traffic without limiting. This is the single most important failure test in the list: a limiter that fails open under pressure is worse than no limiter, because it is trusted.

### T7 — Storage failure

Fill the WAL volume, or make it read-only.

- [ ] Commits fail and requests are refused with 503.
- [ ] No response is returned without a durable record.
- [ ] `aegis_audit_commit_errors_total` increments.
- [ ] Recovery is clean once space is restored.

**Fails if** any response is served after a commit failure.

### T8 — Single-writer enforcement

Start a second process against the same WAL path.

- [ ] It refuses with `WalWriterConflictError`.
- [ ] The first writer is unaffected.
- [ ] The existing chain still verifies.

**Fails if** two writers coexist on one path.

### T9 — Key rotation

Follow [Key Rotation Runbook](../operations/KEY_ROTATION_RUNBOOK.md).

- [ ] Rotation completes without dropping traffic.
- [ ] Records signed before rotation still verify with the retired key.
- [ ] Records after rotation verify with the new key.
- [ ] The retired key is retained.

**Fails if** pre-rotation records become unverifiable. Verify this explicitly; it is easy to assume and expensive to discover later.

### T10 — Backup and restore

Follow [Backup and Restore](../operations/BACKUP_RESTORE.md).

- [ ] A backup is taken without corrupting the active WAL.
- [ ] Restore into a clean environment reproduces the chain.
- [ ] Restored chain verifies, and node count matches.
- [ ] Time from decision to verified restore is recorded.

**Fails if** the restored chain does not verify, or the procedure needed steps not in the runbook. Record the missing steps either way — that is the most valuable output of the test.

### T11 — Rollback

Follow [Rollback Runbook](../operations/ROLLBACK_RUNBOOK.md).

- [ ] Rollback to a prior digest succeeds.
- [ ] WALs are preserved.
- [ ] Post-rollback integrity verifies.

**Fails if** rollback loses or invalidates evidence.

### T12 — Posture observability

- [ ] `aegis_security_enforcement_mode` reads `1` on every replica.
- [ ] Starting one replica in development mode is detected by your alerting within the window you specify.

**Fails if** a development-mode replica can run unnoticed.

### T13 — Bounds

- [ ] Oversized bodies are rejected.
- [ ] Stream bounds terminate long streams without emitting an unevidenced terminal marker.
- [ ] Analysis queue saturation rejects enrichment without failing governed calls.

### T14 — Forensic export

- [ ] Export produces a bundle within requested bounds.
- [ ] Unbounded and empty requests are rejected.
- [ ] `VERIFY.sh` passes.
- [ ] Proofs verify against an independent root.
- [ ] `audit:export` is required and `audit:read` alone is insufficient.

## 5. Infrastructure checklist

Independent of the functional tests:

- [ ] **Ingress:** TLS terminated, client authentication decided, request size limits aligned with `AEGIS_MAX_REQUEST_BODY_BYTES`.
- [ ] **Storage:** power-loss protection confirmed with the vendor, capacity planned for growth, snapshots configured.
- [ ] **Secrets:** signing key in a secret manager or HSM, never in an image or environment file committed anywhere.
- [ ] **Container:** runs non-root with a read-only root filesystem, all capabilities dropped, image pinned by digest.
- [ ] **Network:** NetworkPolicy enforced by the CNI — verified, not assumed — with ingress and egress peers populated.
- [ ] **Monitoring:** alerts firing on the signals in [Monitoring and Alerting](../operations/MONITORING_ALERTING.md).
- [ ] **Logs:** no payloads, no credentials.

## 6. Measurements to record

Record what you measured and the conditions. Do not generalise beyond them.

| Measure | Note |
| --- | --- |
| p50/p95/p99 added latency | Distinguish `total` from `forward` stage |
| p99 evidence commit lag | The number that matters for evidence |
| WAL growth per 1,000 calls | Drives retention cost |
| Storage `fsync` latency | Usually the binding constraint |
| Peak memory under concurrent streams | Scales with concurrency |
| Throughput at which fail-closed engaged | This is a bound you found, not a capacity claim |

**Your measurements describe your environment on the day you took them.** They are not a capacity claim about the software, and they should not be quoted as one.

## 7. Pilot report

Produce a dated record containing:

1. **Scope:** commit or digest, environment, workload, window, data used.
2. **Configuration:** posture, signer, storage, Redis, controls enabled.
3. **Results:** T1–T14 pass or fail, with evidence for each.
4. **Measurements:** as above, with conditions.
5. **Failures and surprises:** what broke, what the runbooks missed.
6. **Gaps:** what the pilot did not test.
7. **Open items:** what remains unknown, marked `[UNKNOWN_MISSING_PRIMARY_SOURCE]` rather than inferred.
8. **Recommendation:** proceed, proceed with conditions, or stop — with reasons.

Sections 5 and 6 are the ones a reviewer will read most closely. A pilot report with no surprises usually means the failure tests were not run.

## 8. What a passing pilot does not establish

- **Not certification.** No independent assessor was involved.
- **Not compliance.** See [Compliance Mapping](../compliance/COMPLIANCE_MAPPING.md).
- **Not a service level.** No SLO or SLA exists.
- **Not production readiness.** It establishes behaviour in your pilot environment.
- **Not legal admissibility.** A judicial determination.
- **Not a capacity claim.** You measured your workload, not the software's limits.
- **Not a security audit.** Functional verification is not adversarial review.

---

**Related:** [Enterprise Readiness](ENTERPRISE_READINESS.md) · [Procurement Checklist](PROCUREMENT_CHECKLIST.md) · [Deployment Profiles](../operations/DEPLOYMENT_PROFILES.md) · [Backup and Restore](../operations/BACKUP_RESTORE.md) · [Key Rotation Runbook](../operations/KEY_ROTATION_RUNBOOK.md) · [Rollback Runbook](../operations/ROLLBACK_RUNBOOK.md) · [Boundaries](../BOUNDARIES.md)
