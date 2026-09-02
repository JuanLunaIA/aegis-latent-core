# Incident Response

**Audience:** operators, security responders, incident commanders.
**Scope:** detecting, containing, and recovering from a security or evidence-integrity incident in a deployment of this gateway.
**Boundary:** this is a technical runbook. It is not an incident response plan for your organisation, it does not satisfy a regulatory notification obligation, and it makes no determination about whether an incident is reportable. Those are decisions for you and your counsel.

---

## 0. The rule that overrides the rest

**Preserve evidence before you remediate.**

The instinct under pressure is to restart the process, rotate the key, and clear the disk. In a system whose product is evidence, each of those destroys the record of what happened. A restarted process loses its in-memory chain and MMR state. A rotated key makes prior signatures unverifiable without the retired key. A cleared disk is unrecoverable.

Take a snapshot first. It costs minutes. Skipping it costs the investigation.

## 1. Detection signals

| Signal | Source | Suggests |
| --- | --- | --- |
| `aegis_security_enforcement_mode` reads `0` in a governed environment | Metrics | A process started in development mode: auth, durable evidence and kernel controls are relaxed |
| `WalWriterConflictError` at startup | Logs | Two writers were pointed at one WAL path |
| `aegis_audit_commit_errors_total` rising | Metrics | Evidence commits are failing; responses may be refused |
| `wal_corrupt` fault state | `/v1/audit/health` | Replay stopped at a malformed line |
| `verify_integrity()` returns invalid | Audit API | Chain linkage or signature mismatch |
| `aegis_waf_blocks_total` spike, or crescendo detections | Metrics | Coordinated probing or injection attempts |
| `aegis_ratelimit_backend_errors_total` rising | Metrics | Redis degraded; limiting may be failing closed at 503 |
| `aegis_circuit_breaker_state` open | Metrics | Upstream failing |
| Unexpected `audit:export` calls | Access logs | Possible evidence exfiltration |
| `aegis_native_stream_wal_errors_total` rising | Metrics | Auxiliary WAL failing; JSONL remains authoritative, so this is a degradation, not evidence loss |

Alert thresholds and rules: [Monitoring and Alerting](../operations/MONITORING_ALERTING.md).

## 2. Severity

Classify by evidence impact, not by noise.

| Severity | Definition | Examples |
| --- | --- | --- |
| **SEV-1** | Evidence integrity is in question, or a signing key may be compromised | Integrity verification fails; key material exposed; two writers confirmed on one path |
| **SEV-2** | Evidence is being lost or refused | Commit errors sustained; WAL storage full; corruption detected |
| **SEV-3** | A control is degraded but evidence is intact | Redis down; WAF bypass suspected; development mode found in a governed environment |
| **SEV-4** | Suspicious activity without confirmed impact | Probing detected and blocked; anomalous access patterns |

A SEV-3 that persists becomes SEV-2. Do not let a degraded control sit.

## 3. Containment

Containment steps that preserve evidence, in order.

**Step 1 — Snapshot before touching anything.**

```bash
# Replace with your paths. Do this on every replica, not just the suspect one.
INCIDENT="/secure/incident-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$INCIDENT"

# WAL and all rotated segments, preserving mode and timestamps.
cp -a /data/aegis.wal.jsonl* "$INCIDENT/"

# Process and host state.
ps auxww > "$INCIDENT/processes.txt"
ls -la --time-style=full-iso /data > "$INCIDENT/data-listing.txt"

# Digest the snapshot so later handling is checkable.
( cd "$INCIDENT" && sha256sum * > SHA256SUMS )
```

Record who took the snapshot, when, from which host, and where it is stored. That record is the start of the custody chain; see [ISO/IEC 27037 Technical Inputs](../compliance/ISO_27037_TECHNICAL_INPUTS.md).

**Step 2 — Stop the bleeding without destroying state.**

| Situation | Do | Do not |
| --- | --- | --- |
| Credential compromise suspected | Revoke the specific API key; leave the process running | Rotate the signing key yet |
| Evidence integrity in question | Drain traffic at the ingress; leave the process running | Restart the gateway |
| WAL storage full | Extend the volume, or rotate and archive | Delete segments |
| Two writers confirmed | Stop the *later* writer; identify how it started | Remove the advisory lock |
| Upstream compromise suspected | Block egress at the network layer | Change `AEGIS_BACKEND_URL` before recording the current value |

**Step 3 — Verify integrity against the snapshot, not the live file.**

```bash
python - <<'PY'
from aegis.core.crypto_audit import CryptographicAuditLedger
led = CryptographicAuditLedger(persistence_path="/secure/incident-.../aegis.wal.jsonl")
ok, idx = led.verify_integrity()
print("valid:", ok, "first bad index:", idx)
led.close()
PY
```

A `False` result with an index tells you where the chain diverges. That index is the investigation's starting point, not its conclusion: corruption from a partial write looks different from deliberate modification, and the surrounding records tell you which.

## 4. Key compromise

Signing-key compromise is the one case where speed beats caution, because every record signed after the compromise is suspect.

1. Snapshot first, as above. You need the pre-rotation state.
2. Identify the exposure window: when the key was created, when exposure began, when it was contained. Records outside the window keep their prior status.
3. Rotate per [Key Rotation Runbook](../operations/KEY_ROTATION_RUNBOOK.md). **Retain the retired key** — destroying it makes prior records unverifiable, which converts a contained incident into permanent evidence loss.
4. Record the rotation in the incident log with the exact timestamp, so record status can be partitioned by signing epoch.
5. Re-verify a sample of records signed before the window using the retired key.

For HMAC signing specifically: the key is symmetric, so anyone who held it could have produced valid signatures. Records signed within the exposure window cannot be attributed to the gateway on cryptographic grounds alone. Say so plainly in the incident record rather than implying otherwise.

## 5. Evidence preservation for the whole incident

Beyond the initial snapshot:

- **Do not edit any file under `evidence/`.** Those are frozen records. Add a new dated record instead; see [Evidence Governance](../institutional/EVIDENCE_GOVERNANCE.md).
- **Export a forensic bundle** for the affected window while the records are still retained in memory: `POST /v1/audit/forensics/export`. Retained-window bounds mean this is time-sensitive. See [Forensic Export](../api/FORENSIC_EXPORT.md).
- **Capture the configuration** the process was actually running, not the configuration you believe it was running. `aegis_security_enforcement_mode` tells you which mode it loaded.
- **Preserve logs at the ingress and in the SIEM**, which hold the request-side view the gateway does not.

## 6. Recovery

Recover only after the snapshot exists and integrity has been assessed.

| Fault | Recovery | Reference |
| --- | --- | --- |
| WAL corruption | Restore from backup, or accept a truncated chain with the divergence point recorded | [Backup and Restore](../operations/BACKUP_RESTORE.md) |
| Two writers | Fix the topology; per-replica volumes, one worker per pod | [DOC-04 §6.4](../institutional/DOC-04_OPERATIONS_PLAYBOOK.md) |
| Bad release | Roll back by digest, preserving WALs | [Rollback Runbook](../operations/ROLLBACK_RUNBOOK.md) |
| Redis loss | Restore the backend; requests fail closed at 503 until it returns | [Backpressure Runbook](../operations/BACKPRESSURE_RUNBOOK.md) |
| Development mode in production | Correct configuration and restart; treat all traffic in that window as ungoverned | [Deployment Profiles](../operations/DEPLOYMENT_PROFILES.md) |

**A truncated chain is a legitimate outcome.** If the chain diverges at index *n*, records 0..*n*-1 remain verifiable. Record the divergence, keep both segments, and do not attempt to repair the file by hand — a hand-edited WAL is worth less than a truncated one.

## 7. Communication boundaries

What this runbook does and does not authorise you to say:

- **Technical facts you can state:** what the integrity check returned, which records fall inside an exposure window, what was preserved and when, which controls were degraded.
- **Determinations you cannot make from this document:** whether the incident is reportable under any regulation, whether evidence remains legally admissible, whether a data breach occurred as a legal matter, whether an individual is affected under a privacy statute.

Route those to counsel and to your organisation's incident process. The technical record supports a determination; it is not the determination. See [Boundaries](../BOUNDARIES.md).

If the incident involves a vulnerability in this software rather than in your deployment, report it privately: [Vulnerability Disclosure](VULNERABILITY_DISCLOSURE.md).

## 8. Post-incident review

Produce a dated record under `evidence/` containing:

- Timeline in UTC, from first signal to resolution.
- What the evidence showed, including integrity results with indices.
- Which controls detected the incident, and which should have but did not.
- Exposure windows, stated precisely.
- What was preserved, where it is, and its digests.
- Corrective actions, each with an owner.
- What remains unknown, marked `[UNKNOWN_MISSING_PRIMARY_SOURCE]` rather than inferred.

The last item is the one most often skipped and most often needed later.

---

**Related:** [Security Controls](SECURITY_CONTROLS.md) · [Threat Model](THREAT_MODEL.md) · [Vulnerability Disclosure](VULNERABILITY_DISCLOSURE.md) · [Backup and Restore](../operations/BACKUP_RESTORE.md) · [Key Rotation Runbook](../operations/KEY_ROTATION_RUNBOOK.md) · [Monitoring and Alerting](../operations/MONITORING_ALERTING.md)
