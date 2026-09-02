# Backup and Restore

**Audience:** operators, SRE, anyone responsible for evidence continuity.
**Scope:** what to back up, how to verify a backup is usable, and how to rehearse a restore.
**Boundary:** procedures here are written against the repository's storage model. None is verified against a live cluster in this repository; each requires rehearsal and acceptance on your target. A backup that has never been restored is a hypothesis.

---

## 1. What must be backed up

Backing up the WAL alone produces an unverifiable archive. Five things travel together.

| Item | Where | Without it |
| --- | --- | --- |
| **WAL and every rotated segment** | `AEGIS_WAL_PATH` and its `.1`, `.2`, … siblings | No evidence at all |
| **Signing key, or a reference to it** | Secret manager, HSM slot, or `AEGIS_SIGNING_KEY` | Records exist but no signature verifies |
| **Retired signing keys** | Your key archive | Records signed before a rotation become unverifiable |
| **Trusted MMR roots** | Wherever you pinned them | Proofs verify only against a root supplied by the gateway, which is not independent |
| **Configuration** | Your config management | You cannot reconstruct which controls were active when the records were written |

**Retired keys are the item most often missed.** Rotation is routine; destroying the retired key converts every record signed under it into an unverifiable blob. Retain retired keys under the same custody as active ones, for at least as long as the records they signed.

Forensic export bundles, if produced, are sensitive evidence and belong under the same controls. See [Forensic Export](../api/FORENSIC_EXPORT.md).

## 2. Backup constraints particular to this system

**Take the backup from a quiesced writer or a consistent snapshot.** The WAL is appended under a lock with `flush` then `fsync` per record. A file-level copy taken mid-append can capture a partial final line. That is recoverable — replay stops at the first malformed line and reports `wal_corrupt` — but it truncates the chain at that point, so you lose everything after it.

Preferred, in order:

1. Filesystem or volume snapshot with the writer briefly quiesced.
2. Copy while the writer is stopped.
3. Copy of rotated segments only, which are no longer being appended to, plus a separate handling decision for the active segment.

**Do not copy the active WAL with a naive `cp` from a running writer and treat it as complete.**

**Back up per replica.** Each replica owns its own WAL path and its own chain. A backup of replica 0 is not a backup of replica 1. Under the Helm chart each claim is `wal-data-<release>-<chart>-<ordinal>`.

## 3. Backup procedure

```bash
# Per replica. Adjust paths to your deployment.
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="/backup/aegis/${REPLICA}/${STAMP}"
mkdir -p "$DEST"

# 1. Quiesce or snapshot. Method depends on your storage; the point is that
#    the active segment must not be mid-append while it is read.

# 2. Copy WAL and all rotated segments, preserving mode and timestamps.
cp -a /data/aegis.wal.jsonl* "$DEST/"

# 3. Record the configuration that produced these records.
env | grep '^AEGIS_' | grep -vi 'key\|secret\|pin\|password' > "$DEST/config.env"

# 4. Record the signing key identifier — never the key material.
echo "signing_key_id=${AEGIS_SIGNING_KEY_ID:-[UNKNOWN_MISSING_PRIMARY_SOURCE]}" >> "$DEST/config.env"

# 5. Digest everything.
( cd "$DEST" && sha256sum ./* > SHA256SUMS )
```

Never write key material into the backup directory. Back up the *reference*; the key itself stays under its own custody with its own access controls.

## 4. Verifying a backup

A backup is verified when it has been restored and its chain checked. Anything less is a file that exists.

```bash
# 1. Bytes intact.
( cd "$DEST" && sha256sum --check --strict SHA256SUMS )

# 2. Chain verifies. Run against a COPY, never the live path — opening a
#    ledger takes the advisory lock, and pointing it at production would
#    contend with the running writer.
python - <<'PY'
from aegis.core.crypto_audit import CryptographicAuditLedger
led = CryptographicAuditLedger(
    persistence_path="/restore/scratch/aegis.wal.jsonl",
    signing_key="<the key that signed these records>",
)
ok, idx = led.verify_integrity()
print("nodes:", len(led.chain), "valid:", ok, "first bad index:", idx)
led.close()
PY
```

`verify_integrity()` returning `True` establishes that the chain links and signatures are consistent under the key you supplied. It does not establish that the archive is complete: a backup truncated at record 500 of 1,000 verifies perfectly for those 500. Check the node count against what you expect.

## 5. Restore

```bash
# 1. Stop the writer for the target replica. A running writer holds the lock
#    and a second opener fails closed with WalWriterConflictError.

# 2. Preserve whatever is currently on the volume before overwriting it.
mv /data/aegis.wal.jsonl "/data/aegis.wal.jsonl.pre-restore-$(date -u +%s)"

# 3. Restore.
cp -a "$DEST"/aegis.wal.jsonl* /data/

# 4. Verify before starting the writer.
#    (Use the verification block in section 4 against /data.)

# 5. Start the writer and confirm posture and integrity.
curl -s localhost:8080/v1/audit/integrity
curl -s localhost:8080/metrics | grep aegis_security_enforcement_mode
```

**Never restore into a path a live writer holds.** The advisory lock will refuse the second opener, which is the guard working correctly; forcing past it by killing the writer mid-append is how you corrupt the file you were trying to protect.

**Restore to the matching replica ordinal.** Restoring replica 2's WAL onto replica 0 does not merge chains; it replaces one independent chain with another and makes the ordinal's history discontinuous.

## 6. Restore drill

Rehearse on a schedule you choose and record the result. An unrehearsed restore procedure is a document, not a capability.

A drill is complete when you have recorded:

- [ ] Backup age used, and how it was taken.
- [ ] `SHA256SUMS` check result.
- [ ] Node count restored versus node count expected.
- [ ] `verify_integrity()` result, including the first bad index if any.
- [ ] Whether the signing key needed was available without escalation.
- [ ] Whether a retired key was needed, and whether it was still retained.
- [ ] Wall-clock time from decision to verified restore.
- [ ] What broke, and what was missing from this document.

The last two are the point of the drill. A drill that goes perfectly and teaches nothing usually means the scenario was too easy.

## 7. Retention

Retention is an operator decision, not a product default. The gateway does not delete WAL segments on a schedule and has no retention enforcement.

Deciding retention needs: your regulatory obligations, your storage budget, the value of old evidence to you, and how long you keep retired signing keys — because evidence outliving its key is unverifiable evidence.

See [Data Retention](../privacy/DATA_RETENTION.md). Retention obligations under any regulation are a determination for you and your counsel; this repository makes none.

## 8. What backup does not establish

- **Not a disaster-recovery plan.** No RPO or RTO is defined or measured here.
- **Not proof of completeness.** A verifying chain may still be a truncated one.
- **Not external immutability.** A backup is a copy under your control, alterable by anyone with access to it.
- **Not custody.** Copying a file does not establish who held it or that it was unmodified between copies. See [ISO/IEC 27037 Technical Inputs](../compliance/ISO_27037_TECHNICAL_INPUTS.md).
- **Not a substitute for archival.** S3 Object Lock archival of rotated segments is a separate, configuration-dependent path.

---

**Related:** [Storage Requirements](STORAGE_REQUIREMENTS.md) · [Key Rotation Runbook](KEY_ROTATION_RUNBOOK.md) · [Rollback Runbook](ROLLBACK_RUNBOOK.md) · [Incident Response](../security/INCIDENT_RESPONSE.md) · [Data Retention](../privacy/DATA_RETENTION.md) · [DOC-04](../institutional/DOC-04_OPERATIONS_PLAYBOOK.md)
