# Deployment Profiles

**Audience:** platform engineers, SRE, security reviewers.
**Scope:** four deployment shapes, what each requires, and what evidence each produces.
**Boundary:** a profile describes required controls. Meeting them is necessary, not sufficient: every profile above local development requires target acceptance of storage, network, identity and key custody that this repository cannot verify. See [Boundaries](../BOUNDARIES.md).

---

## Choosing a profile

| Profile | Use for | Evidence produced | Never use for |
| --- | --- | --- | --- |
| [Local development](#1-local-development) | Reading code, running tests, trying the API | None that should be relied on | Anything with real data |
| [Single-node hardened](#2-single-node-hardened) | Pilots, one-tenant deployments, air-gap precursor | One verifiable chain | Multi-replica availability |
| [Kubernetes](#3-kubernetes) | Multiple replicas behind an ingress | One independent chain per replica | A single global timeline |
| [Air-gapped](#4-air-gapped) | Isolated networks | One verifiable chain, no external anchoring | Anything needing live upstream providers |

**None of these profiles produces cross-replica global ordering.** That does not exist in this system at any scale. See [DOC-01 §8](../institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md).

---

## 1. Local development

**Purpose:** evaluation only. This profile deliberately disables controls so you can run the gateway without a signer, Redis, or a real provider.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e .

export AEGIS_SECURITY_ENFORCEMENT_MODE=development
export AEGIS_DEBUG_MODE=true
export AEGIS_AUTH_DISABLED=true
export AEGIS_BACKEND_URL=http://127.0.0.1:9999   # a mock upstream
aegis
```

| Aspect | State |
| --- | --- |
| Authentication | Disabled |
| Signing | Ephemeral fallback key; signatures are not meaningful |
| Rate limiting | In-memory, per process |
| Durable evidence | Not required |
| Kernel controls | Not required |
| `aegis_security_enforcement_mode` | `0` |

**Evidence boundary:** records produced here are not evidence. The signing key is ephemeral, so nothing verifies after restart, and no control that would make a record trustworthy is enforced. Do not carry a WAL from this profile into any other.

**Fail-closed requirements:** none. That is the point, and it is why this profile must never see real data.

---

## 2. Single-node hardened

**Purpose:** a pilot or a production single-tenant deployment. One process, one WAL, one chain.

**Required controls:**

| Control | Requirement | Why |
| --- | --- | --- |
| `AEGIS_SECURITY_ENFORCEMENT_MODE` | `strict` | Enables the startup invariants below |
| Signing | `AEGIS_SIGNING_KEY` (≥32 bytes) or `AEGIS_PKCS11_LIBRARY_PATH` | Strict mode refuses to start without one |
| Authentication | `AEGIS_API_KEYS` with an explicit principal mapping per key | Strict mode requires the mapping |
| Identity HMAC | `AEGIS_AUTH_IDENTITY_HMAC_KEY` ≥32 bytes | Quota pseudonyms |
| Rate limiting | Redis; `AEGIS_RATE_LIMIT_BACKEND=redis` | Strict mode rejects other backends |
| Durable evidence | `AEGIS_REQUIRE_DURABLE_EVIDENCE=true` | Refuses to serve unevidenced traffic |
| Kernel | `AEGIS_REQUIRE_SECCOMP=true`, `AEGIS_REQUIRE_LSM=true` | Startup verifies both are active |
| Workers | `AEGIS_WORKERS=1` | Multiple workers share one WAL path and the second fails closed |
| Storage | Power-loss-protected device; see [Storage Requirements](STORAGE_REQUIREMENTS.md) | `fsync` is not power-loss durability without it |
| TLS | Terminated at the gateway or a trusted ingress | Not provided by the gateway by default |

**Fail-closed behaviour to expect:** the process refuses to bind if any strict invariant is unmet. That is correct. Read the error rather than relaxing the setting that produced it.

**Evidence boundary:** one verifiable chain, valid under the operator-trust assumption. Backups, retention, and key custody are yours. No external anchoring unless RFC 3161 or S3 Object Lock is configured, and neither is a guarantee of external immutability.

---

## 3. Kubernetes

**Purpose:** multiple replicas behind an ingress, each producing its own chain.

Use the chart at `deploy/helm/`. It renders a `StatefulSet` with one volume claim per replica.

**Required controls beyond the single-node list:**

| Control | Requirement | Why |
| --- | --- | --- |
| Workload kind | `StatefulSet` with `volumeClaimTemplates` | Each replica needs its own WAL path |
| `persistence.accessMode` | `ReadWriteOnce` or `ReadWriteOncePod` | A shared-write volume reintroduces the multi-writer fork |
| `aegis.workers` | `"1"` — pinned by `values.schema.json` | Install-time rejection rather than a runtime crash |
| Pod security context | `runAsNonRoot`, `seccompProfile: RuntimeDefault` | Chart defaults; overriding them silently removes the control |
| Container security context | `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `drop: [ALL]` | Chart defaults |
| NetworkPolicy | `networkPolicy.enabled: true`, with `ingressFrom` and `egressTo` supplied | Ships default-deny with empty peers; you must populate them |
| CNI | Must enforce NetworkPolicy | The manifest is inert otherwise |
| Redis | External, HA, `rediss://` with certificate verification | Not installed by the chart |

**Migrating from the superseded shared-PVC chart** is not an upgrade. The workload kind changes and the claim names do not overlap, so nothing adopts the old volume. Follow [DOC-04 §6.4](../institutional/DOC-04_OPERATIONS_PLAYBOOK.md) before upgrading.

**Evidence boundary:** N replicas produce N independent chains. There is no cross-pod ordering or atomicity. A query spanning replicas is a merge you perform and justify, not a guarantee the system provides. Scaling down retains the departing replica's claim, so its evidence survives.

---

## 4. Air-gapped

**Purpose:** isolated networks with no outbound internet.

**What works:** the gateway, the WAL, signing with a local key or HSM, MMR proofs, forensic export, the dashboard, and local Redis.

**What does not work, and must be disabled explicitly:**

| Capability | Why it fails | Action |
| --- | --- | --- |
| RFC 3161 timestamping | Needs a reachable TSA | Leave `AEGIS_TSA_URL` unset |
| S3 Object Lock archival | Needs an object store | Leave `AEGIS_S3_ARCHIVE_ENABLED=false` |
| SIEM HTTP export | Needs a reachable collector | Leave `AEGIS_SIEM_URL` unset, or point it inside the enclave |
| Webhook alerts | Needs a reachable endpoint | Leave `AEGIS_WEBHOOK_URL` empty |
| Upstream model provider | Needs the provider | Point `AEGIS_BACKEND_URL` at an in-enclave model service |
| `gh attestation verify`, `cosign verify` | Need the transparency log and GitHub | Verify artifacts **before** transfer, at the boundary |

**Supply-chain requirement:** verify every artifact outside the enclave and record the result, because you cannot verify inside it. Transfer the verification record with the artifact. `python -m pip install --require-hashes -r requirements.lock` works offline from a pre-populated wheelhouse.

**Fail-closed requirements:** the same strict invariants as single-node hardened. Do not relax `AEGIS_REQUIRE_DURABLE_EVIDENCE` because the enclave "is already isolated" — isolation is a network property and says nothing about evidence integrity.

**Evidence boundary:** no external anchoring is possible, so every record's time and existence rest entirely on the enclave's own clock and custody. That is a materially weaker provenance position than a connected deployment, and it should be stated in any assessment rather than glossed as equivalent.

---

## Cross-profile checklist

Before any profile above local development goes live:

- [ ] `aegis_security_enforcement_mode` reads `1` on every replica.
- [ ] One writer per WAL path, verified — not assumed.
- [ ] Storage confirmed to honour `fsync`; see [Storage Requirements](STORAGE_REQUIREMENTS.md).
- [ ] Signing key custody documented, and rotation rehearsed per [Key Rotation Runbook](KEY_ROTATION_RUNBOOK.md).
- [ ] Backup taken and a restore rehearsed per [Backup and Restore](BACKUP_RESTORE.md).
- [ ] Alerts firing on the signals in [Monitoring and Alerting](MONITORING_ALERTING.md).
- [ ] Rollback path rehearsed per [Rollback Runbook](ROLLBACK_RUNBOOK.md).
- [ ] Retention decided and documented per [Data Retention](../privacy/DATA_RETENTION.md).

---

**Related:** [Deployment Guide](../../DEPLOYMENT_GUIDE.md) · [Storage Requirements](STORAGE_REQUIREMENTS.md) · [Monitoring and Alerting](MONITORING_ALERTING.md) · [Backup and Restore](BACKUP_RESTORE.md) · [Security Controls](../security/SECURITY_CONTROLS.md) · [DOC-04](../institutional/DOC-04_OPERATIONS_PLAYBOOK.md)
