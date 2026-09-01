# DOC-04 — Operational Engineering Playbook and High-Availability Runbooks

**Document ID:** `DOC-04`
**Title:** Operational Engineering Playbook and High-Availability Runbooks
**Source baseline:** checked-out source metadata is synchronized at `v4.0.2`; external tag, release, registry, OCI, deployment, and acceptance claims require independent readback
**Historical evidence scope:** operational findings and retained evidence through 2026-08-20 UTC remain `v3.1.0`-era records unless explicitly revalidated against the current source
**Canonical language:** US English
**Primary owners:** Platform/SRE owner and release owner
**Required reviewers:** Security owner; evidence custodian; privacy/legal owner when retention, legal hold, or regulated data is affected

## 1. Purpose, authority, and claim controls

This playbook governs startup, strict-mode acceptance, WAL-stall response, signing-key rotation, backup and restore, release rollback, monitoring, and multi-replica operation for the repository baseline. It consolidates the production code, deployment manifests, tests, existing runbooks, formal record, and retained JSON evidence listed in Section 3. It does not create an availability SLO, certify a target environment, establish legal admissibility, or supply an on-call service.

The status vocabulary is inherited without modification from `docs/CLAIMS_MATRIX.md:16-24`: `IMPLEMENTED` means source and regression tests implement the behavior under declared conditions; `MEASURED` means a reproducible artifact exists for a named bounded experiment; `CONFIGURATION-DEPENDENT` means the result depends on deployment controls; `ROADMAP` means the capability is incomplete, unmeasured, a stub, or future work; and `LEGAL-REVIEW-REQUIRED` means the statement could be interpreted as legal, regulatory, certification, procurement, or contractual. Operational acceptance is blocked whenever the source locator changes, a named regression fails, a prerequisite is absent, the environment boundary changes without a rerun, or stronger language is used than the claims matrix permits (`docs/CLAIMS_MATRIX.md:53-63`).

> **Operational boundary:** Aegis waits for its configured authoritative evidence commit before returning a governed successful response. This is an application-visible boundary, not proof of power-loss durability for a filesystem, CSI driver, controller cache, cloud volume, distributed mount, or backup system. The repository does not establish globally ordered multi-replica evidence, multi-region consensus, or a production availability SLO.

## 2. Roles, decision rights, and escalation

| Role | Decision right | Required action during an incident |
|---|---|---|
| Incident commander | Stop traffic, freeze changes, choose recovery branch, and coordinate communications | Record incident scope, UTC times, affected replicas, request IDs, release identity, and decision log. |
| Platform/SRE owner | Runtime, ingress, Redis, storage, probes, orchestration, backups, and restore execution | Preserve evidence before mutation; operate only approved deployment controls; verify recovery observations. |
| Security owner | Signer, key custody, kernel posture, suspected compromise, and integrity interpretation | Approve key rotation or rollback across signer versions; determine isolation and credential-revocation actions. |
| Evidence custodian | WAL preservation, chain verification, retention, custody, and restore acceptance | Retain original bytes and metadata; reject destructive repair or provenance-unknown append paths. |
| Release owner | Artifact identity, provenance, regression gate, claim status, and rollback release selection | Approve immutable release identity and close claim drift after the incident. |
| Privacy/legal owner | Legal hold, data-subject handling, retention exceptions, notification, and regulated-data decisions | Review any deletion, disclosure, jurisdictional transfer, or legal-admissibility statement. |
| Formal-methods reviewer | Interpretation of bounded TLA+, Lean, and Z3 records | Prevent finite-model results from being represented as implementation or infrastructure proofs. |

Escalate immediately to the incident commander, security owner, evidence custodian, and release owner when a governed success lacks durable evidence, integrity verification fails, signing material may be exposed, a required signer is unavailable, a WAL cannot be preserved, or release identity cannot be established. Add the privacy/legal owner when prompts, responses, customer identifiers, retention, legal hold, or external notification may be affected. A repository document does not imply staffed 24/7 support (`docs/CLAIMS_MATRIX.md:50`).

## 3. Source and evidence register

| Source | Exact repository locator | Use and boundary |
|---|---|---|
| Claim control | `docs/CLAIMS_MATRIX.md:16-24,53-63` | Status definitions, approved wording, and falsification protocol. |
| Deployment contract | `DEPLOYMENT_GUIDE.md:9-39,73-99,127-144` | Strict prerequisites, lifecycle, storage, health, and go-live gates. |
| Operator guidance | `docs/PLATFORM_OPERATOR_GUIDE.md:10-115` | Topology, storage, telemetry, backup, rollback, and role boundaries. |
| Runtime settings | `aegis/config.py:644-686` | Backend URL/auth posture and strict invariant validation. |
| Startup and probes | `aegis/proxy/app.py:630-725,937-1002,1368-1401` | Lifespan checks, LSM/Seccomp sequence, liveness, readiness, and CLI binding. |
| Evidence failure path | `aegis/proxy/app.py:826-856,1058-1066,1283-1289` | Durable-commit and Redis failures return `503`. |
| Runtime metrics | `aegis/core/observability.py:41-187` | Exact metric names and optional-export boundary. |
| Burn-rate rules | `deploy/helm/templates/prometheusrule.yaml:1-254`; `aegis/core/slo_alerting.py:117-211` | Existing window pairs and metric expressions; disabled by default in Helm. |
| Helm deployment | `deploy/helm/values.yaml:4-178`; `deploy/helm/templates/deployment.yaml:7-147`; `deploy/helm/templates/pvc.yaml:1-17`; `deploy/helm/templates/pdb.yaml:1-13` | Replicas, probes, security context, PVC, disruption budget, and topology constraints. |
| Compose deployment | `deploy/docker/docker-compose.yml:1-68`; `deploy/docker/Dockerfile:5-98` | Strict local-container startup contract and image entry point. |
| WAL stall runbook/tool | `docs/operations/BACKPRESSURE_RUNBOOK.md:10-59`; `tools/benchmarks/run_backpressure_stall.py:58-212` | Local injected `fsync` seam and recovery criteria. |
| WAL stall evidence | `evidence/execution_2026-08-20/backpressure_stall_report.json:1-45` | In-tree bounded measurement: 2,500 offered requests with a 2 ms injected delay. |
| Keyring implementation | `aegis_server/crypto/keyring.py:70-242`; `aegis_server/crypto/__init__.py:90-98` | Enterprise signer snapshot validation/reload and signer factory wiring. |
| Key rotation test/tool/evidence | `tests/test_keyring_rotation.py`; `tools/benchmarks/run_key_rotation.py:60-178`; `evidence/execution_2026-08-20/key_rotation_report.json:1-25` | Unit contract and three local signer instances; no orchestrator or secret-manager acceptance. |
| Backup/restore | `aegis/core/wal_backup.py:69-360`; `tests/test_wal_backup.py:43-227` | Verified backup/restore library and regression coverage. No repository CLI is provided. |
| Rollback | `docs/operations/ROLLBACK_RUNBOOK.md:10-127` | Preservation, artifact selection, execution boundary, and closeout. |
| Multi-replica boundary | `docs/performance/SCALING_GUIDE.md:10-31,57-78`; `tests/test_gossip_wal_sync.py:1-20`; `tests/test_split_brain.py:1-18` | Per-pod evidence guidance; gossip is identified as a stub; fencing is unit-tested, not deployed by the Helm chart. |
| Formal record | `docs/formal/FORMAL_VERIFICATION.md:8-18,20-46`; `specs/aegis_invariants.tla` | Finite commit-before-emission abstraction; no implementation refinement or filesystem proof. |
| Provenance | `evidence/execution_2026-08-20/manifest.json` | Retained source identity, test counts, artifact hashes, and explicit residual risk. |

## 4. Material claims ledger

| Claim ID | Material claim | Status | Exact locator | Assumptions and operational boundary | Falsification criterion | Human-review owner |
|---|---|---|---|---|---|---|
| `DOC04-CLM-001` | Strict application startup validates debug mode, authentication, durable evidence, Redis backend selection, API keys, and a signing path before socket binding. | `IMPLEMENTED` | `aegis/config.py:669-686`; `aegis/proxy/app.py:630-633`; `tests/test_p0_release_gates.py:19-39` | Configuration parsing reached the lifespan and the same settings object is used. This validator alone does not prove Redis reachability, storage durability, or kernel correctness. | Any strict process binds while one listed invariant is absent, or the named regression fails. | Platform/SRE owner |
| `DOC04-CLM-002` | Required LSM and Seccomp posture is enforced during strict startup when the corresponding settings are true. | `CONFIGURATION-DEPENDENT` | `aegis/proxy/app.py:639-664,720-725`; `DEPLOYMENT_GUIDE.md:27-39` | Target kernel, runtime, profile, image, permissions, and admission policy are reviewed. | Startup succeeds in the target environment after the required control is removed, or a negative test does not fail. | Security owner |
| `DOC04-CLM-003` | A mandatory evidence-commit exception rejects the governed request with HTTP `503`, and a distributed limiter backend outage rejects with HTTP `503`. | `IMPLEMENTED` | `aegis/proxy/app.py:826-856,1058-1066,1283-1289`; `tests/test_p0_release_gates.py:42-60` | The request uses the governed proxy route and strict production configuration. | A governed `2xx` is observed after commit failure, or a Redis backend exception opens the request path. | Platform/SRE owner |
| `DOC04-CLM-004` | The in-tree WAL-stall report observed 2,500 durable records, no failures, no missing or duplicate IDs, valid integrity, and p99 commit latency of 836.3514210795984 ms under 10,000 RPS offered load for 0.25 seconds with 2 ms injected `fsync` delay. | `MEASURED` | `evidence/execution_2026-08-20/backpressure_stall_report.json:17-44` | Local Linux/Python environment in the report; deterministic application injection seam; offered load is not accepted capacity. | Rerun with the same declared workload fails its gate, or report identity/workload fields differ without claim revision. | Release owner |
| `DOC04-CLM-005` | The enterprise file-backed HMAC signer validates a complete owner-only snapshot, activates one key, accepts non-expired verification keys, and retains the prior valid snapshot after an invalid reload. | `IMPLEMENTED` | `aegis_server/crypto/keyring.py:70-242`; `tests/test_keyring_rotation.py` | Applies to the enterprise signer factory and compliance-export signing path, not automatically to the proxy WAL signer. | Initial invalid keyring does not fail, an invalid reload replaces the valid snapshot, or overlap verification violates the unit contract. | Security owner |
| `DOC04-CLM-006` | The retained key-rotation artifact observed 2,033 records across three independent local signer instances, both key IDs, no failed commits, and no unverifiable records. | `MEASURED` | `evidence/execution_2026-08-20/key_rotation_report.json:1-24` | Local threads/signers and atomic file replacement only; no Kubernetes, secret manager, clock-skew, process restart, or proxy-WAL integration claim. | The retained artifact fails schema/gate review or a same-boundary rerun fails. | Release owner |
| `DOC04-CLM-007` | Zero-downtime rotation of the proxy WAL signing key across production replicas is not established by this repository. | `ROADMAP` | Proxy construction: `aegis/proxy/app.py:598-608`; enterprise keyring wiring: `aegis_server/crypto/__init__.py:90-98`; boundary: `docs/operations/KEY_ROTATION_RUNBOOK.md:51-65` | The proxy ledger currently receives the static setting/HSM backend rather than the enterprise rotating signer. | A reviewed integration, regressions, and orchestrated acceptance artifact demonstrate proxy-WAL rotation with overlap, restart, delayed replica, and rollback. | Security owner and release owner |
| `DOC04-CLM-008` | The backup manager copies active and archived WAL files, verifies the copy, writes a manifest, and verifies a restore before and after copying. | `IMPLEMENTED` | `aegis/core/wal_backup.py:100-190,192-287`; `tests/test_wal_backup.py:43-227` | Quiesced or externally snapshotted source; correct signing material when HMAC verification is required; trusted destination. | Tampered input is accepted, a successful result lacks integrity verification, or named tests fail. | Evidence custodian |
| `DOC04-CLM-009` | Crash-consistent live backup and atomic multi-file restore are not established. | `ROADMAP` | `aegis/core/wal_backup.py:128-171,245-264` | `shutil.copy2` is used file by file; the implementation comment says atomic restore, but no temporary-file-and-rename transaction covers the restored file set. | A reviewed implementation and power-loss/concurrent-writer fault tests prove a declared snapshot and atomic replacement boundary. | Evidence custodian |
| `DOC04-CLM-010` | Prometheus metric objects exist for requests, pipeline latency, audit commit latency/errors, pending commits, limiter failures, optional analysis failures, circuit state, and replication lag. | `IMPLEMENTED` | `aegis/core/observability.py:51-151`; metric tests in `tests/test_observability.py`, `tests/test_observability_new.py`, `tests/test_chaos.py:300-335` | `prometheus-client` is installed; metric existence does not mean collection, alert delivery, or SLO acceptance. | A named metric is absent or its declared labels differ. | Observability owner |
| `DOC04-CLM-011` | The current proxy does not attach a `/metrics` endpoint, and Prometheus support is optional; metric-based production monitoring therefore requires an environment-specific exporter/instrumentation integration. | `CONFIGURATION-DEPENDENT` | `aegis/core/observability.py:7-15,185-187`; `aegis/proxy/app.py:630-1402`; `pyproject.toml:76` | No external sidecar or custom application wrapper is assumed. | The deployed artifact exposes and is successfully scraped for all referenced metric series under a reviewed integration. | Observability owner |
| `DOC04-CLM-012` | Existing multi-window rules use `aegis_requests_total` and `aegis_request_duration_seconds_bucket`/`_count` in 1h/5m, 6h/30m, 24h/2h, and 72h/6h pairs. | `CONFIGURATION-DEPENDENT` | `deploy/helm/templates/prometheusrule.yaml:31-254`; `deploy/helm/values.yaml:160-178` | Prometheus Operator, metric export, nonzero denominators, routing, runbooks, and approved SLO semantics exist. Rules are disabled by default. | Rendered rules reference absent series, invalid labels, unapproved semantics, or fail an alert-delivery exercise. | Observability owner and service owner |
| `DOC04-CLM-013` | The Helm chart can create replicas, rolling updates, probes, a PDB, topology spread, and a PVC, but these objects do not prove service or evidence high availability. | `CONFIGURATION-DEPENDENT` | `deploy/helm/templates/deployment.yaml:7-147`; `deploy/helm/templates/pdb.yaml:1-13`; `deploy/helm/templates/pvc.yaml:1-17`; `deploy/helm/values.yaml:4,58-64,121-154` | Scheduler, zones, storage class, ingress, Redis, and disruption behavior must be accepted in the target cluster. | A declared target failure violates its tested service objective or loses/unverifiably forks evidence. | Platform/SRE owner |
| `DOC04-CLM-014` | Cross-replica global ordering, cross-pod atomicity, and multi-region HA are not currently established. | `ROADMAP` | `docs/CLAIMS_MATRIX.md:46`; `docs/performance/SCALING_GUIDE.md:16-25`; `tests/test_gossip_wal_sync.py:1-20` | Current supported wording is “independently verifiable per-replica evidence bundle.” | A deployed, reviewed consensus or centralized-writer design passes partition, failover, recovery, ordering, and restore acceptance. | Architecture owner and release owner |
| `DOC04-CLM-015` | Any statement that restored evidence is legally admissible, compliant, or satisfies a retention mandate requires qualified review. | `LEGAL-REVIEW-REQUIRED` | `docs/CLAIMS_MATRIX.md:48,57-59`; `docs/operations/ROLLBACK_RUNBOOK.md:1-3` | Technical integrity metadata is not a legal conclusion. | Qualified counsel or assessor rejects the statement, or jurisdiction/customer facts change. | Privacy/legal owner |

## 5. Universal operating gates

Before any startup, change, restore, or rollback, record the release tag and commit, immutable image digest when available, configuration version, WAL path and segment inventory, signer scheme and non-secret key ID, Redis endpoint class without credentials, affected replicas, target storage class, target kernel/runtime/profile, and named human approvers. Never place secrets, prompts, responses, provider credentials, or key material in an incident ticket, shell transcript, metric label, or evidence manifest.

The following repository checks are valid from the repository root after the documented virtual environment and hash-locked installation have been created:

```bash
. .venv/bin/activate
python -m compileall -q aegis aegis_server
pytest -q tests/test_p0_release_gates.py tests/test_health.py tests/test_wal_backup.py tests/test_keyring_rotation.py
```

**Expected observation:** all selected tests pass. **Failure branch:** do not deploy; retain the complete test output and environment identity; assign the failure to the release owner. **Rollback:** revert only through source control or select the last reviewed release; do not edit tests to obtain a pass. **Escalation:** involve the security owner for strict, signer, or integrity failures and the evidence custodian for backup/restore failures.

## 6. Startup and strict-mode acceptance runbook

### 6.1 Preconditions

Strict production configuration requires `AEGIS_SECURITY_ENFORCEMENT_MODE=strict`, durable evidence, Redis rate limiting, at least one proxy API key, and a static signing key or configured PKCS#11 path (`aegis/config.py:669-686`). Deployment policy additionally requires the LSM and Seccomp controls declared by `DEPLOYMENT_GUIDE.md:9-39`, durable non-ephemeral WAL storage, a protected secret path, an approved backend URL, and bounded request bodies. A signing key must contain at least 32 bytes under the documented deployment contract; do not generate or display it in this runbook.

For Kubernetes, review the chart before use. The default chart supplies two replicas and one `ReadWriteOnce` PVC (`deploy/helm/values.yaml:4,58-64`), while its pod spread may place replicas on distinct zones/nodes (`deploy/helm/values.yaml:145-154`). This combination is not a validated multi-writer or multi-zone evidence design. Do not use the default replica/PVC arrangement for governed multi-replica traffic until Section 13 is satisfied.

### 6.2 Compose startup

The repository-valid Compose file deliberately requires the backend URL, backend credential, proxy and audit API keys, signing key, and Redis URL. It also attaches the service to an `internal: true` bridge and does not provision Redis (`deploy/docker/docker-compose.yml:5-8,35-42,65-68`). The approved overlay must therefore make the approved upstream and Redis reachable without weakening egress controls.

```bash
docker compose -f deploy/docker/docker-compose.yml config
docker compose -f deploy/docker/docker-compose.yml up -d --build
docker compose -f deploy/docker/docker-compose.yml ps
docker compose -f deploy/docker/docker-compose.yml logs --no-color aegis
curl -fsS http://127.0.0.1:${AEGIS_PORT:-8080}/health
curl -fsS http://127.0.0.1:${AEGIS_PORT:-8080}/ready
```

**Expected observation:** Compose interpolation succeeds without printing secrets into retained logs; the container remains running; `/health` returns HTTP `200` with `status` equal to `healthy`; `/ready` returns HTTP `200` with `status` equal to `ready`. Health checks ledger fault state and analyzer-cache pressure, while readiness only confirms that the forwarder client is initialized (`aegis/proxy/app.py:937-1002`); neither endpoint proves Redis reachability, upstream success, WAL power-loss durability, or signer custody.

**Failure branches:**

| Observation | Action | Rollback and escalation |
|---|---|---|
| Compose interpolation fails | Restore the missing protected variable through the approved secret/configuration system. Do not place it in the repository. | Run `docker compose -f deploy/docker/docker-compose.yml down`; escalate repeated secret-delivery failures to platform and security owners. |
| Startup reports LSM or Seccomp rejection | Correct the host/runtime profile and rerun the negative acceptance test. Do not switch to development mode. | Stop the deployment; retain runtime/profile identity; escalate to security owner. |
| Startup rejects auth, signer, or Redis backend selection | Correct configuration; do not enable debug mode or in-memory limiting. | Stop the deployment; escalate configuration drift to release owner. |
| `/health` is `503` | Inspect only the returned ledger fault state and cache pressure plus sanitized logs. Stop new governed traffic if the ledger is unhealthy. | Preserve WAL bytes before restart; invoke Section 8 for WAL faults. |
| `/ready` is `503` after the startup window | Inspect forwarder initialization, TLS trust, approved egress, and provider configuration. | Keep the replica out of service; rollback the change if the prior reviewed release is healthy. |
| Redis becomes unavailable during requests | Expect governed requests to return `503` and increment `aegis_ratelimit_backend_errors_total` when metrics are integrated. | Do not fail open; repair or fail over Redis; escalate sustained outage to incident commander. |

### 6.3 Kubernetes deployment template

The following is an **explicit deployment template**, not a universal command. Replace the values-file and namespace through the approved deployment system. The chart currently renders image references as `repository:tag`, not digest syntax (`deploy/helm/templates/deployment.yaml:34`); an immutable-digest production workflow requires a reviewed chart change or registry admission policy.

```bash
# DEPLOYMENT TEMPLATE: target-cluster context and reviewed values are required.
helm upgrade --install aegis deploy/helm \
  --namespace aegis --create-namespace \
  -f /approved/config/aegis-values.yaml \
  --wait --atomic
kubectl -n aegis rollout status deployment/aegis-latent-core
kubectl -n aegis get pods,pvc,pdb
```

**Expected observation:** strict startup completes, readiness gates traffic, the PVC is bound to accepted storage, the PDB and spread constraints match the approved topology, and each governed test request can be correlated to exactly one durable record in its declared evidence scope. **Failure branch:** `--atomic` returns the Helm release to the prior revision for deployment failure, but this does not verify evidence continuity. Freeze traffic, preserve WALs, and use Section 12. **Escalation:** any PVC attach conflict, shared-writer ambiguity, or cross-zone scheduling conflict blocks multi-replica acceptance.

## 7. Normal-operation checklist

At each shift handoff or automated control interval, verify that health and readiness are successful, release identity is unchanged, WAL storage has accepted free-space and inode headroom, active and rotated segments are inventoried, backup freshness and the last restore exercise meet the organization’s approved objectives, Redis is reachable over the approved transport, signer status and non-secret key ID are expected, and no integrity, commit, limiter, or startup errors are active. Review metric semantics in Section 11 before using them for pages.

A successful governed response must include `X-Aegis-Evidence-Status: durable` on implemented completion paths (`aegis/proxy/app.py:1359-1363`). Treat the header as a correlation signal, not independent proof: verify the corresponding record and chain in the declared WAL scope. Do not log raw request or response content merely to simplify diagnosis.

## 8. WAL stall and durability incident runbook

### 8.1 Trigger and preconditions

Invoke this runbook for rising `aegis_audit_commit_duration_seconds`, rising `aegis_audit_commit_lag_seconds`, increasing `aegis_audit_pending_commits`, nonzero increments in `aegis_audit_commit_errors_total`, health reporting a non-healthy ledger fault state, storage errors, free-space/inode exhaustion, or an observed mismatch between governed successes and durable records. The older runbook’s `aegis_wal_backpressure_active` name is not declared in `aegis/core/observability.py:51-151`; do not create an alert on that name without implementation and tests.

Preconditions are a named incident commander, a known WAL path, permission to reduce admission, a protected location for original bytes, and an established distinction between requests rejected before evidence admission and failures after admission.

### 8.2 Containment and diagnosis

1. Stop increasing offered load. Use the deployment’s approved ingress or client rate control; do not disable the evidence gate.
2. Record UTC onset, affected replica, request IDs, release identity, free space, inode state, volume and node events, audit commit duration/lag, pending commits, and commit-error counter changes.
3. Drain one affected replica only if the platform can preserve in-flight request IDs. Treat uncertain in-flight operations as failed until evidence is verified.
4. Preserve the active WAL and all numbered segments read-only. Do not truncate, compact, rewrite, or delete them.
5. Correct the external cause when identified: storage outage, full volume, permission/ownership drift, failed mount, encryption-layer delay, or host I/O saturation.
6. After the cause is removed, allow in-flight commits to drain, then verify integrity and request-ID uniqueness before returning traffic.

**Expected observation:** admission is bounded; governed successes stop when commits fail; commit errors are visible; after storage recovery, the chain verifies and every admitted request maps to one terminal durable record within the declared scope. **Failure branch:** if integrity fails, an ID is missing/duplicated, the queue is unbounded, or WAL preservation is impossible, keep traffic stopped and invoke rollback/DR. **Rollback:** use Section 12 with a new explicitly approved active path; never replace the affected bytes in place. **Escalation:** integrity or correlation failures require security, evidence-custodian, and release-owner review.

### 8.3 Repository fault-injection gate

Run this only on an isolated local ledger from the repository root. The tool creates its own synthetic signing material and output-adjacent WAL; it must not point at production evidence.

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_backpressure_stall.py \
  --duration-s 0.25 \
  --offered-rps 10000 \
  --fsync-delay-ms 2 \
  --max-workers 64 \
  --output evidence/backpressure_stall_report.json
```

**Expected observation:** the process exits zero and prints `passed: true`, with no failures, missing IDs, duplicates, or integrity error in the JSON. The in-tree 2026-08-20 report contains 2,500 offered requests, not the 10,000-request result described in older narrative documents; treat the JSON workload as authoritative for this in-tree artifact. **Failure branch:** retain the JSON and adjacent WAL; block release; compare environment and source identity. **Boundary:** the seam calls real `os.fsync` after an injected sleep, but it does not reproduce power loss, controller caches, CSI behavior, or a distributed filesystem. A privileged `dm-delay` test remains a separate disposable-device exercise and is unexecuted in the retained evidence.

### 8.4 WAL and ledger corruption containment runbook

Corruption is handled as an **evidence-preservation incident**, not a service-restoration incident. The governing rule is that no operator repairs evidence bytes in place: a corrupted segment is preserved and quarantined, and a new segment is started, so that the boundary between trustworthy and untrustworthy records stays auditable.

#### 8.4.1 Detection surfaces

| Surface | Signal | Semantics | Locator |
|---|---|---|---|
| Native streaming WAL | Frame CRC32 mismatch or non-UTF-8 payload during open | The loader stops at the **first** bad frame and treats everything after it as absent. This is fail-closed truncation of the readable view, not a silent skip-and-continue. | `aegis_rust_v2/src/wal.rs:186-207,228-254` |
| Native streaming WAL | `aegis_native_stream_wal_errors_total` non-zero | Auxiliary append failed; the auxiliary segment was disabled for the remaining life of that process object. The authoritative JSONL commit already succeeded. | `aegis/proxy/app.py:709-719` |
| JSONL ledger | `verify_integrity()` returns `(False, index)` | First violating node index in the retained window: self-inconsistent `node_hash`, `prev_hash` linkage break, or invalid HMAC signature. | `aegis/core/crypto_audit.py:634-668` |
| Storage backend | Backend read/verify error | Backend-specific; inherits the configured engine's own corruption semantics. | `aegis/storage/` |

Two scope facts must be stated before any conclusion is drawn from a sweep. First, `verify_integrity()` walks the in-memory retained window anchored by `_window_anchor_hash`; it is **not** a full-history verification after deque rollover, so a clean result means "the retained window is self-consistent", not "no record was ever altered". Second, a CRC32 frame check detects accidental torn writes and media faults; it is not adversarial integrity and provides no protection against a capable actor who recomputes the checksum.

#### 8.4.2 Containment sequence

1. **Freeze the writer.** Stop admitting governed traffic to the affected replica before any diagnosis. A process that keeps appending past a detected fault destroys the evidentiary boundary. Drain or remove the replica from the ingress pool; do not restart it in place.
2. **Preserve the bytes.** Copy the affected WAL and ledger files byte-for-byte to quarantine storage before any tool touches them. Record the copy's SHA-256 and the copying operator. Never run a repair, truncate, or reformat utility against the original.
3. **Record the observation.** Capture the failing index or offset, the exact tool output, the process identity, and the wall-clock window. This becomes the boundary marker between records that remain in scope and records that do not.
4. **Classify the fault.** Determine whether the signal indicates a torn write at the tail (typical of an abrupt stop), a mid-file inconsistency (indicates media, filesystem, or actor involvement), or a linkage or signature failure (indicates content alteration or key mismatch rather than media). Mid-file and signature classes escalate to the security owner, not the storage owner.
5. **Start a new segment.** Bring the service back on a **new** WAL path with a fresh segment rather than reusing the damaged one. Chain continuity across that boundary is not claimed; the quarantine record is what links the two eras.
6. **Bound the blast radius.** Enumerate the request identifiers whose evidence falls at or after the boundary and mark them as evidence-incomplete in the incident record. Do not describe them as "durable"; do not reconstruct them from application logs and present the result as ledger evidence.
7. **Escalate for custody.** Notify the evidence custodian and, where a regulated workload is affected, the compliance owner. Whether a gap is reportable is a legal determination and is not made by the platform team.

#### 8.4.3 Recovery semantics that operators frequently misread

- **A valid prefix remains valid.** Frames before the first CRC failure verify normally and remain usable evidence. Corruption at offset *k* does not invalidate records committed before *k*.
- **The tail is unreadable, not repaired.** The loader positions the write head at the end of the valid prefix. Subsequent appends overwrite the damaged region. A zero-length terminator is written and flushed after each frame specifically so that a same-size replacement cannot make a stale, otherwise-valid suffix reachable again on a later open (`aegis_rust_v2/src/wal.rs:156-163`; regression `recovery_terminator_prevents_corrupt_suffix_resurrection`).
- **Restart is not remediation.** Because the loader silently adopts the valid prefix, a restarted process appears healthy. Absent step 3, the truncation event leaves no operator-visible trace. The incident record is the only durable evidence that a boundary exists.
- **`fsync` returned is not media-survival.** A completed `fsync` means the process requested synchronization; power-loss survival remains a property of the device, controller, and filesystem. Corruption after a clean shutdown therefore warrants hardware and filesystem investigation rather than an application bug hunt.

#### 8.4.4 Exit criteria

Containment is complete when: quarantined copies exist with recorded digests; the boundary marker is written to the incident record; the service runs on a new segment; a post-restart `verify_integrity()` sweep returns clean for the new window; affected request identifiers are enumerated and classified evidence-incomplete; and the evidence custodian has acknowledged the record. Restoring availability alone does not close the incident.

## 9. Signing-key rotation runbook

### 9.1 Scope gate

The versioned keyring is wired through the enterprise signer factory (`aegis_server/crypto/__init__.py:90-98`) and used for compliance-export signatures. The proxy WAL ledger is constructed separately with the static configured signing key or HSM backend (`aegis/proxy/app.py:598-608`). Therefore, this section authorizes enterprise keyring rotation only. It does not authorize a claim of zero-downtime proxy-WAL signing-key rotation.

### 9.2 Preconditions and sequence

The security owner must approve the rotation window, secret-manager path, overlap duration, non-secret key IDs, propagation plan, clock assumptions, rollback snapshot, and destruction/retention policy. The keyring must be a regular file with no group or other permission bits, contain version `1`, exactly one active key, unique valid key IDs, and secrets of at least 32 UTF-8 bytes (`aegis_server/crypto/keyring.py:154-235`). Never paste a keyring or secret into a ticket or command transcript.

1. Generate the new key in the approved secret manager.
2. Build a complete new snapshot in the protected delivery mechanism: new key `active`, prior key `verify`, and an approved positive Unix expiry when used.
3. Validate schema and owner-only mode in a non-serving staging path.
4. Atomically rename the staged file over the configured keyring path on each enterprise signer instance. This is a **deployment template action** because secret-manager and orchestrator commands are environment-specific.
5. Observe only the new non-secret key ID activation log, signer reload-failure count, committed/exported artifact status, and signature verification result.
6. Verify artifacts produced before and after activation while the old key remains in overlap.
7. Exercise one delayed instance and one process restart in the target orchestrator before acceptance.
8. After the approved overlap and verification gate, remove or expire the old key through the secret manager and retain the operator event without key material.

**Expected observation:** malformed or unavailable reloads increment the signer’s internal reload-failure count and leave the last valid snapshot active; an initial invalid snapshot prevents construction; valid activation changes the reported key ID without restart; pre- and post-rotation signatures verify during overlap. **Failure branch:** any unverifiable artifact, unknown key ID, secret exposure, invalid snapshot activation, or lost overlap stops rotation. **Rollback:** atomically restore the prior valid snapshot while its old key is still valid. **Escalation:** if overlap is lost or an artifact is unverifiable, stop affected signing operations and involve the security owner and evidence custodian.

Repository validation commands are:

```bash
PYTHONPATH=. .venv/bin/pytest -q tests/test_keyring_rotation.py
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_key_rotation.py \
  --duration-s 0.5 \
  --output evidence/key_rotation_report.json
```

The harness uses synthetic local keys embedded in the tool and three local signer instances. Its result is not production secret-manager, pod, clock, restart, or proxy-WAL evidence.

## 10. Backup and restore runbook

### 10.1 Backup preconditions

The evidence custodian must identify the active WAL, all archived segments, signing-verification mode, destination, retention class, custody controls, and required recovery point/recovery time objectives. Because the library copies files individually, obtain a quiesced source or storage snapshot accepted by the deployment. A live mutable copy is not declared crash-consistent.

The repository provides a Python API, not a command-line tool. The following repository-valid command invokes it without embedding a secret. Set `AEGIS_WAL_PATH`, `AEGIS_BACKUP_DIR`, and `AEGIS_SIGNING_KEY` through the approved protected environment before execution:

```bash
.venv/bin/python -c 'import json,os; from aegis.core.wal_backup import WALBackupManager; r=WALBackupManager(os.environ["AEGIS_SIGNING_KEY"]).backup(os.environ["AEGIS_WAL_PATH"],os.environ["AEGIS_BACKUP_DIR"]); print(json.dumps(r.__dict__,sort_keys=True)); raise SystemExit(0 if r.success else 1)'
```

**Expected observation:** exit zero; `success` is true; the timestamped directory contains the active WAL, archived segments, and `manifest.json`; the result reports node count, chain-tip hash, and backed-up filenames; copied files and manifest have mode `0o600`. **Failure branch:** no source, copy error, or integrity failure returns nonzero. Preserve the failed copy for controlled analysis, keep the prior valid backup, and do not label the new backup valid. **Rollback:** no live state should change during backup; if external quiescing affected service, resume only after source integrity is reconfirmed. **Escalation:** integrity failure requires the evidence custodian and security owner.

### 10.2 Restore preconditions and execution

Restore only while the destination writer is stopped and traffic is blocked from that evidence scope. Identify the reviewed backup directory, a separate target path, the correct verification key material, and a pre-restore backup destination. Never test a restore over the sole production copy.

Set `AEGIS_RESTORE_SOURCE`, `AEGIS_RESTORE_TARGET`, `AEGIS_PRE_RESTORE_BACKUP_DIR`, and `AEGIS_SIGNING_KEY` through the protected environment, then run:

```bash
.venv/bin/python -c 'import json,os; from aegis.core.wal_backup import WALBackupManager; r=WALBackupManager(os.environ["AEGIS_SIGNING_KEY"]).restore(os.environ["AEGIS_RESTORE_SOURCE"],os.environ["AEGIS_RESTORE_TARGET"],pre_restore_backup_dir=os.environ["AEGIS_PRE_RESTORE_BACKUP_DIR"]); print(json.dumps(r.__dict__,sort_keys=True)); raise SystemExit(0 if r.success and r.integrity_valid else 1)'
```

**Expected observation:** the backup verifies before destination changes; the previous target is backed up when present; copied files are mode `0o600`; the restored target verifies; result fields show `success: true` and `integrity_valid: true`. Before reopening traffic, verify ownership, segment inventory, manifest identity, predecessor relationship, signer/key-ID availability, and an authorized disposable governed request on a newly approved active append path.

**Failure branches:** missing/unreadable manifest or WAL, pre-copy integrity failure, copy failure, or post-copy integrity failure blocks traffic. The current restore loops through `shutil.copy2` operations rather than an atomic multi-file transaction; a mid-restore interruption can leave a partial target. Preserve that target, do not append, and restore again to a fresh path from the last verified backup. **Rollback:** select the pre-restore backup only after it independently verifies. **Escalation:** unresolved predecessor, key, or custody mismatch requires evidence and security review; legal-hold or retention impact also requires privacy/legal review.

### 10.3 Disaster-recovery gaps

No retained artifact proves cross-region backup replication, automated failover, immutable object retention, ransomware recovery, key escrow recovery, site-loss recovery, storage power-loss semantics, or a tested customer RPO/RTO. No scheduled backup controller is present in the manifests. These are `ROADMAP` deployment capabilities. A production DR plan must add independent copies, off-site custody, signer/key recovery, periodic restore exercises, failure injection, documented RPO/RTO, and named owners before an HA or DR claim is approved.

## 11. Monitoring and alert response

### 11.1 Exact implemented metric names

| Metric | Meaning in source | First response |
|---|---|---|
| `aegis_requests_total{method,endpoint,status_class}` | Proxy requests by status class | Separate expected policy `4xx` from server/evidence `5xx`; correlate request IDs. |
| `aegis_request_duration_seconds{stage}` | Pipeline-stage histogram; `stage="total"` is end-to-end | Compare `total`, `forward`, WAF, and limiter stages before changing capacity. |
| `aegis_audit_commit_duration_seconds` | Mandatory WAL commit/fsync gate duration | Inspect storage, signer, queueing, free space, and host I/O. |
| `aegis_audit_commit_lag_seconds` | Request arrival to mandatory durable commit | Bound admission and investigate upstream plus commit-path delay. |
| `aegis_audit_pending_commits` | Mandatory commits in flight | Reduce admission if sustained growth accompanies commit latency. |
| `aegis_audit_commit_errors_total` | Mandatory commit failures that reject requests | Page incident commander; preserve WAL; invoke Section 8. |
| `aegis_ratelimit_backend_errors_total` | Distributed limiter errors that reject requests | Verify Redis TLS/auth/network/failover; do not fail open. |
| `aegis_analysis_queue_rejections_total` | Optional analysis jobs rejected because queue is full | Preserve evidence path; tune or scale optional analysis only. |
| `aegis_analysis_errors_total` | Optional asynchronous analysis failures | Investigate enrichment separately from authoritative evidence. |
| `aegis_circuit_breaker_opens_total{provider}` | Upstream circuit transitions to open | Follow provider incident handling; do not infer Aegis capacity failure. |
| `aegis_circuit_breaker_state{provider}` | `0` closed, `1` half-open, `2` open | Validate provider recovery and probe behavior. |
| `aegis_wal_replication_lag_bytes{follower}` | Declared replication-lag gauge | Treat as unsubstantiated for the default deployment; no chart wiring establishes active Raft replication. |

Prometheus and OpenTelemetry are optional and do not block proxy startup (`aegis/core/observability.py:7-22`). The current application does not call an `attach_prometheus_endpoint` function and does not expose `/metrics`; the comment in `aegis/core/observability.py:13-15` describes a required integration that is absent. Before metric-based go-live, add a reviewed collection endpoint or sidecar, test authentication/network exposure, verify every series under traffic and failure injection, and retain a scrape/alert-delivery artifact.

### 11.2 Existing multi-window burn-rate pattern

The Helm rules are disabled by default and may be enabled only after metric export, rule evaluation, routing, and service-objective approval. They use the following existing metric names and windows:

| SLO rule family | Metric expression basis | Long/short windows | Burn threshold and severity |
|---|---|---|---|
| Availability | Error fraction from `aegis_requests_total` | `1h/5m` | `14.4x`, critical |
| Availability | Error fraction from `aegis_requests_total` | `6h/30m` | `6x`, critical |
| Availability | Error fraction from `aegis_requests_total` | `24h/2h` | `3x`, warning |
| Availability | Error fraction from `aegis_requests_total` | `72h/6h` | `1x`, warning |
| Latency | Fraction above 0.5 s using `aegis_request_duration_seconds_bucket{stage="total",le="0.5"}` and `_count` | Same four pairs | Same thresholds and severities |

The generated availability expression counts both `4xx` and `5xx` as errors (`deploy/helm/templates/prometheusrule.yaml:38-44`), despite `deploy/helm/values.yaml:170` describing non-`5xx` availability and `aegis/core/slo_alerting.py:11-13` describing non-`5xx`. Resolve this semantic conflict with the service owner before enabling alerts. The configured runbook URLs point to `docs/runbooks/availability.md` and `latency.md`, which are absent; set `runbookBaseUrl` to reviewed live runbooks before enabling. Guard against absent series and zero denominators, and prove page delivery.

**Critical alert branch:** verify both windows are firing, then classify commit/Redis/internal `5xx`, upstream failure, policy `4xx`, or latency cause. Stop governed traffic for evidence-commit or integrity failures; use dependency failover for Redis/provider failures only when the documented fail-closed path remains intact. **Warning branch:** open a tracked capacity/reliability investigation, compare storage and upstream dimensions, and do not add replicas until the authoritative evidence bottleneck is understood. **Rollback:** disable only a demonstrably invalid rule through the reviewed deployment system; do not silence the underlying runtime failure.

## 12. Release rollback runbook

### 12.1 Kill criteria and preservation

Stop traffic or initiate controlled rollback when a governed success lacks durable evidence, integrity fails, signer policy or overlap is lost, strict startup prerequisites fail, WAL synchronization creates unbounded pressure, release identity is unknown, or credible key/data exposure exists (`docs/operations/ROLLBACK_RUNBOOK.md:23-36`). Before changing the runtime, record incident ID, UTC time, operator/reviewer, image digest, tag and commit, configuration identity, WAL path and segments, signer scheme and key ID, affected replicas, evidence status, pending commits, commit latency, and rollback reason.

Preserve original WAL bytes and metadata read-only. Drain through the approved ingress; never bypass authentication, durable evidence, signing, Redis, LSM, or Seccomp. Select a prior release only after source identity, immutable runtime identity, supply-chain records, WAL/export schema compatibility, security posture, and configuration compatibility are reviewed.

### 12.2 Deployment actions

The following are **deployment templates** and require approved release names and revisions:

```bash
# DEPLOYMENT TEMPLATE: inspect and approve the target revision before execution.
helm -n aegis history aegis
helm -n aegis rollback aegis APPROVED_REVISION --wait
kubectl -n aegis rollout status deployment/aegis-latent-core
```

For Compose, update the approved deployment definition to the reviewed immutable image reference through change control, then execute:

```bash
# DEPLOYMENT TEMPLATE: the Compose file must already contain the approved image identity.
docker compose -f deploy/docker/docker-compose.yml pull aegis
docker compose -f deploy/docker/docker-compose.yml up -d --no-deps aegis
docker compose -f deploy/docker/docker-compose.yml ps
docker compose -f deploy/docker/docker-compose.yml logs --no-color aegis
```

The repository Compose and Helm defaults use mutable tag syntax rather than a digest. Do not represent their default rollback path as forensic image identity. Record the resolved image digest from the deployment platform and add an admission/deployment control that enforces it.

### 12.3 Post-rollback verification

```bash
pytest -q tests/test_p0_release_gates.py
pytest -q tests/test_enterprise_durable_evidence.py
python -m compileall -q aegis aegis_server
```

Then perform one authorized disposable governed request and verify authentication, request ID, durable status before success, exactly one signed linked WAL record in the declared scope, integrity, expected signer/key ID, documented upstream-error behavior, health, and readiness. If rollback crosses signer or WAL/export schema versions, do not append until overlap and compatibility are explicitly approved. **Failure branch:** keep traffic stopped and enter Section 10 restore or the organization’s DR plan. **Closeout:** incident commander, evidence custodian, security owner, and release owner must approve chain continuity and corrective action; availability alone is insufficient.

## 13. Multi-replica and high-availability boundary

The repository-supported operating phrase is **“independently verifiable per-replica evidence bundle,”** not “globally ordered multi-region audit trail” (`docs/CLAIMS_MATRIX.md:53-55`). One worker per pod with an independent accepted WAL can scale request processing, but it creates separate evidence chains. A centralized writer may supply one ordering boundary only after its capacity, queueing, failover, and recovery are accepted. Unit-tested fencing (`tests/test_split_brain.py`) and gossip-stub behavior (`tests/test_gossip_wal_sync.py:1-20`) are not wired by the Helm chart and are not production consensus.

Before enabling more than one governed replica, require all of the following:

| Gate | Required evidence | Failure response |
|---|---|---|
| Evidence topology | One accepted WAL owner per process/pod, or a reviewed centralized writer; no uncoordinated shared-file writers | Keep one replica serving; redesign storage. |
| Storage | Target CSI/filesystem attach, flush, failure, snapshot, and restore tests | Mark topology unverified; do not infer HA from a bound PVC. |
| Redis | TLS/auth, partition, timeout, failover, and consistency exercise | Fail closed; keep service out until dependency recovery is accepted. |
| Signer | Per-replica custody, overlap, delayed-replica, restart, and rollback exercise | Stop rotation or traffic in affected scope. |
| Scheduling | Node/zone failure and PDB exercise with actual storage constraints | Reduce claim to single-failure-domain operation. |
| Evidence merge | Reviewed method preserving original bundle bytes, chain tips, replica ID, time basis, and custody | Do not claim global ordering. |
| Observability | Per-replica labels, scrape coverage, alert delivery, and denominator checks | Block HA acceptance because blind replicas cannot be operated safely. |
| Recovery | Replica loss, volume loss, Redis loss, signer loss, and restore rehearsal | Escalate to architecture and DR owners; retain `ROADMAP` status. |

The default chart’s `RollingUpdate` strategy uses `maxSurge: 1` and `maxUnavailable: 0` (`deploy/helm/templates/deployment.yaml:14-18`), PDB default is `minAvailable: 1`, and topology spread is configured. These are availability mechanisms only. They do not solve shared-PVC write coordination, evidence ordering, signer propagation, Redis HA, or disaster recovery.

## 14. Assumptions, falsification, and review record

This document assumes commands run from the repository root, `.venv` was created and installed using `requirements.lock`, deployment credentials are supplied through an approved protected mechanism, the operator has authorization for the target environment, and no command is redirected to production evidence unless the relevant runbook explicitly permits it. Shell placeholders in sections labeled **deployment template** must be replaced and reviewed; all other commands map to paths and options present in this repository.

Any claim in Section 4 is blocked when its exact locator changes without review, the named test or evidence gate fails, a target environment lacks a prerequisite, a measurement workload changes without a new artifact, the runtime differs from the declared topology, or a qualified reviewer identifies contradictory semantics. Human reviewers must record disposition, evidence path, operational boundary, and residual risk. Formal checks remain bounded abstractions: `docs/formal/FORMAL_VERIFICATION.md:44-46` explicitly records the absence of a machine-checked implementation refinement.

## 15. Consolidated disaster-recovery and readiness gaps

| Gap | Status | Operational consequence | Required owner |
|---|---|---|---|
| No deployed global evidence ordering or multi-region consensus | `ROADMAP` | Replicas cannot be represented as one globally ordered evidence chain. | Architecture owner |
| Default two-replica Helm deployment uses one `ReadWriteOnce` PVC without writer coordination | `CONFIGURATION-DEPENDENT` | Scheduling/attach conflict or unsafe shared writes can defeat availability or integrity. | Platform/SRE owner |
| No scheduled backup controller or retained target-environment restore artifact | `ROADMAP` | Backup freshness and RPO/RTO are not established. | Evidence custodian |
| Backup source copy and multi-file restore lack a proven crash-consistent/atomic transaction | `ROADMAP` | Concurrent writes or interruption can produce an inconsistent copy/partial target. | Evidence custodian |
| Enterprise rotating keyring is not the proxy WAL signer path | `ROADMAP` | Proxy-WAL zero-downtime rotation is unsubstantiated. | Security owner |
| Prometheus metric endpoint is not attached; Helm alerting is disabled by default | `CONFIGURATION-DEPENDENT` | Existing alert expressions cannot be assumed collectible or routable. | Observability owner |
| Availability rule semantics conflict on whether `4xx` consumes the budget | `CONFIGURATION-DEPENDENT` | Pages and error-budget reporting may misclassify policy/client rejections. | Service owner |
| Configured burn-rate runbook URLs target absent files | `ROADMAP` | Alerts may link responders to a nonexistent procedure. | Observability owner |
| No retained site-loss, ransomware, key-loss, or cross-region failover exercise | `ROADMAP` | Disaster recovery and business continuity claims are blocked. | DR owner and security owner |
| No legal determination for retention, custody, or admissibility | `LEGAL-REVIEW-REQUIRED` | Technical verification cannot be described as legal sufficiency. | Privacy/legal owner |

## 16. Approval criteria

The platform/SRE owner may approve single-replica operation only after strict startup, target storage, Redis, signer, probes, backup, restore, rollback, monitoring, and incident escalation are exercised in the target environment. Multi-replica approval additionally requires Section 13 and must retain per-replica wording unless a centralized or consensus evidence design is independently accepted. The release owner must reconcile the in-tree JSON artifacts with any older narrative measurement before publication. The privacy/legal owner must review any regulated retention, legal-hold, compliance, or admissibility representation.

Approval is revoked on any falsification criterion in Section 4. Recovery restores service only when evidence continuity, release identity, signer validity, dependency health, and the declared operational boundary have all been re-established.

## 17. Related repository documents

- `DEPLOYMENT_GUIDE.md`
- `docs/PLATFORM_OPERATOR_GUIDE.md`
- `docs/operations/BACKPRESSURE_RUNBOOK.md`
- `docs/operations/KEY_ROTATION_RUNBOOK.md`
- `docs/operations/ROLLBACK_RUNBOOK.md`
- `docs/performance/SCALING_GUIDE.md`
- `docs/formal/FORMAL_VERIFICATION.md`
- `docs/security/WAL_HARDENING_2026-08-20.md`
- `docs/CLAIMS_MATRIX.md`
- `evidence/execution_2026-08-20/manifest.json`
- `evidence/execution_2026-08-20/backpressure_stall_report.json`
- `evidence/execution_2026-08-20/key_rotation_report.json`
