# Platform Operator Guide — Aegis Latent Core v3.1.0

This guide is for SRE, platform, infrastructure, and security operations teams deploying Aegis in a controlled environment. It defines the deployment dependencies, topology choices, telemetry, failure handling, backup expectations, and rollback boundaries. It does not establish an availability SLO, compliance status, or authorization.

**Last verified:** 2026-08-18 UTC
**Release baseline:** `v3.1.0`
**Audience:** Platform engineering, SRE, security operations
**Primary deployment contract:** [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md)

## Operating model

Aegis commits authoritative evidence before returning a governed successful response. The evidence path depends on the filesystem, signer, process, kernel, network, Redis and configuration. Optional enrichment runs after the authoritative record and can be rejected under queue pressure.

A production operator must distinguish three states:

| State | Meaning | Operator action |
|---|---|---|
| `durable` | The evidence commit completed according to the configured local contract | Continue normal processing and retain telemetry |
| `failed` | A required control or evidence commit failed | Treat the governed operation as failed; preserve diagnostics and investigate |
| `unverified` | The environment lacks an acceptance artifact or prerequisite | Do not claim production readiness for that boundary |

## Required baseline

Strict deployments should set the following controls through a protected configuration system:

```env
AEGIS_SECURITY_ENFORCEMENT_MODE=strict
AEGIS_REQUIRE_DURABLE_EVIDENCE=true
AEGIS_REQUIRE_DISTRIBUTED_LIMITER=true
AEGIS_RATE_LIMIT_BACKEND=redis
AEGIS_REQUIRE_LSM=true
AEGIS_REQUIRE_SECCOMP=true
AEGIS_MAX_REQUEST_BODY_BYTES=1048576
```

Use an external secret manager or protected signer service for `AEGIS_SIGNING_KEY`, upstream credentials, Redis credentials, and keyring material. Mount only the evidence directory as writable when the container posture permits it. Run as a non-root identity, drop unnecessary Linux capabilities, use a read-only root filesystem, and apply the target Seccomp and AppArmor/SELinux profiles.

## Topology decision table

| Topology | Evidence behavior | Suitable use | Not proven |
|---|---|---|---|
| Single process and WAL | One chain and one storage path | Local evaluation and small controlled deployment | Host, volume and key custody are single failure domains |
| One worker per pod | Each pod creates an independently verifiable bundle | Horizontal application scale with per-pod custody | Global ordering and cross-pod atomicity |
| Three replicas with shared key control | Each replica verifies active and overlap keys | Rotation and failover exercise | Secret-manager propagation and coordinated storage acceptance |
| Centralized writer | One ordered writer owns the evidence sequence | Global ordering requirement | Writer capacity, queue behavior and multi-region recovery |

Do not infer global ordering, multi-region high availability, or a production SLO from a local per-replica WAL.

## Storage and durability

The WAL must reside on storage whose failure and flush semantics are accepted for the deployment. `fsync` completion is an application-visible boundary, not a universal guarantee about hardware power-loss behavior, cloud volume replication, filesystem journaling, or backup durability.

Monitor free space, write latency, synchronization errors, inode exhaustion, WAL rotation, backup freshness, restore-test status, filesystem permissions and ownership. Preserve original WAL bytes and metadata during incident handling. Do not compact, rewrite or delete evidence in place without an approved process and qualified review.

## Redis and upstream controls

Redis is a required distributed limiter dependency in strict multi-worker deployments. A Redis outage must fail closed or return the documented error path. Operators must monitor TLS, connection pool exhaustion, command latency, replication state, authentication failures, rate-limit key growth and failover behavior.

The upstream provider is a separate trust and availability boundary. Validate hostname, scheme, port, certificate verification, allowlist policy, timeout, retry, circuit state, response-size limits and provider error behavior. Do not treat upstream `2xx` as evidence that the request was durable; Aegis must complete its own evidence gate.

## Kernel and container controls

Startup checks for Seccomp and AppArmor/SELinux provide a declared prerequisite assertion. They do not prove that a host remains uncompromised or that every syscall, profile rule, namespace and capability is correct. Acceptance requires the target kernel, container runtime, image digest, profile version and admission policy.

The deployment review should record:

| Control | Evidence |
|---|---|
| User and group | Image metadata and runtime identity |
| Capabilities | `capsh` or runtime inspection output |
| Seccomp | Profile, runtime mode and negative test |
| AppArmor/SELinux | Enforcing state, profile name and denial test |
| Filesystem | Read-only root, writable mounts and permissions |
| Network | Namespace, egress policy, firewall and NetworkPolicy |
| Secrets | Manager path, identity, rotation and access audit |

## Telemetry and alerts

Emit structured metrics and logs for request ID, evidence status, commit latency, WAL synchronization, signer availability, keyring reload, Redis failure, queue depth, queue rejection, upstream status, circuit state, body-limit rejection, WAF decision, integrity verification and startup rejection. Do not log raw prompt content, response content, signing material or provider credentials.

Recommended alert conditions are below. Thresholds are deployment-specific and must be validated against a measured baseline.

| Signal | Why it matters | First action |
|---|---|---|
| Evidence commit failure | Governed response may be blocked | Preserve request ID and WAL diagnostics; stop claiming success |
| `fsync` latency increase | Queueing and timeout risk | Compare storage latency, free space and write errors |
| Queue saturation | Optional analysis may be rejected; memory risk | Bound workers, inspect downstream analyzer and preserve core path |
| Redis unavailable | Distributed limiting cannot be evaluated | Verify TLS, auth, network and failover |
| Keyring reload failure | Rotation may be incomplete | Preserve last valid snapshot and inspect permissions/schema |
| Integrity failure | Evidence chain may be altered or truncated | Isolate the segment, preserve bytes and begin incident procedure |
| Upstream error spike | Provider path is degraded | Inspect circuit state and provider contract |
| Kernel startup rejection | Declared posture is not met | Do not bypass strict mode; fix host/runtime configuration |

## Operational acceptance scenarios

Run the local harnesses before an environment-specific pilot:

```bash
python tools/security/run_waf_corpus.py
python tools/benchmarks/run_backpressure_stall.py --offered-rps 10000 --fsync-delay-ms 2
python tools/benchmarks/run_key_rotation.py
python tools/benchmarks/run_pqc_timing.py --samples 1000000
```

The retained release evidence is local and bounded. It covers 15 malicious and 8 benign WAF cases, 10,000 offered backpressure requests, 2,239 local key-rotation records and 1,000,000 timing samples per declared ML-DSA operation. The ML-DSA verify experiment returned `p=0.0`, so no constant-time claim is approved.

## Backup, restore and rollback

Back up WAL segments, release manifests, configuration metadata, signer key IDs, image digests and verification results. A restore test must verify original bytes, ownership, permissions, chain integrity and the expected predecessor relationship before the restored evidence is accepted.

Rollback must use an identified image digest and preserve evidence continuity. Do not roll back by deleting the active WAL or replacing signer material without recording the transition. Follow [`docs/operations/ROLLBACK_RUNBOOK.md`](operations/ROLLBACK_RUNBOOK.md).

## Escalation boundary

The operator owns runtime health and evidence preservation. The security reviewer owns threat interpretation. The privacy/legal owner owns data handling and regulatory decisions. The release owner owns claims and provenance. A production incident must have a named escalation owner; a repository document cannot substitute for staffing or an on-call contract.

## Related documents

- [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md)
- [`docs/operations/BACKPRESSURE_RUNBOOK.md`](operations/BACKPRESSURE_RUNBOOK.md)
- [`docs/operations/KEY_ROTATION_RUNBOOK.md`](operations/KEY_ROTATION_RUNBOOK.md)
- [`docs/operations/ROLLBACK_RUNBOOK.md`](operations/ROLLBACK_RUNBOOK.md)
- [`docs/security/THREAT_MODEL.md`](security/THREAT_MODEL.md)
- [`docs/performance/SCALING_GUIDE.md`](performance/SCALING_GUIDE.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
