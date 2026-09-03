# Platform Operator Guide — Aegis Latent Core

This guide is for SRE, platform, infrastructure, and security operations teams deploying Aegis in a controlled environment. It defines the deployment dependencies, topology choices, telemetry, failure handling, backup expectations, and rollback boundaries. It does not establish an availability SLO, compliance status, or authorization.

**Last verified:** 2026-08-27 UTC
**Release baseline:** `v4.1.0` source; external release status requires independent readback
**Source baseline:** `v4.1.0`; source metadata does not establish publication or target acceptance
**Retained evidence baseline:** published `v3.1.0` artifacts; retained measurements remain historical
**Distribution verification:** resolve the signed tag, GitHub Release assets, package registries, OCI digest, and attestations independently before deployment
**Audience:** Platform engineering, SRE, security operations
**Primary deployment contract:** [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md)

## Operating model

Aegis commits authoritative evidence before returning a non-streaming governed response or the success terminal marker of an SSE response. Sanitized non-terminal SSE events may be emitted while evidence is `pending-terminal`. The evidence path depends on the filesystem, signer, process, kernel, network, Redis and configuration. Optional enrichment runs after the authoritative record and can be rejected under queue pressure.

An operator evaluating a target environment must distinguish three states:

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
AEGIS_STREAM_QUEUE_MAX_ITEMS=64
AEGIS_STREAM_QUEUE_MAX_BYTES=1048576
AEGIS_MAX_STREAM_EVENT_BYTES=65536
AEGIS_STREAM_DEIDENTIFIER_WINDOW_CHARS=128
```

Use an external secret manager or protected signer service for `AEGIS_SIGNING_KEY`, upstream credentials, Redis credentials, and keyring material. Mount only the evidence directory as writable when the container posture permits it. Run as a non-root identity, drop unnecessary Linux capabilities, use a read-only root filesystem, and apply the target Seccomp and AppArmor/SELinux profiles.

## Configuration surfaces and enumerated settings

The repository contains **two** settings classes, and both bind environment variables with the prefix `AEGIS_`. An operator who does not first establish which surface is deployed can set a variable that the running process never reads.

| Surface | Settings class | Entry point | Locator |
|---|---|---|---|
| Primary gateway | `AegisSettings` | `aegis` / `aegis-server` console scripts mapped to `aegis.proxy.app:main` | `aegis/config.py:22-24` |
| Alternate server | separate settings model | `aegis_server` package | `aegis_server/config.py:35` |

Both declare `env_prefix="AEGIS_"`, so a field named `security_enforcement_mode` is supplied as `AEGIS_SECURITY_ENFORCEMENT_MODE` on either surface. Because the literal variable name never appears in the source, searching the code for the variable string returns nothing; resolve names through the field definition instead.

**Enumerated settings and their accepted values.** These reject unknown values at startup rather than falling back to a default, so a typo is a startup failure and not a silent downgrade.

| Variable | Surface | Accepted values | Default | Locator |
|---|---|---|---|---|
| `AEGIS_SECURITY_ENFORCEMENT_MODE` | Primary gateway | `strict`, `development` | `strict` | `aegis/config.py:348-352` |
| `AEGIS_AUTH_MODE` | Primary gateway | `api_key`, `oidc`, `mtls`, `api_key_mtls`, `oidc_mtls` | `api_key` | `aegis/config.py:148-151` |
| `AEGIS_SIEM_FORMAT` | Primary gateway | `cef`, `rfc5424`, `splunk`, `datadog` | `cef` | `aegis/config.py:714` |
| `AEGIS_SECURITY_ENFORCEMENT_MODE` | Alternate server | `strict`, `development` | `strict` | `aegis_server/config.py:45` |
| `AEGIS_LOG_LEVEL` | Alternate server | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` | `aegis_server/config.py:54` |
| `AEGIS_STORAGE_PROVIDER` | Alternate server | `sqlite`, `postgres`, `dynamodb` | see field | `aegis_server/config.py:121` |
| `AEGIS_SIGNER_PROVIDER` | Alternate server | `hmac`, `vault` | see field | `aegis_server/config.py:169` |

Composite authentication modes require both factors: `api_key_mtls` and `oidc_mtls` do not fall back to a single factor when the second is unavailable.

**Naming corrections.** Two variable names circulate in external material and are wrong. There is no `AEGIS_STORAGE_BACKEND`; the field is `storage_provider`, so the variable is `AEGIS_STORAGE_PROVIDER`. The value `permissive` is not accepted for the enforcement mode; the only values are `strict` and `development`. Setting either incorrect name or value produces a startup validation error rather than the intended behavior, which is the desired fail-closed outcome but is frequently misdiagnosed as an unrelated fault.

**Dependent requirements.** Several providers impose conditional requirements that are validated at startup: selecting `postgres` requires a DSN, and selecting `vault` requires a Vault URL plus credentials (`aegis_server/config.py:262-271`). Configure the dependent values in the same change as the provider selection.

**Isolated local evaluation only.** `AEGIS_SECURITY_ENFORCEMENT_MODE=development` relaxes required authentication, durable evidence, distributed limiting, and privileged kernel controls. Combined with `AEGIS_DEBUG_MODE=true`, `AEGIS_AUTH_DISABLED=true`, and a mock upstream, it is intended for isolated local evaluation. It must never be selected for governed traffic, and evidence produced under it must not be presented as governed evidence.

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

The JSONL file at `AEGIS_WAL_PATH` is the replay authority. If the native extension loads, Aegis also opens `<wal_path>.stream.rwal` as an optional 256 MiB `RustWal` segment and appends one CRC-framed copy after each committed terminal stream node. Treat that segment as auxiliary: never replace JSONL replay or recovery with it. An append failure increments `aegis_native_stream_wal_errors_total`, disables the auxiliary segment for that process and leaves the authoritative JSONL commit and client terminal marker intact; alert on any non-zero increase and rotate or repair the native segment before restarting it.

## Streaming controls

`BoundedStreamProxy` uses `AEGIS_STREAM_QUEUE_MAX_ITEMS` and `AEGIS_STREAM_QUEUE_MAX_BYTES` together; the latter is retained canonical SSE bytes per active queue, not a total-response limit. `AEGIS_MAX_STREAM_EVENT_BYTES` bounds both upstream and canonical events and must not exceed the queue byte budget. `AEGIS_STREAM_DEIDENTIFIER_WINDOW_CHARS` is finite logical-text holdback for cross-event PHI/PCI interception. Exceeding a byte, event or duration limit closes upstream immediately, commits exactly one terminal failure outcome and omits the success terminal marker.

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

Emit structured metrics and logs for request ID, evidence status, commit latency, WAL synchronization, signer availability, keyring reload, Redis failure, queue depth, queue rejection, upstream status, circuit state, body-limit rejection, WAF decision, integrity verification and startup rejection. The implemented stream metrics are `aegis_stream_duration_seconds{provider,outcome}`, `aegis_stream_tokens_total{provider}`, and `aegis_stream_redactions_total{provider,entity}`. Do not invent queue gauges that the process does not expose, and do not log raw prompt content, response content, signing material or provider credentials.

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

## Forensic dashboard and export

The Next.js forensic dashboard reaches Aegis only from server route handlers. Configure `AEGIS_PRIMARY_BASE_URL` and `AEGIS_DASHBOARD_API_KEY` in the dashboard server environment; `aegis-client.server.ts` imports `server-only`, adds the bearer key on the server, disables caching and bounds backend responses. Never expose the audit key through `NEXT_PUBLIC_*` or browser code.

The dashboard export flow posts to its same-origin `/api/v1/forensics/export` route, which proxies `POST /v1/audit/forensics/export` and returns `application/zip`. The bounded ZIP contains a manifest and executable `VERIFY.sh`; preserve the archive bytes, run verification after extraction, and treat the package as technical integrity evidence rather than a legal-admissibility determination.

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
