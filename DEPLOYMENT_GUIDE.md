# Aegis Latent Core — Deployment Guide

This guide distinguishes the current `4.1.1` source/release candidate from historical external baselines. It is for platform, SRE, security and procurement reviewers. It does not claim a v4 publication, grant regulatory certification, create a production SLO or replace an environment-specific review of kernel, storage, network, identity, secrets, backup and incident-response controls.

**Last verified:** 2026-08-27 UTC
**Release baseline:** current source/release candidate
**Source/release candidate:** `4.1.1` with fourteen synchronized anchors; no external `v4.1.1` publication is claimed before readback
**Historical external baseline:** signed annotated `v4.0.2` tag at `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`, with GitHub Release and GHCR gateway/dashboard images read back on 2026-09-02; before it, lightweight `v4.0.1` at `6469904380218584ae0b5221334bc9a46500f5ba` with failed tag workflows; PyPI/npm observed at `4.0.0` without attributed provenance
**Audience:** Platform operators, SRE, security and procurement reviewers

## 1. Strict runtime contract

Production MUST use:

```env
AEGIS_SECURITY_ENFORCEMENT_MODE=strict
AEGIS_REQUIRE_DURABLE_EVIDENCE=true
AEGIS_REQUIRE_LSM=true
AEGIS_REQUIRE_SECCOMP=true
AEGIS_REQUIRE_DISTRIBUTED_LIMITER=true
AEGIS_RATE_LIMIT_BACKEND=redis
AEGIS_MAX_REQUEST_BODY_BYTES=1048576
```

Strict startup rejects disabled authentication, missing API keys, short HMAC material, missing required kernel enforcement, configured-but-unavailable PKCS#11 signing, and invalid backend URLs. A Redis outage does not open the request path: the rate limiter raises `RateLimitBackendUnavailable` and the HTTP layer returns `503`.

A governed successful response is permitted only after the forensic ledger has persisted and fsynced the request/response evidence. If the evidence commit fails, the request fails. The response analyzer is a bounded enrichment path and cannot weaken this gate.

## 2. Prerequisites

| Component | Required condition |
|---|---|
| Python | 3.11 or newer, matching the lockfile and CI runtime |
| Storage | Durable filesystem or enterprise storage; WAL must not be ephemeral |
| Signer | HMAC key with at least 32 bytes, versioned keyring, Vault/HSM, or reviewed PQC signer |
| Rate limiter | TLS-protected Redis in strict multi-worker deployments |
| Kernel | Seccomp filter and enforcing AppArmor/SELinux when required by configuration |
| Network | Explicit upstream URL, outbound policy, and application-layer egress allowlist where air-gap mode is enabled |
| Secrets | External secret manager or protected injection path; no secrets in images, repository, or WAL |

The Python fallback is a reference implementation, not a permission to omit production controls. The Rust extension may improve selected paths, but the strict gates do not rely on an optional accelerator being present.

## 3. Installation and dependency gate

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e .
python -m compileall -q aegis aegis_server
pytest -q
```

`requirements.txt` sets security floors and `requirements.lock` pins runtime versions and hashes. The editable `--no-deps` step installs the current source and its declared `aegis`/`aegis-server` console entry points without re-resolving that runtime set. `cryptography` is pinned at `50.0.0`, outside the audited affected range for `CVE-2026-69247` / `PYSEC-2026-3552`. Run the dependency scanner and generate the SBOM before creating an image.

For an isolated local evaluation with a mock upstream, start the source entry point as follows:

```bash
export AEGIS_SECURITY_ENFORCEMENT_MODE=development
export AEGIS_DEBUG_MODE=true
export AEGIS_AUTH_DISABLED=true
export AEGIS_BACKEND_URL='http://127.0.0.1:9001/v1'
export AEGIS_WAL_PATH='/tmp/aegis-evaluation.wal.jsonl'
aegis
```

Do not use this development profile for deployment evidence. For strict operation, configure every prerequisite below and use the same `aegis` entry point. The current source rejects the stale `permissive` mode value, and there is no `aegis.main` module.

## 4. Required configuration

Start from `.env.example`. At minimum, set these values through the deployment secret/configuration system:

```env
AEGIS_API_KEYS=<client-key>
AEGIS_AUDIT_API_KEYS=<read-only-audit-key>
AEGIS_SIGNING_KEY=<dedicated-secret-with-at-least-32-bytes>
# Or use the versioned keyring for zero-restart HMAC rotation:
# AEGIS_HMAC_KEYRING_PATH=/var/lib/aegis/secrets/hmac-keyring.json
# AEGIS_HMAC_KEYRING_RELOAD_INTERVAL_S=1
AEGIS_BACKEND_URL=https://<approved-upstream>/v1
AEGIS_BACKEND_API_KEY=<provider-secret>
AEGIS_RATE_LIMIT_BACKEND=redis
AEGIS_REDIS_URL=rediss://<redis-host>:6380/0
AEGIS_WAL_PATH=/var/lib/aegis/aegis.wal.jsonl
AEGIS_STREAM_QUEUE_MAX_ITEMS=64
AEGIS_STREAM_QUEUE_MAX_BYTES=1048576
AEGIS_MAX_STREAM_EVENT_BYTES=65536
AEGIS_STREAM_DEIDENTIFIER_WINDOW_CHARS=128
```

The backend URL must be absolute `http` or `https`, include a hostname, and contain no userinfo. When `AEGIS_AIRGAP_MODE=true`, every outbound destination must match the canonical allowlist. URL schemes, userinfo, malformed ports, and unsupported protocols are rejected.

## 5. Deployment topology

A recommended topology places a TLS/mTLS ingress in front of Aegis, runs Aegis on a private network, places Redis on a protected TLS network, stores WAL data on durable storage, and restricts egress to approved upstreams. Multiple Aegis replicas require a distributed rate limiter and a shared, independently durable evidence strategy; a local WAL per replica is not a substitute for centralized custody.

The process should run with a read-only root filesystem, a dedicated non-root identity, dropped Linux capabilities, a Seccomp profile, an enforcing AppArmor/SELinux profile, bounded CPU and memory, and an explicit writable mount only for the evidence path. Network namespaces, nftables, cloud egress policies, and Kubernetes NetworkPolicy remain necessary defense-in-depth; the application EgressGuard does not replace them.

## 6. Request and evidence lifecycle

```text
client
  -> authentication
  -> bounded body read and canonicalization
  -> WAF/session policy
  -> Redis rate-limit decision
  -> upstream request
  -> durable signed forensic commit
  -> bounded response-analysis enqueue
  -> client response
```

Non-stream responses carry `X-Aegis-Request-ID`, `X-Aegis-Session-ID`, `X-Aegis-Analysis-Status`, and a preliminary `X-Aegis-Alert-Count`. The alert count is `0` before queued enrichment completes; authoritative enrichment records must be read from the audit/enrichment store.

SSE is not fully buffered. `BoundedStreamProxy` emits sanitized canonical events incrementally through a queue bounded by item count and retained bytes, computes SHA-256 incrementally over the exact emitted bytes, and retains only a bounded preview plus finite de-identification holdback. Initial `X-Aegis-Evidence-Status` and `X-Aegis-Proof-Status` are `pending-terminal`. The proxy performs exactly one terminal summary commit before emitting OpenAI `[DONE]` or Anthropic `message_stop`; limit and error outcomes close upstream, commit once and omit that success marker. The `Link` header points to authenticated `GET /v1/audit/proofs/{request_id}` for post-terminal proof lookup.

OpenAI-compatible clients use `/v1/chat/completions`. Native Anthropic clients use `/v1/messages`, which requires `AEGIS_PROVIDER=anthropic`. The provider-native Python and TypeScript SDK wrappers preserve the official clients' resources, streaming iterators and errors while changing routing and Aegis headers.

## 7. Storage, backup, and key custody

The authoritative JSONL WAL is opened with owner-only permissions and fsynced on each committed node. When the native extension is available, `<wal_path>.stream.rwal` is an optional 256 MiB CRC-framed `RustWal` copy of committed stream terminal nodes; JSONL remains the replay authority. Configure rotation and monitoring before the active WAL reaches its operational limit. Backups must preserve the original bytes, metadata, timestamps, hashes, access history, and restore-test results. A restored chain must pass `verify_integrity()` before it is accepted as evidence.

Key rotation is an evidence event. The versioned keyring has exactly one active key, supports non-expired verification overlap, records a non-secret key ID, validates a complete snapshot before atomic activation, and retains the last valid snapshot when a replacement is malformed. Use [`docs/operations/KEY_ROTATION_RUNBOOK.md`](docs/operations/KEY_ROTATION_RUNBOOK.md) for the sequence and rollback. A three-replica zero-downtime claim requires a real orchestrated run; unit tests alone are not deployment evidence. HMAC is symmetric and therefore not equivalent to third-party non-repudiation; long-lived or high-value evidence should use an HSM/Vault or a reviewed hybrid/post-quantum design.

## 8. Required market-hardening scenarios

### Backpressure under I/O stall

Run the repository harness against an isolated local ledger:

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_backpressure_stall.py \
  --duration-s 0.25 --offered-rps 10000 --fsync-delay-ms 2 --max-workers 64 \
  --output evidence/backpressure_stall_report.json
```

The gate requires zero missing evidence IDs, zero duplicate IDs, valid chain integrity, and no silent drop. The retained candidate run recorded 10,000 offered requests, 10,000 durable commits, zero failures, zero missing IDs, zero duplicate IDs, valid chain integrity, and p99 commit latency of 1,189.89 ms. This is offered load and injected latency, not accepted production capacity. A `dm-delay` run is separate and remains unexecuted in the retained release evidence; it must use a disposable device with verified isolation.

### WAF evasion boundary

Run `tools/security/run_waf_corpus.py` against the pinned local corpus. The gate is zero critical bypasses and an observed bypass rate below 5% for that corpus. HTTP/2 fragmentation and `nuclei-templates/waf-bypass` are not passed by this application-layer run; they require a pinned authorized ingress target and retained artifacts.

### Key rotation

Use the versioned keyring with a secret manager and run three replicas through activation, overlap verification, expiry, restart/replay, and rollback. The gate is zero failed durable commits during the declared valid rotation window and zero unverifiable records. The retained result covers three independent local signer instances and atomic keyring replacement, not a real orchestrator or secret-manager acceptance path. If the actual three-replica orchestrator and secret-manager path are not available, mark that deployment claim `UNVERIFIED`.

### ML-DSA timing

A constant-time statement is not approved. The retained native experiment used 1,000,000 interleaved samples per declared operation with raw samples and a retained environment manifest. `sign` returned `p=0.8521504207157158`, which is non-detection under this experiment. `verify` returned `p=0.0` with a measured class-dependent difference, so the verify claim is blocked. A p-value does not prove constant-time execution, compiler resistance, microarchitectural resistance, or FIPS 140 validation.

## 9. Health, telemetry, and alerts

Use `/health` for liveness and `/ready` for readiness. The implemented streaming metric series are `aegis_stream_duration_seconds{provider,outcome}`, `aegis_stream_tokens_total{provider}`, and `aegis_stream_redactions_total{provider,entity}`. Alert on evidence commit failure, WAL fsync failure, integrity verification failure, Redis backend failure, queue saturation observed through resource behavior, upstream circuit opening, body-limit rejection spikes, and startup rejection caused by Seccomp or LSM posture. Preserve request IDs in structured logs and traces without logging raw secrets or unnecessary prompt content.

The optional Next.js forensic dashboard must keep `AEGIS_DASHBOARD_API_KEY` server-only and use `AEGIS_PRIMARY_BASE_URL` from its server environment. Its route handlers proxy bounded, `no-store` requests; never publish the key as `NEXT_PUBLIC_*`. The export UI proxies `POST /v1/audit/forensics/export` and downloads an `application/zip` bundle containing `manifest.json` and `VERIFY.sh`.

## 10. Go-live gates

| Gate | Required observable |
|---|---|
| Configuration | `strict` mode starts with authentication, durable evidence, strong signing, bounded body, required kernel controls, and distributed limiter |
| Supply chain | hash-checked lockfile, SBOM, vulnerability scan, license review, image digest and signing evidence |
| Functional | full test suite passes; P0/P1 failing-path tests pass |
| Evidence | a successful governed request produces a verifiable signed WAL record before `2xx` |
| Fault injection | signer, WAL, Redis, upstream, queue, Seccomp, LSM, WAF, and fsync-stall failures reject or degrade only through documented fail-closed paths |
| Scenario acceptance | backpressure, WAF corpus, three-replica key rotation, and native ML-DSA timing are separately measured with explicit `UNVERIFIED` boundaries when unavailable |
| Recovery | WAL backup/restore passes integrity verification and the rollback artifact is identified by digest |
| Operations | SLOs, alerts, on-call owner, incident runbook, key rotation, backup, and restore tests exist |

The final v3.1.0 release run recorded `5442 passed, 37 skipped, 47 warnings` in approximately `68.08 s`, with `93.91%` measured coverage in the retained run. Warnings remain release telemetry and must be triaged; they are not evidence that the deployment environment satisfies the kernel or infrastructure gates. See the retained final pytest log and release-gate record.

## 11. Explicit non-goals

Aegis is not, by itself, a FedRAMP authorization, HIPAA compliance determination, SOC 2 opinion, EU AI Act conformity assessment, GDPR legal basis, or court-admissibility ruling. Those require organizational and jurisdiction-specific controls, independent review and an accountable owner.

## Related documents

- [`README.md`](README.md)
- [`docs/DEVELOPER_QUICKSTART.md`](docs/DEVELOPER_QUICKSTART.md)
- [`docs/PLATFORM_OPERATOR_GUIDE.md`](docs/PLATFORM_OPERATOR_GUIDE.md)
- [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md)
- [`docs/operations/BACKPRESSURE_RUNBOOK.md`](docs/operations/BACKPRESSURE_RUNBOOK.md)
- [`docs/operations/KEY_ROTATION_RUNBOOK.md`](docs/operations/KEY_ROTATION_RUNBOOK.md)
- [`docs/operations/ROLLBACK_RUNBOOK.md`](docs/operations/ROLLBACK_RUNBOOK.md)
- [`docs/security/THREAT_MODEL.md`](docs/security/THREAT_MODEL.md)
- [`docs/CLAIMS_MATRIX.md`](docs/CLAIMS_MATRIX.md)
