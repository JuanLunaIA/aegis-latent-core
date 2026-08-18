# Aegis Latent Core deployment guide

This guide describes the **implemented** deployment contract. It does not grant regulatory certification. A production deployment must pass the repository release gates and an environment-specific review of kernel, storage, network, identity, secrets, backup, and incident-response controls.

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
| Signer | HMAC key with at least 32 bytes, Vault/HSM, or reviewed PQC signer |
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
python -m compileall -q aegis aegis_server
pytest -q
```

`requirements.txt` sets security floors and `requirements.lock` pins versions and hashes. `cryptography` is pinned at `50.0.0`, outside the audited affected range for `CVE-2026-69247` / `PYSEC-2026-3552`. Run the dependency scanner and generate the SBOM before creating an image.

## 4. Required configuration

Start from `.env.example`. At minimum, set these values through the deployment secret/configuration system:

```env
AEGIS_API_KEYS=<client-key>
AEGIS_AUDIT_API_KEYS=<read-only-audit-key>
AEGIS_SIGNING_KEY=<dedicated-secret-with-at-least-32-bytes>
AEGIS_BACKEND_URL=https://<approved-upstream>/v1
AEGIS_BACKEND_API_KEY=<provider-secret>
AEGIS_RATE_LIMIT_BACKEND=redis
AEGIS_REDIS_URL=rediss://<redis-host>:6380/0
AEGIS_WAL_PATH=/var/lib/aegis/aegis.wal.jsonl
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

Non-stream responses carry `X-Aegis-Request-ID`, `X-Aegis-Session-ID`, `X-Aegis-Analysis-Status`, and a preliminary `X-Aegis-Alert-Count`. The alert count is `0` before queued enrichment completes; authoritative enrichment records must be read from the audit/enrichment store. Stream responses are buffered under the configured bound so they cannot escape before evidence persistence.

## 7. Storage, backup, and key custody

The WAL is opened with owner-only permissions and fsynced on each committed node. Configure rotation and monitoring before the active WAL reaches its operational limit. Backups must preserve the original bytes, metadata, timestamps, hashes, access history, and restore-test results. A restored chain must pass `verify_integrity()` before it is accepted as evidence.

Key rotation is an evidence event. Retain the key identifier and verification material needed to validate historical records, or use a reviewed key-enveloping/signing architecture. HMAC is symmetric and therefore not equivalent to third-party non-repudiation; long-lived or high-value evidence should use an HSM/Vault or a reviewed hybrid/post-quantum design.

## 8. Health, telemetry, and alerts

Use `/health` for liveness and `/ready` for readiness. Alert on evidence commit failure, WAL fsync failure, integrity verification failure, Redis backend failure, queue saturation, upstream circuit opening, body-limit rejection spikes, and startup rejection caused by Seccomp or LSM posture. Preserve request IDs in structured logs and traces without logging raw secrets or unnecessary prompt content.

## 9. Go-live gates

| Gate | Required observable |
|---|---|
| Configuration | `strict` mode starts with authentication, durable evidence, strong signing, bounded body, required kernel controls, and distributed limiter |
| Supply chain | hash-checked lockfile, SBOM, vulnerability scan, license review, image digest and signing evidence |
| Functional | full test suite passes; P0/P1 failing-path tests pass |
| Evidence | a successful governed request produces a verifiable signed WAL record before `2xx` |
| Fault injection | signer, WAL, Redis, upstream, queue, Seccomp, and LSM failures reject or degrade only through documented fail-closed paths |
| Recovery | WAL backup/restore passes integrity verification and the rollback artifact is identified by digest |
| Operations | SLOs, alerts, on-call owner, incident runbook, key rotation, backup, and restore tests exist |

The reconstructed repository baseline recorded `5374 passed, 80 skipped, 47 warnings in 23.35s`. Warnings remain release telemetry and must be triaged; they are not evidence that the deployment environment satisfies the kernel or infrastructure gates.

## 10. Explicit non-goals

Aegis is not, by itself, a FedRAMP authorization, HIPAA compliance determination, SOC 2 opinion, EU AI Act conformity assessment, GDPR legal basis, or court-admissibility ruling. Those require organizational and jurisdiction-specific controls, independent review, and an accountable owner.
