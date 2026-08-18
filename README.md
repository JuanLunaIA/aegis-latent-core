# Aegis Latent Core

Aegis Latent Core is an OpenAI-compatible LLM gateway with request policy enforcement, durable forensic evidence, and bounded asynchronous response enrichment. The repository is designed for **auditable deployment**, not for self-declared regulatory certification.

## Security posture

The default runtime mode is `strict`. In this mode the application refuses to serve traffic unless authentication, durable evidence, strong signing, request-size bounds, distributed rate limiting, and required kernel capabilities are satisfied. Development mode is explicit and must not be used as production evidence.

A governed request follows this order:

1. Authenticate the caller.
2. Enforce the request-body limit and canonicalize JSON.
3. Apply WAF and session-behavior checks.
4. Apply the configured rate limiter. A Redis failure raises `RateLimitBackendUnavailable`; the request is rejected rather than allowed through.
5. Forward the request to the configured upstream.
6. Persist the request and complete response through the forensic ledger. The ledger fsyncs the WAL before the request receives a successful response.
7. Enqueue optional response analysis on a bounded worker queue. Queue saturation is observable and does not weaken the evidence gate.

For streaming requests, the response is buffered under the configured bound, committed as durable evidence, and only then emitted as SSE. This is intentional: a successful governed response without durable evidence is forbidden by the strict contract.

## What is and is not guaranteed

| Control | Implemented behavior | Verification |
|---|---|---|
| Evidence durability | Request/response evidence is committed and fsynced before a governed `2xx` response. | `tests/test_p0_release_gates.py`, ledger tests |
| Strong signing | Strict ledgers reject the ephemeral Ed25519 fallback. HMAC-SHA256, configured HSM, or configured PQC signer must be available. | `test_strong_ledger_rejects_ephemeral_fallback` |
| Chain integrity | Node hashes bind predecessor, request hash, response hash, Merkle root, and signature. | `verify_integrity()` and crypto tests |
| Rate limiting | Redis backend failures raise and produce a `503` at the HTTP boundary. | `tests/test_ratelimiter_new.py` |
| Request bounds | Body-size middleware rejects oversized bodies before application processing. | `tests/test_p0_release_gates.py` |
| Kernel controls | Strict startup requires configured Seccomp and LSM/AppArmor/SELinux enforcement. Non-sandbox enforcement failures raise. | `tests/test_seccomp_extended.py`, `tests/test_lsm_guard_new.py` |
| Response analysis | Analysis is executed by bounded workers and serialized per session; it is not required for evidence durability. | analyzer and proxy integration tests |
| Egress | Air-gap allowlists accept canonical host/IP entries only; schemes, userinfo, malformed ports, and unsupported URLs are blocked. | `tests/test_egress_guard.py` |

The repository does **not** by itself constitute FedRAMP, HIPAA, SOC 2, EU AI Act, GDPR, or legal certification. Those outcomes require organizational controls, deployment evidence, independent assessment, and jurisdiction-specific review.

## Runtime requirements

Python 3.11+ is supported by the project configuration. The lockfile pins dependencies and includes hashes. `cryptography` is pinned at `50.0.0` to stay outside the affected range of the audited `CVE-2026-69247` / `PYSEC-2026-3552` advisory. The runtime also requires the configured upstream, a strong signing key or signing backend, and a distributed rate-limit backend in strict deployments.

The following variables are minimum strict-runtime controls:

```bash
export AEGIS_SECURITY_ENFORCEMENT_MODE=strict
export AEGIS_API_KEYS='replace-with-a-secret-key'
export AEGIS_SIGNING_KEY='at-least-32-bytes-of-secret-material'
export AEGIS_RATE_LIMIT_BACKEND=redis
export AEGIS_REDIS_URL='rediss://redis.internal:6380/0'
export AEGIS_REQUIRE_DISTRIBUTED_LIMITER=true
export AEGIS_REQUIRE_DURABLE_EVIDENCE=true
export AEGIS_REQUIRE_LSM=true
export AEGIS_REQUIRE_SECCOMP=true
export AEGIS_MAX_REQUEST_BODY_BYTES=1048576
export AEGIS_BACKEND_URL='https://llm.internal.example/v1'
export AEGIS_WAL_PATH='/var/lib/aegis/aegis.wal.jsonl'
```

Do not commit real keys, bearer tokens, WAL data, or provider credentials. Use a secret manager and mount the WAL on durable storage with owner-only permissions.

## Installation and verification

Use the repository lockfile in a clean environment. The exact command depends on the operator's Python packaging policy; the release gate requires hash-checked installation from `requirements.lock` and a dependency/SBOM scan before deployment.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m compileall -q aegis aegis_server
pytest -q
```

The reconstruction baseline was verified with:

```text
5374 passed, 80 skipped, 47 warnings in 23.35s
```

The warning count is retained as release telemetry; it is not converted into a success claim. The test suite is the behavioral gate, while the deployment gate must additionally validate the actual kernel, LSM, Redis, TLS, storage, and signer environment.

## Observability contract

Every governed request receives `X-Aegis-Request-ID` and `X-Aegis-Session-ID`. The response-analysis state is exposed through `X-Aegis-Analysis-Status` with values `queued` or `not-sampled`. `X-Aegis-Alert-Count: 0` is a preliminary count because enrichment runs after the durable evidence commit; authoritative alerts are available from the audit/enrichment record, not from that preliminary header.

Operators must alert on evidence-commit failures, WAL fsync failures, rate-limit backend failures, queue saturation, Seccomp/LSM startup rejection, upstream circuit opening, and integrity-verification failure. A request must not be retried as successful when its evidence commit failed.

## Repository layout

| Path | Purpose |
|---|---|
| `aegis/proxy/app.py` | FastAPI proxy lifecycle, authentication, request controls, evidence gate, and bounded enrichment queue |
| `aegis/core/crypto_audit.py` | Canonical forensic ledger, Merkle chain, signatures, WAL persistence, and integrity verification |
| `aegis/core/ratelimiter.py` | In-memory development limiter and fail-closed Redis limiter |
| `aegis/core/seccomp_guard.py` | Seccomp capability and enforcement guard |
| `aegis/core/lsm_guard.py` | AppArmor/SELinux detection and strict assertion |
| `aegis/proxy/egress_guard.py` | Canonical air-gap egress allowlist |
| `aegis_server/` | Enterprise persistence and compliance API lifecycle |
| `tests/test_p0_release_gates.py` | Blocking P0/P1 regression tests |
| `requirements.txt` | Version floors and advisory remediation constraints |
| `requirements.lock` | Pinned, hash-checked dependency resolution |

## Non-goals and residual risk

Application-layer egress controls do not replace network namespaces, nftables, Kubernetes NetworkPolicy, or cloud egress policy. HMAC-SHA256 is not quantum-resistant; deployments with long-lived evidence or quantum-sensitive threat models should use a reviewed hybrid or post-quantum signing architecture. Strict startup proves that configured controls are present at process initialization; it does not prove that an external provider, filesystem, kernel, or network remains healthy indefinitely. Continuous monitoring, key rotation, backup, restore testing, and independent review remain operational requirements.

## License

The repository is licensed under the terms in `LICENSE` and `COMMERCIAL.md`.
