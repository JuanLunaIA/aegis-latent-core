# Aegis Latent Core

**AI governance and evidence gateway for multi-provider LLM applications.**

Aegis Latent Core is an OpenAI-compatible gateway that applies request policy, WAF, egress, rate-limit, and session controls before forwarding traffic to an upstream model provider. For governed traffic, it builds a canonical evidence record, signs the record, commits it to a durable write-ahead log, and exposes the evidence status to the caller. Optional response enrichment runs behind a bounded queue and is never a substitute for the authoritative evidence commit.

> **Product boundary:** Aegis is an AI Governance and Evidence Gateway. It is not an LLM, a universal WAF, a compliance certification, a legal-admissibility ruling, a production SLO, or a replacement for network, identity, privacy, retention, or incident-response controls.

[![Release](https://img.shields.io/github/v/release/JuanLunaIA/aegis-latent-core?display_name=tag&sort=semver)](https://github.com/JuanLunaIA/aegis-latent-core/releases)
[![CI](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml/badge.svg)](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml)
[![Security](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/security.yml/badge.svg)](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-AGPLv3%20%2B%20commercial-blue.svg)](LICENSE)

**Last verified:** 2026-08-24 UTC
**Release baseline:** published [`v3.1.0`](https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v3.1.0)
**Current-main baseline:** post-PR #99, commit `45d95188d40792639fdd654369765a7233bef09a`

## Baselines and claim scope

The published release baseline is **v3.1.0**. The repository state described as **current main** is commit `45d95188d40792639fdd654369765a7233bef09a` after PR #99. Streaming SSE with bounded `pending-terminal` evidence, native Anthropic `POST /v1/messages`, the Python and TypeScript SDKs, portable MMR proofs, the forensic dashboard and ZIP export, the auxiliary `RustWal` stream segment, and the SSE benchmark are current-main capabilities; they are **not attributed to the v3.1.0 tag**. Release evidence and current-main implementation evidence must be evaluated separately.

## Who should evaluate Aegis

Aegis is intended for platform, application-security, and AI-engineering teams operating more than one model provider or requiring provider-independent evidence for governed AI traffic. The initial commercial focus is B2B SaaS, fintech, and regulated enterprise platform teams that need private deployment and verifiable evidence but are not asking this repository to become a universal authorization or certification product.

The relevant buyer committee typically includes the CISO or AppSec owner, platform engineering, AI/ML engineering, compliance or legal, procurement, and an executive sponsor. The recommended proof sequence is **local evaluation → evidence replay → controlled pilot → security review → procurement package → production rollout**.

## The problem Aegis addresses

Standard access logs can show that an API call occurred. They do not, by themselves, establish the exact governed request and response hashes, the policy path, the evidence commit boundary, the signing scheme, the chain predecessor, or whether the request was rejected before or after the evidence boundary. Aegis makes those transitions explicit and verifiable under declared deployment controls.

## Request and evidence lifecycle

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Aegis Gateway
    participant W as Policy/WAF/Egress
    participant U as Upstream Model
    participant L as Signed WAL
    participant Q as Bounded Enrichment

    C->>A: Authenticated OpenAI-compatible or Anthropic request
    A->>W: Size, canonicalization, WAF, session, rate-limit
    W-->>C: Fail-closed response + durable error evidence when rejected
    W->>U: Forward only after admission
    U-->>A: Complete response or bounded SSE events
    A->>L: Non-stream: hash, sign, append, flush, fsync
    L-->>A: Non-stream durable evidence status
    A->>Q: Optional bounded response analysis
    A-->>C: Non-stream response + portable MMR proof headers
    A-->>C: Stream events through bounded queue
    A->>L: Stream terminal summary, sign, append, flush, fsync
    L-->>A: Terminal commit complete
    A-->>C: Protocol terminal marker
```

The strict lifecycle is:

1. Authenticate the caller and assign a request identifier.
2. Enforce request-size bounds and canonicalize the request representation.
3. Apply WAF, session-behavior, egress, and rate-limit controls.
4. Reject on a required-control failure instead of silently weakening the security path.
5. Forward to the configured upstream provider.
6. For non-streaming calls, capture the response, compute canonical hashes, sign the evidence, append to the WAL, flush, and `fsync` before returning it.
7. For SSE calls, relay sanitized logical events through a byte-accounted bounded queue. Incrementally hash the exact emitted bytes; on termination, commit one signed terminal summary before emitting the protocol terminal marker. The initial streaming header is therefore `X-Aegis-Evidence-Status: pending-terminal`, not `durable`.
8. Run optional response enrichment through a bounded worker path after the authoritative record exists.

## Core contract

| Control | Implemented behavior | Evidence and boundary |
|---|---|---|
| Evidence durability | For non-streaming governed calls, the core proxy commits request/response evidence before returning and emits `X-Aegis-Evidence-Status: durable`. Streaming SSE starts with `pending-terminal`; one signed terminal summary is committed before the protocol terminal marker, and the proof is retrieved after termination. | `tests/test_p0_release_gates.py`, `tests/test_proxy_streaming.py`, proxy failure-path tests and WAL integrity tests. The target filesystem and storage provider still require deployment validation. |
| Durable terminal errors | Upstream non-2xx responses, circuit-open paths, and network faults use the durable error-evidence path when the evidence boundary is available. | `tests/test_enterprise_durable_evidence.py` and v3.1.0 release evidence. A storage failure after admission is a fail-closed operational incident, not a successful response. |
| Chain integrity | Audit nodes bind predecessor, request hash, response hash, Merkle root, signature, and scheme metadata. | `aegis/core/crypto_audit.py` and `verify_integrity()`. Detection of tampering is not the same as immutable external storage. |
| Strong signing | Strict ledgers reject the ephemeral Ed25519 fallback. HMAC-SHA256, configured PKCS#11, or configured native signing must satisfy the selected policy; the legacy HSM interface now fails closed instead of deriving a software key. | Signer tests and strict startup gates. Mocked PKCS#11 tests are adapter evidence only, HMAC is symmetric, and no HSM interoperability, key non-exportability, FIPS validation, or third-party non-repudiation is established. |
| Key rotation | The enterprise signer supports an atomic, versioned HMAC keyring with one active key, historical verify keys, explicit expiry, and non-secret `key_id` metadata. | `aegis_server/crypto/keyring.py`, `tests/test_keyring_rotation.py`. Three-replica deployment evidence remains required for a production claim. |
| Rate limiting | Redis-backed distributed limiting fails closed when the backend is unavailable; development in-memory limiting is not a production substitute. | Rate-limiter tests and deployment configuration. Redis/TLS/HA behavior is deployment-dependent. |
| Enterprise identity and tenant binding | The unreleased candidate derives immutable principals from configured API-key mappings, strict OIDC claims, or explicitly pinned mTLS certificates. Tenant/session headers do not select the evidence tenant or quota key. | `aegis/auth/`, `aegis/proxy/dependencies.py`, and auth integration tests. IdP, TLS terminator, certificate lifecycle, and Redis acceptance remain deployment-dependent; current mTLS source is leaf-pin mode, not universal PKI validation. |
| Finalized-segment archival | Rotated JSONL WAL segments receive versioned manifests and can be uploaded through the optional S3 Object Lock adapter with SHA-256, version, lock-mode, and retention verification. Optional RFC 3161 acceptance requires OpenSSL verification against an explicit CA file. | `aegis/storage/`, `aegis/anchoring/`, and focused tests. This is not a regulatory WORM, legal-admissibility, or external-time guarantee without target acceptance. |
| Privacy-safe telemetry | Closed-schema security events omit prompt/response/token text, embeddings, raw tenant/session identifiers, signer names, and exception strings; an optional bounded SQLite spool exports to supported SIEM encodings. | `aegis/telemetry/` and privacy sentinel tests. Downstream delivery, retention, access control, and operational SLOs are external. |
| Capability reporting | `aegis.crypto` exposes a machine-readable inventory that distinguishes implemented, optional-runtime, stub, and external-validation-required states. | `aegis/crypto/capabilities.py` and focused tests. The current ZK API is a non-real test stub, portable MMR proofs grow O(log n), and no FIPS validation is claimed. |
| TEE attestation boundary | TEE device nodes are reported as discovery only. Caller-authored legacy reports are rejected; an injected verifier can provide authenticated normalized claims for exact measurement, signer, nonce, freshness, debug, TCB, and report-data policy evaluation. | `aegis/core/tee_manager.py` and hardware-module tests. The repository does not implement an enclave loader, vendor quote parsing, certificate/collateral validation, host-root confidentiality, or target attestation acceptance. |
| Differential-privacy boundary | An internal Laplace count primitive uses sensitivity one and a system CSPRNG for one release under add/remove-one-record adjacency. | `aegis/core/dp_analytics.py` and deterministic tests. No DP HTTP endpoint is published; repeated releases require a durable accountant, stable dataset/query identity, memoization, and reviewed contribution bounds that are not implemented here. |
| Fuzzing capability boundary | Fuzzing is available only when `cargo`, `cargo-fuzz`, a private workspace, a bounded parseable manifest, and all exact confined regular target files exist; run state distinguishes clean, crash artifact, tool error, timeout, and unavailable. | `aegis/core/fuzzing_harness.py` and focused tests. The current tree has no cargo-fuzz workspace or Kani harness, measured coverage remains unavailable, and bounded tests are not exhaustive proof. |
| Advisory AI context | `.aegis_ai_context/`, `llms.txt`, and `.cursorrules` provide repository navigation and claim boundaries for coding assistants. | Offline context tests validate structure and links. These files are advisory data: they cannot override authorization, establish runtime behavior, or turn current-main source into a release. |
| Request bounds | Oversized bodies are rejected before normal application processing. | P0/P1 release tests. Limits must be sized for the deployed provider and streaming policy. |
| WAF | NFKC normalization, zero-width stripping, critical pattern blocks, structural depth guard, and weighted local analysis run at the application boundary. | `tests/data/waf_corpus_v1.json` and `tools/security/run_waf_corpus.py`. Ingress HTTP/2 parsing is outside the application boundary. |
| Egress | Canonical allowlists reject schemes, userinfo, malformed ports, unsupported forms, and non-approved endpoints. | `aegis/proxy/egress_guard.py` and tests. This does not replace firewall, namespace, NetworkPolicy, or cloud egress controls. |
| Kernel controls | Strict startup can require Seccomp and LSM/AppArmor/SELinux capabilities and rejects missing enforcement outside explicit sandbox mode. | `aegis/core/seccomp_guard.py`, `aegis/core/lsm_guard.py`, deployment tests. The target kernel still needs acceptance testing. |
| Response enrichment | Analysis is bounded, observable, and serialized per session where required. It is optional and cannot weaken the durable evidence contract. | Analyzer and queue tests. Queue behavior under real I/O saturation is described in the backpressure runbook. |
| Portable inclusion proof | Every new ledger record stores a self-contained `aegis-mmr-inclusion-v1` proof, leaf digest, ordered peaks, and root. Non-streaming responses return these as `X-Aegis-MMR-*` headers; streamed calls expose an authenticated post-terminal proof link. | Cross-language golden vectors and WAL-replay/tamper tests. A valid proof establishes inclusion in the declared MMR root; it does not by itself establish external timestamping, retention, or legal admissibility. |

## Quickstart for local evaluation

The local path is for development, tests, and evidence replay. It is not a production deployment profile.

```bash
git clone https://github.com/JuanLunaIA/aegis-latent-core.git
cd aegis-latent-core
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m compileall -q aegis aegis_server
pytest -q
```

For a minimal local gateway, use the repository’s example configuration and a local or mocked upstream. Never put provider keys, bearer tokens, signing secrets, WAL records, or customer payloads into source control.

## Current-main SDKs

The current-main Python distribution in [`sdk/python`](sdk/python) is a drop-in integration that subclasses the official OpenAI and Anthropic clients. Existing request/response model types and sync/async resource APIs are preserved while Aegis tenant, session, and bearer-auth headers are injected at construction. The native Anthropic `/v1/messages` ingress requires `AEGIS_PROVIDER=anthropic`; it preserves the Anthropic Messages response shape instead of translating it to OpenAI objects.

The edge-compatible current-main TypeScript package in [`sdk/typescript`](sdk/typescript) verifies `aegis-mmr-inclusion-v1` proofs with Web Crypto and supplies provider-native wrappers and constructor options rather than re-declaring provider payloads. The official OpenAI and Anthropic packages are peer dependencies, so their native resources, request parameters, response models, streaming iterators, retries and error types remain authoritative. Both SDKs consume the same frozen proof vectors under `sdk/shared/`.

The unreleased Python SDK candidate also includes privacy-minimized LangChain and LlamaIndex callback adapters. Publication workflows are disabled unless external trusted-publisher, environment, signed-tag, and repository-variable prerequisites are configured. See [`docs/DEVELOPER_INTEGRATIONS_GUIDE.md`](docs/DEVELOPER_INTEGRATIONS_GUIDE.md).

```python
from aegis_sdk.openai import OpenAI

client = OpenAI(
    aegis_api_key="gateway-token",
    gateway_url="https://aegis.internal",
    tenant_id="tenant-42",
)
response = client.chat.completions.create(
    model="gpt-4.1-mini",
    messages=[{"role": "user", "content": "hello"}],
)
```

Proof verification is opt-in because callers must obtain the trusted MMR root through an independently approved channel. Enabling verification while trusting the root from the same untrusted response would detect corruption but would not provide an independent trust anchor.

## Current-main forensic audit dashboard

The current-main [`dashboard`](dashboard) is a read-only Next.js 16 and React 19 interface. It renders only authenticated gateway data: overview health, a filterable retained-window ledger, canonical JCS and DAG-CBOR node projections with CIDv1 identifiers, an interactive MMR verifier with a local Web Crypto sandbox, live Prometheus-derived metrics, and a bounded forensic export workflow. It contains no fallback sample data.

```bash
cd sdk/typescript && npm ci && npm run build
cd ../../dashboard && npm ci
export AEGIS_PRIMARY_BASE_URL='https://aegis.internal'
export AEGIS_DASHBOARD_API_KEY='retrieve-from-your-secret-manager'
npm run dev
```

`AEGIS_DASHBOARD_API_KEY` is server-only and is never serialized into browser bundles. The export endpoint requires the `audit:export` scope when per-key scopes are configured. Each bounded ZIP contains an RFC 8785 JCS `manifest.json`, canonical DAG-CBOR `ledger_slice.cbor` identified by CIDv1, `merkle_proof.json`, `audit_certificate.pdf`, and `VERIFY.sh`. The certificate is a technical integrity report, not a certification or legal-admissibility conclusion.

## Strict deployment path

Strict mode is the intended production posture. It requires authentication, durable evidence, strong signing, bounded request bodies, a distributed rate-limit backend, durable storage, and the configured kernel controls. Use a secret manager and mount the WAL on a durable, owner-readable path.

```bash
export AEGIS_SECURITY_ENFORCEMENT_MODE=strict
export AEGIS_API_KEYS='replace-with-a-secret-manager-reference'
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

For zero-restart HMAC rotation, configure an owner-readable keyring path instead of relying on a single process-start secret:

```bash
export AEGIS_SIGNER_PROVIDER=hmac
export AEGIS_HMAC_KEYRING_PATH='/var/lib/aegis/secrets/hmac-keyring.json'
export AEGIS_HMAC_KEYRING_RELOAD_INTERVAL_S=1
```

The keyring protocol, overlap window, expiry, rollback, and three-replica acceptance criteria are in [`docs/operations/KEY_ROTATION_RUNBOOK.md`](docs/operations/KEY_ROTATION_RUNBOOK.md). A keyring path is not a secret manager; the deployment must still establish custody, access control, atomic delivery, backup, destruction, and auditability.

## Evidence and signing model

The local ledger is an append-only JSONL WAL with an in-memory bounded chain and optional archived segments. Each record contains request and response hashes, chain linkage, a Merkle root, signature metadata, and the request identifier. The WAL is flushed and synchronized before the durable response path completes.

Supported signing choices are deployment-dependent:

| Signer | Appropriate boundary | Important limitation |
|---|---|---|
| HMAC-SHA256 | Single-node or shared-secret self-hosted deployments | Symmetric key; every verifier that holds the key can also sign. HMAC is classical, not quantum-resistant. |
| HSM/Vault-backed signer | Enterprise deployments requiring key isolation or remote custody | Availability, policy, TLS/mTLS, rotation, and offline verification require the target deployment’s own evidence. |
| Native ML-DSA-65 signer | Environments that build and load the real Rust backend | The retained 1M-sample candidate artifact found no significant timing difference for `sign` (`p=0.8521504207157158`) but did not meet the threshold for `verify` (`p=0.0`); no constant-time claim is approved. See [`docs/security/PQC_CONSTANT_TIME.md`](docs/security/PQC_CONSTANT_TIME.md). |

Aegis does not fabricate ML-DSA signatures when the native backend is unavailable. It reports the backend as unavailable and requires an explicit real fallback policy. A timing result with `p > 0.05` would mean only that statistically significant leakage was not detected under the named experiment; it would not prove constant-time execution.

## Backpressure and failure semantics

Durable evidence is a hot-path invariant. Under storage or `fsync` stall, the request path may block or reject according to the configured bounds; it must not silently drop authoritative evidence. The enrichment queue may reject optional work, but a queue policy cannot turn a governed accepted response into an unrecorded response.

The deterministic fault-injection harness is:

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_backpressure_stall.py \
  --duration-s 0.25 --offered-rps 10000 --fsync-delay-ms 2 --max-workers 64 \
  --output evidence/backpressure_stall_report.json
```

The retained v3.1.0 run offered 10,000 requests at 10,000 RPS with a 2 ms injected `fsync` delay. It recorded 10,000 durable commits, zero failures, zero missing IDs, zero duplicate IDs, and valid chain integrity. The observed p99 commit latency was 1,189.89 ms. This is a bounded fault-injection result with substantial queueing. It is not a production capacity or SLO claim. See [`docs/operations/BACKPRESSURE_RUNBOOK.md`](docs/operations/BACKPRESSURE_RUNBOOK.md).

## WAF and ingress boundary

The local corpus currently covers 15 executable malicious cases and 8 benign cases. The v3.1.0 candidate run recorded zero observed bypasses and zero benign false positives for that pinned corpus. Because the corpus is small, its confidence interval is wide; the result is a regression signal, not universal detection coverage.

The application harness does not execute HTTP/2 fragmentation, pseudo-header ordering, continuation-boundary differentials, compressed-body parser differences, or ingress-specific normalization. `nuclei-templates/waf-bypass` is not treated as executed unless a pinned revision runs against an authorized disposable local target and produces a retained artifact. See [`docs/security/WAF_TESTING.md`](docs/security/WAF_TESTING.md).

## Observability and operations

Governed responses expose `X-Aegis-Request-ID`, `X-Aegis-Session-ID`, `X-Aegis-Evidence-Status`, `X-Aegis-Analysis-Status`, and, after a non-streaming durable commit, the `X-Aegis-MMR-Format`, `X-Aegis-MMR-Leaf`, `X-Aegis-MMR-Proof`, and `X-Aegis-MMR-Root` proof headers. Streaming responses expose a `Link` to `/v1/audit/proofs/{request_id}` and remain `pending-terminal` until the authenticated terminal lookup succeeds. Authoritative records are in the evidence store.

Operators should alert on evidence-commit failures, WAL synchronization failures, rate-limit backend failures, queue saturation, circuit opening, upstream error spikes, keyring reload failures, missing key overlap, signer unavailability, Seccomp/LSM startup rejection, and integrity-verification failure. Preserve WAL segments and reports read-only during incident handling. Roll back to the prior signed/image-digest release when a kill criterion is met.

On current main, when the PyO3 extension is available, each terminal streaming record is also appended once to an auxiliary CRC32-framed, memory-mapped `RustWal` segment at `<AEGIS_WAL_PATH>.stream.rwal` inside the same executor call that performs the authoritative JSONL ledger commit. The native segment is bounded to 256 MiB. If its append fails after the JSONL commit, Aegis increments `aegis_native_stream_wal_errors_total`, logs the degradation, disables the auxiliary segment for the process and preserves the client-visible terminal marker because the JSONL chain remains the replay authority. Streaming telemetry also exposes duration histograms, token counters and bounded-category redaction counters without payload labels.

## Deployment topologies

| Topology | Use | Evidence boundary | Open risk |
|---|---|---|---|
| Single process / single durable WAL | Local evaluation and small self-hosted deployments | One process owns the chain and storage path | Process, volume, and key custody are single failure domains. |
| One worker per pod | Horizontal application scaling with independent local bundles | Each pod produces an independently verifiable bundle | Cross-replica global ordering is not implied. |
| Three replicas with shared key control | Rotation and failover exercise | Each node includes key ID and can verify overlap material | Secret-manager propagation, clock, storage, and replica orchestration require acceptance evidence. |
| Centralized writer | Ordered evidence across stateless gateway replicas | A single writer or approved ordering service owns the durable sequence | Writer availability, queue behavior, and cross-region failure modes remain architecture work. |

Cross-replica global audit ordering and multi-region HA are not claimed by the current release. Use the scaling guide and roadmap as the authoritative boundary.

## Benchmark interpretation

The repository separates dispatch microbenchmarks, client-visible proxy overhead, upstream-inclusive latency, WAL durability throughput, WAF corpus metrics, and native crypto timing. Each measurement must identify workload, hardware, warmup, sample count, percentile method, raw artifact, and boundary.

The previously published 2.70 µs result is a background-dispatch microbenchmark, not end-to-end gateway latency. Per-worker throughput is constrained by the interpreter, event-loop scheduling, upstream behavior, storage, and deployment topology. No README claim of “zero latency,” “zero overhead,” “10k RPS capacity,” or “1B RPM” is authorized without a new artifact that satisfies the claim matrix.

The current-main Phase 2 in-process streaming harness is [`benchmarks/bench_streaming_sse.py`](benchmarks/bench_streaming_sse.py). Its retained working-tree measurement is [`evidence/commercial_phase2_streaming_benchmark.json`](evidence/commercial_phase2_streaming_benchmark.json). It exercises 1,000 deterministic SSE events per round and reports first-byte latency, transformation throughput, queue high-water marks and `tracemalloc` peak memory. It excludes network and durable-WAL latency and therefore is not an end-to-end capacity result.

See [`docs/benchmarks/README.md`](docs/benchmarks/README.md), [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md), and [`docs/performance/SCALING_GUIDE.md`](docs/performance/SCALING_GUIDE.md).

## Security and supply-chain posture

The release process produces a lockfile, SBOM, dependency/advisory results, provenance envelope, release-gate record, repository manifest, asset hashes, and rollback instructions. The security policy is in [`SECURITY.md`](SECURITY.md); the public claim controls are in [`docs/CLAIMS_MATRIX.md`](docs/CLAIMS_MATRIX.md). Vulnerability reports should use the private reporting path described in `SECURITY.md`, not public issue comments.

The repository does not claim SOC 2, HIPAA, FedRAMP, EU AI Act conformity, GDPR compliance, FIPS 140 validation, or court admissibility by itself. It provides code and evidence paths that an organization may evaluate as part of a broader control system and independent assessment. Framework references are contribution mappings, not certifications or legal conclusions.

## Commercial path

The commercial model is intentionally staged:

| Package | Scope | Promise boundary |
|---|---|---|
| Community / OSS | AGPL self-hosted evaluation and open-source use | No support or SLA promise. |
| Team / Pilot | Time-bounded, production-like evaluation with a named scope | Fixed scope, evidence replay, deployment checklist, and explicit support hours. |
| Production | Commercial self-hosted deployment, updates, and deployment guidance | Annual commercial terms sized by deployment and request tier; no unsupported certification promise. |
| Enterprise | Procurement, architecture assistance, security review, and negotiated response targets | Requires an accountable support operation, legal terms, data-retention statement, and explicit exclusions. |
| Sovereign / OEM | Air-gapped, redistribution, embedded, escrow, or dedicated assurance | Future offer only after capacity, legal review, and independent assurance exist. |

Pricing hypotheses, cost-to-serve assumptions, procurement blockers, and buyer questions are in [`docs/COMMERCIAL_STRATEGY_US.md`](docs/COMMERCIAL_STRATEGY_US.md) and [`docs/BUYER_GUIDE_US.md`](docs/BUYER_GUIDE_US.md). The repository does not fabricate customer logos, testimonials, adoption numbers, support coverage, or ROI guarantees.

## Repository map

| Path | Purpose |
|---|---|
| `docs/DEVELOPER_QUICKSTART.md` | Clone, install, run, test and extend the repository without weakening the evidence gate. |
| `docs/PLATFORM_OPERATOR_GUIDE.md` | Deployment topology, storage, Redis, kernel posture, telemetry and rollback boundaries. |
| `docs/FAQ_TECHNICAL.md` | Technical questions about lifecycle, failure semantics, WAF, timing and topology. |
| `docs/FAQ_PROCUREMENT.md` | Procurement questions about support, licensing, pricing hypotheses and assurance boundaries. |
| `docs/FAQ_SECURITY.md` | Security questions about FIPS, PQC, HTTP/2, WAF and supply chain. |
| `docs/compliance/COMPLIANCE_MAPPING.md` | Framework contribution map with customer-assessment boundaries. |
| `docs/privacy/DATA_RETENTION.md` | Persisted data, retention decisions, privacy risks and operator controls. |
| `docs/architecture/ARCHITECTURE.md` | System boundary, request state machine and topology behavior. |
| `docs/benchmarks/BENCHMARK_RESULTS.md` | Canonical v3.1.0 benchmark results and reproduction commands. |
| `docs/operations/ROLLBACK_RUNBOOK.md` | Evidence-preserving rollback and recovery procedure. |
| `docs/institutional/README.md` | Six-volume institutional architecture, security, operations, regulatory, and procurement review suite with claim controls. |
| `aegis/proxy/app.py` | Core FastAPI proxy lifecycle, request controls, evidence gate, streaming policy, headers, and bounded enrichment. |
| `aegis/proxy/waf.py` | Application-layer WAF and normalization pipeline. |
| `aegis/proxy/egress_guard.py` | Canonical egress allowlist and endpoint validation. |
| `aegis/core/crypto_audit.py` | Canonical forensic ledger, signatures, WAL persistence, rotation, and integrity verification. |
| `aegis/core/forensic_bundle.py` | Bounded JCS/DAG-CBOR evidence bundle, CIDv1 manifest, PDF certificate and offline verifier. |
| `dashboard/` | Read-only Next.js forensic dashboard and server-side authenticated BFF. |
| `sdk/python/` and `sdk/typescript/` | Python drop-in official-client subclasses; TypeScript provider-native wrappers with provider SDK peer dependencies; portable MMR proof verification. |
| `benchmarks/bench_streaming_sse.py` | Reproducible 1,000+ event in-process SSE transformation benchmark. |
| `aegis/core/ratelimiter.py` | In-memory development limiter and fail-closed Redis limiter. |
| `aegis/core/seccomp_guard.py` | Seccomp capability and enforcement guard. |
| `aegis/core/lsm_guard.py` | AppArmor/SELinux detection and strict assertion. |
| `aegis_server/crypto/keyring.py` | Versioned HMAC keyring with atomic reload and overlap verification. |
| `aegis_server/` | Enterprise persistence and compliance API lifecycle. |
| `tests/test_p0_release_gates.py` | Blocking P0/P1 regression tests for the v3.1.0 release line. |
| `tests/test_market_hardening_gates.py` | New WAF and fsync fault-injection regression gates. |
| `tools/benchmarks/run_backpressure_stall.py` | Reproducible local WAL-stall benchmark. |
| `tools/security/run_waf_corpus.py` | Reproducible local WAF corpus harness. |
| `tools/benchmarks/run_key_rotation.py` | Local multi-instance atomic key rotation exercise. |
| `tools/benchmarks/run_pqc_timing.py` | Native ML-DSA timing harness with raw-sample retention. |
| `docs/CLAIMS_MATRIX.md` | Public claim status, evidence locator, and falsification boundary. |
| `docs/architecture/` | Architecture index and decision records. |
| `docs/operations/` | Backpressure, rotation, rollback, and operational runbooks. |
| `docs/security/` | Threat model, WAF testing, PQC assessment, and assurance roadmap. |
| `docs/benchmarks/` | Measurement contract and interpretation rules. |
| `requirements.lock` | Hash-checked dependency resolution. |

## Documentation index

| Audience | Start here |
|---|---|
| Developer | [`docs/DEVELOPER_QUICKSTART.md`](docs/DEVELOPER_QUICKSTART.md), [`docs/REPOSITORY_MAP.md`](docs/REPOSITORY_MAP.md), and [`CONTRIBUTING.md`](CONTRIBUTING.md). |
| Platform operator | [`docs/PLATFORM_OPERATOR_GUIDE.md`](docs/PLATFORM_OPERATOR_GUIDE.md), [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md), and the operations runbooks. |
| Security reviewer | [`SECURITY.md`](SECURITY.md), [`docs/security/THREAT_MODEL.md`](docs/security/THREAT_MODEL.md), [`docs/FAQ_SECURITY.md`](docs/FAQ_SECURITY.md), and [`docs/CLAIMS_MATRIX.md`](docs/CLAIMS_MATRIX.md). |
| Buyer and procurement | [`docs/PRODUCT_BRIEF_US.md`](docs/PRODUCT_BRIEF_US.md), [`docs/BUYER_GUIDE_US.md`](docs/BUYER_GUIDE_US.md), [`docs/FAQ_PROCUREMENT.md`](docs/FAQ_PROCUREMENT.md), and [`docs/COMMERCIAL_STRATEGY_US.md`](docs/COMMERCIAL_STRATEGY_US.md). |
| Compliance and privacy | [`docs/compliance/COMPLIANCE_MAPPING.md`](docs/compliance/COMPLIANCE_MAPPING.md) and [`docs/privacy/DATA_RETENTION.md`](docs/privacy/DATA_RETENTION.md). |
| Institutional reviewer | [`docs/institutional/README.md`](docs/institutional/README.md), its claim-evidence graph, unsupported-claims report, and document-control record. |
| Release owner | [`CHANGELOG.md`](CHANGELOG.md), [`docs/benchmarks/BENCHMARK_RESULTS.md`](docs/benchmarks/BENCHMARK_RESULTS.md), release artifacts, and the gate record. |

## Non-goals and residual risk

Application-layer controls do not replace network segmentation, firewall policy, Kubernetes NetworkPolicy, cloud IAM, a secret manager, immutable backup, disaster-recovery testing, or an incident-response program. Strict startup checks prove configured prerequisites at initialization; they do not prove that an external provider, filesystem, kernel, signer, or network remains healthy indefinitely. HMAC-SHA256 is classical and symmetric; long-lived or quantum-sensitive evidence requires a reviewed migration or hybrid architecture. ML-DSA availability is not equivalent to constant-time proof, FIPS 140 validation, or certification.

A release is blocked when a governed accepted response lacks durable evidence in the declared test scope, a chain fails verification, a critical WAF corpus case bypasses, a valid key rotation loses or invalidates a record, a timing experiment exposes leakage, a supply-chain gate fails, or public documentation overstates the evidence. See [`docs/SECURITY_ASSURANCE_ROADMAP.md`](docs/SECURITY_ASSURANCE_ROADMAP.md) for the external-assurance path.

## License

The repository is licensed under the terms in [`LICENSE`](LICENSE) and [`COMMERCIAL.md`](COMMERCIAL.md). Commercial use cases, AGPL obligations, exemptions, future-version rights, and contractual terms require the applicable license text and legal review; this README is not legal advice.

## Current release

The current published release is [`v3.1.0`](https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v3.1.0). The baseline before this branch is post-PR #100 at commit `7647fad798b3b79a98cc15323299f40d185b7b4c`; the enterprise-maturation work described above is an **unreleased candidate** and is not attributed to the `v3.1.0` tag. No `v4.0.0` version, tag, registry publication, OCI release, WORM status, SLSA level, legal admissibility, or production-readiness claim is made. The ML-DSA `verify` timing claim remains blocked because the retained experiment returned `p=0.0`; a published release is not evidence that every deployment prerequisite or external assurance requirement has been satisfied.

## External reference boundaries

The documentation uses NIST AI RMF, NIST CSF, NIST FIPS 204, W3C WCAG 2.2, CISA Secure by Design, IETF HTTP/2 and other primary sources as reference frameworks. These sources define terminology or review lenses. They do not certify Aegis or replace customer-specific legal, security, privacy or accessibility review.

## Related documents

- [`docs/DEVELOPER_QUICKSTART.md`](docs/DEVELOPER_QUICKSTART.md)
- [`docs/DEVELOPER_INTEGRATIONS_GUIDE.md`](docs/DEVELOPER_INTEGRATIONS_GUIDE.md)
- [`docs/PLATFORM_OPERATOR_GUIDE.md`](docs/PLATFORM_OPERATOR_GUIDE.md)
- [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md)
- [`docs/FAQ_TECHNICAL.md`](docs/FAQ_TECHNICAL.md)
- [`docs/FAQ_SECURITY.md`](docs/FAQ_SECURITY.md)
- [`docs/FAQ_PROCUREMENT.md`](docs/FAQ_PROCUREMENT.md)
- [`docs/compliance/COMPLIANCE_MAPPING.md`](docs/compliance/COMPLIANCE_MAPPING.md)
- [`docs/privacy/DATA_RETENTION.md`](docs/privacy/DATA_RETENTION.md)
