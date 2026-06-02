<div align="center">

<br/>

# Aegis Latent Core

### The open-source inference governance layer every production LLM deployment is missing.

**Drop-in OpenAI-compatible proxy · Cryptographic audit chain · Real-time entropy forensics · SOC2 / HIPAA compliance exports · Zero infrastructure changes required**

<br/>

[![CI](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml/badge.svg)](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml)
[![License: AGPLv3 / Commercial](https://img.shields.io/badge/License-AGPLv3%20%7C%20Commercial-blue.svg)](COMMERCIAL.md)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](deploy/docker/)
[![Helm](https://img.shields.io/badge/Helm-chart%20included-0F1689?logo=helm&logoColor=white)](deploy/helm/)

<br/>

[**Quickstart**](#-five-minute-quickstart) ·
[**Architecture**](#-architecture) ·
[**Performance**](#-performance-characteristics) ·
[**Storage**](#-storage-backends) ·
[**Vault Integration**](#-hashicorp-vault-transit-signing) ·
[**Compliance**](#-compliance-exports-soc2--hipaa) ·
[**Configuration**](#-configuration-reference) ·
[**Deploy**](#-docker--kubernetes) ·
[**License**](#-licensing)

</div>

---

## The problem with LLM in production

You ship an LLM-powered application. The model works. Evaluations pass. Then something unexpected surfaces in production — a behavioral drift nobody can explain, a response that shouldn't have occurred, a potential data exfiltration event that appears in a security audit three weeks later. And you have no evidence trail.

**Every LLM call is a black box. Aegis makes it an auditable, forensic event.**

Aegis sits between your application and any OpenAI-compatible endpoint — GPT-4, Claude via proxy, Llama through Ollama, Mixtral on vLLM — and instruments every inference with:

- A **cryptographic chain of custody** backed by a Merkle Mountain Range structure with tamper-evident linking of every request/response pair.
- **Real-time entropy forensics** on token logprob distributions: KL divergence, JS divergence, EMA drift, MoE gate entanglement — signals that reveal jailbreaks, model poisoning, and stealth prompt injection.
- A **WAF layer** trained on adversarial prompt patterns, Unicode normalization attacks, and structural payload analysis.
- A **pluggable storage layer** (SQLite, PostgreSQL, DynamoDB) for durable audit node persistence across restarts and multi-node deployments.
- **HashiCorp Vault Transit signing** for HSM-backed key isolation in enterprise environments.
- **SOC2 Type II and HIPAA compliance export bundles** — cryptographically sealed JSON packages suitable for auditor submission.

No model changes. No agent rewrites. One environment variable change.

---

## Architecture

```
Your Application
       │
       │  OpenAI-compatible HTTP
       ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Aegis Proxy Layer                        │
│                                                                 │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │   WAF    │  │ Rate Limiter │  │  Auth (API Key / mTLS)   │  │
│  └────┬─────┘  └──────┬───────┘  └───────────┬──────────────┘  │
│       └───────────────┴──────────────────────┘                  │
│                              │                                  │
│                   ┌──────────▼──────────┐                       │
│                   │   LLM Forwarder     │  ← httpx async        │
│                   │  (Rust accel. opt.) │    (streaming SSE)    │
│                   └──────────┬──────────┘                       │
│                              │                                  │
│         ┌────────────────────▼───────────────────────┐          │
│         │           Response (returned immediately)  │          │
│         └────────────────────────────────────────────┘          │
│                              │ FastAPI BackgroundTask           │
│                   ┌──────────▼──────────┐                       │
│                   │  Off-path Analytics │  ← zero latency       │
│                   │  Shannon entropy    │    to caller          │
│                   │  KL / JS divergence │                       │
│                   │  MoE gate monitor   │                       │
│                   └──────────┬──────────┘                       │
│                              │                                  │
│         ┌────────────────────▼───────────────────────┐          │
│         │        Cryptographic Audit Ledger           │          │
│         │  Merkle Mountain Range (MMR)                │          │
│         │  HMAC-SHA256  ─or─  Vault Transit ML-DSA   │          │
│         └────────────────────┬───────────────────────┘          │
│                              │                                  │
│    ┌─────────────────────────▼───────────────────┐              │
│    │             Storage Provider                │              │
│    │  SQLite (WAL) ┃ PostgreSQL ┃ DynamoDB       │              │
│    └─────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
              │                          │
              │ pass-through             │ SOC2/HIPAA
              ▼                         ▼
         LLM Backend            Compliance Bundle
    (OpenAI / Ollama / vLLM)   (sealed JSON + signature)
```

**Aegis never modifies the response your application receives.** The analytics pipeline runs entirely out-of-band via FastAPI `BackgroundTasks` — the caller receives the upstream response immediately, with no blocking wait for forensic processing or storage writes.

---

## Performance characteristics

Understanding Aegis's latency profile is important for production capacity planning.

### Standard pass-through mode (`AEGIS_FORCE_LOGPROBS=false`)

| Operation | Added latency |
|---|---|
| WAF inspection + auth | < 0.5 ms |
| Request forwarding overhead (httpx) | < 1 ms |
| **Background analytics + storage write** | **0 ms** (off-path) |
| **Total user-facing overhead** | **< 2 ms p99** |

In this mode Aegis adds negligible overhead. The audit chain is populated but entropy forensics are limited to response-level analysis without per-token logprob data.

### Forensic analysis mode (`AEGIS_FORCE_LOGPROBS=true`, default)

| Factor | Impact |
|---|---|
| Upstream payload inflation | **3–8×** larger response JSON |
| Additional upstream processing time | 50–300 ms (model-dependent) |
| Additional upstream token generation | Minimal (logprobs are sampled, not generated) |
| **Aegis-added latency to caller** | **< 2 ms** (analytics still off-path) |

**The latency cost of `AEGIS_FORCE_LOGPROBS=true` is paid entirely at the upstream LLM backend**, not inside Aegis. Aegis receives the larger payload and hands it to the caller immediately; the logprob extraction, entropy computation, and storage write happen in a background task that the caller never waits for.

**When to disable logprob injection:**
- High-throughput batch inference where per-token forensics are not required.
- Upstream backends that do not support `logprobs` (e.g. some open-source servers).
- Cost-sensitive deployments billed per output token.

In those cases, set `AEGIS_FORCE_LOGPROBS=false`. The audit chain remains intact with request/response hashes; only the per-token entropy analysis is unavailable.

---

## Storage backends

Aegis v2 introduces a pluggable storage layer. Set `AEGIS_STORAGE_PROVIDER` to select the backend.

### SQLite (`AEGIS_STORAGE_PROVIDER=sqlite`)

**Best for:** Single-node deployments, development, edge deployments, and workloads under ~10M audit nodes.

```bash
AEGIS_STORAGE_PROVIDER=sqlite
AEGIS_SQLITE_PATH=/var/aegis/audit.db
```

SQLite is configured with `PRAGMA journal_mode=WAL` on every connection, enabling unlimited concurrent readers alongside a single writer without contention. The file is crash-consistent via WAL checkpointing. For single-process Uvicorn deployments this is the lowest-ops storage option.

**Limitations:** Not safe for multi-worker Uvicorn (use `workers=1` or switch to PostgreSQL for multi-worker setups).

### PostgreSQL (`AEGIS_STORAGE_PROVIDER=postgres`)

**Best for:** Multi-node / multi-worker deployments, high write throughput, and workloads requiring server-side JSON indexing.

```bash
AEGIS_STORAGE_PROVIDER=postgres
AEGIS_POSTGRES_DSN=postgresql://aegis:secret@pg.corp.example.com:5432/aegis_audit
AEGIS_POSTGRES_MIN_POOL_SIZE=2
AEGIS_POSTGRES_MAX_POOL_SIZE=20
```

Uses `asyncpg` connection pooling. The `node_data` column is `JSONB`, enabling future `GIN` index queries on individual forensic fields. Each Uvicorn worker holds its own pool; PostgreSQL serialises concurrent writes at the server level.

**Schema is created automatically** on `initialize()`. For production, run the DDL under a migration tool (Flyway, Alembic) and grant the application user only `INSERT`, `SELECT` on `audit_nodes`.

### DynamoDB (`AEGIS_STORAGE_PROVIDER=dynamodb`)

**Best for:** AWS-native deployments, serverless architectures, and workloads that need auto-scaling write throughput without managing a database server.

```bash
AEGIS_STORAGE_PROVIDER=dynamodb
AEGIS_DYNAMODB_TABLE=aegis-audit-nodes
AEGIS_DYNAMODB_REGION=us-east-1
```

Uses `aioboto3` with on-demand billing mode. A GSI on `(partition_key, timestamp)` enables time-ordered listing. IAM permissions required: `dynamodb:PutItem`, `dynamodb:GetItem`, `dynamodb:Query`, `dynamodb:CreateTable`, `dynamodb:DescribeTable`.

**For DynamoDB Local** (development):
```bash
AEGIS_DYNAMODB_ENDPOINT_URL=http://localhost:8000
```

---

## HashiCorp Vault Transit signing

By default, Aegis signs each audit node with **HMAC-SHA256** using a local key (`AEGIS_HMAC_SIGNING_KEY`). This is suitable for self-hosted deployments where the signing key can be stored in a secrets manager and injected as an environment variable.

For enterprise deployments requiring **HSM-backed key non-exportability**, **FIPS 140-3 compliance**, or **centralized key lifecycle management**, Aegis integrates with HashiCorp Vault's Transit secrets engine.

```
Aegis worker  ──HTTPS──►  HashiCorp Vault
                           /v1/transit/sign/aegis-signing-key
                              │
                          Key stays inside Vault / HSM
                          Signature bytes returned
```

The private signing key **never leaves Vault**. Aegis receives only the signature.

### Setting up Vault Transit

```bash
# 1. Enable the Transit secrets engine
vault secrets enable transit

# 2. Create the signing key (Ed25519 or ML-DSA-65 for post-quantum)
vault write -f transit/keys/aegis-signing-key type=ed25519

# 3. Create a policy that allows only signing (no key export)
vault policy write aegis-sign - << EOF
path "transit/sign/aegis-signing-key" {
  capabilities = ["update"]
}
EOF

# 4. Create an AppRole for Aegis
vault auth enable approle
vault write auth/approle/role/aegis \
  policies=aegis-sign \
  token_ttl=1h \
  token_max_ttl=4h

# 5. Retrieve credentials
vault read auth/approle/role/aegis/role-id       # → AEGIS_VAULT_ROLE_ID
vault write -f auth/approle/role/aegis/secret-id  # → AEGIS_VAULT_SECRET_ID
```

```bash
# Aegis configuration
AEGIS_SIGNER_PROVIDER=vault
AEGIS_VAULT_URL=https://vault.corp.example.com
AEGIS_VAULT_ROLE_ID=<role-id>
AEGIS_VAULT_SECRET_ID=<secret-id>
AEGIS_VAULT_TRANSIT_KEY=aegis-signing-key
AEGIS_VAULT_TRANSIT_MOUNT=transit
AEGIS_VAULT_MAX_RETRIES=3
AEGIS_VAULT_RETRY_BASE_DELAY_S=0.25
```

**Retry behavior:** Transient Vault failures (5xx, network errors) are retried with exponential backoff and jitter: `delay = base_delay × 2^attempt + uniform(0, base_delay)`. After `max_retries` attempts the signing call raises `RuntimeError`, which is caught in the background task — the node is persisted unsigned with `is_fallback=True` recorded in `node_data`.

**Vault Enterprise namespaces:** Set `AEGIS_VAULT_NAMESPACE=your/namespace`.

---

## Compliance exports (SOC2 / HIPAA)

The enterprise layer provides on-demand sealed audit bundle exports suitable for auditor submission.

### Triggering an export

```bash
curl -X POST http://localhost:8080/v1/enterprise/compliance/export \
  -H "Authorization: Bearer sk-audit-key" \
  -H "Content-Type: application/json" \
  -d '{"from_offset": 0, "limit": 10000, "tenant_id": null}'
```

```json
{
  "export_id": "f7a2c1d4-...",
  "output_path": "/var/aegis/exports/aegis_compliance_f7a2c1d4_20260601T120000Z.json",
  "node_count": 10000,
  "chain_hash": "a3f8c2...",
  "bundle_signature": "4d2e9f...",
  "signer_scheme": "hmac-sha256",
  "generated_at": "2026-06-01T12:00:00.123456Z",
  "integrity_valid": true
}
```

### Bundle structure

```json
{
  "aegis_compliance_bundle": {
    "format_version": "1.0",
    "export_id": "<uuid4>",
    "generated_at": "<ISO 8601 UTC>",
    "generated_by": "aegis-latent-core/2.0.1",
    "export_params": { "from_offset": 0, "limit": 10000, "tenant_id": null },
    "node_count": 10000,
    "audit_chain": [ ... ],
    "verification_manifest": {
      "chain_hash": "<SHA-256 of canonical audit_chain JSON>",
      "bundle_signature": "<hex signature over chain_hash>",
      "signer_scheme": "hmac-sha256",
      "integrity_report": { "is_valid": true, "node_count": 10000, ... },
      "integrity_status": "VALID"
    }
  }
}
```

The `chain_hash` is SHA-256 of the `audit_chain` array serialised with sorted keys and no whitespace — a deterministic canonical form that auditors can independently recompute. `bundle_signature` proves the bundle was sealed by the Aegis instance holding the signing credential.

### Verifying a bundle offline

```python
import asyncio
from aegis_server.compliance import ComplianceExporter
from aegis_server.crypto import LocalHMACSigner

signer = LocalHMACSigner(signing_key="your-hmac-key")
result = asyncio.run(
    ComplianceExporter.verify_bundle("/path/to/bundle.json", signer)
)
print(result)
# {
#   "valid": True,
#   "chain_hash_match": True,
#   "signature_valid": True,
#   "node_count": 10000,
#   "integrity_status": "VALID",
#   ...
# }
```

### Paginated exports for large datasets

```bash
# Export in 10,000-node pages automatically
curl -X POST http://localhost:8080/v1/enterprise/compliance/export \
  -H "Authorization: Bearer sk-audit-key" \
  -d '{"from_offset": 0, "limit": 100000}'
```

The `ComplianceExporter.export_range_paginated()` method handles fan-out across multiple bundles for datasets exceeding the 100,000-node per-bundle hard cap.

---

## Five-minute quickstart

### Option A — pip

```bash
pip install aegis-latent-core[enterprise]
cp .env.example .env
# Edit .env: set AEGIS_BACKEND_URL, AEGIS_API_KEYS, AEGIS_HMAC_SIGNING_KEY
aegis-enterprise-server
```

### Option B — Docker

```bash
git clone https://github.com/JuanLunaIA/aegis-latent-core.git
cd aegis-latent-core
cp .env.example .env
docker compose up -d
```

### Option C — from source

```bash
git clone https://github.com/JuanLunaIA/aegis-latent-core.git
cd aegis-latent-core
pip install ".[enterprise,dev]"
cp .env.example .env
aegis-enterprise-server
```

### Verify it's running

```bash
curl http://localhost:8080/health
# {"status":"healthy","version":"2.0.1"}

curl http://localhost:8080/v1/enterprise/health \
  -H "Authorization: Bearer sk-audit-key"
# {
#   "status": "healthy",
#   "storage_provider": "sqlite",
#   "signer_provider": "hmac",
#   "node_count": 0,
#   "integrity_valid": true
# }
```

---

## Connect your application

**Change one line:**

```python
# Before
import openai
client = openai.OpenAI(api_key="sk-...")

# After — every call is now forensically instrumented
import openai
client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="sk-aegis-key1",
)
```

Works with any OpenAI-compatible client: **LangChain**, **LlamaIndex**, **AutoGen**, **DSPy**, raw `curl`.

---

## Configuration reference

All settings are controlled via environment variables or a `.env` file.

### Core proxy

| Variable | Default | Description |
|---|---|---|
| `AEGIS_BACKEND_URL` | `http://localhost:11434` | Upstream LLM endpoint |
| `AEGIS_BACKEND_API_KEY` | _(empty)_ | Forwarded to upstream |
| `AEGIS_API_KEYS` | _(empty)_ | Comma-separated proxy keys. **Required in production.** |
| `AEGIS_AUDIT_API_KEYS` | _(inherits)_ | Read-only keys for audit/compliance endpoints |
| `AEGIS_FORCE_LOGPROBS` | `true` | Inject logprobs into every request (see [Performance](#-performance-characteristics)) |
| `AEGIS_TOP_LOGPROBS` | `20` | Top logprobs per token (max 20) |

### Storage

| Variable | Default | Description |
|---|---|---|
| `AEGIS_STORAGE_PROVIDER` | `sqlite` | `sqlite` · `postgres` · `dynamodb` |
| `AEGIS_SQLITE_PATH` | `./aegis_audit.db` | SQLite database file path |
| `AEGIS_POSTGRES_DSN` | _(empty)_ | asyncpg DSN (required for postgres) |
| `AEGIS_POSTGRES_MIN_POOL_SIZE` | `2` | Minimum pool connections |
| `AEGIS_POSTGRES_MAX_POOL_SIZE` | `10` | Maximum pool connections |
| `AEGIS_DYNAMODB_TABLE` | `aegis-audit-nodes` | DynamoDB table name |
| `AEGIS_DYNAMODB_REGION` | `us-east-1` | AWS region |
| `AEGIS_DYNAMODB_ENDPOINT_URL` | _(empty)_ | Override endpoint (DynamoDB Local) |

### Signing

| Variable | Default | Description |
|---|---|---|
| `AEGIS_SIGNER_PROVIDER` | `hmac` | `hmac` · `vault` |
| `AEGIS_HMAC_SIGNING_KEY` | _(empty)_ | HMAC key ≥ 32 bytes. **Required for hmac.** |
| `AEGIS_VAULT_URL` | _(empty)_ | Vault server URL |
| `AEGIS_VAULT_TOKEN` | _(empty)_ | Static Vault token |
| `AEGIS_VAULT_ROLE_ID` | _(empty)_ | AppRole RoleID (preferred) |
| `AEGIS_VAULT_SECRET_ID` | _(empty)_ | AppRole SecretID |
| `AEGIS_VAULT_TRANSIT_KEY` | `aegis-signing-key` | Transit secrets engine key name |
| `AEGIS_VAULT_TRANSIT_MOUNT` | `transit` | Transit mount path |
| `AEGIS_VAULT_MAX_RETRIES` | `3` | Retry attempts on transient failure |
| `AEGIS_VAULT_RETRY_BASE_DELAY_S` | `0.25` | Exponential backoff base (seconds) |
| `AEGIS_VAULT_NAMESPACE` | _(empty)_ | Vault Enterprise namespace |

### Compliance

| Variable | Default | Description |
|---|---|---|
| `AEGIS_COMPLIANCE_EXPORT_DIR` | `./aegis_exports` | Bundle output directory |

### Server

| Variable | Default | Description |
|---|---|---|
| `AEGIS_HOST` | `0.0.0.0` | Bind address |
| `AEGIS_PORT` | `8080` | Bind port |
| `AEGIS_WORKERS` | `1` | Uvicorn worker count |
| `AEGIS_LOG_LEVEL` | `INFO` | `DEBUG` · `INFO` · `WARNING` · `ERROR` |
| `AEGIS_CORS_ORIGINS` | _(empty)_ | Comma-separated allowed CORS origins |

---

## API reference

### Proxy

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe |
| `POST` | `/v1/chat/completions` | OpenAI chat completions |
| `POST` | `/v1/completions` | OpenAI legacy completions |
| `POST` | `/v1/enterprise/proxy/chat/completions` | Chat completions with explicit background audit |

### Audit (read-only keys)

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/enterprise/health` | Enterprise layer health + node count |
| `GET` | `/v1/enterprise/audit/nodes` | Paginated node listing (`?offset=&limit=&tenant_id=`) |
| `GET` | `/v1/enterprise/audit/nodes/{hash}` | Single node by SHA-256 hash |
| `GET` | `/v1/enterprise/audit/integrity` | Full chain integrity verification |

### Compliance (audit keys)

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/enterprise/compliance/export` | Trigger a sealed compliance bundle |
| `GET` | `/v1/enterprise/compliance/bundles` | List previously exported bundles |

---

## Docker & Kubernetes

### Docker Compose

```bash
cp .env.example .env
docker compose -f deploy/docker/docker-compose.yml up -d
```

### Helm

```bash
kubectl create secret generic aegis-keys \
  --from-literal=AEGIS_BACKEND_API_KEY=sk-your-upstream-key \
  --from-literal=AEGIS_API_KEYS=sk-proxy-key-1,sk-proxy-key-2 \
  --from-literal=AEGIS_AUDIT_API_KEYS=sk-audit-readonly \
  --from-literal=AEGIS_HMAC_SIGNING_KEY=$(python3 -c \
    "from aegis_server.crypto import LocalHMACSigner; print(LocalHMACSigner.generate_key())")

helm install aegis ./deploy/helm \
  --set aegis.backendUrl=https://api.openai.com \
  --set aegis.storageProvider=postgres \
  --set aegis.postgresDsn=postgresql://aegis:pass@pg:5432/aegis_audit \
  --set aegis.existingSecret=aegis-keys
```

---

## Security hardening checklist

- [ ] Set `AEGIS_API_KEYS` — never run auth-disabled in production.
- [ ] Set `AEGIS_AUDIT_API_KEYS` separately (read-only principle of least privilege).
- [ ] Generate a strong `AEGIS_HMAC_SIGNING_KEY` (`≥ 32 bytes`) or deploy Vault Transit.
- [ ] Mount storage paths on persistent, access-controlled volumes.
- [ ] Enable `AEGIS_REQUEST_ENTROPY_GUARD=true` in hardened deployments.
- [ ] Configure `AEGIS_WEBHOOK_URL` to forward alerts to your SIEM.
- [ ] Use PostgreSQL or DynamoDB for multi-worker deployments.
- [ ] Rotate `AEGIS_HMAC_SIGNING_KEY` annually; use Vault for automated rotation.
- [ ] Back up the SQLite WAL or PostgreSQL database on a schedule.

---

## Development

```bash
pip install ".[enterprise,dev]"
make test-cov      # full test suite with coverage
make lint          # ruff
make type          # mypy
make security      # bandit SAST
```

---

## Licensing

Aegis Latent Core is **dual-licensed**.

### Open Source (AGPLv3)

Free to use, modify, and distribute under the [GNU Affero General Public License v3](LICENSE). If you run Aegis as a network service you must make your modifications available under the same license.

**AGPLv3 is appropriate for:**
- Open-source projects.
- Internal self-hosted deployments where source disclosure is acceptable.
- Research and development.
- Local testing and evaluation.

### Commercial License

For **closed-source production deployments** — embedding Aegis in a SaaS product, OEM integration, or enterprise on-premises installation where AGPLv3 copyleft is not acceptable — a Commercial License is available.

See [COMMERCIAL.md](COMMERCIAL.md) for terms and contact information.

---

<div align="center">

Built for the engineers who ship LLMs to production and need to know exactly what happened — after the fact, under audit, or in real time.

**[Get started in 5 minutes](#-five-minute-quickstart)**

</div>
