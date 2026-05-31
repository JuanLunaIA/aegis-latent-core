<div align="center">

# AEGIS Latent Core

### Forensic-grade governance for LLM inference — without replacing your stack.

**OpenAI-compatible proxy · Merkle audit chain · Entropy telemetry · Production-ready in minutes**

<br/>

[![CI](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml/badge.svg)](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-81%20passing-brightgreen)](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml)

<br/>

[**Get started**](#-five-minute-quick-start) · [**Integrate**](#-connect-your-applications) · [**API**](#-api-reference) · [**Configure**](#-configuration) · [**Docker**](#-docker--kubernetes) · [**Report issue**](https://github.com/JuanLunaIA/aegis-latent-core/issues)

</div>

---

## Table of contents

| | Section |
| :--- | :--- |
| **01** | [Why AEGIS](#why-aegis) |
| **02** | [How it works](#how-it-works) |
| **03** | [Capability matrix](#capability-matrix) |
| **04** | [Five-minute quick start](#-five-minute-quick-start) |
| **05** | [Connect your applications](#-connect-your-applications) |
| **06** | [API reference](#-api-reference) |
| **07** | [Configuration](#-configuration) |
| **08** | [Docker & Kubernetes](#-docker--kubernetes) |
| **09** | [Governance & compliance](#governance--compliance) |
| **10** | [Project structure](#project-structure) |
| **11** | [Quality assurance](#quality-assurance) |
| **12** | [Troubleshooting](#troubleshooting) |
| **13** | [Security & licence](#security--licence) |

---

## Why AEGIS

Large language models are no longer experimental tooling — they are **production systems** carrying reputational, regulatory, and security risk. Yet most deployments still treat inference as an opaque HTTP call: no durable chain of custody, no statistical signal when model behaviour drifts, and no single control plane for keys and abuse.

**AEGIS Latent Core** is a drop-in **forensic telemetry proxy** that sits in front of any OpenAI-compatible backend. Your applications keep their SDKs; your security and compliance teams gain **evidence-grade auditability** from day one.

> **The proposition:** One integration point. Cryptographic lineage for every request. Optional entropy intelligence on model outputs. Zero rip-and-replace.

| Without AEGIS | With AEGIS |
| :--- | :--- |
| Provider logs only; tampering is hard to disprove | Append-only Merkle ledger + integrity API |
| Backend API keys scattered across services | Centralised proxy keys; provider secrets stay server-side |
| Prompt injection reaches the model unchecked | Configurable WAF + optional entropy guard |
| No standard forensic headers for SIEM | `X-Aegis-Request-ID`, session IDs, alert counts |
| Redis mandatory for rate limiting | In-memory limiter by default; Redis when you scale out |

**Built for:** platform engineering leads, AI governance officers, security architects, and founders shipping regulated or high-trust AI products.

**Repository:** [github.com/JuanLunaIA/aegis-latent-core](https://github.com/JuanLunaIA/aegis-latent-core)

---

## How it works

```mermaid
flowchart TB
    subgraph Clients["Your estate"]
        APP["Applications · Agents · IDEs"]
        SDK["OpenAI SDK · LangChain · curl"]
    end

    subgraph AEGIS["AEGIS Latent Core :8080"]
        AUTH["API key auth"]
        WAF["WAF · normalisation"]
        RL["Rate limit"]
        FWD["Async forwarder"]
        TEL["Entropy · KL · JS telemetry"]
        LEDGER["Merkle audit ledger"]
    end

    subgraph Upstream["Inference providers"]
        OLL["Ollama"]
        OAI["OpenAI"]
        VLLM["vLLM · Azure OpenAI"]
    end

    WAL[("aegis.wal.jsonl")]

    APP --> SDK
    SDK -->|"Bearer AEGIS key"| AUTH
    AUTH --> WAF --> RL --> FWD
    FWD --> OLL & OAI & VLLM
    FWD --> TEL --> LEDGER --> WAL
```

**Request path (milliseconds overhead):**

1. Client authenticates to AEGIS (not directly to the provider).
2. Payload is normalised, inspected by the WAF, and optionally entropy-screened.
3. Request is forwarded; `logprobs` may be injected for downstream analysis.
4. Response telemetry is evaluated; alerts and forensic headers are attached.
5. State is committed to the Merkle chain and persisted to the WAL.

Optional host hardening (seccomp, LSM verification) **degrades gracefully** in containers and sandboxes — the proxy remains operational.

---

## Capability matrix

| Layer | Capability | Outcome |
| :--- | :--- | :--- |
| **Proxy** | OpenAI-compatible `/v1/chat/completions` & `/v1/completions` | No client rewrites |
| **Provenance** | Merkle Mountain Range + WAL persistence | Tamper-evident history |
| **Audit API** | `/v1/audit/*` with separate read keys | Least-privilege forensics |
| **Telemetry** | Shannon entropy, KL & JS divergence on `logprobs` | Detect semantic drift & collapse |
| **Security** | Constant-time API keys, prompt-injection WAF | Defence in depth |
| **Scale** | In-memory or Redis GCRA rate limiting | Laptop to multi-node |
| **Ops** | Docker, Helm chart, GitHub Actions CI | Ship with confidence |

---

## ⚡ Five-minute quick start

<details>
<summary><strong>Prerequisites checklist</strong></summary>

- [ ] Python **3.11+**
- [ ] Git
- [ ] An OpenAI-compatible backend (Ollama recommended for local proof-of-value)
- [ ] `curl` and optionally `jq`

</details>

### Step 1 — Clone & install

```bash
git clone https://github.com/JuanLunaIA/aegis-latent-core.git
cd aegis-latent-core

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Step 2 — Configure

```bash
cp .env.example .env
```

Minimum viable `.env`:

```env
AEGIS_API_KEYS=sk-aegis-key1
AEGIS_AUDIT_API_KEYS=sk-audit-readonly-key
AEGIS_BACKEND_URL=http://localhost:11434
```

### Step 3 — Start a model backend

**Local (Ollama) — fastest path:**

```bash
ollama serve
ollama pull llama3.2
```

**Managed (OpenAI):**

```env
AEGIS_BACKEND_URL=https://api.openai.com/v1
AEGIS_BACKEND_API_KEY=sk-your-provider-key
```

### Step 4 — Launch AEGIS

```bash
aegis-server
```

| Endpoint | Purpose |
| :--- | :--- |
| [http://localhost:8080/health](http://localhost:8080/health) | Liveness |
| [http://localhost:8080/docs](http://localhost:8080/docs) | Interactive OpenAPI |

### Step 5 — Validate

```bash
# Health (no auth)
curl -s http://localhost:8080/health | jq

# Inference via proxy — note: AEGIS key, not provider key
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-aegis-key1" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3.2",
    "messages": [{"role": "user", "content": "Confirm AEGIS is operational."}]
  }' | jq

# Forensic audit plane
curl -s http://localhost:8080/v1/audit/health \
  -H "Authorization: Bearer sk-audit-readonly-key" | jq
```

**Automated smoke test** (with server + backend running):

```bash
make smoke
# or: ./scripts/smoke_test.sh
```

---

## 🔌 Connect your applications

Point your existing OpenAI client at AEGIS. **No SDK fork required.**

| Client setting | Value |
| :--- | :--- |
| `base_url` / `api_base` | `http://localhost:8080/v1` (or your deployment URL) |
| `api_key` | Any key from `AEGIS_API_KEYS` |

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="sk-aegis-key1",   # proxy credential — not the provider key
)

completion = client.chat.completions.create(
    model="llama3.2",
    messages=[{"role": "user", "content": "Summarise our Q3 risk posture."}],
)
print(completion.choices[0].message.content)
```

AEGIS forwards to `AEGIS_BACKEND_URL` using `AEGIS_BACKEND_API_KEY` — your provider secret never leaves the proxy tier.

### Provider wiring guide

| Provider | `AEGIS_BACKEND_URL` | `AEGIS_BACKEND_API_KEY` |
| :--- | :--- | :--- |
| **Ollama** | `http://localhost:11434` | *(leave empty)* |
| **OpenAI** | `https://api.openai.com/v1` | `sk-...` |
| **vLLM** | `http://localhost:8000/v1` | per deployment |
| **Azure OpenAI** | `https://{resource}.openai.azure.com/openai/deployments/{id}` | Azure API key |

**Session continuity:** send `X-Session-ID: your-correlation-id` or set `user` in the JSON body — echoed as `X-Aegis-Session-ID` on responses.

---

## 📡 API reference

### Inference (proxy)

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/chat/completions` | Proxy key | Chat completions (streaming supported) |
| `POST` | `/v1/completions` | Proxy key | Legacy completions |

### Operations

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | — | Liveness probe |
| `GET` | `/ready` | — | Readiness probe |
| `GET` | `/docs` | — | Swagger UI |

### Forensic audit

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/audit/health` | Audit key | Ledger status & node count |
| `GET` | `/v1/audit/integrity` | Audit key | Full-chain Merkle verification |
| `GET` | `/v1/audit/nodes` | Audit key | Paginated nodes (`?limit=&offset=&tenant_id=`) |
| `GET` | `/v1/audit/nodes/{hash}` | Audit key | Single node lookup |
| `GET` | `/v1/audit/tenants` | Audit key | Distinct tenant IDs in window |

### Response headers (chat)

| Header | Meaning |
| :--- | :--- |
| `X-Aegis-Request-ID` | Immutable forensic identifier |
| `X-Aegis-Session-ID` | Correlated session / tenant context |
| `X-Aegis-Alert-Count` | Entropy alerts raised for this response |

---

## ⚙️ Configuration

All variables are prefixed with `AEGIS_`. Full template: [`.env.example`](.env.example).

### Essential

| Variable | Default | Description |
| :--- | :--- | :--- |
| `AEGIS_BACKEND_URL` | `http://localhost:11434` | Upstream LLM base URL |
| `AEGIS_BACKEND_API_KEY` | *(empty)* | Provider credential (server-side only) |
| `AEGIS_API_KEYS` | *(empty)* | Comma-separated client keys |
| `AEGIS_AUDIT_API_KEYS` | *falls back to API keys* | Read-only audit plane keys |
| `AEGIS_WAL_PATH` | `./aegis.wal.jsonl` | Write-ahead log location |

### Performance & limits

| Variable | Default | Description |
| :--- | :--- | :--- |
| `AEGIS_RATE_LIMIT_BACKEND` | `memory` | `memory` or `redis` |
| `AEGIS_REDIS_URL` | `redis://localhost:6379` | Redis when using distributed GCRA |
| `AEGIS_RATE_LIMIT_THRESHOLD` | `60` | Requests per minute per session |
| `AEGIS_HOST` / `AEGIS_PORT` | `0.0.0.0` / `8080` | Bind address |

### Security posture

| Variable | Default | Description |
| :--- | :--- | :--- |
| `AEGIS_WAF_STRICT_MODE` | `true` | Block known injection patterns |
| `AEGIS_REQUEST_ENTROPY_GUARD` | `false` | Aggressive request entropy blocking |
| `AEGIS_FORCE_LOGPROBS` | `true` | Request logprobs for telemetry |
| `AEGIS_AUTH_DISABLED` | `false` | **Development only** — disables auth |

### Observability

| Variable | Default | Description |
| :--- | :--- | :--- |
| `AEGIS_LOG_LEVEL` | `INFO` | `DEBUG` · `INFO` · `WARNING` · `ERROR` |
| `AEGIS_WEBHOOK_URL` | *(empty)* | POST destination for alert JSON (Slack, SIEM, etc.) |
| `AEGIS_KL_ALERT_THRESHOLD` | `2.0` | KL divergence alert threshold |
| `AEGIS_ENTROPY_ALERT_THRESHOLD_BITS` | `1.0` | Entropy collapse sensitivity |

---

## 🐳 Docker & Kubernetes

### Docker Compose

From the repository root:

```bash
cp .env.example .env
# Edit .env, then:
docker compose -f deploy/docker/docker-compose.yml up --build
```

- **Port:** `8080`
- **Persistent WAL:** Docker volume `aegis-wal` → `/data/aegis.wal.jsonl`

### Helm (optional)

```bash
helm lint deploy/helm/
helm install aegis deploy/helm/ -f deploy/helm/values.yaml
```

Image reference (when publishing to GHCR): `ghcr.io/juanlunia/aegis-latent-core`

---

## Governance & compliance

AEGIS is designed to **support** — not replace — your governance programme. It furnishes the artefacts auditors and risk committees typically request:

| Requirement theme | How AEGIS helps |
| :--- | :--- |
| **Traceability** | Append-only ledger with integrity verification endpoint |
| **Separation of duties** | Distinct proxy vs audit API keys |
| **Evidence export** | JSON audit nodes suitable for SIEM ingestion |
| **Model behaviour monitoring** | Entropy / divergence alerts on `logprobs` |
| **Framework alignment** | Facilitates evidence for NIST AI RMF traceability & EU AI Act logging expectations |

> AEGIS provides **technical controls and records**. Legal compliance remains your organisation's responsibility and process design.

---

## Project structure

```
aegis-latent-core/
├── aegis/
│   ├── config.py              # Centralised settings (pydantic-settings)
│   ├── auth/                  # Constant-time API key validation
│   ├── core/                  # MMR, ledger, rate limiting, telemetry
│   └── proxy/                 # FastAPI application, WAF, forwarder
├── tests/                     # 81 automated tests
├── deploy/
│   ├── docker/                # Dockerfile + Compose
│   └── helm/                  # Kubernetes chart
├── scripts/smoke_test.sh      # End-to-end local validation
├── specs/                     # TLA+ formal specifications (roadmap)
├── .env.example
└── pyproject.toml
```

Modules such as `ebpf_monitor`, `tpm`, and `blockchain_anchor` represent **extended hardening roadmap** — the production proxy path relies on `crypto_audit`, `mmr`, `ratelimiter`, `telemetry`, and `proxy/*`.

### Embed in your own FastAPI app

```python
from aegis.config import AegisSettings
from aegis.proxy.app import create_app

settings = AegisSettings(
    backend_url="https://api.openai.com/v1",
    backend_api_key="sk-provider-secret",
    api_keys="client-facing-key",
    audit_api_keys="read-only-audit-key",
)
app = create_app(settings)
```

---

## Quality assurance

```bash
make dev        # Install with development dependencies
make test       # Run full test suite (81 tests)
make test-cov   # Coverage gate: 65% on runtime core
make lint       # Ruff on production modules
make smoke      # Live smoke test against :8080
```

**CI pipeline** (GitHub Actions): Ruff · Mypy · Pytest (3.11 & 3.12) · Bandit · Helm lint · Docker build on release.

---

## Troubleshooting

| Symptom | Likely cause | Resolution |
| :--- | :--- | :--- |
| `401 Authorization header required` | Missing `Bearer` token | `Authorization: Bearer sk-aegis-key1` |
| `503 No API keys configured` | Empty `AEGIS_API_KEYS` | Set keys in `.env` |
| Timeout / `502` on chat | Backend unreachable | Verify Ollama (`curl localhost:11434/api/tags`) or provider URL |
| `403` WAF rejection | Injection pattern matched | Rephrase prompt; do not disable WAF in production |
| `429 Rate limit exceeded` | Session threshold hit | Wait or increase `AEGIS_RATE_LIMIT_THRESHOLD` |
| Empty audit ledger | No successful chats yet | Complete at least one `200` chat completion |
| High `X-Aegis-Alert-Count` | Model distribution shift | Review telemetry thresholds & prompt |

---

## Security & licence

- **Never commit** `.env`, private keys, or production `*.wal.jsonl` files — all are gitignored.
- **Vulnerability reports:** [GitHub Security Advisories](https://github.com/JuanLunaIA/aegis-latent-core/security/advisories/new) — see [SECURITY.md](SECURITY.md).
- **Licence:** [Apache License 2.0](LICENSE)

---

<div align="center">

### Ship AI with evidence, not assumptions.

**[⭐ Star the repo](https://github.com/JuanLunaIA/aegis-latent-core)** · **[Report a bug](https://github.com/JuanLunaIA/aegis-latent-core/issues)** · **[Changelog](CHANGELOG.md)**

Maintained by **[JuanLunaIA](https://github.com/JuanLunaIA)**

</div>
