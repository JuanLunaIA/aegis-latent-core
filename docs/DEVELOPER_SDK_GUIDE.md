# Aegis SDK Developer Guide

**Source version:** `4.0.2`  
**Package identities:** Python `aegis-latent-sdk` / import `aegis_sdk`; npm `aegis-latent-sdk`  
**Status:** the checked-out `v4.0.2` source baseline/release target exists; public package artifacts were independently observed at `4.0.0`. This guide does not establish `4.0.2` registry publication, trusted-publishing provenance, production fitness, or provider certification.

## 1. Scope

The Python and TypeScript SDKs route supported OpenAI or Anthropic operations through an Aegis gateway and verify portable `aegis-mmr-inclusion-v1` proofs. They do not implement a zero-knowledge proof system, do not make the MMR root trustworthy by themselves, and do not make unsupported provider endpoints available.

The authoritative implementation paths are:

| Component | Path | Public surface |
|---|---|---|
| Python package | `sdk/python/` | `aegis_sdk` |
| TypeScript package | `sdk/typescript/` | package root plus `aegis-latent-sdk/proof` |
| Python integrations | `sdk/python/src/aegis_sdk/integrations/` | LangChain and LlamaIndex callback adapters |
| Proof wire contract | `aegis-mmr-inclusion-v1` | Response headers and proof endpoint linked by `Link` |

## 2. Python SDK

### 2.1 Clean-checkout development

```bash
cd sdk/python
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m ruff check src tests
python -m mypy --config-file pyproject.toml
python -m pytest -q
python -m pip wheel . --no-deps --wheel-dir dist
```

The package name and import namespace differ intentionally:

```python
from aegis_sdk.openai import OpenAI

client = OpenAI(
    aegis_api_key="proxy-key",
    gateway_url="https://gateway.example",
    tenant_id="tenant-1",
)
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "hello"}],
)
```

The wrapper subclasses the official provider client. Provider response types and method behavior remain owned by the installed provider SDK. The gateway must implement the selected endpoint and provider wire format.

### 2.2 Proof verification

The public proof helpers are `AegisProofError`, `InclusionProof`, `canonical_proof_json`, `verify_inclusion`, `verify_inclusion_hash`, and `verify_proof_headers`.

For automatic non-streaming verification, configure `verify_proof=True` and supply an independently pinned `trusted_mmr_root`. Never derive the trusted root from the same untrusted response whose proof is being checked. Verification establishes inclusion relative to that root; it does not establish authorship, external immutability, global ordering, non-repudiation, or legal admissibility.

Streaming starts before the terminal evidence record exists. Initial streaming headers therefore cannot contain the final proof. Follow the returned proof `Link` only after terminal commit.

### 2.3 Framework callbacks

The optional LangChain and LlamaIndex adapters live under `aegis_sdk.integrations`. They exchange bounded correlation and proof metadata. They do not establish framework-wide interception of every internal operation and must not be described as capturing all prompt or response content.

Run their focused tests with:

```bash
cd sdk/python
python -m pytest -q tests/integrations
```

## 3. TypeScript SDK

### 3.1 Clean-checkout development

```bash
cd sdk/typescript
npm ci
npm run check
npm pack --dry-run
```

`npm run check` runs strict type checking, Vitest, and the production build.

### 3.2 Gateway options

```ts
import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { anthropicGatewayOptions, openAIGatewayOptions } from "aegis-latent-sdk";

const openai = new OpenAI(openAIGatewayOptions({
  aegisApiKey: process.env.AEGIS_API_KEY!,
  gatewayUrl: "https://aegis.internal",
  tenantId: "tenant-42",
}));

const anthropic = new Anthropic(anthropicGatewayOptions({
  aegisApiKey: process.env.AEGIS_API_KEY!,
  gatewayUrl: "https://aegis.internal",
  tenantId: "tenant-42",
}));
```

Do not embed provider or Aegis credentials in browser bundles. The Anthropic native route is valid only when the gateway is configured for Anthropic.

### 3.3 Portable proof verification

```ts
import { parseInclusionProof, verifyInclusionHash } from "aegis-latent-sdk/proof";

const proof = parseInclusionProof(untrustedJson);
const valid = await verifyInclusionHash(leafHashHeader, proof, pinnedRoot);
```

The verifier binds the leaf index, leaf count, mountain topology, path directions, complete peak set, and independently supplied root. The v1 construction hashes lowercase hexadecimal strings to remain wire-compatible with the Python and Rust accumulator; it is not a conventional binary-digest MMR.

## 4. Authentication, tenancy, and rate limits

SDK callers authenticate with an Aegis credential. The gateway derives tenant and quota identity from verified credentials; caller-supplied tenant, session, or provider-user fields are correlation inputs rather than identity sources.

Rate-limit responses expose generic request-bucket fields (`X-RateLimit-Limit`, `X-RateLimit-Remaining`) and dimension-specific request/token fields. A finite `Retry-After` is included on HTTP 429 when the configured bucket can compute a finite recovery delay.

For mTLS behind an allowlisted proxy, the gateway accepts `X-Forwarded-Client-Cert` plus `X-SSL-Client-SHA256`; the historical `X-Client-Cert-SHA256` alias remains accepted. Forwarded certificate assertions from a source outside configured trusted proxy CIDRs are ignored. Conflicting fingerprint headers are rejected.

## 5. Release and provenance boundaries

The synchronized source version is `4.0.2`. The canonical package identities are `aegis-latent-sdk` for both Python and npm. Similar names such as `aegis-sdk` or `@aegis-latent/sdk` are different registry identities and must not be substituted.

A valid source gate does not prove registry provenance. Release workflows require an annotated signed tag whose semantic version exactly matches all package anchors and whose commit is reachable from `origin/main`. Publication additionally depends on protected environments, registry-side trusted-publisher configuration, and successful workflow execution.

## 6. Verification matrix

| Surface | Command | Acceptance condition |
|---|---|---|
| Python SDK | `cd sdk/python && python -m ruff check src tests && python -m mypy --config-file pyproject.toml && python -m pytest -q` | Every command exits 0 |
| TypeScript SDK | `cd sdk/typescript && npm run check` | Typecheck, Vitest, and build exit 0 |
| Core Python | `python -m pytest -q` | Suite exits 0; report exact pass/skip totals |
| Rust core | `cd aegis_rust_v2 && cargo test --locked && cargo clippy --locked --all-targets --all-features -- -D warnings` | Tests and Clippy exit 0 |
| Formal scope | `scripts/verify_formal_artifacts.sh` | Two Z3 checks are `unsat`, Lean compiles, and all bounded TLC models report no error |
| Release contract | `python scripts/verify_release_contract.py --root . --tag v4.0.2` | `release source contract: READY` |

These checks establish only their stated source and bounded-model properties. They do not imply full implementation refinement, performance, production readiness, compliance certification, or external service acceptance.

## 7. Falsification and rollback

An SDK compatibility claim is falsified if a documented constructor, export, or proof vector fails against the pinned package lock and supported runtime. Proof interoperability is falsified if the Python and TypeScript verifiers disagree on the same canonical vector. Tenant isolation is falsified if changing an untrusted tenant/session header changes the authenticated tenant or quota key. The release-source claim is falsified by any version mismatch or failed contract diagnostic.

SDK changes should be reverted as one commit if they break provider-native response types, proof vectors, edge-runtime constraints, strict type checking, or the package identity contract.

## 8. Related documents

- [`DEVELOPER_INTEGRATIONS_GUIDE.md`](DEVELOPER_INTEGRATIONS_GUIDE.md)
- [`DEVELOPER_QUICKSTART.md`](DEVELOPER_QUICKSTART.md)
- [`CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`../sdk/python/README.md`](../sdk/python/README.md)
- [`../sdk/typescript/README.md`](../sdk/typescript/README.md)
- [`../.aegis_ai_context/09_COMMAND_AND_CI_MATRIX.md`](../.aegis_ai_context/09_COMMAND_AND_CI_MATRIX.md)
