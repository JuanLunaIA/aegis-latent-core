# Aegis SDK Developer Guide

**Source version:** `4.1.2`
**Package identities:** Python `aegis-latent-sdk` / import `aegis_sdk`; npm `aegis-latent-sdk`
**Status:** the checked-out `v4.1.2` source baseline/release target exists; public package artifacts were independently observed at `4.0.0`. This guide does not establish `4.1.2` registry publication, trusted-publishing provenance, production fitness, or provider certification; no `4.1.2` artifact is published anywhere.

## 1. Scope

The Python and TypeScript SDKs route supported OpenAI or Anthropic operations through an Aegis gateway and verify portable `aegis-mmr-inclusion-v1` proofs. They do not implement a zero-knowledge proof system, do not make the MMR root trustworthy by themselves, and do not make unsupported provider endpoints available.

The authoritative implementation paths are:

| Component | Path | Public surface |
|---|---|---|
| Python package | `sdk/python/` | `aegis_sdk` |
| TypeScript package | `sdk/typescript/` | package root plus `aegis-latent-sdk/proof` |
| Python integrations | `sdk/python/src/aegis_sdk/integrations/` | LangChain and LlamaIndex callback adapters |
| Proof wire contract | `aegis-mmr-inclusion-v1` | Response headers and proof endpoint linked by `Link` |

## 1.1 Installing from a registry

Both SDKs are published and were read back at `4.1.2` on 2026-09-04
([Release Status §1.0](RELEASE_STATUS.md)):

```bash
pip install aegis-latent-sdk
npm  install aegis-latent-sdk
```

The SDKs verify proofs. They do not enforce policy, hold a signing key, or
produce evidence, so installing one grants no gateway capability. The engine
that produces evidence is a different package, `aegis-latent-core`, which
carries both the gateway CLIs and the embedded `aegis.wrap()` entry point; see
[Developer quickstart](DEVELOPER_QUICKSTART.md).

The npm version history for `aegis-latent-sdk` is `4.0.0` then `4.1.2` — the
`4.1.1` publish failed and was never rerun, so the gap is a publishing history
rather than a yanked release.

The sections below build the SDKs from this repository, which is what
contributors and evidence runs use.

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

### 2.4 Worked Python patterns

Every symbol below is exported by the checked-out `4.1.2` source tree. The constructors are keyword-only; `aegis_api_key`, `gateway_url`, and `tenant_id` are required.

**Synchronous drop-in.** The class subclasses the official client, so the request surface is unchanged.

```python
from aegis_sdk.openai import OpenAI

client = OpenAI(
    aegis_api_key="<gateway key>",
    gateway_url="https://aegis.internal.example",
    tenant_id="team-platform",
    session_id="optional-session-correlator",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Summarize this incident report."}],
)
```

**Asynchronous drop-in.** `AsyncOpenAI` and `AsyncAnthropic` take the same keyword arguments.

```python
import asyncio
from aegis_sdk.openai import AsyncOpenAI

async def main() -> None:
    client = AsyncOpenAI(
        aegis_api_key="<gateway key>",
        gateway_url="https://aegis.internal.example",
        tenant_id="team-platform",
    )
    result = await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "ping"}],
    )
    print(result.choices[0].message.content)

asyncio.run(main())
```

**Anthropic native route.** The gateway exposes `POST /v1/messages` in addition to the OpenAI-compatible surface.

```python
from aegis_sdk.anthropic import Anthropic

client = Anthropic(
    aegis_api_key="<gateway key>",
    gateway_url="https://aegis.internal.example",
    tenant_id="team-platform",
)

message = client.messages.create(
    model="claude-sonnet-4-5",
    max_tokens=512,
    messages=[{"role": "user", "content": "Explain the retention policy."}],
)
```

**Automatic proof verification.** Setting `verify_proof=True` without a `trusted_mmr_root` raises: the root must be pinned out of band, never taken from the response being checked.

```python
from aegis_sdk.openai import OpenAI

client = OpenAI(
    aegis_api_key="<gateway key>",
    gateway_url="https://aegis.internal.example",
    tenant_id="team-compliance",
    verify_proof=True,
    trusted_mmr_root="<64-hex root pinned from an independent channel>",
)
```

A response-level hook then validates the proof headers on each non-streaming response and raises `AegisProofError` on mismatch.

**Streaming and the `pending-terminal` boundary.** This is the single most misread behavior in the SDK. A stream's initial headers are emitted before the terminal evidence record exists, so they carry `X-Aegis-Evidence-Status: pending-terminal` and **no** final proof. The verification hook deliberately returns early for those responses rather than failing, so `verify_proof=True` does not verify a stream inline.

```python
from aegis_sdk.openai import OpenAI

client = OpenAI(
    aegis_api_key="<gateway key>",
    gateway_url="https://aegis.internal.example",
    tenant_id="team-platform",
)

with client.chat.completions.stream(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Stream a summary."}],
) as stream:
    for event in stream:
        ...  # consume incrementally; nothing is buffered whole by the gateway
```

To obtain evidence for a stream, follow the returned proof `Link` **after** the terminal marker, once the single terminal summary has been committed. Treat a stream as unverified until that retrieval succeeds, and never infer a terminal outcome from receipt of content alone.

**Framework callbacks.** Both adapters record bounded counters, timing, correlation, and proof state only. They retain no prompt, response, node, or embedding content, and they do not intercept every internal framework operation.

```python
from aegis_sdk.integrations import (
    AegisLangChainCallback,
    AegisLlamaIndexCallback,
    MemoryMetricSink,
)

sink = MemoryMetricSink()
langchain_callback = AegisLangChainCallback(sink, trusted_root="<pinned root>")
llamaindex_callback = AegisLlamaIndexCallback(sink, trusted_root="<pinned root>")

# LangChain and LangGraph both accept handlers through the callbacks argument:
#   chain.invoke(payload, config={"callbacks": [langchain_callback]})
# LlamaIndex registers through its callback manager.

for metric in sink.metrics:
    print(metric)
```

`LangChainCallbackHandler` and `LlamaIndexCallbackHandler` are exported aliases of the same classes for readers who prefer framework-conventional names. Because these adapters observe framework events rather than gateway admission, a metric recorded here is telemetry about your application, not gateway evidence; the authoritative record remains the ledger node.

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

### 3.4 Worked TypeScript patterns

The package ships subpath exports `.`, `./proof`, `./providers`, `./gateway`, `./openai`, `./anthropic`, `./verifier`, and `./types`. Provider clients are **peer dependencies**, not bundled: install `openai` in the range `>=4 <7` or `@anthropic-ai/sdk` in the range `>=0.39 <1` alongside the SDK. Because they are peers, the provider package your application resolves is the one the wrapper extends, which keeps provider behavior authoritative and avoids a duplicated client instance.

```bash
npm install aegis-latent-sdk openai
```

**Drop-in client.** `OpenAI` extends the official client, so the request surface is unchanged.

```ts
import { OpenAI } from "aegis-latent-sdk/openai";

const client = new OpenAI({
  aegisApiKey: process.env.AEGIS_API_KEY!,
  gatewayUrl: "https://aegis.internal.example",
  tenantId: "team-platform",
});

const completion = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Summarize this incident report." }],
});
```

**Option builders.** When you would rather construct the official client yourself, the gateway module returns the option objects instead of subclassing.

```ts
import { openAIGatewayOptions, anthropicGatewayOptions } from "aegis-latent-sdk/gateway";

const options = openAIGatewayOptions({
  aegisApiKey: process.env.AEGIS_API_KEY!,
  gatewayUrl: "https://aegis.internal.example",
  tenantId: "team-platform",
});
```

A session identifier and a W3C trace context are generated with `globalThis.crypto.randomUUID()` when you do not supply them, so correlation works without extra wiring.

**Portable proof verification with Web Crypto.** Verification is asynchronous because it runs on `SubtleCrypto`, obtained from `globalThis.crypto?.subtle`. It therefore works in browsers, Node, Deno, and workers without a Node-specific crypto import, and a `SubtleCrypto` instance can be injected for tests.

```ts
import {
  parseInclusionProof,
  verifyInclusion,
  verifyInclusionHash,
  verifyProofHeaders,
} from "aegis-latent-sdk/proof";

// Pin the root from an independent channel — never from the response under test.
const trustedRoot = process.env.AEGIS_TRUSTED_MMR_ROOT!;

const proof = parseInclusionProof(await proofResponse.json());
const ok = await verifyInclusion(leafBytes, proof, trustedRoot);

// Verify without disclosing the record body:
const okByDigest = await verifyInclusionHash(leafSha256Hex, proof, trustedRoot);

// Or verify directly from a non-streaming response's headers:
await verifyProofHeaders(response.headers, trustedRoot);
```

`parseInclusionProof` validates the envelope shape before any hashing occurs, so a malformed or version-mismatched proof is rejected rather than partially processed. As on the Python side, a stream's initial headers carry `pending-terminal` and contain no final proof; retrieve it from the linked proof endpoint after the terminal marker.

**Environments without Web Crypto.** `resolveSubtleCrypto` throws when no implementation is reachable rather than silently degrading to a non-cryptographic fallback. If you hit that error, supply an implementation explicitly instead of disabling verification.

## 4. Authentication, tenancy, and rate limits

SDK callers authenticate with an Aegis credential. The gateway derives tenant and quota identity from verified credentials; caller-supplied tenant, session, or provider-user fields are correlation inputs rather than identity sources.

Rate-limit responses expose generic request-bucket fields (`X-RateLimit-Limit`, `X-RateLimit-Remaining`) and dimension-specific request/token fields. A finite `Retry-After` is included on HTTP 429 when the configured bucket can compute a finite recovery delay.

For mTLS behind an allowlisted proxy, the gateway accepts `X-Forwarded-Client-Cert` plus `X-SSL-Client-SHA256`; the historical `X-Client-Cert-SHA256` alias remains accepted. Forwarded certificate assertions from a source outside configured trusted proxy CIDRs are ignored. Conflicting fingerprint headers are rejected.

## 5. Release and provenance boundaries

The synchronized source version is `4.1.2`. The canonical package identities are `aegis-latent-sdk` for both Python and npm. Similar names such as `aegis-sdk` or `@aegis-latent/sdk` are different registry identities and must not be substituted.

A valid source gate does not prove registry provenance. Release workflows require an annotated signed tag whose semantic version exactly matches all package anchors and whose commit is reachable from `origin/main`. Publication additionally depends on protected environments, registry-side trusted-publisher configuration, and successful workflow execution.

## 6. Verification matrix

| Surface | Command | Acceptance condition |
|---|---|---|
| Python SDK | `cd sdk/python && python -m ruff check src tests && python -m mypy --config-file pyproject.toml && python -m pytest -q` | Every command exits 0 |
| TypeScript SDK | `cd sdk/typescript && npm run check` | Typecheck, Vitest, and build exit 0 |
| Core Python | `python -m pytest -q` | Suite exits 0; report exact pass/skip totals |
| Rust core | `cd aegis_rust_v2 && cargo test --locked && cargo clippy --locked --all-targets --all-features -- -D warnings` | Tests and Clippy exit 0 |
| Formal scope | `scripts/verify_formal_artifacts.sh` | Two Z3 checks are `unsat`, Lean compiles, and all bounded TLC models report no error |
| Release contract | `python scripts/verify_release_contract.py --root . --tag v4.1.2` | `release source contract: READY` |

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
