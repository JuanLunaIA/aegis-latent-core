# Aegis TypeScript SDK

**Audience:** developers integrating a TypeScript or JavaScript application with an Aegis gateway.
**Scope:** installation, gateway configuration, provider clients, and inclusion-proof verification.
**Boundary:** the SDK talks to a gateway and verifies proofs. It establishes nothing about the gateway's trustworthiness — see [§ Proof verification](#proof-verification), which is the section that matters most.

---

## Install

**From this source tree** — the supported path while registry versions lag:

```bash
cd sdk/typescript
npm ci
npm run build
```

Then reference it from your project, or from the dashboard workspace which already does.

> **Registry caution.** npm carries `aegis-latent-sdk` at `4.0.0`; this source tree is `4.1.1`. Installing from npm gets you different code from what this document describes. See [Release Status](../../docs/RELEASE_STATUS.md).

## Configure a gateway

```ts
import { openAIGatewayOptions, type AegisGatewayConfig } from "aegis-latent-sdk";

const config: AegisGatewayConfig = {
  baseUrl: "http://127.0.0.1:8080",
  apiKey: process.env.AEGIS_API_KEY!,   // never hard-code
  sessionId: "session-1",
};

const options = openAIGatewayOptions(config);
```

`anthropicGatewayOptions` is the equivalent for the Anthropic surface.

## Provider clients

```ts
import { OpenAI } from "aegis-latent-sdk";

const client = new OpenAI({
  baseUrl: "http://127.0.0.1:8080",
  apiKey: process.env.AEGIS_API_KEY!,
  sessionId: "session-1",
});

const response = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Hello, Aegis." }],
});
```

**Compatibility is bounded by the SDK's tests** — the provider surfaces and dependency ranges those tests exercise, not every provider version or endpoint.

## Proof verification

This is the part that is easy to get wrong, and getting it wrong makes the verification meaningless.

```ts
import { parseInclusionProof, proofVerifyingFetch } from "aegis-latent-sdk";

// The root MUST come from a channel independent of the gateway that served
// the response. A root read from the same response proves nothing.
const trustedRoot = await loadRootFromYourOwnAnchor();

const fetchWithVerification = proofVerifyingFetch({
  trustedRoot,
  onVerificationFailure: (error) => {
    // A verification failure is a security event, not a retryable error.
    throw error;
  },
});
```

> **A proof verified against a root supplied by the gateway that produced it establishes internal consistency and nothing more.** The system would be attesting to itself. The SDK cannot tell whether the root you passed is genuinely independent, because a root is a root.

`parseInclusionProof` parses and schema-validates an `InclusionProofV1` when you hold the proof rather than the response.

Schema and semantics: [MMR Proof v1](../../docs/api/MMR_PROOF_V1.md).

## Web Crypto

Verification uses Web Crypto. `resolveSubtleCrypto` locates the implementation across browsers, Node and edge runtimes, and throws where none is available rather than falling back to a hand-rolled hash. **No cryptographic primitive is implemented in this package.**

## Streaming

A stream reports evidence as `pending-terminal` until its terminal summary commits, and no inclusion proof exists before then.

**Check for the terminal marker.** A client that treats connection close as success will silently accept a stream whose terminal commit failed — the gateway withholds the marker precisely so you can tell, and it cannot make you look.

## Instrumentation

`instrumentOperation`, `instrumentOpenAIOperation` and `instrumentAnthropicOperation` accept `OperationHooks` for observing requests. **Do not log governed content, API keys, or raw proof payloads from a hook.**

## Errors

| Error | Thrown when |
| --- | --- |
| `AegisProofError` | A proof is malformed, fails schema validation, or does not verify against the supplied root |

`AegisProofError` on a well-formed proof means the proof did not verify. Treat it as a security event.

## Secure defaults

- Read the API key from the environment. Never hard-code it, and never expose it to a browser bundle.
- Verify proofs against an independently obtained root, always.
- Pin the package to an exact version or commit.
- Use HTTPS for any gateway that is not on localhost.

## Develop

```bash
cd sdk/typescript
npm ci
npm run build
npm test
```

---

**Related:** [Integrations Guide](../../docs/DEVELOPER_INTEGRATIONS_GUIDE.md) · [MMR Proof v1](../../docs/api/MMR_PROOF_V1.md) · [Audit Endpoints](../../docs/api/AUDIT_ENDPOINTS.md) · [Boundaries](../../docs/BOUNDARIES.md)
