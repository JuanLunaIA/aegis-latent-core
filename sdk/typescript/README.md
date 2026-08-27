# Aegis TypeScript SDK

The **`aegis-latent-sdk`** package provides a strict, dependency-free runtime for `aegis-mmr-inclusion-v1` verification and transparent provider-operation instrumentation.

## Develop from a clean checkout

The checked-out source baseline/release target is `v4.0.2` with 14 synchronized anchors. npm was last observed at `4.0.0`, but
[registry presence](https://www.npmjs.com/package/aegis-latent-sdk) does not prove
that the failed `v4.0.1` tag workflow produced it. Do not use a `4.0.2` registry
install until publication and readback succeed; for source development, use this checkout and do not substitute a similarly named
package. Run these commands from the repository root:

```bash
cd sdk/typescript
npm ci
npm run typecheck
npm test
npm run build
npm pack --dry-run
```

`npm run check` is the equivalent combined typecheck, test, and build gate. The
`cd sdk/typescript` step is required because the lockfile, TypeScript configs,
tests, and generated `dist/` package are component-relative. See the
[repository overview](../../README.md), [developer quickstart](../../docs/DEVELOPER_QUICKSTART.md),
[SDK guide](../../docs/DEVELOPER_SDK_GUIDE.md), and
[integration guide](../../docs/DEVELOPER_INTEGRATIONS_GUIDE.md) for canonical project
documentation.

Use the structural constructor options with the official provider packages; Aegis does not replace or re-declare their response types:

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

The Anthropic native route is available only when the gateway itself is configured with `AEGIS_PROVIDER=anthropic`. Keep provider tokens in a server or approved secret boundary; do not embed them in a browser bundle.

```ts
import { parseInclusionProof, verifyInclusionHash } from "aegis-latent-sdk/proof";

const proof = parseInclusionProof(untrustedJson);
const valid = await verifyInclusionHash(leafHashHeader, proof, pinnedRoot);
```

The runtime uses `SubtleCrypto`, `TextEncoder`, `TextDecoder`, `Headers`, and typed arrays. It does not import Node built-ins, `Buffer`, provider SDKs, or filesystem APIs. Node 18+ and edge runtimes with Web Crypto are supported; callers may inject `SubtleCrypto` explicitly.

`instrumentOperation` wraps a selected native provider method while preserving its receiver, argument tuple, synchronous or asynchronous result, thrown errors, and async-iterable laziness. The OpenAI and Anthropic aliases are provider labels only; no vendor package is bundled and no payload is normalized.

The MMR v1 algorithm intentionally hashes ASCII lowercase hexadecimal strings to match the established Python/Rust accumulator. It is not a conventional binary-digest MMR. Proof validation binds the logical leaf index, mountain topology, path directions, complete peak set, and independently trusted root. `X-Aegis-MMR-Leaf` is already the leaf SHA-256 digest; it does not contain request or response bytes.
