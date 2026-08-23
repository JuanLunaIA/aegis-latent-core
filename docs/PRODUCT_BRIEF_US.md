# Product Brief — Aegis Latent Core

This brief is for executive sponsors, economic buyers, platform leaders and security reviewers evaluating Aegis. It defines the product category, buyer problem, evidence wedge, initial ICP, proof sequence and non-goals. It is not a certification, legal opinion, production SLO, or binding commercial offer.

**Last verified:** 2026-08-22 UTC
**Release baseline:** published `v3.1.0`
**Current-main baseline:** post-PR #99, commit `45d95188d40792639fdd654369765a7233bef09a`
**Positioning owner:** Product and release owner
**Primary claim control:** [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)

## Baseline note

The published release is **v3.1.0**. Current main after PR #99 adds bounded SSE with `pending-terminal` evidence, native Anthropic `POST /v1/messages`, Python drop-in and TypeScript provider-native SDK integration, portable MMR proofs, a read-only forensic dashboard, bounded forensic ZIP export, and an auxiliary `RustWal` stream segment. These current-main capabilities are not attributed to the v3.1.0 tag.

## Category

Aegis Latent Core is an **OpenAI-compatible AI Governance and Evidence Gateway** for teams that route governed AI traffic through multiple model providers and need durable, provider-independent evidence of the request/response lifecycle.

## The buyer problem

AI platform teams need to move across model providers while security, privacy, compliance and legal teams need a stable control boundary. Provider dashboards and ordinary access logs vary by vendor and do not necessarily provide a single, replayable evidence contract for request hashes, response hashes, policy outcomes, signing metadata and durability status.

Aegis places a controlled gateway in that boundary. It authenticates the caller, enforces request and egress controls, evaluates WAF/session policy, applies distributed rate limiting and forwards to the selected provider. For non-streaming calls, it commits signed evidence before returning the governed response and can return durable MMR proof headers. For SSE, the initial status is `pending-terminal`; a bounded relay commits one signed terminal summary before the protocol terminal marker, with proof retrieval after termination.

## Initial ICP

The first buyer is a B2B SaaS, fintech or regulated-enterprise platform/security team operating more than one model provider and requiring private deployment. The committee commonly includes a platform owner, an AppSec or CISO sponsor, an AI/ML engineering owner, a privacy/compliance or legal reviewer, procurement and an executive sponsor. Healthcare, government, defense, industrial and scientific deployments are expansion tracks, not proof of vertical compliance.

## Evidence wedge

The product is evaluated through concrete artifacts rather than broad category language:

| Capability | Buyer outcome | Evidence boundary |
|---|---|---|
| Provider ingress and SDK integration | Current main supports the OpenAI-compatible surface and native Anthropic `POST /v1/messages`. Python provides drop-in official-client subclasses; TypeScript uses provider-native wrappers with official SDK peer dependencies. | Supported routes and integration tests; provider semantics still require validation. These additions are not attributed to v3.1.0. |
| Durable signed evidence | Security and compliance teams can replay a record of the governed lifecycle under explicit storage and signer controls. | WAL commit, hashes, signature metadata, key ID and integrity verification. |
| WAF and request controls | Application-layer prompt and structural policy checks occur before upstream forwarding. | Pinned corpus and application boundary; ingress parser remains separate. |
| Provider-independent policy | Egress, rate-limit, session and evidence policies do not depend on one provider dashboard. | Gateway configuration and deployment tests. |
| Portable proof and forensic review | Current main provides MMR inclusion proofs, a read-only dashboard, and bounded ZIP export with JCS, DAG-CBOR, CIDv1, PDF and `VERIFY.sh`. | Proof roots require an independent trust anchor; exports are technical evidence, not legal-admissibility determinations. |
| Private deployment | Customers can keep provider traffic and evidence inside their own infrastructure. | Customer topology, network, retention, backup and key-custody evidence. |

## Measured boundaries

The published v3.1.0 release retained four market-hardening artifacts. The backpressure run preserved 10,000 durable records under a 2 ms injected `fsync` delay but recorded p99 commit latency of 1,189.89 ms. The WAF corpus contains 15 malicious and 8 benign cases. The key-rotation exercise covers three independent local signer instances. The ML-DSA timing experiment passed non-detection for `sign` but returned `p=0.0` for `verify`; no constant-time claim is approved.

Current main separately retains a bounded in-process SSE benchmark of 7 rounds × 1,000 deterministic events. It excludes network, provider and durable-WAL latency and is not capacity or SLO evidence. The auxiliary native `RustWal` segment is likewise not the replay authority; the JSONL ledger remains authoritative.

## Proof sequence

The recommended evaluation is local evaluation, evidence replay, controlled pilot, security review, procurement package and production rollout. The pilot should preserve request/response test vectors, raw benchmark artifacts, a threat model, deployment prerequisites, SBOM/provenance, rollback instructions and a list of controls not provided by Aegis.

## Market context

Portkey, Helicone, LiteLLM and Protect AI provide directional market signals around AI gateway, observability, routing, runtime controls, enterprise support and private deployment. Their public pages do not establish feature parity or Aegis buyer willingness to pay. Aegis should differentiate narrowly through the durable evidence boundary and reproducible failure semantics rather than generic “AI security platform” language.

## What Aegis is not

Aegis is not an LLM, a complete model-safety system, a universal WAF, an authorization to process regulated data, a SOC 2 report, a HIPAA determination, a FedRAMP authorization, an EU AI Act conformity assessment, GDPR legal basis, FIPS 140 validation, a court-admissibility ruling, or a substitute for customer identity, network, privacy, retention or incident-response controls.

## Buyer diligence questions

A buyer should ask which HTTP/2 component owns normalization, which storage system provides durability, how key custody and rotation are performed, how a response is correlated with exactly one evidence record, what happens when Redis or the signer is unavailable, how a three-replica rotation is verified, and what independent review has been completed. The repository provides explicit answers and marks missing evidence rather than filling gaps with marketing language.

## Procurement package

The initial package should include the immutable release link, source and asset hashes, SPDX SBOM, provenance envelope, release-gate record, threat model, data-retention statement, deployment checklist, support matrix, vulnerability disclosure policy, rollback procedure, WAF corpus report and benchmark limitations. Customer counsel and security reviewers remain the decision owners for contractual, legal and compliance conclusions.

## Related documents

- [`README.md`](../README.md)
- [`docs/BUYER_GUIDE_US.md`](BUYER_GUIDE_US.md)
- [`docs/FAQ_PROCUREMENT.md`](FAQ_PROCUREMENT.md)
- [`docs/COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md)
- [`docs/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
