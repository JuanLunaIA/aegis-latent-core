<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core 3.1.0 Candidate
## AI Governance and Evidence Gateway

**Audience:** US enterprise platform, AppSec, AI engineering, compliance, legal, and procurement teams
**Status:** Product prospectus and evaluation guide; not a certification, legal opinion, or binding commercial offer

## Executive brief

Aegis Latent Core is an OpenAI-compatible gateway for governed AI traffic. It authenticates callers, applies request and egress policy, runs application-layer WAF and session checks, applies distributed rate limiting, forwards to an upstream model provider, and commits a signed evidence record before returning a governed successful response. The evidence record binds the request and response hashes, chain linkage, signer metadata, request identifiers, and durable status under the declared storage and signer configuration.

The core product is an **evidence boundary**. It does not attempt to make a broad claim that a model, organization, deployment, or jurisdiction is automatically compliant. It provides a control point and reproducible evidence paths for a customer’s broader governance program.

## Why the category matters

Teams that route AI requests through multiple providers often need a stable internal boundary for authentication, policy, provider routing, error handling, and evidence. Ordinary provider dashboards and application logs may be useful but are not a provider-independent evidence contract. Aegis makes the request lifecycle explicit and publishes the evidence status to the caller.

## Product capabilities

| Capability | What it does | Boundary |
|---|---|---|
| OpenAI-compatible gateway | Provides a stable client-facing integration surface for supported request types. | Provider-specific behavior and streaming parameters still require integration tests. |
| Durable signed evidence | Hashes and signs governed records, appends to a WAL, flushes, and synchronizes before the governed success path. | Storage, backup, host, and external immutability remain deployment controls. |
| Durable error evidence | Records upstream non-2xx, circuit-open, and network-fault evidence where the evidence boundary remains available. | Storage failure after admission is a fail-closed incident, not evidence of success. |
| WAF and request policy | Normalizes text, blocks critical patterns, guards structure, and applies weighted local analysis. | Application-layer boundary; ingress HTTP/2 parser behavior is separate. |
| Egress and rate limiting | Validates endpoint forms and fails closed when the distributed limiter is unavailable in strict mode. | Network policy and Redis/HA behavior remain customer-owned. |
| Bounded enrichment | Runs optional response analysis in bounded workers after authoritative evidence exists. | Enrichment may be rejected or delayed without weakening evidence. |
| Key rotation | Supports an atomic versioned HMAC keyring with overlap, expiry, and non-secret key IDs. | Three-replica propagation and secret-manager custody require deployment evidence. |

## Integration example

```python
from openai import OpenAI

client = OpenAI(
    api_key="<aegis-api-key-from-secret-manager>",
    base_url="https://aegis.internal.example/v1",
)
```

The customer must validate the actual provider, model parameters, streaming behavior, authentication policy, retention, and error semantics. A one-line client configuration change is not a promise that every provider feature is identical through the gateway.

## Evidence contract

A governed response is returned with `X-Aegis-Evidence-Status: durable` when the authoritative evidence path has completed under the configured contract. Request and session identifiers allow correlation. The response-analysis alert count may be preliminary because enrichment runs after the durable commit; authoritative enrichment is read from its evidence store.

The ledger supports integrity verification through chain linkage, hashes, signatures, WAL replay, and export manifests. HMAC-SHA256 is symmetric and classical. Native ML-DSA-65 is configuration-dependent and does not, by itself, establish constant-time execution, FIPS 140 validation, or legal admissibility.

## Performance and resilience evidence

The release separates dispatch microbenchmarks, end-to-end proxy behavior, upstream latency, WAL durability, WAF corpus metrics, and native crypto timing. The background dispatch measurement in `docs/BENCHMARKS.md` is not end-to-end latency. The v3.1.0 candidate backpressure run offered 10,000 requests at 10k RPS with a 2 ms injected `fsync` delay and observed 10,000 durable records, zero failures, zero missing IDs, zero duplicate IDs, and valid chain integrity. It observed p99 commit latency of 1,189.89 ms. This demonstrates tested correlation under an injected seam; it is not accepted production capacity or an SLO.

The local WAF corpus contains 15 malicious and 8 benign cases. The current run observed zero bypasses and zero false positives for that pinned corpus, with a wide confidence interval because the corpus is small. HTTP/2 fragmentation and `nuclei-templates/waf-bypass` are not represented by that application-layer result.

## Assurance status

The project distinguishes repository evidence, deployment acceptance, and independent assurance. It does not claim SOC 2, HIPAA, FedRAMP, EU AI Act conformity, GDPR compliance, FIPS 140 validation, court admissibility, or a customer-specific SLO. A customer must validate ingress, storage, backup/restore, secret manager, key rotation, kernel controls, Redis, TLS, network policy, retention, and incident response.

## Buyer evaluation path

The recommended path is local evaluation, evidence replay, controlled pilot, security review, procurement package, and production rollout. The buyer package should contain the immutable release link, source/tree and asset hashes, SBOM, provenance, release gate, claim matrix, threat model, deployment guide, key-rotation runbook, backpressure report, WAF report, vulnerability disclosure policy, retention statement, support matrix, and rollback criteria.

## Packaging and pricing hypothesis

Aegis is staged as Community/OSS, Team/Pilot, Production, Enterprise, and future Sovereign/OEM packages. The commercial strategy includes illustrative pilot and annual ranges for validation only; it does not publish a binding price, unlimited support, automatic AGPL exemption, or 24/7 promise. See [`COMMERCIAL.md`](../COMMERCIAL.md) and [`COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md).

## Explicit non-goals

Aegis is not an LLM, a universal WAF, a universal model-safety system, a network firewall, a secret manager, an immutable backup service, a legal-admissibility ruling, a certification body, or a replacement for customer identity, privacy, retention, compliance, and incident-response controls. It does not claim global cross-replica ordering or multi-region HA in the current topology. The `zk_proof` and public-blockchain anchoring surfaces remain open or dependency-gated work.

## References

[1]: https://www.nist.gov/itl/ai-risk-management-framework "NIST AI Risk Management Framework"
[2]: https://www.nist.gov/cyberframework "NIST Cybersecurity Framework"
[3]: https://csrc.nist.gov/pubs/fips/204/final "FIPS 204: Module-Lattice-Based Digital Signature Standard"
[4]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v3.0.1 "Aegis Latent Core v3.0.1 release artifacts"
[5]: https://portkey.ai/pricing "Portkey pricing"
[6]: https://www.helicone.ai/pricing "Helicone pricing"
[7]: https://www.litellm.ai/pricing "LiteLLM pricing"

The referenced frameworks provide external context. They do not certify Aegis or a customer deployment.
