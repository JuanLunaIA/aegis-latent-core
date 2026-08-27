# Aegis Latent Core
## AI Governance and Evidence Gateway

This prospectus is for US enterprise platform, AppSec, AI engineering, compliance, legal and procurement teams evaluating Aegis. It explains the product category, evidence wedge, measured boundaries and recommended evaluation path. It is not a certification, legal opinion, production SLO, warranty or binding commercial offer.

**Last verified:** 2026-08-27 UTC
**Source baseline/release target:** `v4.0.2` with 14 synchronized anchors; source metadata does not establish external lifecycle state; verify the tag, GitHub Release, PyPI, npm, OCI digest, signature, and attestation through independent readback
**Historical external baseline:** lightweight `v4.0.1` tag at `6469904380218584ae0b5221334bc9a46500f5ba` with failed tag workflows; PyPI/npm observed at `4.0.0` without attributed provenance

## Baseline note

The checked-out source baseline/release target is **4.0.2** with 14 synchronized anchors. It adds bounded SSE with `pending-terminal` evidence, native Anthropic `POST /v1/messages`, Python drop-in and TypeScript provider-native SDK integration, portable MMR proofs, a read-only forensic dashboard, bounded JCS/DAG-CBOR/CIDv1/PDF/`VERIFY.sh` ZIP export, and an auxiliary `RustWal` stream segment. These checked-out-source capabilities do not establish external lifecycle or production-acceptance state; verify the `v4.0.2` tag, GitHub Release, PyPI and npm artifacts, OCI digest, signature, and attestation through independent readback.

## Executive brief

Aegis Latent Core is an OpenAI-compatible gateway for governed AI traffic. It authenticates callers, applies request and egress policy, runs application-layer WAF and session checks, applies distributed rate limiting, forwards to an upstream model provider, and commits a signed evidence record before returning a governed successful response. The evidence record binds request and response hashes, chain linkage, signer metadata, request identifiers and durable status under the declared storage and signer configuration.

The core product is an **evidence boundary**. It does not claim that a model, organization, deployment or jurisdiction is automatically compliant. It provides a control point and reproducible evidence paths for a customer's broader governance program.

## Why the category matters

Teams routing AI requests through multiple providers often need a stable internal boundary for authentication, policy, provider routing, error handling and evidence. Ordinary provider dashboards and application logs may be useful but are not necessarily a provider-independent evidence contract. Aegis makes the request lifecycle explicit and publishes evidence status to the caller.

## Product capabilities

| Capability | What it does | Boundary |
|---|---|---|
| Provider ingress | Provides an OpenAI-compatible surface; the checked-out `v4.0.2` source also preserves native Anthropic `POST /v1/messages` wire types. | Provider-specific behavior and streaming parameters still require integration tests; Anthropic ingress is not attributed to v3.1.0. |
| Durable signed evidence | Hashes and signs governed records, appends to a WAL, flushes and synchronizes before the governed success path. | Storage, backup, host and external immutability remain deployment controls. |
| Durable error evidence | Records upstream non-2xx, circuit-open and network-fault evidence where the evidence boundary remains available. | Storage failure after admission is a fail-closed incident, not evidence of success. |
| WAF and request policy | Normalizes text, blocks critical patterns, guards structure and applies weighted local analysis. | Application-layer boundary; ingress HTTP/2 parser behavior is separate. |
| Egress and rate limiting | Validates endpoint forms and fails closed when the distributed limiter is unavailable in strict mode. | Network policy and Redis/HA behavior remain customer-owned. |
| Bounded enrichment | Runs optional response analysis in bounded workers after authoritative evidence exists. | Enrichment may be rejected or delayed without weakening evidence. |
| Key rotation | Supports an atomic versioned HMAC keyring with overlap, expiry and non-secret key IDs. | Three-replica propagation and secret-manager custody require deployment evidence. |
| Portable proof and forensic export | The checked-out `v4.0.2` source stores portable MMR proofs and provides a read-only dashboard plus bounded JCS/DAG-CBOR/CIDv1/PDF/`VERIFY.sh` ZIP export. | A trusted root must come from an independent channel; the PDF is a technical report, not a certification. |

## Integration example

```python
from openai import OpenAI

client = OpenAI(
    api_key="<aegis-api-key-from-secret-manager>",
    base_url="https://aegis.internal.example/v1",
)
```

The customer must validate the actual provider, model parameters, streaming behavior, authentication policy, retention and error semantics. A one-line client configuration change is not a promise that every provider feature is identical through the gateway.

## Evidence contract

A non-streaming governed response is returned with `X-Aegis-Evidence-Status: durable` when the authoritative evidence path has completed under the configured contract, and the checked-out `v4.0.2` source can include `X-Aegis-MMR-*` proof headers. A stream instead starts with `X-Aegis-Evidence-Status: pending-terminal`; its bounded relay commits one terminal summary before the protocol terminal marker, and proof retrieval occurs after termination. Request and session identifiers allow correlation. The response-analysis alert count may be preliminary because enrichment runs after the durable commit; authoritative enrichment is read from its evidence store.

The ledger supports integrity verification through chain linkage, hashes, signatures, WAL replay and export manifests. The merged-source Python SDK is drop-in through official-client subclasses; TypeScript integration remains provider-native and declares the official provider SDKs as peer dependencies. HMAC-SHA256 is symmetric and classical. Native ML-DSA-65 is configuration-dependent and does not, by itself, establish constant-time execution, FIPS 140 validation or legal admissibility.

## Performance and resilience evidence

The release separates dispatch microbenchmarks, end-to-end proxy behavior, upstream latency, WAL durability, WAF corpus metrics and native crypto timing. The background dispatch measurement in [`docs/BENCHMARKS.md`](BENCHMARKS.md) is not end-to-end latency.

The v3.1.0 backpressure run offered 10,000 requests at 10,000 RPS with a 2 ms injected `fsync` delay and observed 10,000 durable records, zero failures, zero missing IDs, zero duplicate IDs and valid chain integrity. It observed p99 commit latency of 1,189.89 ms. This demonstrates tested correlation under an injected seam; it is not accepted production capacity or an SLO.

The checked-out `v4.0.2` source also retains an in-process bounded SSE benchmark (7 rounds × 1,000 deterministic events). It excludes network, provider and durable-WAL latency and is not capacity or SLO evidence. Its optional native `RustWal` stream segment is auxiliary; the JSONL ledger remains the replay authority.

The local WAF corpus contains 15 malicious and 8 benign cases. The run observed zero bypasses and zero false positives for that pinned corpus, with a wide confidence interval because the corpus is small. HTTP/2 fragmentation and `nuclei-templates/waf-bypass` are not represented by that application-layer result.

The local key-rotation exercise recorded 2,239 signatures across three independent signer instances with zero failed commits and zero unverifiable records. Secret-manager propagation and real orchestrator acceptance remain unverified. The ML-DSA timing experiment used 1,000,000 samples per operation; `sign` returned `p=0.8521504207157158`, while `verify` returned `p=0.0`. No constant-time verification claim is approved.

## Assurance status

The project distinguishes repository evidence, deployment acceptance and independent assurance. It does not claim SOC 2, HIPAA, FedRAMP, EU AI Act conformity, GDPR compliance, FIPS 140 validation, court admissibility or a customer-specific SLO. A customer must validate ingress, storage, backup/restore, secret manager, key rotation, kernel controls, Redis, TLS, network policy, retention and incident response.

Framework references such as NIST AI RMF, NIST CSF, NIST FIPS 204, W3C WCAG 2.2, CISA Secure by Design, IETF HTTP/2, ISO/IEC 42001 and applicable legal texts are review lenses or contribution mappings. They do not certify Aegis or the customer's deployment.

## Buyer evaluation path

The recommended path is local evaluation, evidence replay, controlled pilot, security review, procurement package and production rollout. The buyer package should contain the immutable release link, source and asset hashes, SBOM, provenance, release gate, claims matrix, threat model, deployment guide, key-rotation runbook, backpressure report, WAF report, vulnerability disclosure policy, retention statement, support matrix and rollback criteria.

## Packaging and pricing hypothesis

Aegis is staged as Community/OSS, Team/Pilot, Production, Enterprise and future Sovereign/OEM packages. The commercial strategy includes illustrative pilot and annual ranges for validation only; it does not publish a binding price, unlimited support, automatic AGPL exemption or 24/7 promise. See [`COMMERCIAL.md`](../COMMERCIAL.md) and [`COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md).

## Explicit non-goals

Aegis is not an LLM, a universal WAF, a universal model-safety system, a network firewall, a secret manager, an immutable backup service, a legal-admissibility ruling, a certification body or a replacement for customer identity, privacy, retention, compliance and incident-response controls. It does not claim global cross-replica ordering or multi-region HA in the current topology. The `zk_proof` and public-blockchain anchoring surfaces remain open or dependency-gated work.

## Related documents

- [`README.md`](../README.md)
- [`docs/PRODUCT_BRIEF_US.md`](PRODUCT_BRIEF_US.md)
- [`docs/BUYER_GUIDE_US.md`](BUYER_GUIDE_US.md)
- [`docs/FAQ_PROCUREMENT.md`](FAQ_PROCUREMENT.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/benchmarks/BENCHMARK_RESULTS.md`](benchmarks/BENCHMARK_RESULTS.md)
- [`docs/security/THREAT_MODEL.md`](security/THREAT_MODEL.md)
- [`docs/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md)

## References

[1]: https://www.nist.gov/itl/ai-risk-management-framework "NIST AI Risk Management Framework"
[2]: https://www.nist.gov/cyberframework "NIST Cybersecurity Framework"
[3]: https://csrc.nist.gov/pubs/fips/204/final "FIPS 204: Module-Lattice-Based Digital Signature Standard"
[4]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v3.1.0 "Aegis Latent Core v3.1.0 release artifacts"
[5]: https://www.w3.org/TR/WCAG22/ "Web Content Accessibility Guidelines (WCAG) 2.2"
[6]: https://www.cisa.gov/securebydesign "CISA Secure by Design"
[7]: https://www.rfc-editor.org/rfc/rfc9113 "HTTP/2 RFC 9113"
[8]: https://www.iso.org/standard/81230.html "ISO/IEC 42001:2023"
