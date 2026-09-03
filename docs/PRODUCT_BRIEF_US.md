# Product Brief — Aegis Latent Core

This brief is for executive sponsors, economic buyers, platform leaders and security reviewers evaluating Aegis. It defines the product category, buyer problem, evidence wedge, initial ICP, proof sequence and non-goals. It is not a certification, legal opinion, production SLO, or binding commercial offer.

**Last verified:** 2026-08-27 UTC
**Release baseline:** checked-out source baseline/release target `v4.1.2` with 14 synchronized anchors
**Source baseline/release target:** `v4.1.1` with 14 synchronized anchors; source metadata does not establish external lifecycle state; verify the tag, GitHub Release, PyPI, npm, OCI digest, signature, and attestation through independent readback
**External baseline:** signed annotated `v4.1.1` tag at `5a137c86ecd914842493babb7e863033498f68c9`, with GitHub Release (31 assets), PyPI `aegis-latent-sdk` `4.1.1`, and GHCR gateway/dashboard images read back on 2026-09-03; npm remains at `4.0.0`, the one surface the release did not reach
**Historical external baseline:** signed annotated `v4.0.2` tag at `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`, with GitHub Release and GHCR gateway/dashboard images read back on 2026-09-02; before it, lightweight `v4.0.1` at `6469904380218584ae0b5221334bc9a46500f5ba` with failed tag workflows; PyPI/npm observed at `4.0.0` without attributed provenance
**Positioning owner:** Product and release owner
**Primary claim control:** [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)

## Baseline note

The checked-out source baseline/release target is **4.1.1** with 14 synchronized anchors. It adds bounded SSE with `pending-terminal` evidence, native Anthropic `POST /v1/messages`, Python drop-in and TypeScript provider-native SDK integration, portable MMR proofs, a read-only forensic dashboard, bounded forensic ZIP export, and an auxiliary `RustWal` stream segment. These checked-out-source capabilities do not establish external lifecycle or production-acceptance state; verify the `v4.1.1` tag, GitHub Release, PyPI and npm artifacts, OCI digest, signature, and attestation through independent readback.

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
| Provider ingress and SDK integration | The checked-out `v4.1.2` source supports the OpenAI-compatible surface and native Anthropic `POST /v1/messages`. Python provides drop-in official-client subclasses; TypeScript uses provider-native wrappers with official SDK peer dependencies. | Supported routes and integration tests; provider semantics still require validation. These additions are not attributed to v3.1.0. |
| Durable signed evidence | Security and compliance teams can replay a record of the governed lifecycle under explicit storage and signer controls. | WAL commit, hashes, signature metadata, key ID and integrity verification. |
| WAF and request controls | Application-layer prompt and structural policy checks occur before upstream forwarding. | Pinned corpus and application boundary; ingress parser remains separate. |
| Provider-independent policy | Egress, rate-limit, session and evidence policies do not depend on one provider dashboard. | Gateway configuration and deployment tests. |
| Portable proof and forensic review | The checked-out `v4.1.2` source provides MMR inclusion proofs, a read-only dashboard, and bounded ZIP export with JCS, DAG-CBOR, CIDv1, PDF and `VERIFY.sh`. | Proof roots require an independent trust anchor; exports are technical evidence, not legal-admissibility determinations. |
| Private deployment | Customers can keep provider traffic and evidence inside their own infrastructure. | Customer topology, network, retention, backup and key-custody evidence. |

## Measured boundaries

The published v3.1.0 release retained four market-hardening artifacts. The backpressure run preserved 10,000 durable records under a 2 ms injected `fsync` delay but recorded p99 commit latency of 1,189.89 ms. The WAF corpus contains 15 malicious and 8 benign cases. The key-rotation exercise covers three independent local signer instances. The ML-DSA timing experiment passed non-detection for `sign` but returned `p=0.0` for `verify`; no constant-time claim is approved.

The checked-out `v4.1.2` source separately retains a bounded in-process SSE benchmark of 7 rounds × 1,000 deterministic events. It excludes network, provider and durable-WAL latency and is not capacity or SLO evidence. The auxiliary native `RustWal` segment is likewise not the replay authority; the JSONL ledger remains authoritative.

## Proof sequence

The recommended evaluation is local evaluation, evidence replay, controlled pilot, security review, procurement package and production rollout. The pilot should preserve request/response test vectors, raw benchmark artifacts, a threat model, deployment prerequisites, SBOM/provenance, rollback instructions and a list of controls not provided by Aegis.

## Market context

Portkey, Helicone, LiteLLM and Protect AI provide directional market signals around AI gateway, observability, routing, runtime controls, enterprise support and private deployment. Their public pages do not establish feature parity or Aegis buyer willingness to pay. Aegis should differentiate narrowly through the durable evidence boundary and reproducible failure semantics rather than generic “AI security platform” language.

## What Aegis is not

Aegis is not an LLM, a complete model-safety system, a universal WAF, an authorization to process regulated data, a SOC 2 report, a HIPAA determination, a FedRAMP authorization, an EU AI Act conformity assessment, GDPR legal basis, FIPS 140 validation, a court-admissibility ruling, or a substitute for customer identity, network, privacy, retention or incident-response controls.

## Value framing by stakeholder

Each row states what the role gains, the single artifact that role should verify first, and the claim that role must not carry into an internal business case. The third column is the operative one: most failed evaluations trace to a stakeholder assuming a property from an adjacent column.

| Stakeholder | What the gateway offers this role | Verify first | Must not be claimed by this role |
|---|---|---|---|
| CISO / AppSec lead | A governed admission path and a tamper-evident record of what was asked and answered, with failure paths that fail closed rather than silently degrade | The threat model's non-goals, then its controls | Certification, independent audit, protection against a host-root or hypervisor adversary, or prevention of prompt injection |
| Platform / SRE engineer | Deterministic, bounded resource behavior per stream, named metrics, and written runbooks for stall, corruption, rotation, and rollback | The topology boundary matrix for the intended deployment | An availability target, a recovery objective, capacity, or evidence continuity across failover |
| AI / data engineer | An OpenAI-compatible surface and native Anthropic route with drop-in clients, plus bounded incremental redaction that settles identifiers before release | Drop-in behavior and redaction scope against your own traffic | Any latency or throughput figure not measured on your workload, or detection of identifier classes outside the supported grammars |
| Chief compliance officer / legal counsel | Technical inputs that may contribute to a control narrative: retention controls, minimisation by hashing rather than body storage, and a signed, linked record | The regulatory dossier read as contribution mapping | Conformity, certification, safe-harbour status, admissibility, or resolution of an erasure obligation |
| CFO / procurement director | A self-hosted deployment with no per-token metering, an inspectable licence boundary, and a quote built from named cost drivers | The licence path and the cost-driver input schedule | Observed contract value, return-on-investment percentage, avoided fines, customer counts, or a valuation |

Two cross-cutting cautions. First, the runtime is customer-operated in every supported model, so operational cost, availability, and recovery belong to the buyer regardless of which commercial tier is selected. Second, the evidence model records governed interactions; it does not evaluate whether a model's answer was correct, safe, or appropriate, and no stakeholder should present it as a quality or safety assurance for model output.

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
