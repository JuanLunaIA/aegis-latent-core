# Procurement FAQ — Aegis Latent Core

This FAQ is for procurement officers, economic buyers, legal teams, CISOs and evaluation committees. It explains what the repository can support, what requires a commercial agreement or customer assessment, and which questions must be answered before a quote. It is not a binding offer or legal advice.

**Last verified:** 2026-08-27 UTC
**Release baseline:** checked-out source baseline `v5.0.1` with fourteen synchronized anchors — **published 2026-09-24 on every surface except PyPI `aegis-latent-core`**, read back the same day (`docs/RELEASE_STATUS.md` §1.0a); the previous release is `v5.0.0`, published 2026-09-16 on every surface except PyPI `aegis-latent-core` — per-surface readbacks, the latest published release and the historical baselines are stated once, and only, in [`docs/RELEASE_STATUS.md`](RELEASE_STATUS.md) §1.0–§1.1, which is the only document that establishes publication state
**Audience:** Procurement, legal, security and executive sponsors
**Commercial documents:** [`COMMERCIAL.md`](../COMMERCIAL.md), [`docs/COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md)

## Which product baseline is being evaluated?

The checked-out source baseline is **5.0.1** with 14 synchronized anchors — published 2026-09-24 on every surface except PyPI `aegis-latent-core` (see `docs/RELEASE_STATUS.md` §1.0a); **5.0.0** is the previous release. Its bounded SSE `pending-terminal` flow, native Anthropic `POST /v1/messages`, Python and TypeScript SDKs, portable MMR proofs, forensic dashboard and bounded ZIP export are checked-out-source capabilities. They do not establish external lifecycle or production-acceptance state; verify the `v4.1.1` tag, GitHub Release, PyPI and npm artifacts, OCI digest, signature, and attestation through independent readback. Procurement documents, security evidence and acceptance tests must name one baseline rather than combining them.

## What category is this product?

Aegis is an OpenAI-compatible AI Governance and Evidence Gateway. Its differentiated technical boundary is durable, independently verifiable evidence for governed request/response lifecycles. It is not a general compliance product, universal WAF, model-safety system, or managed security service.

## Who is the intended buyer?

The initial buyer is a platform or security team operating multi-provider AI applications that needs an explicit evidence boundary, policy enforcement and replayable records. The buying committee commonly includes platform engineering, AppSec, AI engineering, privacy/compliance, legal, procurement and an accountable executive sponsor.

## What is included in the open-source evaluation?

The repository includes source, tests, public documentation, local benchmark harnesses, CI definitions and release evidence. Community use is subject to the repository license. The open-source path does not include private onboarding, a response-time commitment, incident coverage, custom integration work, certification, or a customer-specific assurance package.

## Is commercial licensing available?

The repository states an AGPLv3 plus commercial licensing structure. The actual effect of network-use obligations, exemptions, future-version rights, warranties, indemnities, tax, redistribution and support must be defined in an executed agreement reviewed by customer counsel. `COMMERCIAL.md` is not a substitute for the license text or counsel.

## Is pricing fixed?

No. The retained internal hypotheses are Team/Pilot USD 10,000–30,000, Production USD 40,000–100,000, and Enterprise USD 100,000–250,000+. They are not list prices, observed ACV, vertical ACV, a valuation, or binding offers. The documented directional packages are a free community path, a time-boxed pilot, commercial self-hosted production terms, and an enterprise tier only when accountable support and legal capacity exist.

| Package | Directional scope | Price status |
|---|---|---|
| Community / OSS | Source, tests, documentation and self-hosted evaluation | No commercial support promise |
| Team / Pilot | Defined workload, evidence replay, bounded architecture review and limited implementation support | Illustrative fixed-scope hypothesis |
| Production | Commercial self-hosted deployment, updates and deployment guidance | Annual hypothesis sized by topology and support |
| Enterprise | Multiple environments, security review and negotiated response targets | Custom hypothesis requiring staffing and legal terms |
| Sovereign / OEM | Air-gapped, redistribution, escrow or embedded rights | Future/custom only; not a default offer |

## What inputs are required before quoting?

A defensible quote requires topology, environments, request volume, model providers, streaming profile, ingress and egress, retention, storage, backup, secret manager, key custody, support hours, incident escalation, rollback owner, security questionnaire scope, legal entity, data-processing role, geography and required assurance artifacts. A quote that omits these inputs is not an enterprise-ready quote.

## Is 24/7 support available?

The repository does not claim 24/7 support. A support commitment requires named staffing, hours, severity definitions, response and restoration objectives, escalation, supported versions, maintenance windows, exclusions and an incident operating model. Do not infer support coverage from a GitHub repository or an annual price hypothesis.

## Is there a production SLO?

No repository-wide production SLO is published. Local benchmark measurements are not SLOs. A customer-specific SLO requires a measured workload, topology, dependency model, capacity plan, error budget, telemetry, staffing and contract.

## Is Aegis SOC 2, HIPAA, FedRAMP or GDPR compliant?

No. The repository provides technical controls and contribution mappings that a customer may evaluate as part of a broader program. It does not provide a SOC 2 report, HIPAA determination, FedRAMP authorization, EU AI Act conformity assessment, GDPR legal basis, or FIPS 140 validation.

## What security evidence is available?

The release includes source, tests, claims matrix, dependency and supply-chain artifacts, WAF corpus result, backpressure result, local key-rotation result, ML-DSA timing result, provenance and asset hashes. The evidence is bounded. In particular, the ML-DSA verify timing claim is blocked, HTTP/2 and Nuclei WAF testing were not executed, and real secret-manager orchestration acceptance remains unverified.

## Can procurement rely on the benchmark numbers?

Procurement can use them as evaluation inputs, not universal promises. The backpressure artifact preserved 2,500 durable records under an injected seam at 10,000 RPS offered and recorded p99 commit latency of 836.3514210795984 ms (`evidence/execution_2026-08-20/backpressure_stall_report.json`); the current baseline records 51.87 ms (`evidence/execution_2026-09-16/`). A previously published 10,000-record run with p99 1,189.89 ms is retracted (`UC-018`) — no artifact in this tree produces it. The WAF corpus is small. The key-rotation run is local. The timing experiment is not a proof of constant-time behavior.

## What source integration and evidence artifacts are available?

The checked-out `v5.0.1` source supports native Anthropic `POST /v1/messages` in addition to the OpenAI-compatible ingress. The Python SDK is drop-in through official-client subclasses. TypeScript uses provider-native wrappers and options, with the official provider packages as peer dependencies; it does not replace their models or normalize their payloads. Non-streaming responses can return durable status and `X-Aegis-MMR-*` proof headers. Streaming responses begin `pending-terminal`, commit one terminal summary before the protocol terminal marker, and expose post-terminal proof retrieval.

The read-only forensic dashboard can request a bounded ZIP containing a JCS manifest, canonical DAG-CBOR ledger slice with CIDv1, MMR proof JSON, a technical PDF certificate and `VERIFY.sh`.

## Does an export have legal admissibility?

No. An export can provide integrity and provenance inputs for a broader evidentiary record. Admissibility is a jurisdiction-specific legal decision that depends on acquisition, custody, authentication, relevance, reliability, testimony and procedure.

## What is the recommended buying sequence?

Start with a local evaluation, run evidence replay, execute a controlled pilot with a named workload, complete security and privacy review, confirm support and rollback ownership, then negotiate commercial and legal terms. Do not begin with a certification claim or an unbounded capacity promise.

## Procurement red flags

Pause the purchase if a proposal uses “compliant,” “certified,” “court-admissible,” “quantum-safe,” “zero latency,” “unlimited throughput,” “24/7,” or “production-ready” without a named artifact, scope, reviewer, contract and falsification condition.

## Related documents

- [`README.md`](../README.md)
- [`docs/BUYER_GUIDE_US.md`](BUYER_GUIDE_US.md)
- [`docs/PRODUCT_BRIEF_US.md`](PRODUCT_BRIEF_US.md)
- [`docs/COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md)
- [`COMMERCIAL.md`](../COMMERCIAL.md)
- [`docs/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md)
- [`SECURITY.md`](../SECURITY.md)
