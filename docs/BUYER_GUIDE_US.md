# Buyer Guide — Aegis Latent Core

This guide is for CISO and AppSec reviewers, platform leaders, AI/ML engineering, privacy/compliance, procurement and executive sponsors evaluating Aegis. It describes the product boundary, verification questions, pilot acceptance criteria and procurement blockers. It is not a certification, legal opinion, production SLO, or binding offer.

**Last verified:** 2026-08-22 UTC
**Release baseline:** published `v3.1.0` (latest published)
**Merged v4 source baseline:** commit `2050a310ec295afc61d033ff842c9a535a4f3105` with 14 synchronized `4.0.0` anchors; no v4 tag, GitHub Release, PyPI/npm/OCI publication, or production-release acceptance
**Audience:** US enterprise buyer committee
**Commercial context:** [`docs/COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md)

## Baseline to request

The latest published release remains **v3.1.0**. Commit `2050a310ec295afc61d033ff842c9a535a4f3105` is the merged v4 source baseline and contains 14 synchronized `4.0.0` anchors. Its bounded SSE `pending-terminal` evidence, native Anthropic `POST /v1/messages`, Python and TypeScript SDKs, MMR proofs, forensic dashboard and bounded forensic ZIP export are merged-source capabilities, not v3.1.0 tag claims. The synchronized anchors do not constitute a v4 tag, GitHub Release, PyPI/npm/OCI publication, or production-release acceptance. A buyer should require the quote, SBOM, test evidence and acceptance plan to identify the same baseline.

## Executive answer

Aegis is most relevant when an organization wants a provider-independent gateway for governed AI traffic and needs durable evidence that can be independently verified under its own storage and key-custody controls. It is not a compliance shortcut and should be evaluated as one component of a broader security and governance program.

## Questions by buyer role

| Role | Question | Evidence-led answer |
|---|---|---|
| CISO / AppSec | What attack surface does Aegis cover? | The gateway covers authenticated request admission, request-size bounds, application-layer WAF/session policy, egress endpoint validation, distributed rate-limit failure handling and evidence integrity. It does not cover every model, identity, network, endpoint or semantic attack. |
| Platform engineering | Where does it run? | Self-hosted Python/FastAPI with optional Rust acceleration and optional enterprise storage/signer integrations. The customer owns the runtime, network, secrets, storage and operating objectives. |
| AI/ML engineering | Does it replace provider SDKs? | No. The merged v4 source exposes an OpenAI-compatible surface and native Anthropic `POST /v1/messages`. Python is drop-in through official-client subclasses. TypeScript wrappers remain provider-native and use the official provider packages as peer dependencies; provider models and behavior remain authoritative. |
| Compliance / legal | Does it make us compliant? | No. It can provide control and evidence paths that may support an organization's review. Certification, conformity, legal privilege, admissibility and regulatory conclusions belong to the customer and qualified external reviewers. |
| Procurement | What is included? | Packaging is staged: AGPL community use, a bounded pilot, commercial self-hosted production terms and an enterprise tier only when support, response targets, legal terms and assurance capacity are explicitly available. |
| Privacy | Does Aegis retain prompts? | The deployment controls retention and evidence content. Request/response hashes and metadata may be retained even when raw bodies are not. The customer must define lawful basis, minimization, retention, deletion, residency and access controls. |
| SRE | What happens when storage stalls? | Non-streaming calls return durable headers only after commit. Streams begin `pending-terminal`; their byte/item-bounded relay commits one terminal summary before the protocol terminal marker. The optional native `RustWal` stream segment is auxiliary, while JSONL remains the replay authority. |
| Security architecture | What happens when a key rotates? | The versioned keyring supports one active key, historical verification keys with expiry, atomic reload and non-secret key IDs. A production three-replica claim still requires a real deployment run. |

## Merged v4 source forensic verification

The merged v4 source stores portable `aegis-mmr-inclusion-v1` proofs. Non-streaming responses can carry `X-Aegis-MMR-*` headers; streams provide post-terminal proof retrieval because no completed proof exists in their initial headers. The read-only dashboard exposes retained evidence without fallback sample data and can request a bounded ZIP containing a JCS manifest, canonical DAG-CBOR ledger slice with CIDv1, proof JSON, technical PDF and `VERIFY.sh`. The buyer must pin the trusted MMR root independently, and the export does not determine legal admissibility.

## What the buyer can verify

A buyer can clone the release, inspect the source, run the P0/P1 tests, verify the claims matrix, inspect the SBOM and lockfile, reproduce the local corpus and review the retained release assets. The local evidence is bounded. It does not prove the buyer's ingress, storage, provider, secret manager, kernel, network, backup, support or legal environment.

## Security review checklist

Request the exact release tag and hashes, run the pinned tests, inspect the SBOM and lockfile, review the threat model, verify the deployment kernel and storage assumptions, validate TLS/mTLS and secret-manager integration, test rollback, and run traffic through the actual ingress boundary. Treat missing external-assurance artifacts as open procurement items rather than implied passes.

## Data and retention questions

Aegis can store hashes, model/endpoint metadata, tenant identifiers, sampling metadata, signature metadata and WAL records. Customer deployments must decide whether raw bodies are retained, whether redaction or pseudonymization occurs before evidence construction, how tenant isolation is enforced, and how retention/deletion obligations interact with chain continuity. The repository does not provide a universal answer for every jurisdiction or data category.

## Pilot acceptance criteria

A serious pilot should pass a declared request/response evidence-correlation test, upstream fault test, Redis/rate-limit failure test, WAL replay/integrity test, key-rotation test, pinned WAF corpus, rollback exercise, and security review of the target ingress, storage, secret manager and container profile. The pilot report must state request volume, workload, environment, rejected traffic, evidence completeness, failed cases and residual risk.

The pilot should also record the ML-DSA decision explicitly. The current release has no approved constant-time verify claim because the retained experiment returned `p=0.0`. A buyer that requires a constant-time cryptographic claim must treat this as a release blocker or define an approved alternative signer boundary.

## Procurement blockers before production

Production procurement should remain blocked when there is no accountable support owner, no incident/disclosure process, no customer-specific retention and residency statement, no rollback owner, no independent security review for the intended risk tier, no tested key custody, no target storage durability evidence, or any public claim stronger than its underlying artifact.

## Commercial validation questions

Before accepting a pricing proposal, ask which topology, environments, request tier, provider mix, retention, storage, support hours, response targets, security questionnaire scope, legal entity, deployment geography, escalation process, release cadence and exclusions are included. The retained Team/Pilot USD 10,000–30,000, Production USD 40,000–100,000 and Enterprise USD 100,000–250,000+ ranges are internal hypotheses pending buyer interviews, normalized quotes, paid pilots and cost-to-serve data. They are not list prices, observed ACV, vertical ACV or a valuation.

## Decision boundary

The correct procurement question is not “Does Aegis make us compliant?” It is “Does this gateway provide a control and evidence boundary that, under our deployment and organizational controls, reduces the verification gap we currently have?” The answer requires a customer-specific pilot and qualified review.

## Related documents

- [`README.md`](../README.md)
- [`docs/PRODUCT_BRIEF_US.md`](PRODUCT_BRIEF_US.md)
- [`docs/FAQ_PROCUREMENT.md`](FAQ_PROCUREMENT.md)
- [`docs/COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md)
- [`docs/compliance/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md)
- [`docs/privacy/DATA_RETENTION.md`](privacy/DATA_RETENTION.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
