# Buyer Guide — Aegis Latent Core v3.1.0

This guide is for CISO and AppSec reviewers, platform leaders, AI/ML engineering, privacy/compliance, procurement and executive sponsors evaluating Aegis. It describes the product boundary, verification questions, pilot acceptance criteria and procurement blockers. It is not a certification, legal opinion, production SLO, or binding offer.

**Last verified:** 2026-08-18 UTC
**Release baseline:** `v3.1.0`
**Audience:** US enterprise buyer committee
**Commercial context:** [`docs/COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md)

## Executive answer

Aegis is most relevant when an organization wants a provider-independent gateway for governed AI traffic and needs durable evidence that can be independently verified under its own storage and key-custody controls. It is not a compliance shortcut and should be evaluated as one component of a broader security and governance program.

## Questions by buyer role

| Role | Question | Evidence-led answer |
|---|---|---|
| CISO / AppSec | What attack surface does Aegis cover? | The gateway covers authenticated request admission, request-size bounds, application-layer WAF/session policy, egress endpoint validation, distributed rate-limit failure handling and evidence integrity. It does not cover every model, identity, network, endpoint or semantic attack. |
| Platform engineering | Where does it run? | Self-hosted Python/FastAPI with optional Rust acceleration and optional enterprise storage/signer integrations. The customer owns the runtime, network, secrets, storage and operating objectives. |
| AI/ML engineering | Does it replace provider SDKs? | It exposes an OpenAI-compatible gateway surface, but provider behavior, model-specific parameters, streaming semantics, token limits and upstream availability still require integration testing. |
| Compliance / legal | Does it make us compliant? | No. It can provide control and evidence paths that may support an organization's review. Certification, conformity, legal privilege, admissibility and regulatory conclusions belong to the customer and qualified external reviewers. |
| Procurement | What is included? | Packaging is staged: AGPL community use, a bounded pilot, commercial self-hosted production terms and an enterprise tier only when support, response targets, legal terms and assurance capacity are explicitly available. |
| Privacy | Does Aegis retain prompts? | The deployment controls retention and evidence content. Request/response hashes and metadata may be retained even when raw bodies are not. The customer must define lawful basis, minimization, retention, deletion, residency and access controls. |
| SRE | What happens when storage stalls? | The authoritative path blocks or rejects rather than silently dropping evidence. Optional enrichment may be bounded and rejected. Operators must monitor WAL latency, queue depth, evidence correlation and recovery. |
| Security architecture | What happens when a key rotates? | The versioned keyring supports one active key, historical verification keys with expiry, atomic reload and non-secret key IDs. A production three-replica claim still requires a real deployment run. |

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

Before accepting a pricing proposal, ask which topology, environments, request tier, provider mix, retention, storage, support hours, response targets, security questionnaire scope, legal entity, deployment geography, escalation process, release cadence and exclusions are included. Published ranges are hypotheses pending buyer interviews, quotes, paid pilots and cost-to-serve data.

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
