# Buyer Guide — Aegis Latent Core

This guide is for CISO and AppSec reviewers, platform leaders, AI/ML engineering, privacy/compliance, procurement and executive sponsors evaluating Aegis. It describes the product boundary, verification questions, pilot acceptance criteria and procurement blockers. It is not a certification, legal opinion, production SLO, or binding offer.

**Last verified:** 2026-08-27 UTC
**Release baseline:** checked-out source baseline/release target `v4.1.1` with 14 synchronized anchors
**Source baseline/release target:** `v4.1.1` with 14 synchronized anchors; source metadata does not establish external lifecycle state; verify the tag, GitHub Release, PyPI, npm, OCI digest, signature, and attestation through independent readback
**External baseline:** signed annotated `v4.1.1` tag at `5a137c86ecd914842493babb7e863033498f68c9`, with GitHub Release (31 assets), PyPI `aegis-latent-sdk` `4.1.1`, and GHCR gateway/dashboard images read back on 2026-09-03; npm remains at `4.0.0`, the one surface the release did not reach
**Historical external baseline:** signed annotated `v4.0.2` tag at `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`, with GitHub Release and GHCR gateway/dashboard images read back on 2026-09-02; before it, lightweight `v4.0.1` at `6469904380218584ae0b5221334bc9a46500f5ba` with failed tag workflows; PyPI/npm observed at `4.0.0` without attributed provenance
**Audience:** US enterprise buyer committee
**Commercial context:** [`docs/COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md)

## Baseline to request

The checked-out source baseline/release target is **4.1.1** with 14 synchronized anchors. Its bounded SSE `pending-terminal` evidence, native Anthropic `POST /v1/messages`, Python and TypeScript SDKs, MMR proofs, forensic dashboard and bounded forensic ZIP export are checked-out-source capabilities. They do not establish external lifecycle or production-acceptance state; verify the `v4.1.1` tag, GitHub Release, PyPI and npm artifacts, OCI digest, signature, and attestation through independent readback. A buyer should require the quote, SBOM, test evidence and acceptance plan to identify the same baseline.

## Executive answer

Aegis is most relevant when an organization wants a provider-independent gateway for governed AI traffic and needs durable evidence that can be independently verified under its own storage and key-custody controls. It is not a compliance shortcut and should be evaluated as one component of a broader security and governance program.

## Questions by buyer role

| Role | Question | Evidence-led answer |
|---|---|---|
| CISO / AppSec | What attack surface does Aegis cover? | The gateway covers authenticated request admission, request-size bounds, application-layer WAF/session policy, egress endpoint validation, distributed rate-limit failure handling and evidence integrity. It does not cover every model, identity, network, endpoint or semantic attack. |
| Platform engineering | Where does it run? | Self-hosted Python/FastAPI with optional Rust acceleration and optional enterprise storage/signer integrations. The customer owns the runtime, network, secrets, storage and operating objectives. |
| AI/ML engineering | Does it replace provider SDKs? | No. The checked-out `v4.1.1` source exposes an OpenAI-compatible surface and native Anthropic `POST /v1/messages`. Python is drop-in through official-client subclasses. TypeScript wrappers remain provider-native and use the official provider packages as peer dependencies; provider models and behavior remain authoritative. |
| Compliance / legal | Does it make us compliant? | No. It can provide control and evidence paths that may support an organization's review. Certification, conformity, legal privilege, admissibility and regulatory conclusions belong to the customer and qualified external reviewers. |
| Procurement | What is included? | Packaging is staged: AGPL community use, a bounded pilot, commercial self-hosted production terms and an enterprise tier only when support, response targets, legal terms and assurance capacity are explicitly available. |
| Privacy | Does Aegis retain prompts? | The deployment controls retention and evidence content. Request/response hashes and metadata may be retained even when raw bodies are not. The customer must define lawful basis, minimization, retention, deletion, residency and access controls. |
| SRE | What happens when storage stalls? | Non-streaming calls return durable headers only after commit. Streams begin `pending-terminal`; their byte/item-bounded relay commits one terminal summary before the protocol terminal marker. The optional native `RustWal` stream segment is auxiliary, while JSONL remains the replay authority. |
| Security architecture | What happens when a key rotates? | The versioned keyring supports one active key, historical verification keys with expiry, atomic reload and non-secret key IDs. A production three-replica claim still requires a real deployment run. |

## Role decision frameworks

The table above answers questions. This section sequences them into an ordered evaluation each role can run, with an explicit gate at the end. A gate that cannot be answered from a cited artifact is a **stop**, not a caveat: the correct outcome is to defer the decision until the evidence exists, because every unresolved gate below has been the cause of a late-stage procurement failure in comparable deployments.

### CISO and AppSec lead

| Step | Action | Artifact to demand | Disqualifying finding |
|---|---|---|---|
| 1 | Fix the risk tier and the data classes that will transit the gateway | Written data-classification decision | Regulated data admitted before a lawful basis exists |
| 2 | Read the threat model's non-goals before its controls | `docs/institutional/DOC-03_THREAT_MODEL.md` §5.3 | An assumed control that the non-goals explicitly exclude |
| 3 | Confirm who is trusted: host root, operators, key holders | Trust-boundary table, DOC-01 §7 | Integrity expectation that survives a hostile administrator |
| 4 | Establish signer custody and whether symmetric HMAC is acceptable for the intended dispute posture | Key-management design | Non-repudiation expected from a symmetric key |
| 5 | Review supply-chain gates rather than accepting a summary | Pinned actions, SBOM, signed tag, dependency and container scans | Any claim of certification or independent audit |
| 6 | Scope an independent security review for the intended tier | Statement of work for that review | Reliance on repository self-assessment alone |

**Gate.** Proceed only when the residual risks are written down, owned by name, and accepted by the accountable executive. No certification, attestation, or independent audit report exists for this project; a review that assumes one has already failed.

### Head of AI and ML engineering

| Step | Action | Artifact to demand | Disqualifying finding |
|---|---|---|---|
| 1 | Enumerate the provider surfaces and routes actually used | Integration inventory | A route or provider version outside the tested surface |
| 2 | Validate drop-in behavior against your own client code | SDK test evidence and a local spike | Divergence in streaming, tool-calling, or error semantics |
| 3 | Measure added latency on your workload, in your environment | Your own benchmark run | Any performance figure taken from documentation rather than measured locally |
| 4 | Decide redaction scope: which identifier classes must never leave | De-identifier configuration and window sizing | An identifier class outside the supported bounded grammars |
| 5 | Test split-boundary and backpressure behavior deliberately | Fixture replay with fragmented identifiers | Cleartext release of an in-scope identifier |
| 6 | Confirm evidence semantics for streaming responses | Terminal-summary and proof-retrieval walkthrough | An assumption that every SSE event is individually committed |

**Gate.** Proceed only when the redaction scope is explicitly bounded, the residual classes are documented, and latency is measured on your traffic. Provider models and their behavior remain authoritative; the gateway governs and records, it does not change model output quality.

### Platform and SRE owner

| Step | Action | Artifact to demand | Disqualifying finding |
|---|---|---|---|
| 1 | Choose a topology and read its evidence semantics first | DOC-01 §8.5 boundary matrix | Multiple workers sharing one WAL path |
| 2 | Align ingress timeouts with the stream duration bound | Ingress configuration review | Idle timeout shorter than the configured stream bound |
| 3 | Establish storage durability expectations with the storage owner | Target storage design and acceptance | Reliance on a returned `fsync` as media-survival proof |
| 4 | Rehearse the corruption-containment and rollback runbooks | DOC-04 §8.4 and §12 executed in a lab | An untested restore or rollback path |
| 5 | Wire the named metrics and define alert thresholds | DOC-04 §11 metric names | Alerting on inferred rather than implemented metric names |

**Gate.** Proceed only when a named owner has executed backup, restore, rollback, and corruption containment in a non-production environment. No recovery objective is committed by this project.

### Chief compliance officer and legal counsel

| Step | Action | Artifact to demand | Disqualifying finding |
|---|---|---|---|
| 1 | Determine controller and processor roles for the deployment | Written data-protection analysis | Assuming the project is a processor in a self-hosted deployment |
| 2 | Decide the lawful basis for retaining evidence **before** committing in-scope records | Counsel memorandum | Discovering the erasure tension after records are anchored |
| 3 | Read the regulatory dossier as contribution mapping, not conformity | `docs/institutional/DOC-05_REGULATORY_DOSSIER.md` | Any reading of a mapping row as a conformity conclusion |
| 4 | Fix retention, residency, and access with the privacy owner | `docs/privacy/DATA_RETENTION.md` and deployment settings | Retention chosen by default rather than by decision |
| 5 | Record which determinations remain reserved to counsel | Claim register with owners | An expectation that a technical control settles a legal question |

**Gate.** Proceed only when the lawful basis, retention period, and erasure posture are decided in writing. This project makes no certification, conformity, admissibility, or legal-privilege determination, and none may be inferred from any control it implements.

### CFO and procurement director

| Step | Action | Artifact to demand | Disqualifying finding |
|---|---|---|---|
| 1 | Establish the licence path: AGPLv3 obligations or a commercial agreement | Open-source review by counsel | Distribution obligations discovered after deployment |
| 2 | Treat published package ranges as planning hypotheses, not quotes | `docs/COMMERCIAL_STRATEGY_US.md` packaging table | A range cited to the business as an observed market price |
| 3 | Require a quote built from named cost drivers | DOC-06 §11 input schedule | A tier label priced without an environment and scope |
| 4 | Separate software cost from the cost you will carry operationally | Your own infrastructure and staffing estimate | Assuming the supplier operates the runtime |
| 5 | Fix acceptance criteria in the agreement before the pilot starts | DOC-06 §12.2 criteria with agreed thresholds | Acceptance defined after results are known |
| 6 | Confirm what support actually means, in hours and exclusions | Written support schedule with staffing behind it | An inferred round-the-clock or restoration commitment |

**Gate.** Proceed only when the support boundary is staffed and written, acceptance is measurable and pre-agreed, and no unvalidated financial claim has entered the business case. This project publishes no observed contract value, customer count, return-on-investment percentage, or valuation, and none may be constructed from its documentation.

## v4.1.1 source forensic verification

The checked-out `v4.1.1` source stores portable `aegis-mmr-inclusion-v1` proofs. Non-streaming responses can carry `X-Aegis-MMR-*` headers; streams provide post-terminal proof retrieval because no completed proof exists in their initial headers. The read-only dashboard exposes retained evidence without fallback sample data and can request a bounded ZIP containing a JCS manifest, canonical DAG-CBOR ledger slice with CIDv1, proof JSON, technical PDF and `VERIFY.sh`. The buyer must pin the trusted MMR root independently, and the export does not determine legal admissibility.

## What the buyer can verify

A buyer can clone the release, inspect the source, run the P0/P1 tests, verify the claims matrix, inspect the SBOM and lockfile, reproduce the local corpus and review the retained release assets. The local evidence is bounded. It does not prove the buyer's ingress, storage, provider, secret manager, kernel, network, backup, support or legal environment.

## Security review checklist

Request the exact release tag and hashes, run the pinned tests, inspect the SBOM and lockfile, review the threat model, verify the deployment kernel and storage assumptions, validate TLS/mTLS and secret-manager integration, test rollback, and run traffic through the actual ingress boundary. Treat missing external-assurance artifacts as open procurement items rather than implied passes.

## Data and retention questions

Aegis can store hashes, model/endpoint metadata, tenant identifiers, sampling metadata, signature metadata and WAL records. Customer deployments must decide whether raw bodies are retained, whether redaction or pseudonymization occurs before evidence construction, how tenant isolation is enforced, and how retention/deletion obligations interact with chain continuity. The repository does not provide a universal answer for every jurisdiction or data category.

## Pilot acceptance criteria

A serious pilot should pass a declared request/response evidence-correlation test, upstream fault test, Redis/rate-limit failure test, WAL replay/integrity test, key-rotation test, pinned WAF corpus, rollback exercise, and security review of the target ingress, storage, secret manager and container profile. The pilot report must state request volume, workload, environment, rejected traffic, evidence completeness, failed cases and residual risk.

The pilot should also record the ML-DSA decision explicitly. The checked-out source baseline/release target has no approved constant-time verify claim because the retained experiment returned `p=0.0`. A buyer that requires a constant-time cryptographic claim must treat this as a release blocker or define an approved alternative signer boundary.

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
