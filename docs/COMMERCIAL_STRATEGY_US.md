> **INTERNAL DOCUMENT — NOT FOR EXTERNAL DISTRIBUTION**

# US Commercial Strategy — Aegis Latent Core

This document describes a US-market positioning and packaging hypothesis for Aegis Latent Core. It is for commercial stakeholders, founders, product owners, procurement and support planners. It is not a binding offer, a forecast, legal advice, or evidence of market validation.

**Last verified:** 2026-08-27 UTC
**Release baseline:** checked-out source baseline/release target `v4.1.1` with 14 synchronized anchors
**Source baseline/release target:** `v4.1.1` with 14 synchronized anchors; source metadata does not establish external lifecycle state; verify the tag, GitHub Release, PyPI, npm, OCI digest, signature, and attestation through independent readback
**Historical external baseline:** signed annotated `v4.0.2` tag at `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`, with GitHub Release and GHCR gateway/dashboard images read back on 2026-09-02; before it, lightweight `v4.0.1` at `6469904380218584ae0b5221334bc9a46500f5ba` with failed tag workflows; PyPI/npm observed at `4.0.0` without attributed provenance
**Market scope:** United States, self-hosted enterprise AI infrastructure
**Positioning decision:** [`docs/architecture/ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md`](architecture/ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md)

## Baseline discipline

The checked-out source baseline/release target is **4.1.1** with 14 synchronized anchors. It adds bounded SSE with `pending-terminal` evidence, native Anthropic `POST /v1/messages`, Python drop-in and TypeScript provider-native SDK integration, portable MMR proofs, a read-only forensic dashboard, bounded JCS/DAG-CBOR/CIDv1/PDF/`VERIFY.sh` exports, an auxiliary `RustWal` stream segment, and a bounded in-process SSE benchmark. These are checked-out-source implementation and evidence items. They do not establish external lifecycle or production-acceptance state; verify the `v4.1.1` tag, GitHub Release, PyPI and npm artifacts, OCI digest, signature, and attestation through independent readback. Any proposal must identify the exact deliverable baseline.

## Positioning

Aegis should sell into three adjacent budgets: AI gateway and traffic governance, AI security and guardrails, and audit/evidence infrastructure. The initial message should stay narrow: **provider-independent gateway control plus durable, independently verifiable evidence**. It should not claim to replace a full AI security control plane, a compliance authorization product or a provider's entire observability platform.

## Market signals

Public comparable offers provide directional packaging signals. Portkey publishes self-serve and enterprise tiers around gateway, observability, retention, private deployment and support. Helicone publishes usage and retention controls with enterprise differentiation in support and contractual terms. LiteLLM publishes open-source self-hosting and enterprise capacity/architecture/support pricing. Protect AI positions enterprise AI gateway and runtime-control products around discovery, governance and security. [1] [2] [3] [4]

These are market signals, not evidence of feature parity, competitive superiority, or Aegis buyer willingness to pay. Pricing must be refreshed before an external offer.

## Initial ICP

The first ICP is a B2B SaaS, fintech or regulated-enterprise platform/security team running multiple model providers and requiring private deployment. The buyer must have enough operational maturity to own durable storage, secret management, incident response and an internal platform team. Government, defense, healthcare, industrial and scientific segments remain expansion tracks because their assurance and procurement requirements exceed what the current repository independently proves.

## Buyer committee and sales motion

The economic buyer is usually an executive sponsor responsible for AI risk, platform reliability or security. The technical champion is platform engineering or AppSec. AI/ML engineering validates provider compatibility and latency boundaries. Compliance/legal reviews evidence, retention, data handling and claims. Procurement reviews licensing, support, indemnity, security questionnaires and vendor viability.

The sales motion is **local evaluation → evidence replay → controlled pilot → security review → procurement package → production rollout**. A pilot must produce a customer-owned evidence bundle rather than a slide-only demonstration. The bundle should include request/response vectors, WAF results, WAL/replay checks, key-rotation evidence, SBOM/provenance, deployment assumptions and rollback results.

## Packaging hypothesis

| Package | Buyer | Included | Price hypothesis to validate | Hard boundary |
|---|---|---|---|---|
| Community / OSS | Developers and evaluators | AGPL self-hosting, source, tests, public docs and issue tracking | Free | No support, SLA, private onboarding or procurement commitment |
| Team / Pilot | Platform team validating one workload | Time-boxed pilot, bounded architecture review, evidence replay, test plan and limited implementation support | `$10k–$30k` fixed pilot for a defined 4–8 week scope | No production SLO, certification or unlimited engineering promise |
| Production | One enterprise deployment | Commercial self-hosted terms, release updates, deployment guidance, evidence package and named support window | `$40k–$100k` annual minimum hypothesis | Requires written support capacity and exclusions; not per-token pricing |
| Enterprise | Multiple environments or regulated procurement | Security review support, architecture assistance, negotiated response targets, private deployment guidance and procurement artifacts | `$100k–$250k+` annual hypothesis | No 24/7 or sovereign claim without staffing, contract and tested operating model |
| Sovereign / OEM | Air-gapped, embedded, redistribution or escrow | Dedicated contract, redistribution rights, escrow/assurance terms and specialized support | Custom only | Not a current default offer; requires legal, support and assurance capacity |

The ranges are **internal hypotheses only**. They are not public list prices, observed ACV, vertical ACV, replacement-cost evidence, or a company/IP valuation. They require buyer interviews, normalized comparable quotes, support-cost modeling and paid-pilot evidence. The underlying primary-source review is [`evidence/documentation_audit_2026-08-22/PRICING_BENCHMARK.md`](../evidence/documentation_audit_2026-08-22/PRICING_BENCHMARK.md); it finds that the public comparables do not support deriving an Aegis list price, observed ACV, or valuation.

## Cost-to-serve model

The commercial owner should model engineering hours per pilot, release support hours, security-questionnaire effort, incident-response coverage, cloud or lab infrastructure, legal review, independent testing and opportunity cost. The minimum annual price must cover the support boundary plus a reserve for incident and release work; a high list price does not create assurance capacity.

```text
annual_floor = (engineering_hours × loaded_hourly_cost)
             + (support_hours × loaded_hourly_cost)
             + security_review_cost
             + legal_and_contract_cost
             + infrastructure_cost
             + risk_reserve
```

ROI should be presented as a customer-specific sensitivity model based on evidence-reconstruction effort, provider-switching cost, incident triage time and procurement requirements. Do not promise avoided fines, avoided incidents or a fixed percentage reduction in regulatory risk.

## Unit economics model skeleton

This section supplies **structure only**. Every symbol below is an input the commercial owner must measure; no value is filled in, because this repository holds no customer, cost, pipeline, or renewal data from which one could be derived. A populated version of this model is a business artifact produced after the validation plan runs — it is not a documentation deliverable, and any number appearing here without a cited measurement source should be treated as a defect.

### Input register

| Symbol | Input | How it must be obtained | Status |
|---|---|---|---|
| `S_h` | Fully loaded hourly cost of engineering and support staff | Payroll and overhead accounting | Not held in this repository |
| `E_p` | Engineering hours consumed per pilot | Time logged against a real paid pilot | Requires at least the two pilots named in the validation plan |
| `E_o` | Recurring support and release hours per production account per year | Logged support and maintenance time | Requires a staffed support window to exist |
| `I_c` | Infrastructure and lab cost attributable per account | Cloud and lab billing, allocated | Not held in this repository |
| `A_c` | Assurance cost per account: questionnaires, reviews, remediation | Logged security and legal effort | Not held in this repository |
| `M_c` | Marketing and demand-generation spend in a period | Marketing ledger | No spend history exists |
| `Sa_c` | Sales and pre-sales cost in the same period | Sales compensation and pre-sales time | No sales organisation exists yet |
| `N_w` | New customers won in that period | Signed agreements | Zero observed to date |
| `P` | Realised annual contract value per account | Executed contracts, not the hypothesis ranges | No executed commercial agreement is recorded |
| `r` | Annual retention rate | Renewal outcomes across at least one full term | No renewal cycle has elapsed |

### Definitions

```text
gross_margin      = (P - (E_o × S_h) - I_c - A_c) / P
CAC               = (M_c + Sa_c) / N_w
LTV               = (P × gross_margin) / (1 - r)          # r < 1
payback_months    = CAC / ((P × gross_margin) / 12)
pilot_cost        = E_p × S_h
```

The `annual_floor` expression in the previous section is the lower bound that `P` must clear before any of these ratios can be positive; a package priced below its own floor cannot be rescued by volume.

### Interpretation rules

1. **Every ratio is undefined until its inputs are measured.** `N_w` is currently zero, so `CAC` is undefined rather than low. `r` has never been observed, so `LTV` is undefined rather than favourable. Presenting an undefined ratio as an attractive one is the specific failure this section exists to prevent.
2. **`P` means realised contract value.** The packaging hypothesis ranges are planning inputs, not observations, and must never be substituted for `P` to manufacture a margin or `LTV` figure.
3. **Self-hosted deployment changes the cost shape.** The customer operates the runtime and pays for its own infrastructure, so `I_c` covers only supplier-side lab and support environments. Gateway request volume is therefore a poor proxy for cost-to-serve; support and assurance effort dominate.
4. **Assurance cost is not amortised by default.** `A_c` tends to be front-loaded and buyer-specific; a regulated buyer can consume more review effort in one procurement cycle than several unregulated accounts combined. Model it per account, not as a fixed percentage.
5. **`r` requires an elapsed term.** Retention cannot be estimated from interest, pilots, or intent. Until one full term has elapsed for at least one paying account, `LTV` remains unavailable.
6. **Nothing in this model is a forecast.** These are accounting identities. They describe how measured inputs combine; they do not predict demand, win rate, or willingness to pay, and they must not be presented to an investor or buyer as evidence of either.

### Publication guardrails

Do not publish CAC, LTV, gross margin, payback, ROI percentages, avoided-fine estimates, avoided-incident counts, or any customer-count claim until the corresponding input is measured and its source is citable. Where a buyer requests an ROI case, supply a customer-specific sensitivity model built from that buyer's own evidence-reconstruction effort, provider-switching cost, and procurement overhead, with the assumptions stated and owned by the buyer. This repository does not contain an evidence-backed vertical ACV, replacement-cost figure, or company valuation, and none may be inferred from this section.

## Validation plan

The pricing hypothesis should be treated as falsifiable. Before publishing a quote, complete at least the following:

| Test | Minimum evidence | Failure interpretation |
|---|---|---|
| Buyer interviews | 10 structured interviews across platform, AppSec, compliance and procurement | Positioning or buyer pain is not yet validated |
| Paid pilot | At least 2 pilots with defined scope, acceptance and support hours | Price or implementation scope is not yet validated |
| Cost-to-serve | Logged engineering, support, legal and infrastructure hours | Gross-margin hypothesis is unknown |
| Security review | Repeated questionnaire themes and unresolved blockers | Assurance package is incomplete |
| Support exercise | Simulated severity and escalation path | Support tier cannot be sold as staffed |
| Renewal signal | Expansion, renewal or explicit loss reason | Willingness to pay remains unverified |

## Procurement package

The production package should contain the immutable release tag, source and asset hashes, SPDX SBOM, provenance envelope, release-gate record, claims matrix, threat model, deployment checklist, key-rotation runbook, backpressure runbook, WAF corpus report, vulnerability disclosure policy, retention/data-handling statement, support matrix, rollback criteria and an explicit list of customer-owned controls.

## Support boundary

Community support is public and best effort. Pilot support is time-boxed and scoped. Production support requires a named owner, supported versions, response windows, escalation path, maintenance policy and exclusions. Enterprise support requires actual staffing, incident coverage, release cadence and legal terms. Until those exist, the repository must not publish “24/7,” “mission-critical SLA” or “sovereign assurance” language.

## Legal and license boundary

`COMMERCIAL.md` requires counsel review before it states the effect of AGPL network obligations, exemptions, future-version rights, warranty, indemnity, tax, data registration, certificate delivery or redistribution. This strategy is not legal advice and does not change the license.

## Success metrics

The commercial owner should measure pilot-to-production conversion, time to first evidence replay, security-review cycle time, unresolved procurement blockers, support hours per deployment, incident response load, renewal rate and gross margin by topology. GitHub stars, fabricated logos and vanity throughput are not sales evidence.

## Related documents

- [`README.md`](../README.md)
- [`docs/PRODUCT_BRIEF_US.md`](PRODUCT_BRIEF_US.md)
- [`docs/BUYER_GUIDE_US.md`](BUYER_GUIDE_US.md)
- [`docs/FAQ_PROCUREMENT.md`](FAQ_PROCUREMENT.md)
- [`COMMERCIAL.md`](../COMMERCIAL.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`evidence/documentation_audit_2026-08-22/PRICING_BENCHMARK.md`](../evidence/documentation_audit_2026-08-22/PRICING_BENCHMARK.md)

## References

[1]: https://portkey.ai/pricing "Portkey pricing"
[2]: https://www.helicone.ai/pricing "Helicone pricing"
[3]: https://www.litellm.ai/pricing "LiteLLM pricing"
[4]: https://protectai.com/ "Protect AI / Prisma AIRS"
