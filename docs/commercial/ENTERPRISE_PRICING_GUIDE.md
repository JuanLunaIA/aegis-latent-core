<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Enterprise Pricing Guide

**Audience:** procurement, finance, and the account team preparing a quote.

> ## `[HYPOTHESIS-UNVALIDATED]`
>
> **Every figure in this document is an unvalidated pricing hypothesis.** It is published so a buyer can start a conversation from a number instead of from a silence — not because the number has been tested.
>
> No executed commercial agreement exists anywhere in this project. There is therefore **no list price, no average selling price, no annual contract value, no win rate, and no evidence that anyone has paid any of these amounts.** §9 states exactly what has to happen before any figure here may be restated as firm.
>
> This is the **single source of truth for pricing.** Any number in any other document that disagrees with this one is stale and this one governs (`COMMERCIAL.md`, `docs/COMMERCIAL_STRATEGY_US.md`).

## Read this before quoting anything

`docs/institutional/UNSUPPORTED_CLAIMS.md` blocks the claims a pricing document invites, and none of them is made here:

| Blocked | Why it stays blocked |
|---|---|
| "Our ACV is $X" (`UC-033`) | An asking figure is what is asked. Annual contract value is what was signed. **No executed contract is cited anywhere in this repository**, so no ACV, no average deal size, and no win rate may be quoted. |
| "These are our list prices" | A list price is an offer the vendor stands behind. These are hypotheses about what the market will bear. Calling them list prices asserts a commercial position that no validation supports. |
| "Pricing and procurement readiness are established" (`UC-028`) | These are hypotheses about what the market will bear, published so a buyer can start a conversation. They are not validated by revenue. |
| "We provide a 99.95% SLA and round-the-clock response" (`UC-019`) | The SLA matrix below is a **proposed schedule for negotiation**. No rota is staffed, no service credits are contracted, and no production history supports an availability figure. |
| Customer references, logos, case studies | There are none to cite. Do not create them. |

A quote is an offer. Anything describing what customers *have done* needs an executed agreement behind it, and there is not one in this tree.

## The pricing model

Total contract value is built from four independent parts rather than a single tier, so a buyer pays for what they deploy:

$$\text{TCV} = \text{Base Subscription} + \sum \text{Engine Licenses} + \text{MGT Volume} + \text{Support Tier}$$

The commercial subscription grants production use under the Proprietary Commercial License, which supersedes AGPLv3 for the covered deployment. **The AGPLv3 distribution remains free and fully functional** — see "What the free tier keeps" below, because that boundary is a legal statement, not a marketing one.

> **`[FRAMEWORK-ONLY]` — the commercial licence text does not yet exist.** `CR-04` in [Commercial Readiness](COMMERCIAL_READINESS.md) records it as **`NOT STARTED`**: counsel-drafted template, 2–4 weeks, gated on a buyer who needs it. A buyer who asks today to see the agreement will find there is nothing to send.
>
> This is stated here, beside the model that depends on it, rather than left for the buyer to discover after they have spent review cycles. Everything below describes what a subscription is intended to grant once that document exists.

## Packages

| SKU | Annual hypothesis `[UNVALIDATED]` | Engines included | Intended for |
|---|---|---|---|
| Community | $0 (AGPLv3) | Standalone gateway; every engine importable | Evaluation, research, open-source deployment |
| Aegis Core | $45,000 | Control plane + any one engine | Teams needing one capability in production |
| Aegis Enterprise | $95,000 | Control plane + Veracity + Sanctum | Regulated workloads needing evidence and redaction |
| Aegis Omnia | $175,000 | All four engines | Organisations standardising on one governance layer |
| Aegis Sovereign | $250,000–$500,000+ | All four, plus air-gapped delivery and custom key custody | Deployments where the vendor cannot reach the environment |

The Sovereign band is a range because its scope is bounded by the customer's environment — air-gapped delivery, a bespoke key ceremony, and offline update procedures are quoted per engagement rather than listed.

### Engine add-ons

Priced for a buyer who already owns a gateway and wants one capability:

| Add-on | Annual hypothesis `[UNVALIDATED]` | What it is |
|---|---|---|
| Veracity Engine | $35,000 | Evidence commitment, portable inclusion proofs, cryptographic erasure |
| Sanctum Engine | $30,000 | Streaming de-identification and request scanning |
| Agentis Engine | $25,000 | Agent-to-agent execution receipts |
| Sovereign Vault | $50,000 | ML-DSA signing, hybrid KEM, PKCS#11 custody |

Each maps to a licensable module name in the token: `veracity`, `sanctum`, `agentis`, `sovereign`, and `omnia` as the wildcard.

### Volume: Million Governed Transactions

| Tier | Annual governed transactions | Hypothesis per MGT `[UNVALIDATED]` |
|---|---|---|
| 1 | up to 10M | included in base |
| 2 | 10M – 50M | $1,500 |
| 3 | 50M – 250M | $950 |
| 4 | 250M+ | $500 |

Per-transaction rather than per-token, because a per-token line item makes an infrastructure budget unforecastable — the same spend swings with prompt length and model choice, neither of which the buyer's finance team controls.

**MGT is a contractual term, not a runtime meter.** The licence token carries `max_annual_mgt` so the agreement can be read off the token, and `aegis/licensing/validator.py` neither counts transactions nor enforces the cap. Reconciliation is a commercial process against the customer's own telemetry. Do not describe Aegis as metering or enforcing usage.

## Professional services

Fixed-scope engagements, quoted before work begins:

| Engagement | Hypothesis `[UNVALIDATED]` | Deliverable |
|---|---|---|
| GxP qualification pack | $35,000 | Fixed-scope IQ/OQ execution and a signed technical dossier |
| Custom connector development | $50,000 | One bespoke upstream or downstream connector, with tests |
| Key custody and HSM provisioning architecture | $25,000 | A reviewed key ceremony and custody design |

The GxP pack delivers **qualification evidence for a named installation**. It does not make the software validated, compliant, or approved: 21 CFR Part 11 turns on predicate rules, intended use, and a validation lifecycle the customer owns (`DOC-05 §5.4`).

## Support tiers

The severity schedule below is a **template for negotiation**. Nothing in it is in force until an agreement is executed, and the targets are commitments the vendor would be undertaking rather than a service level already being met.

| Severity | Definition | Proposed first response | Proposed mitigation |
|---|---|---|---|
| 1 — Critical | Evidence commit path broken; governed traffic refused; integrity verification failing | 1 hour | 4 hours |
| 2 — Major | Elevated commit latency; limiter degraded; auxiliary WAL failure | 4 business hours | 1 business day |
| 3 — Minor | Documentation defect; dashboard issue; SDK integration question | 1 business day | Next maintenance release |

**A prospective buyer should test these against `UC-019` before relying on them.** They describe an intended support operation. A staffed rota, an escalation path, and service credits are contract terms to be agreed, and the response targets above cannot be evidenced by anything in this repository.

## What the free tier keeps

This matters legally, not just commercially. The AGPLv3 distribution is **not** crippled:

- Every engine in `aegis/engines/` is importable and fully functional without a licence token.
- Licence enforcement is **off by default**. `AEGIS_LICENSE_ENFORCEMENT=required` is opt-in, and is intended for a commercial distribution that wants entitlement mismatches to surface at startup.
- No feature is withheld by a runtime check in the AGPLv3 build.

What a commercial subscription buys is the **licence grant** — production use under terms that supersede AGPLv3 network-copyleft obligations — plus support, indemnification, and the professional services above. It does not buy access to code that was hidden.

## The AGPLv3 question a legal team will raise

Many corporate legal teams restrict AGPLv3 because of its Section 13 network provision. The commercial licence exists precisely to resolve that: it supersedes AGPLv3 for the covered deployment, so the obligations do not attach.

Two cautions for whoever writes the response:

- **Indemnification is a contract term, not a property of the software.** Any cap is whatever the executed agreement says. No figure is published here, because publishing one would imply an underwritten position that does not exist in this repository.
- **This is not legal advice**, and nothing here is a legal opinion about a buyer's obligations under any licence. Their counsel decides.

## 9. What must happen before any figure here is stated as firm

`[HYPOTHESIS-UNVALIDATED]` is not a permanent disclaimer to be worn indefinitely. It is a status with an exit condition, and this is the condition.

A figure in this document may be restated as a firm price **only when all five are true and each is recorded with a date**:

| # | Gate | Why it is necessary | Status |
|---|---|---|---|
| 1 | **≥3 buyer interviews** with a named economic buyer who owns a record-keeping obligation, each recording what they would pay and what they compared it against | Three is the minimum at which a number stops being one person's opinion. Fewer, and the price reflects whoever was most polite | `NOT STARTED` |
| 2 | **≥1 executed paid pilot** at a stated fee, with written acceptance criteria | A price nobody has paid is a guess. A price one buyer has paid is a data point | `NOT STARTED` (`CR-05`) |
| 3 | **A cost-to-serve model** with measured inputs — support hours actually spent, infrastructure, the founder's time per account | Without it, a margin cannot be computed and the price could be below cost. Nothing in this repository measures any of these | `NOT STARTED` |
| 4 | **A comparables set** built from publicly published vendor pricing, with sources and retrieval dates | An anchor drawn from memory is not a comparable | `NOT STARTED` |
| 5 | **The commercial licence template exists** (`CR-04`) | A price for a grant that has not been drafted cannot be accepted, whatever the number says | `NOT STARTED` |

**All five are `NOT STARTED`.** Until they are not, every number above stays labelled, and no document derived from this one may restate a figure as a list price, a quote, an observed contract value, or evidence of market validation.

Gates 1 and 2 are the same activity as `CR-05` in [Commercial Readiness](COMMERCIAL_READINESS.md). Pricing validation is not a separate project; it is a by-product of finding the first design partner, which is why that action blocks more than its own row.

## Related

- [`COMMERCIAL.md`](../../COMMERCIAL.md) — the licence terms themselves
- [`docs/commercial/CONNECTOR_ECOSYSTEM.md`](CONNECTOR_ECOSYSTEM.md) — what integrates with what
- [`docs/commercial/SOFTWARE_ESCROW_POLICY.md`](SOFTWARE_ESCROW_POLICY.md) — continuity terms
- [`docs/institutional/DOC-06_COMMERCIAL_PROCUREMENT.md`](../institutional/DOC-06_COMMERCIAL_PROCUREMENT.md) — the governed procurement position
- [`docs/institutional/UNSUPPORTED_CLAIMS.md`](../institutional/UNSUPPORTED_CLAIMS.md) — what may not be claimed
