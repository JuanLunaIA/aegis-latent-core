# Commercial Readiness — Human-Executable Actions

**Audience:** the maintainer, and anyone assessing what stands between this repository and an enterprise sale.
**Scope:** the seven actions that **cannot be performed by a coding agent** and that no amount of code changes substitutes for, set against what is already sellable today.
**Boundary:** this document records *intent and cost*, not progress. Every item below is **NOT STARTED** unless a linked artifact says otherwise. Nothing here is a claim that any of it has happened.

---

## Why this file exists separately

Three independent audits of this repository converged on the same conclusion: the remaining gaps are not primarily engineering gaps. The code-level findings were fixable and have been worked; what is left needs a signature, a purchase order, or another human being.

Keeping them here, apart from the engineering trackers, is deliberate. An agent can close a `CLM` row; it cannot commission a penetration test, sign an escrow agreement, or hire a second maintainer. Conflating the two produces a roadmap that looks closeable and is not.

**On the cost and timeline figures below.** They are planning estimates for *procuring a service*, gathered from public vendor pricing. They are not measurements, not quotes, and not commitments. They are also **not** valuations of this project — this corpus contains no valuation claim, and `docs/CLAIMS_MATRIX.md` governs that.

---

## The truth table

Two columns. The left is what can be sold today to a buyer who checks; the right is what no document can close.

### SELLABLE NOW — verifiable today, by the buyer, without our cooperation

| Capability | What a buyer can check | Locator |
|---|---|---|
| **Evidence before emission** | Issue a governed non-streaming call; the record is durable before the response is observable | `CLM-043`, `CLM-003` |
| **Portable inclusion proofs** | Run the 12-line verifier against a root obtained independently; alter a byte and it fails | `CLM-005`, `CLM-044`, [Prove It](../PROVE_IT.md) |
| **Fail-closed durability** | Remove the signer, fill the volume, break the chain — governed traffic refuses, `/health` stays up | `CLM-002` |
| **Refusals are evidence** | Trigger a WAF block; the refusal is committed before the error returns | `CLM-060` |
| **Self-hosted custody** | Read the source. No telemetry, no vendor endpoint, no managed service | `LICENSE` |
| **Open-source core** | Complete, AGPLv3, no feature withheld by a runtime check | `ENTERPRISE_PRICING_GUIDE.md` §What the free tier keeps |
| **Embedded mode** | `aegis.wrap(client)` — same controls in-process, with its stated boundary | `CLM-061` |
| **A governed claim surface** | 104 claims with locators (`verify_claims.py`: 104 claims, 0 findings, measured 2026-09-21); 67 published non-claims (`UC-001`…`UC-067`); CI rejects overclaiming prose | `CLAIMS_MATRIX.md`, `UNSUPPORTED_CLAIMS.md` |
| **A paid pilot** | Fixed scope, written acceptance criteria, real failure tests | [Pilot Proposal](SALES_KIT/PILOT_PROPOSAL.md) |

**That column is not small.** It is enough to run a real evaluation and a paid pilot, and it is more independently checkable than most vendors in this category offer. What it is not is enough to clear an enterprise procurement gate.

### BLOCKS ENTERPRISE CLOSE — needs a signature, a purchase order, or another person

| ID | Action | Owner | Status | Cost | Timeline | What it unblocks |
|---|---|---|---|---|---|---|
| CR-01 | Independent penetration test | Founder | **NOT STARTED** | $15–25k | 4–6 weeks | "Externally assessed" claims; most security questionnaires |
| CR-02 | SOC 2 Type I | Founder | **NOT STARTED** | $20–80k/yr | 3–6 months | Mid-market and enterprise procurement |
| CR-03 | Executed software escrow | Founder | **NOT STARTED** | $5–10k | 2–4 weeks | The bus-factor objection, partially |
| CR-04 | Counsel-reviewed commercial licence | Founder + counsel | **NOT STARTED** | $3–5k | 2–4 weeks | Every AGPL-blocked buyer |
| CR-05 | Design partner / first reference | Founder | **NOT STARTED** | Founder time | 2–3 months | All revenue; all references; **and pricing validation** |
| CR-06 | Second maintainer | Founder | **NOT STARTED** | $150–250k/yr | 2–4 months | Bus factor = 1; any staffed support commitment |
| CR-07 | Pricing validation | Founder | **NOT STARTED** | Founder time | Concurrent with CR-05 | Removing `[HYPOTHESIS-UNVALIDATED]` from every figure |

**All seven are `NOT STARTED`.** None of them is a code change, and no amount of documentation substitutes for any of them.

**The ordering that matters:** `CR-05` is upstream of almost everything. It unblocks `CR-07` directly (a price nobody has paid is a guess), it makes `CR-01` and `CR-02` rational spends rather than speculative ones, and it is the only item that produces revenue. A founder with limited time should treat the other six as consequences of it.

---

## CR-01 — Independent penetration test

- **Owner:** Founder
- **Action:** Commission a penetration test from an established firm (Cure53, NCC Group and Trail of Bits are the names that recur in this space).
- **Estimated cost:** $15,000–25,000
- **Estimated timeline:** 4–6 weeks
- **Deliverable:** A published report, and a remediation record for every finding.
- **What it would unblock:** `docs/CLAIMS_MATRIX.md` currently permits no external-assurance claim. A completed test is the first artifact that changes that, and it is the single most common request in a security questionnaire.
- **Scope note:** the WAF is a heuristic pattern layer, not an injection boundary (`UC-042`). A test scoped to "can you bypass the WAF" will succeed and tell you little. Scope it to the evidence path: forge a receipt, get a response emitted without a durable commit, extract another tenant's records.

## CR-02 — SOC 2 Type I

- **Owner:** Founder
- **Action:** Engage a compliance automation platform (Vanta, Drata) plus an auditor.
- **Estimated cost:** $20,000–80,000 per year, platform and audit combined
- **Estimated timeline:** 3–6 months to Type I
- **Deliverable:** A SOC 2 Type I report.
- **What it would unblock:** Most enterprise procurement processes treat its absence as disqualifying rather than negotiable.
- **Honest note:** Type I attests that controls are *designed* appropriately at a point in time. Type II, which attests they *operated* over a period, is what larger buyers eventually ask for, and it cannot start until Type I exists.

## CR-03 — Software escrow

- **Owner:** Founder
- **Action:** Execute an escrow agreement with a neutral agent (NCC Group, Escrow London).
- **Estimated cost:** $5,000–10,000 to establish
- **Estimated timeline:** 2–4 weeks
- **Deliverable:** An executed agreement with defined release conditions.
- **What it would unblock:** The bus-factor objection, partially. `docs/commercial/SOFTWARE_ESCROW_POLICY.md` already sets out the policy; this is the step that makes it real.
- **Honest note:** Escrow addresses source availability if the maintainer disappears. It does not provide anyone who can *operate* the code — that is CR-06.

## CR-04 — Commercial licence terms

- **Owner:** Founder + qualified counsel
- **Action:** Draft the commercial licence that sits beside AGPLv3 in a dual-licence model.
- **Estimated cost:** $3,000–5,000
- **Estimated timeline:** 2–4 weeks
- **Deliverable:** A signable commercial licence template.
- **What it would unblock:** Buyers whose legal departments refuse AGPL outright. `COMMERCIAL.md` describes the intent; a template is what lets a deal proceed.
- **Boundary:** this repository takes no position on whether a given deployment triggers AGPL §13. That is the buyer's counsel's call, and neither this file nor any other in the corpus is legal advice.

## CR-05 — Design partners

- **Owner:** Founder
- **Action:** Identify 5–10 mid-market fintech or healthtech companies with a statutory evidence requirement, and offer a paid pilot.
- **Estimated cost:** $0 direct; the cost is founder time
- **Estimated timeline:** 2–3 months to first signature
- **Deliverable:** 1–2 signed pilot agreements.
- **What it would unblock:** Everything downstream. There is no revenue, no reference customer, and no validated pricing hypothesis until this exists.
- **Targeting note:** the moat is cryptographic non-repudiation and pre-emission durability. A prospect without a statutory or regulatory need for immutable proof does not need this product, and selling to them produces a pilot that does not renew. Qualify on the requirement, not on the interest.
- **The agent does not do this.** No part of this repository's tooling contacts prospects.

## CR-06 — Second maintainer

- **Owner:** Founder
- **Action:** Hire a senior systems or cryptography engineer.
- **Estimated cost:** $150,000–250,000 per year
- **Estimated timeline:** 2–4 months
- **Deliverable:** A second person who can independently triage, patch and release.
- **Acceptance test, and it must be a real one:** the second maintainer ships a security fix end to end — triage, patch, review, release, publish — **without the founder in the loop**. Anything short of that leaves the bus factor at 1 with extra headcount.
- **What it would unblock:** The `CRITICAL` bus-factor finding that every audit raised, and the procurement conversations that stop there.

## CR-07 — Pricing validation

- **Owner:** Founder
- **Action:** Three buyer interviews with a named economic buyer, one executed paid pilot at a stated fee, a cost-to-serve model with measured inputs, and a comparables set with sources and dates.
- **Estimated cost:** $0 direct; founder time, concurrent with `CR-05`
- **Estimated timeline:** Follows the first design partner
- **Deliverable:** Every figure in [Enterprise Pricing Guide](ENTERPRISE_PRICING_GUIDE.md) loses its `[HYPOTHESIS-UNVALIDATED]` label, or changes.
- **Why it is a separate row:** the pricing guide currently carries a full SKU table that no evidence supports. Publishing it is defensible **only because it is labelled**; the label is a status with an exit condition, not a permanent disclaimer. The five gates are in that document §9, and all five are `NOT STARTED`.
- **The failure mode to avoid:** quoting a number in a live deal and discovering afterwards that it is below cost to serve. Nothing in this repository measures support hours, infrastructure, or founder time per account, so the margin on every figure is presently unknown.

---

## What these seven do not fix

Recording this so the list is not mistaken for a finish line. Completing all seven leaves these standing, because they are architectural rather than commercial:

- **No cluster-wide total order.** Multiple replicas write independent chains. `CLM-064` forbids "global ordering" and "multi-pod linearizability" claims, and a SOC 2 report does not change that.
- **The WAF is a heuristic speed bump.** It raises the cost of a literal-pattern bypass and is not an injection boundary (`UC-042`).
- **HMAC signing provides no non-repudiation.** Any key holder can forge (`UC-041`). Only an asymmetric tier — HSM or PQC identity — changes that, and it is configuration, not a purchase.
- **No revocation checking on RFC 3161 timestamps.** Signature and chain are verified; OCSP/CRL is not, because a forensic verifier is frequently offline.

---

**Related:** [Claims Matrix](../CLAIMS_MATRIX.md) · [Software Escrow Policy](SOFTWARE_ESCROW_POLICY.md) · [Enterprise Pricing Guide](ENTERPRISE_PRICING_GUIDE.md) · [Security Assurance Roadmap](../SECURITY_ASSURANCE_ROADMAP.md) · [Release Status](../RELEASE_STATUS.md)
