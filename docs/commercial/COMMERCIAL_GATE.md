<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Commercial gate record

**Audience:** founder and anyone deciding whether a campaign, a price, or a
sales claim may ship.
**Scope:** the conditions for the first paid Order, the first reference, and the
first public price.
**Boundary:** a gate record. It does not create demand, a customer, or a
certification.

> **COMMERCIAL GATE: BLOCKED**
>
> There is no signed customer, no validated price, no reference, no insurance,
> no entity, and no counsel-reviewed contract. The product can be evaluated; it
> cannot be sold as a certified or SLA-backed service.

## Why it is blocked

| Blocker | Evidence | What closes it |
| --- | --- | --- |
| No entity / tax setup | `docs/legal/ENTITY_AND_TAX_MEMO.md` E1–E10 | owner forms/selects entity; accountant records tax |
| No counsel-reviewed contract | `docs/legal/LEGAL_GATE.md` | dated opinion on licence, terms, DPA, MSA |
| No insurance | `docs/legal/INSURANCE_AND_ESCROW_DECISIONS.md` | broker quote and bound policy, or written self-insure decision |
| No reference customer | this file | signed pilot with permission to reference |
| No validated price | `docs/commercial/ENTERPRISE_PRICING_GUIDE.md` | at least one paid Order or a documented willingness-to-pay test |
| No independent assurance | `docs/assurance/ASSURANCE_STATUS.md` | pen test / SOC 2, if the segment requires it |
| No staffed support | `docs/enterprise/SUPPORT_MODEL.md` | a named rotation and a signed support scope |
| No hosted gateway | `docs/legal/DATA_MAP.md` | a managed service, or disqualify buyers who require one |

## What may be done while blocked

- Discovery calls, with the disqualifiers in `ICP_AND_DISQUALIFIERS.md`.
- A **free, scoped evaluation** under a written evaluation agreement that has
  been counsel-reviewed; no payment, no production SLA.
- A paid pilot **only after** the entity, counsel and insurance rows that the
  pilot requires are closed.
- Public content that describes the product and its boundaries.
- Publishing a price **hypothesis** clearly labelled as such; not a checkout.

## What may not be done

- A public price list presented as an offer, or a checkout that takes money
  before an entity and tax decision exist.
- A customer logo, quote, or case study without a signed release.
- Any claim of a certification, audit, compliance status, assurance, a
  completed penetration test, production readiness, an uptime figure, or
  staffed support.
- A discount that implies a certification or a support level that does not
  exist.
- An invoice from an individual if the contract names a company, or vice versa.

## Exit criteria

1. `LEGAL_GATE.md` is `OPEN` for the documents the first Order uses.
2. `ENTITY_AND_TAX_MEMO.md` E1–E10 are recorded.
3. A named buyer signs an Order Form and pays the first invoice.
4. The support scope and response target are written and staffed, or explicitly
   "no SLA" in the Order.
5. A reference release is signed, or the buyer is explicitly anonymous.
6. The price is recorded as paid, not proposed.

## Pipeline truth

| Stage | Definition | Current count |
| --- | --- | --- |
| Target | fits the ICP and has a named buyer | `[OWNER INPUT REQUIRED]` |
| Discovery completed | the 10 questions in `ICP_AND_DISQUALIFIERS.md` answered | `[OWNER INPUT REQUIRED]` |
| Evaluation | running the software under a written evaluation agreement | `[OWNER INPUT REQUIRED]` |
| Paid pilot | signed Order and invoice paid | **0** |
| Reference | signed release and published case study | **0** |

Do not fill this table with "interested" or "warm lead". A stage changes only on
a dated artifact.
