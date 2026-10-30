<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Insurance and escrow decisions

**Audience:** owner, broker, counsel, and enterprise buyers.
**Scope:** the risk-transfer products a real buyer will ask about, and the
current state of each.
**Boundary:** a decision record with open fields. No policy has been quoted or
bound, and no escrow agreement exists.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent. This is **not legal advice** and not insurance advice.

## 1. Current state

| Product | State | Evidence | Buyer impact |
| --- | --- | --- | --- |
| Commercial general liability | `NOT QUOTED` | no broker engagement recorded | some vendors require a certificate |
| Professional liability / tech E&O | `NOT QUOTED` | no broker engagement recorded | enterprise security review asks for limits |
| Cyber liability | `NOT QUOTED` | no broker engagement recorded | incident-response cost transfer |
| Directors & officers | `NOT QUOTED` | no company formed | needed after a company or raise |
| Workers' compensation | `NOT APPLICABLE` | no employees | changes with first hire |
| Source-code escrow | `NOT SIGNED` | `ESCROW_TERM_SHEET.md` is a draft | some buyers require it for self-hosted software |
| Key-custody escrow | `NOT OFFERED` | private signing key is never deposited | do not promise key escrow |

## 2. Insurance decisions

| # | Decision | Options | Owner input |
| --- | --- | --- | --- |
| I1 | Which policies before the first paid pilot? | CGL + tech E&O / cyber / none | `[OWNER INPUT REQUIRED]` |
| I2 | Limits | `[USD 1M / 2M / 5M]` | `[OWNER INPUT REQUIRED]` |
| I3 | Deductible the business can absorb | `[USD amount]` | `[OWNER INPUT REQUIRED]` |
| I4 | Broker | `[NAME]` | `[OWNER INPUT REQUIRED]` |
| I5 | Does the policy cover AI-assisted software and cryptographic claims? | ask broker in writing | `[OWNER INPUT REQUIRED]` |
| I6 | Does the policy cover a hosted console in the US? | ask broker | `[OWNER INPUT REQUIRED]` |

Do not tell a customer "insured" until a certificate of insurance exists and
the policy period covers the Order.

## 3. Escrow decisions

Source-code escrow is a buyer requirement in some regulated procurements. It is
not a substitute for the public source and not a guarantee of support.

| # | Decision | Options | Consequence |
| --- | --- | --- | --- |
| X1 | Offer escrow at all? | yes / no / only enterprise | procurement friction |
| X2 | Escrow agent | `[NAME]` | tri-party agreement and annual fee |
| X3 | Deposit content | source at a named tag + build instructions + SBOM | must be reproducible |
| X4 | Release conditions | insolvency / cessation of support / breach | counsel must define |
| X5 | Verification | agent verifies deposit / no verification | unverified deposit can be stale |
| X6 | Private signing key | **never deposited** | escrow is source, not signing authority |
| X7 | Fee | `[USD / year]` | pass-through or included |

The draft `ESCROW_TERM_SHEET.md` is not an offer and has no agent, fee, or
release condition agreed.

## 4. Gate

Insurance and escrow are **OPEN**. A paid enterprise Order that requires either
must not be signed until the relevant rows are recorded. A customer may accept
"not offered" if it is stated early; it may not be told a policy exists when it
does not.
