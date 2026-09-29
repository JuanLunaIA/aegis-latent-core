<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Legal Stack: Drafts for Counsel

**Audience:** the owner, and the qualified software-licensing and corporate counsel who will review these drafts.
**Scope:** the documents needed to sell Aegis Latent Core code under a commercial licence: licence, paid pilot, escrow term sheet, founder-to-company IP assignment, an open-core decision memo, and the questions counsel has to answer. Prepared 2026-09-29 (Mission XVI, Phase 2).
**Boundary:** drafts only. Nothing here has been reviewed, offered, signed or filed. The agent that prepared them did not sign anything, engage any party or spend anything. The register items they serve (`REG-H03`, `REG-H04`, `REG-H09`, `REG-H10`) stay open until a human closes them.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent for the owner and qualified counsel. It is not legal advice, has not been reviewed by a lawyer, has not been offered to anyone, and nobody has signed it. Bracketed fields `[●]` are open decisions, not defaults. Do not send it to a counterparty before counsel has reviewed it.

## What is here

| Draft | Serves | Depends on | Owner action to close |
| --- | --- | --- | --- |
| [Commercial Licence Template](COMMERCIAL_LICENSE_TEMPLATE.md) | `REG-H04` | Entity formed and IP assigned; open-core decision; counsel questions 1 to 6 | Counsel review, then the owner signs each individual licence |
| [Paid Pilot Agreement Template](PILOT_AGREEMENT_TEMPLATE.md) | `REG-H06` | Commercial licence terms for the "proceed" outcome | Counsel review; owner signs a pilot with a named customer |
| [Escrow Term Sheet](ESCROW_TERM_SHEET.md) | `REG-H03` | An agent chosen by the owner; support terms | Owner engages an agent; tri-party agreement signed |
| [IP Assignment Draft](IP_ASSIGNMENT_DRAFT.md) | `REG-H09` | Entity formed | Counsel review; founder and company sign |
| [Open-core Decision Memo](OPEN_CORE_DECISION_MEMO.md) | `REG-H04` | Owner decision | Owner records the decision; counsel confirms |
| [Questions for Counsel](COUNSEL_QUESTIONS.md) | `REG-H04`, `REG-H10` | None | Counsel answers in writing |

## Order of work

1. Counsel answers the questions that block everything else: who the licensor is (`REG-H09`), and whether the AI-assisted origin of the code affects what the licensor can warrant.
2. The entity is formed and the IP assignment is signed. Until then the copyright holder is an individual, so an individual would be the licensor.
3. The owner decides the open-core boundary from the memo.
4. Counsel finalises the licence, then the pilot agreement.
5. Escrow follows a first paying customer who needs it, since it is priced per arrangement.

## Rules these drafts follow

- **No figure without a source.** Every price, fee, cap and date is a bracketed field. Pricing hypotheses live in the [Pricing Guide](../commercial/ENTERPRISE_PRICING_GUIDE.md) and stay `[HYPOTHESIS-UNVALIDATED]` until a pilot sets one.
- **Product statements come from the claims register.** The drafts incorporate [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md) and [`docs/BOUNDARIES.md`](../BOUNDARIES.md) by reference and repeat none of their content with more force.
- **No compliance, certification or admissibility promise.** None is made anywhere in the stack, and each licence must say so.
- **The signing key is never deposited or shared.** The licence-signing private key is a secret in the strongest sense (`scripts/generate_commercial_license.py`); the custody procedure may be deposited, the key may not.

## What this phase did not do

It did not engage counsel, form an entity, contact an escrow agent, send a draft to a prospect, or file anything. Those are the owner's actions.
