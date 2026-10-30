<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# ICP and disqualifiers

**Audience:** founder, sales, and anyone deciding whether a lead is worth a
discovery call.
**Scope:** the buyer Aegis can serve today, the buyer it cannot, and the
questions that reveal the difference in ten minutes.
**Boundary:** a hypothesis, not a validated market. No customer has paid, no
reference exists, and the pricing is `[HYPOTHESIS-UNVALIDATED]`.

## 1. Primary ICP

| Dimension | Fit | Why |
| --- | --- | --- |
| Company type | AI application vendor, model gateway, or regulated enterprise building an AI product | needs evidence of what the model saw and returned |
| Buyer | CTO, VP Engineering, Head of AI Platform, security architect | owns the architecture and the audit answer |
| Customer's customer | bank, insurer, healthcare payer, public sector | asks "show me the record" before signing |
| Deployment | self-hosted, private cloud, or BYOC | Aegis is self-hosted; a prospect that refuses to operate software is a mismatch |
| Volume | 100k–10M governed requests/month | enough pain to pay, small enough for one gateway |
| Trigger | a security review, audit, incident, or procurement blocker about AI logs | urgency exists before the first call |
| Technical capacity | can run a container and PostgreSQL, or has a platform team | no fully managed service today |

## 2. Secondary ICP

- A system integrator or consultancy that builds AI for regulated clients and
  wants a repeatable evidence layer.
- An AI vendor that already has SOC 2 but cannot prove what its model did on a
  specific request.
- An insurer or bank innovation lab running a pilot, not yet in production.

## 3. Anti-ICP (disqualify early)

| Signal | Why it is a no today |
| --- | --- |
| "We need a fully managed SaaS; we do not run infrastructure." | no vendor-hosted gateway exists |
| "Send us your SOC 2 report." | no report exists; the honest answer is no |
| "We need a BAA before a pilot." | no BAA is offered |
| "We need 24/7 phone support with a 15-minute SLA." | no staffed rotation or SLA |
| "We are a 5-person startup; we just want cheap log storage." | the value is governed evidence, not log storage |
| "We need FedRAMP / IL5." | no authorization |
| "Can you make our model compliant with the EU AI Act?" | the product can produce evidence; it does not certify compliance |
| "We will sign after you add SSO, SCIM and a free tier." | SSO/SCIM are not implemented; no free tier |
| "We need a reference customer in our industry." | none exists yet |

## 4. Discovery questions

1. What does your customer ask you to prove about an AI request today, and what
   do you hand them?
2. Where does that evidence live, who can change it, and how would you know?
3. Which regulator, auditor, or procurement gate is driving this?
4. What happens if the model provider changes a response after the fact?
5. Who operates the infrastructure, and can you run a container and Postgres?
6. What is the monthly governed-request volume and peak concurrency?
7. What have you already tried: logs, APM, an AI gateway, a homegrown ledger?
8. What would make this a "must solve this quarter" rather than "nice to have"?
9. What is the budget owner's name and the approval path?
10. What would disqualify us in your process? (Ask; do not wait to discover it.)

## 5. Qualification score

| Signal | Points |
| --- | --- |
| regulated end customer | +2 |
| self-hosting accepted | +2 |
| audit/procurement trigger this quarter | +2 |
| 100k+ governed requests/month | +1 |
| platform team can operate Postgres | +1 |
| accepts "no SOC 2 / no SLA" for a pilot | +2 |
| demands managed SaaS | −3 |
| demands BAA/FedRAMP/SOC 2 before pilot | −3 |
| price-shopping log storage | −2 |
| no named budget owner | −1 |

A score below 4 is a nurture lead, not a pilot. Do not discount the product to
compensate for a missing certification; that converts a truth gap into a
pricing gap and does not close it.

## 6. What to say when the fit is wrong

> "Aegis is self-hosted and does not have SOC 2, a BAA, or a managed service.
> If those are hard gates today, we are not the right vendor yet. I would rather
> tell you now than after a security review."

That sentence is the brand. It is also the only sentence that survives contact
with a procurement team.
