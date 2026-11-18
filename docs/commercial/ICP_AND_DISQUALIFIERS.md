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
| Deployment | self-hosted under the source licence, private cloud, BYOC, or the managed service | the managed service carries no SLA or certification; a prospect who needs either is a mismatch |
| Volume | 100k–10M governed requests/month | enough pain to pay, small enough for one gateway |
| Trigger | a security review, audit, incident, or procurement blocker about AI logs | urgency exists before the first call |
| Technical capacity | can run a container and PostgreSQL, or uses the managed service through a URL and an API key | self-hosting needs a platform team |

## 1.1 Segment ranking and beachhead (2026-11-18)

The ranking weighs control pressure, how often the buyer is examined, budget, a clear owner, and whether the work can start with one narrow workflow. It is not a ranking by market size, and it is `[HYPOTHESIS-UNVALIDATED]` until a pilot converts.

| Rank | Segment | First workflow | Likely sponsor | What they need to see |
| ---: | --- | --- | --- | --- |
| 1 | Financial services | fraud, AML, credit or regulated customer service | CRO, model risk, CISO, AI platform | a reproducible record per decision that survives effective challenge |
| 2 | Enterprise AI platforms | an agent with tools or write access | VP Engineering, CISO, AI platform | neutral, portable evidence independent of the model vendor |
| 3 | Health and life sciences | clinical copilot, AI/ML device or GxP workflow | QA, regulatory, clinical safety | lineage, change control and a dossier |
| 4 | Government | one high-impact AI use or a tender | CAIO, CIO/CISO, procurement | inventory, oversight, portability, ability to suspend |
| 5 | Insurance | claims, underwriting, pricing or fraud | CRO/actuary, market conduct | inputs, model, override and outcome per case |
| 6 | BPO and contact centres | payments queue or regulated campaign | COO, QA, security | consent, PCI/PII redaction and a reproducible dispute |
| 7 | Legal and judicial | one research or drafting matter | general counsel, legal ops, CISO | technical chain of custody and human review |
| 8 | Regulated science and industry | batch, trial, process or device | quality/CSV, R&D, safety | data integrity, change control, reproducibility |

**Beachhead.** Start with rank 1 or rank 2, never all eight. Each vertical needs its own vocabulary, validation, retention and contract. The second vertical gets a package only after the first one converts a pilot to production.

**The champion** is usually not the CTO. It is the person who today assembles an audit, examination, dispute or RFP file by hand and cannot vouch for its integrity.

**Buyer committee.** Risk or quality owner (defines what must be shown), technical owner (integrates, accepts overhead), security and privacy (capture, access, minimisation), legal or regulatory (limits claims), internal audit or QA (checks the file), procurement and third-party risk (evaluates the vendor), business owner (pays).

**Trigger events.** An audit, examination or inspection within 6 to 12 months; an agent with tool or sensitive-data access going to production; a change of model, provider, prompt, dataset or policy; an incident (leak, bias, fraud, wrong output, outage); a new contract that requires demonstrating controls; an ISO/IEC 42001, NIST AI RMF, GxP or ICT-resilience programme starting; an enterprise customer asking "how do you prove it".

**The wedge offer** is a paid pilot on one workflow, one environment and synthetic or consented data, ending in an acceptance report signed by engineering and risk: a bundle verified offline by a second operator, a one-byte alteration detected, signer, WAL and storage failures injected with no unevidenced upstream call, a forged-tenant negative test, and a written list of what the pilot does not prove. The report, not the demo, is what converts to production.

**Pricing unit.** Price per governed workflow, evidence volume, environment, retention and assurance level. Do not price by tokens, users or raw trace count: that places Aegis in a price comparison with gateways and observability tools.

## 2. Secondary ICP

- A system integrator or consultancy that builds AI for regulated clients and
  wants a repeatable evidence layer.
- An AI vendor that already has SOC 2 but cannot prove what its model did on a
  specific request.
- An insurer or bank innovation lab running a pilot, not yet in production.

## 3. Anti-ICP (disqualify early)

| Signal | Why it is a no today |
| --- | --- |
| "We need a managed SaaS with a contractual SLA." | the managed service exists but has no SLA |
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
| demands an SLA on the managed service | −3 |
| demands BAA/FedRAMP/SOC 2 before pilot | −3 |
| price-shopping log storage | −2 |
| no named budget owner | −1 |

A score below 4 is a nurture lead, not a pilot. Do not discount the product to
compensate for a missing certification; that converts a truth gap into a
pricing gap and does not close it.

## 6. What to say when the fit is wrong

> "Aegis does not have SOC 2, a BAA, or a contractual SLA on the managed service.
> If those are hard gates today, we are not the right vendor yet. I would rather
> tell you now than after a security review."

That sentence is the brand. It is also the only sentence that survives contact
with a procurement team.
