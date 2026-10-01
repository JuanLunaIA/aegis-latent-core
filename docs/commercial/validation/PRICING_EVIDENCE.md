<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
-->

# Public Pricing Signals, Read 2026-09-30

**Audience:** the founder, before the first buyer interview and before any number is quoted.
**Scope:** the public prices of six adjacent products (LLM observability and AI gateways), read on 2026-09-30 through the Pricing Optimizer AI connector.
**Boundary:** a dated snapshot from a third-party aggregator, not a confirmation by the vendors. These are adjacent products, not equivalent ones. This is not a price recommendation, a valuation or evidence of what anyone will pay, and it changes no figure in the [Enterprise Pricing Guide](../ENTERPRISE_PRICING_GUIDE.md), whose numbers stay `[HYPOTHESIS-UNVALIDATED]`.

## What was read

Amounts are as the aggregator lists them, in USD. "Observed" is the aggregator's own observation date, so the six rows are not from the same day. Every row's evidence link is the aggregator's page for that product.

| Product | Listed public plans | Observed | Aggregator evidence |
| --- | --- | --- | --- |
| Portkey | Developer free; Production $49 per month with 100k recorded logs, then $9 per additional 100k requests; Enterprise on request | 2026-09-21 | [portkey](https://pricingoptimizerai.com/products/portkey) |
| Langfuse | Hobby free; Core $29 per month; Pro $199 per month; Enterprise $2,499 per month | 2026-08-31 | [langfuse](https://pricingoptimizerai.com/products/langfuse) |
| Helicone | Hobby free; Pro $79 per month | 2026-08-27 | [helicone](https://pricingoptimizerai.com/products/helicone) |
| LangSmith | Developer $0 per seat, then pay as you go; Plus $39 per seat per month; Enterprise on request | 2026-08-29 | [langsmith](https://pricingoptimizerai.com/products/langsmith) |
| Braintrust | Starter $0 plus usage rates; Pro $249 per month plus usage rates; Enterprise on request | 2026-09-21 | [braintrust](https://pricingoptimizerai.com/products/braintrust) |
| Opik | Open source free; Free Cloud free; Pro Cloud $19 per month; Enterprise on request | 2026-08-29 | [opik](https://pricingoptimizerai.com/products/opik) |

The vendors' own pricing pages, which the aggregator names as its sources and which are the only thing to quote from: [Portkey](https://portkey.ai/pricing), [Langfuse](https://langfuse.com/pricing), [Helicone](https://www.helicone.ai/pricing), [LangSmith](https://www.langchain.com/pricing), [Braintrust](https://www.braintrust.dev/pricing), [Opik](https://www.comet.com/site/pricing).

## What it says about the guide

The listed self-serve paid figures run from $19 to $2,499 per month. Annualised, that is $228 to $29,988 per year. The lowest priced package in the guide, Aegis Core, is $45,000, which is above the top of that range.

That gap is not a finding that the guide is wrong. These products sell subscriptions for developers who want visibility into model calls, and the guide's hypothesis is for a regulated buyer who needs a record a third party can check. It does mean every buyer will hold this contrast in mind. The answer to it is what a record that an outsider verifies is worth to that buyer, and only the interviews can measure that. Until then the guide's own section 9 stands: no figure is firm.

## What it does not say

- **Not equivalent products.** The aggregator describes all six as observability or gateway products. Whether any of them offers tamper-evident records or a portable proof was not checked, and nothing here claims that none does.
- **Different units.** Seats, recorded logs, requests and flat monthly fees do not compare directly, and a table of them is not a market price.
- **Blank is not zero.** Where the aggregator shows no amount, the price is unpublished or unverified. "Enterprise on request" means the price is set in a sales conversation.
- **Ages differ and prices move.** The six observations span 2026-08-27 to 2026-09-21. Open the vendor page before writing any of these numbers anywhere else.
- **One source.** No second aggregator or vendor page was compared for this note. The earlier [official-source benchmark](../../../evidence/documentation_audit_2026-08-22/PRICING_BENCHMARK.md) deliberately recorded pricing models and no amounts, and that choice stands for anything that must last.

## What was tried and gave nothing

- **A description-only query** to Pricing Optimizer AI returned `extraction_failed`; the read above started from Portkey's pricing page instead.
- **G2** lists an "AI Governance Tools" category with five products, but the product list came back empty for this account, so no ratings or review counts are recorded.
