# Official-Source Pricing Signals for Aegis Packaging Review

**Research date:** 2026-08-22 UTC
**Purpose:** Calibrate Aegis packaging hypotheses after PR #99. This is not a valuation, list-price recommendation, quote, or evidence of buyer willingness to pay.
**Evidence boundary:** The official pages below are dynamic and were not archived in this repository. The table therefore records only pricing-model categories that remained consistent across the reviewed official sources; it does not preserve third-party numeric prices as durable evidence.

## Primary-source signals

| Comparable | Pricing model observed | Enterprise signal | Comparison boundary |
|---|---|---|---|
| Portkey / PRISMA AIRS AI Gateway | Free entry and paid self-serve tiers with recorded-log/request limits. | Custom/contact-sales pricing. | A close gateway comparator, but published units mix logs and requests and do not map directly to Aegis evidence events or support scope. |
| Helicone | Free entry, paid team tiers, request usage and storage usage. | Custom/contact-sales pricing. | Gateway and observability comparator; request logs do not establish equivalent governance or forensic-evidence semantics. |
| LiteLLM | Open-source self-hosting plus a commercial Enterprise offer sized by capacity, architecture and support. | Custom quote; some support commitments may be separately priced. | Relevant open-core signal, but customer infrastructure and operations remain separate costs. |
| Cloudflare AI Gateway | Core gateway features combined with usage-priced billing, guardrail and log-export services. | Account-team pricing for Enterprise conditions. | Ecosystem and multi-unit pricing do not form a single comparable gateway license. |
| Langfuse | Free and paid observability tiers, usage priced by telemetry units, and commercial Enterprise offerings. | Cloud and self-hosted terms differ. | LLM observability rather than an equivalent gateway; billable units are not requests or Aegis evidence records. |
| immudb | Open-source software plus paid hosting/support offers. | Enterprise by quote. | Adjacent immutable database/support comparator, not an AI gateway or governance platform. |

## Primary URLs

- Portkey pricing: https://portkey.ai/pricing
- Portkey enterprise audit logs: https://docs.portkey.ai/docs/product/enterprise-offering/audit-logs
- Helicone pricing: https://www.helicone.ai/pricing
- Helicone gateway overview: https://docs.helicone.ai/gateway/overview
- LiteLLM pricing: https://www.litellm.ai/pricing
- LiteLLM enterprise: https://www.litellm.ai/enterprise
- LiteLLM billing metrics: https://docs.litellm.ai/docs/proxy/billing_metrics
- Cloudflare AI Gateway pricing: https://developers.cloudflare.com/ai-gateway/reference/pricing/
- Cloudflare AI Gateway audit logs: https://developers.cloudflare.com/ai-gateway/reference/audit-logs/
- Langfuse pricing: https://langfuse.com/pricing
- Langfuse billable units: https://langfuse.com/docs/administration/billable-units
- Langfuse audit logs: https://langfuse.com/docs/administration/audit-logs
- immudb enterprise/support: https://immudb.io/enterprise
- immudb documentation: https://docs.immudb.io/master/immudb.html

## Decision

The public market signals do **not** support deriving an Aegis list price, observed ACV, replacement cost, or startup/IP valuation. Most comparable Enterprise offers require a quote, and the products use incompatible billing units. The current Aegis ranges remain explicitly labeled internal hypotheses:

- Team/Pilot: USD 10,000–30,000 fixed, scoped 4–8 week engagement.
- Production: USD 40,000–100,000 annual-contract hypothesis.
- Enterprise: USD 100,000–250,000+ annual-contract hypothesis.

These figures originate in Aegis's internal strategy document, not in the comparable-source pages. They are neither public list prices nor observed ACV. Aegis has no evidence-backed vertical ACV, engineering replacement-cost estimate, or startup/IP valuation in the audited corpus.

## Reproducibility requirement

Before citing an exact third-party amount in a commercial artifact, preserve the rendered official source with retrieval timestamp, URL, currency, billing period, plan scope and SHA-256 digest. Revalidate immediately before use because public pricing pages can change without versioned history.

## Falsification and next evidence

Change the Aegis bands only after at least ten structured buyer interviews, two paid pilots, logged cost-to-serve, normalized Enterprise quotes for identical workload/topology/support scenarios, and explicit conversion or renewal evidence. A materially different willingness-to-pay distribution or gross-margin floor would falsify the retained bands.
