# Aegis Latent Core — US Commercial Strategy

**Status:** Pricing and packaging hypotheses; not a binding offer  
**Market scope:** United States, self-hosted enterprise AI infrastructure

## Positioning

Aegis should sell into three adjacent budgets: AI gateway and traffic governance, AI security and guardrails, and audit/evidence infrastructure. The initial message should stay narrow: provider-independent gateway control plus durable, independently verifiable evidence. It should not compete by claiming to replace a full AI security control plane, a compliance authorization product, or a provider’s entire observability platform.

Public comparable offers show a recurring market pattern. Portkey publishes a free tier for prototypes and a $49/month production tier with request/log limits, while its enterprise tier is custom and tied to retention, private deployment, advanced compliance, data isolation, and support [1]. Helicone presents self-serve usage, retention and ingestion controls, with enterprise differentiation in support, SLAs, compliance, and customized agreements [2]. LiteLLM states that its self-hosted open-source gateway is free and that enterprise pricing is sized to annual request capacity, deployment architecture, and support needs rather than tokens [3]. Protect AI positions its enterprise AI gateway/control plane around discovery, governance, and runtime security but does not publish a simple self-serve price on the reviewed page [4].

These are directional market signals, not evidence of feature parity or buyer willingness to pay. Pricing must be refreshed before any external offer.

## Initial ICP

The first ICP is a B2B SaaS, fintech, or regulated-enterprise platform/security team running multiple model providers and needing private deployment. The buyer has enough operational maturity to own durable storage, secret management, incident response, and an internal platform team. Government, defense, healthcare, industrial, and scientific segments remain expansion tracks because their assurance and procurement requirements exceed what the current repository independently proves.

## Buyer committee and sales motion

The economic buyer is usually an executive sponsor responsible for AI risk, platform reliability, or security. The technical champion is platform engineering or AppSec. AI/ML engineering validates provider compatibility and latency boundaries. Compliance/legal reviews evidence, retention, data handling, and claims. Procurement reviews licensing, support, indemnity, security questionnaires, and vendor viability.

The sales motion is **local evaluation → evidence replay → controlled pilot → security review → procurement package → production rollout**. A pilot must produce a customer-owned evidence bundle rather than a slide-only demonstration. The bundle includes request/response vectors, WAF results, WAL/replay checks, key-rotation evidence, SBOM/provenance, deployment assumptions, and rollback results.

## Packaging hypothesis

| Package | Buyer | Included | Price hypothesis to validate | Hard boundary |
|---|---|---|---|---|
| Community / OSS | Developers and evaluators | AGPL self-hosting, source, tests, public docs, community issue tracking | Free | No support, SLA, private onboarding, or procurement commitment. |
| Team / Pilot | Platform team validating one workload | Time-boxed pilot, bounded architecture review, evidence replay, test plan, and limited implementation support | **$10k–$30k fixed pilot** for a defined 4–8 week scope | No promise of production SLO, certification, or unlimited engineering. |
| Production | One enterprise deployment | Commercial self-hosted terms, release updates, deployment guidance, evidence package, and named support window | **$40k–$100k annual minimum hypothesis**, sized by deployment topology, support hours, and request tier | Requires written support capacity and exclusions; not per-token pricing. |
| Enterprise | Multiple environments or regulated procurement | Security review support, architecture assistance, negotiated response targets, private deployment guidance, and procurement artifacts | **$100k–$250k+ annual hypothesis**, only with accountable operations and legal review | No “sovereign” or 24/7 claim without staffing, contract, and tested operating model. |
| Sovereign / OEM | Air-gapped, embedded, redistribution, or escrow | Dedicated contract, redistribution rights, escrow/assurance terms, and specialized support | Custom only | Not a current default offer. Requires legal, support, and external assurance capacity. |

The ranges are **illustrative hypotheses**, not market facts or commitments. They must be validated through at least three buyer interviews, comparable vendor quotes, support-cost modeling, and one controlled paid pilot. A solo maintainer should not sell a high-touch enterprise SLA that cannot be staffed.

## Cost-to-serve model

The commercial owner should model engineering hours per pilot, release support hours, security questionnaire effort, incident response coverage, cloud or lab infrastructure, legal review, independent testing, and opportunity cost. The minimum annual price must cover the support boundary plus a reserve for incident and release work; a high list price does not create assurance capacity.

A simple sensitivity model is:

```text
annual_floor = (engineering_hours × loaded_hourly_cost)
             + (support_hours × loaded_hourly_cost)
             + security_review_cost
             + legal_and_contract_cost
             + infrastructure_cost
             + risk_reserve
```

ROI should be presented as a sensitivity model based on customer-observed evidence-reconstruction effort, provider-switching cost, incident triage time, and procurement requirements. Do not promise avoided fines, avoided incidents, or a fixed percentage reduction in regulatory risk.

## Procurement package

The production package should contain the immutable release tag, source and asset hashes, SPDX SBOM, provenance envelope, release-gate record, claim matrix, threat model, deployment checklist, key-rotation runbook, backpressure runbook, WAF corpus report, vulnerability disclosure policy, retention/data-handling statement, support matrix, rollback criteria, and an explicit list of controls that remain customer-owned.

## Support boundary

Community support is public and best effort. Pilot support is time-boxed and scoped. Production support requires a named owner, supported versions, response windows, escalation path, maintenance policy, and exclusions. Enterprise support requires actual staffing, incident coverage, release cadence, and legal terms. Until those are in place, the repository must not publish “24/7,” “mission-critical SLA,” or “sovereign assurance” language.

## Legal and license boundary

`COMMERCIAL.md` must receive counsel review before it states the effect of AGPL network obligations, exemptions, future-version rights, warranty, indemnity, tax, data registration, certificate delivery, or redistribution. This strategy is not legal advice and does not change the license.

## Success metrics

The commercial owner should measure pilot-to-production conversion, time to first evidence replay, security-review cycle time, number of unresolved procurement blockers, support hours per deployment, incident response load, renewal rate, and gross margin by topology. GitHub stars, fabricated logos, and vanity throughput are not sales evidence.

## Sources

[1]: https://portkey.ai/pricing "Portkey pricing"
[2]: https://www.helicone.ai/pricing "Helicone pricing"
[3]: https://www.litellm.ai/pricing "LiteLLM pricing"
[4]: https://protectai.com/ "Protect AI / Prisma AIRS"
