# ADR-001 — Position Aegis as an AI Governance and Evidence Gateway

**Date:** 2026-08-18  
**Status:** Accepted for v3.0.1 market-hardening work  
**Deciders:** Release owner; qualified security reviewer required before external enterprise claims

## Context

Aegis combines an OpenAI-compatible proxy, request policy enforcement, WAF and egress controls, durable signed evidence, provider adaptation, and bounded asynchronous enrichment. The repository also contains domain-specific compliance and forensic modules, but several high-assurance properties remain deployment-dependent, unmeasured, roadmap-bound, or subject to independent/legal review.

The current prospectus uses a broad “enterprise AI governance” narrative across many verticals. The top-level market message must be narrower than the repository’s full module inventory so a buyer can understand the core value and a reviewer can verify each claim.

## Options considered

| Option | Advantages | Failure mode / cost |
|---|---|---|
| AI security / prompt firewall | Clear threat-detection category and familiar buyer language | Understates durable evidence, provider independence, offline verification, and operational governance. It also places the product in direct feature comparison with mature runtime security vendors. |
| Generic LLM framework | Broad developer audience | Misrepresents the product boundary and creates an unbounded feature surface. It does not explain why the ledger, WAL, signing, and deployment controls exist. |
| Universal compliance platform | Strong executive appeal | Unsupported without organizational controls, certifications, independent assessment, jurisdictional mapping, and procurement evidence. Creates legal and diligence risk. |
| **AI Governance and Evidence Gateway** | Expresses the actual integration point and differentiator: provider-independent control plus durable, independently verifiable evidence | Requires precise claim controls, clear non-goals, deployment-specific validation, and a staged commercial motion. |

## Decision

Aegis will be presented as an **OpenAI-compatible AI Governance and Evidence Gateway** for platform/security teams operating multi-provider AI applications that need policy enforcement and durable evidence. The core product promise is:

> **Route governed AI traffic through a provider-independent gateway and produce durable, independently verifiable evidence of the request/response lifecycle under explicit deployment controls.**

The product is not presented as an LLM, a universal WAF, a compliance certification, a legal-admissibility ruling, a replacement for network controls, or a substitute for an organization’s security, privacy, retention, or incident-response program.

## Consequences

### Positive

The message maps directly to the implemented request lifecycle, creates a defensible distinction from simple observability, and gives security, platform, compliance, and procurement reviewers a single system boundary to evaluate. It also allows vertical presets to be described as control mappings rather than unsupported claims of sector-wide compliance.

### Negative

The narrower positioning reduces the apparent breadth of the initial market story. Enterprise buyers will still require independent review, deployment evidence, support capacity, legal review, and customer references. The repository must maintain a claim ledger so benchmark and roadmap language cannot drift into the README or prospectus.

### Revisit triggers

Revisit this ADR only when one of the following is evidenced: an independent security assessment, a production pilot with published scope and consent, a supported enterprise operations model with named SLA boundaries, a verified multi-region HA implementation, or a new product category with a stronger measured buyer outcome.

## Verification

The claim matrix at [`../CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md) is the normative public-language control. The falsification condition is any customer-facing document that claims a certification, production SLO, constant-time cryptography, universal WAF bypass rate, or globally ordered multi-region evidence without a matching artifact and boundary statement.
