# Aegis Latent Core — US Product Brief

## Category

Aegis Latent Core is an **OpenAI-compatible AI Governance and Evidence Gateway** for teams that route governed AI traffic through multiple model providers and need durable, provider-independent evidence of the request/response lifecycle.

## The buyer problem

AI platform teams need to move quickly across model providers while security, compliance, and legal teams need a stable control boundary. Provider dashboards and ordinary access logs vary by vendor and usually do not provide a single, replayable evidence contract for request hashes, response hashes, policy outcomes, signing metadata, and durability status.

Aegis places a controlled gateway in that boundary. It authenticates the caller, enforces request and egress controls, evaluates WAF/session policy, applies distributed rate limiting, forwards to the selected provider, and commits a signed evidence record before the governed response is returned.

## Initial ICP

The first buyer is a B2B SaaS, fintech, or regulated-enterprise platform/security team operating more than one LLM provider and requiring private deployment. The buyer has a platform owner, an AppSec or CISO sponsor, an AI/ML engineering owner, a compliance/legal reviewer, and procurement involvement. Healthcare, government, defense, industrial, and scientific deployments are expansion tracks, not proof of vertical compliance.

## What the product provides

| Capability | Buyer outcome | Evidence boundary |
|---|---|---|
| OpenAI-compatible gateway | Applications can adopt a stable internal control point without rewriting every provider integration. | API contract and integration tests. |
| Durable signed evidence | Security and compliance teams can replay a record of the governed lifecycle under explicit storage and signer controls. | WAL/storage commit, hashes, signature, key ID, integrity verification. |
| WAF and request controls | Prompt-injection and structural policy checks occur before upstream forwarding. | Application boundary and pinned corpus; ingress parser remains separate. |
| Provider-independent policy | Egress, rate-limit, session, and evidence policies do not depend on one provider dashboard. | Gateway configuration and deployment tests. |
| Private deployment | Customers can keep provider traffic and evidence inside their own infrastructure. | Customer topology, network, retention, and key-custody evidence. |

## Proof sequence

The recommended evaluation is local evaluation, evidence replay, controlled pilot, security review, procurement package, and production rollout. The pilot should preserve request/response test vectors, raw benchmark artifacts, a threat model, deployment prerequisites, SBOM/provenance, rollback instructions, and a list of controls not provided by Aegis.

## What Aegis is not

Aegis is not an LLM, a complete model-safety system, a universal WAF, an authorization to process regulated data, a SOC 2 report, a HIPAA determination, a FedRAMP authorization, an EU AI Act conformity assessment, FIPS 140 validation, a court-admissibility ruling, or a substitute for customer identity, network, privacy, retention, or incident-response controls.

## Buyer diligence questions

A buyer should ask which HTTP/2 component owns normalization, which storage system provides durability, how key custody and rotation are performed, how a response is correlated with exactly one evidence record, what happens when Redis or the signer is unavailable, how a three-replica rotation is verified, and what independent review has been completed. The repository provides explicit answers and marks missing evidence rather than filling gaps with marketing language.

## Procurement package

The initial package should include the immutable release link, source and asset hashes, SPDX SBOM, provenance envelope, release-gate record, threat model, data-retention statement, deployment checklist, support matrix, vulnerability disclosure policy, rollback procedure, WAF corpus report, and benchmark limitations. Customer counsel and security reviewers remain the decision owners for contractual, legal, and compliance conclusions.
