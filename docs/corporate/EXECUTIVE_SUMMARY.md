# Executive Summary

**Audience:** executives, technology leaders, investors, senior procurement.
**Scope:** what Aegis Latent Core is, the problem it addresses, how it differs technically, and what it does not establish.
**Boundary:** every capability below is described in [Claims Matrix](../CLAIMS_MATRIX.md) with its evidence state. No independent assurance exists.

---

## What it is

Aegis Latent Core is an **AI Governance and Cryptographic Evidence Gateway**. It sits between an application and a model provider. For each admitted call it applies policy, forwards the request, and commits a hash-linked, signed evidence record to a durable log **before the response reaches the caller**.

It is self-hosted. The organisation running it holds its own evidence, its own keys, and its own data. There is no hosted service and no vendor access.

## The problem

Organisations are placing AI systems into decisions that are consequential, regulated, or contested. When one of those decisions is later questioned — by a regulator, an auditor, a customer, or a court — the organisation needs to establish what the system was actually asked and what it actually returned.

Conventional application logs are a weak answer. They are typically written after the response, mutable by anyone with access, unverifiable by a third party, and easy to lose. An organisation asserting "our logs show X" is asking the questioner to trust the organisation's own infrastructure.

The gap is not storage. It is **evidence with a verifiable relationship to what happened**.

## The approach

Three properties, in order of how much they matter:

**Ordering.** Evidence is committed before the caller can observe the response. A design that returns first and commits later makes the record optional, and an optional record is not evidence. For streaming, the terminal marker is withheld until the terminal summary commits.

**Verifiability by a third party.** Each record is a leaf in a Merkle Mountain Range. A portable inclusion proof lets a party who does not trust the gateway verify that a disclosed record was included under a root they obtained independently.

**Bounded, stated claims.** Every public claim carries an evidence state, a locator and an explicit boundary. The register also records what the project refuses to say.

## Technical differentiators

| | What it means |
| --- | --- |
| Commit-before-emission | The response is not returned until the record is durable |
| Portable inclusion proofs | Third-party verification without the gateway, against an independently obtained root |
| Provider independence | OpenAI-compatible surface; the provider is a configured endpoint, not a lock-in |
| Self-hosted custody | The licensor holds no customer evidence, keys or payloads |
| Fail-closed by default | Refuses to serve unevidenced traffic rather than degrading silently |
| Formal artifacts | Bounded Z3, Lean and TLA+/TLC models of core invariants |
| Governed claims | A public register with locators and boundaries, checked in CI |

The last row is unusual and worth noting: the project's documentation is gated by automated checks that reject unsupported assurance language.

## What it does not establish

Stated here rather than in a footnote, because an executive reading only this page should leave with the correct picture.

- **No certification.** No SOC 2, ISO 27001, HIPAA attestation, or FedRAMP authorisation. None is in progress.
- **No compliance determination.** The system produces technical inputs. Whether an obligation is met is decided by the customer and their assessor.
- **No legal admissibility.** A judicial determination, not a product feature.
- **No immutability guarantee.** Tampering is detected on read, not prevented. An operator with root can alter records — this is the design's largest residual assumption.
- **No production SLO or capacity claim.** Benchmarks are local measurements.
- **No universal PII removal.** Redaction is deterministic pattern matching over three payload fields.
- **No cross-replica global ordering.** Each replica produces an independent chain.
- **No independent assurance of any kind.**

## Commercial path

Dual-licensed: AGPLv3, or a commercial licence. See [COMMERCIAL.md](../../COMMERCIAL.md).

The AGPL network clause is the practical decision point: an organisation that modifies the software and exposes it to third parties over a network must offer them the corresponding source. Organisations for whom that is unacceptable need the commercial licence.

Evaluation is self-service — the source, the claims register, and the pilot playbook are all public. See [Pilot Playbook](../enterprise/PILOT_PLAYBOOK.md).

## Risk summary

An honest assessment for a decision-maker:

| Risk | Severity | Mitigation |
| --- | --- | --- |
| **Single maintainer; bus factor of one** | High | Pin and vendor the source; build internal capability; negotiate continuity terms |
| **No independent assurance** | High for regulated buyers | Commission your own review; the source is available |
| **No production-scale evidence** | Medium | Measure in your own pilot; do not rely on published numbers |
| **Registry lag** — SDKs at `4.0.0`, source at `4.1.2` | Medium | Install from source, or verify which version you actually have |
| **Operator-trust assumption** | Inherent | Control host access; this is not solvable in software |
| **No SLA** | Medium | Commercial agreement, or accept it explicitly |
| **Cross-replica ordering absent** | High if you need one timeline | No mitigation; this is a design property |

**Who it fits:** organisations that want evidence custody in their own infrastructure, have platform engineering capacity, can perform their own security assessment, and prefer a documented boundary to a marketed one.

**Who it does not fit:** organisations requiring a vendor-operated service, certification before deployment, a contractual SLA from the open-source project, or a single global evidence timeline.

## What to read next

| You want | Read |
| --- | --- |
| The condensed version | [Product One-Pager](PRODUCT_ONE_PAGER.md) |
| Direct answers to hard questions | [Corporate FAQ](CORPORATE_FAQ.md) |
| To verify a claim | [Claims Matrix](../CLAIMS_MATRIX.md) |
| To assess security | [Threat Model](../security/THREAT_MODEL.md), [Security Controls](../security/SECURITY_CONTROLS.md) |
| To run an evaluation | [Pilot Playbook](../enterprise/PILOT_PLAYBOOK.md) |
| To start procurement | [Procurement Checklist](../enterprise/PROCUREMENT_CHECKLIST.md) |

---

**Related:** [Product One-Pager](PRODUCT_ONE_PAGER.md) · [Corporate FAQ](CORPORATE_FAQ.md) · [Enterprise Readiness](../enterprise/ENTERPRISE_READINESS.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md)
