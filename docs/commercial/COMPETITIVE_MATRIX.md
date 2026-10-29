<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Competitive matrix

**Audience:** founder, sales, and a buyer comparing alternatives.
**Scope:** the categories a buyer evaluates, what each is good at, and where
Aegis is not the answer.
**Boundary:** a positioning tool, not a benchmark. It makes no unverified claim
about a named competitor's internals or current pricing. Verify any competitor
claim against that vendor's public documentation before repeating it.

## 1. The comparison a buyer actually makes

| Category | What it solves | What it usually does not solve | Aegis position |
| --- | --- | --- | --- |
| Build it in-house | exact fit, full control | months of work, no independent evidence design, maintenance | Aegis is the shortest path to a governed record, but in-house can be right for a very large platform team |
| LLM observability / tracing | traces, prompts, evals, cost | durable pre-response evidence, self-hosted custody, tamper detection | complementary; Aegis is not an eval or tracing UI |
| AI gateway / proxy | routing, retries, provider abstraction, quotas | evidence before emission, portable inclusion proofs | overlapping on the proxy path, different on the ledger |
| Cloud provider native logging | low effort, integrated IAM | portable proof, self-hosted custody, cross-provider consistency | a log is not a signed evidence chain |
| DLP / WAF / prompt firewall | block bad input/output | prove what was admitted, refused, and returned | complementary; Aegis records the refusal as evidence |
| GRC / compliance SaaS | control tracking, questionnaires | per-request technical evidence | complementary; Aegis feeds the GRC tool |
| SIEM | correlate events | durable, portable request evidence | complementary; Aegis emits content-free events |

## 2. Where Aegis is different

1. **Evidence before emission.** For admitted non-streaming outcomes, the
   governed record is committed before the caller sees the response. A tracing
   tool logs after the fact; a gateway may log asynchronously.
2. **Portable inclusion proof.** A verifier can check a disclosed leaf against a
   separately trusted root without the gateway's state. This is not a
   blockchain and not a legal-admissibility decision; it is a proof of inclusion
   in the operator's chain.
3. **Self-hosted custody.** The project has no telemetry path to customer
   content. The operator owns the WAL, keys and retention.
4. **Source-available, not open source.** The licence is commercial from 5.0.3;
   earlier releases keep their published terms. A buyer who requires OSI open
   source is a mismatch.
5. **Honest absence.** No SOC 2, ISO 27001, HIPAA BAA, FedRAMP, PCI DSS,
   independent pen test, or 24/7 SLA. The product is useful without those; it
   cannot pretend to have them.

## 3. Where Aegis loses

| Buyer need | Why Aegis loses | What to do |
| --- | --- | --- |
| managed service with no operations | no hosted gateway | disqualify, or offer a partner-operated deployment later |
| SOC 2 before pilot | no report | disqualify or run a scoped pilot with a security addendum |
| BAA / PHI in scope | no BAA | disqualify |
| FedRAMP / IL5 | no authorization | disqualify |
| 99.99% SLA | single-node reference, no staffed on-call | disqualify |
| very high throughput with HA | single-writer design; active-passive only | scope a pilot and a written architecture review |
| open-source licence requirement | commercial licence from 5.0.3 | disqualify |
| free tier | no permanent free tier | offer a 30-day evaluation |

## 4. Objection -> evidence

| Objection | Answer | Source |
| --- | --- | --- |
| "How is this different from logging?" | the record is committed before the response and can be verified against a root | `docs/PROVE_IT.md`, `CLM-003`, `CLM-005` |
| "Why not just use an AI gateway?" | a gateway routes; Aegis adds durable evidence and refusal records | `docs/CLAIMS_MATRIX.md` |
| "Can I verify without you?" | yes, with the portable proof verifier and a root you obtain independently | `sdk/`, `docs/PROVE_IT.md` |
| "Where is my data?" | self-hosted; the hosted console does not receive prompts | `docs/legal/DATA_MAP.md` |
| "Are you SOC 2?" | no | `docs/assurance/ASSURANCE_STATUS.md` |
| "Can you sign a BAA?" | no | same |
| "What is the SLA?" | none; support is email | `docs/enterprise/SUPPORT_MODEL.md` |
| "Can we see a reference?" | no public reference yet | `docs/commercial/COMMERCIAL_READINESS.md` |

## 5. Win condition

A pilot wins when the buyer's security reviewer can run the verifier themselves,
the operator can show a record committed before the response, and the buyer
accepts the absent certifications because the evidence is inspectable. A deal
that requires a certificate before the first request is not a pilot; it is a
procurement cycle the company cannot serve yet.

## 6. What not to do

- Do not compare on a feature-count table; the categories solve different jobs.
- Do not claim a competitor "has no evidence" without reading their docs.
- Do not turn a missing certificate into a discount; it changes the price, not
  the truth.
- Do not name a customer or a logo that has not signed.
