<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Positioning

**Audience:** anyone writing or speaking to a buyer about this product.
**Scope:** the problem, its cost, the differentiator, how to handle the competitive question, and what this product is not.
**Boundary:** every capability statement below maps to a row in [Claims Matrix](../CLAIMS_MATRIX.md). Regulatory text is described as the buyer's obligation, never as an obligation this software satisfies — that determination belongs to the buyer and their assessor (`UC-021`). Where this file appears to permit something the matrix does not, the matrix governs.

---

## 1. The problem, in the buyer's words

An organisation puts a language model somewhere consequential — a claims decision, a credit note, a triage suggestion, a trade rationale. Six months later someone asks what the model was told and what it said.

The answer comes from a log. And the log is a row in Postgres, a document in Elasticsearch, a line in a file.

> **A database administrator can change it. So can anyone who reaches the database. So can the application that wrote it.**

Nobody has to be malicious for this to fail. A retention job trims the table. A migration rewrites a column. An incident-response script deletes a range. The record is not destroyed by an attacker; it is destroyed by ordinary operations, and nobody can prove afterwards which.

That is the whole problem, and it is not a logging problem. **A record that the interested party could have changed is not evidence.** It was never evidence. It reads as evidence right up until the moment someone with a reason to doubt it asks a single question: *what stops you from having edited this?*

Today, in almost every AI deployment, the answer is "our internal controls" — which is to say, nothing a third party can check.

## 2. What that costs

Three specific exposures. Each is the buyer's obligation, not a property of this software.

**You cannot defend the decision.** In a dispute, a regulatory examination or an internal investigation, mutable logs shift the argument from *what happened* to *whether your records can be trusted*. That is a much worse argument to be having, and you are having it under time pressure.

**Record-keeping obligations assume records that survive.** EU AI Act Article 12 requires automatic logging over a high-risk system's lifetime. HIPAA's audit controls require mechanisms that record and examine activity in systems holding electronic protected health information. SEC Rule 17a-4, after the 2022 amendments, permits either WORM media **or** an audit-trail alternative that can demonstrate the integrity of a record's history — which is precisely a claim about tamper-evidence rather than about storage media (`UC-006`, `UC-007`). MiFID II obliges firms to retain records of relevant communications (Directive 2014/65/EU Article 16(7), five years, up to seven on request), and MiFIR Article 25(1) keeps order and transaction data for five years.

None of these is satisfied by this product, and this document does not say otherwise. What they establish is that **the buyer already owes someone a record they can stand behind**, and an editable row does not produce one.

**The gap widens with every call.** Volume is the problem's multiplier. A thousand governed calls a day is a third of a million a year, each one a decision someone might later question, none of them independently checkable.

## 3. The differentiator: you verify it, not us

Three properties. The third is the one that matters, and the first two exist to make it true.

### 3.1 The evidence exists before the answer does

For an admitted non-streaming call, the record is written, flushed and `fsync`-ed **before the response can be observed by the caller** (`CLM-043`, `CLM-003`). Not queued for a log shipper. Not written asynchronously and probably durable. Durable, then the response.

Ordering is the entire point. A record written after the response is a record that might not have been written at all — the process can die in between, and the one call anyone will ever ask about is disproportionately the one where something went wrong. **Evidence that exists only when nothing went wrong is not evidence.**

Streaming carries the same discipline in the shape streaming allows: events emit incrementally, evidence reads `pending-terminal`, and the terminal marker is withheld until the terminal summary commits (`CLM-046`, `CLM-004`). Refusals are evidence too — a blocked request is committed to the same signed chain before the error returns (`CLM-060`).

### 3.2 The chain is append-only and tamper-evident

Each record is hash-linked to its predecessor and signed, and each is a leaf in a Merkle Mountain Range. Altering a record breaks the link, and the break is detected on read.

Said exactly: **tampering is detected, not prevented.** An operator with filesystem access can alter or delete records. Every integrity statement in this corpus terminates at that boundary, and it is stated here rather than discovered later.

### 3.3 A third party verifies the proof without trusting us — or you

This is the wedge.

A portable inclusion proof lets someone who does not trust the gateway, and does not trust the organisation running it, check that a specific disclosed record is included under a Merkle root they obtained independently (`CLM-005`, `CLM-044`). Two SDK implementations — Python and TypeScript — verify the same proof.

The consequence for a buyer is the sentence worth leading with:

> When your regulator, your counterparty or your auditor doubts your AI records, you do not ask them to trust your controls. You hand them a proof and a verifier, and they check it themselves.

The load-bearing condition, which must be stated every single time the capability is: **the root must be obtained independently of whoever handed you the proof** (`CLM-044`). A proof checked against a root supplied by the same gateway that produced it establishes internal consistency and nothing more. Anyone who omits that is selling a circular verification, and a cryptographer on the buyer's side will catch it in the first call.

### 3.4 You hold everything

Self-hosted. The licensor holds no evidence, no keys, no payloads, and has no access to any deployment. There is no SaaS tier and no telemetry back-channel.

For this buyer that is not a deployment preference. A vendor who holds your evidence is a vendor who can be compelled, breached, or wound up — and a vendor-held attestation has the same defect as the mutable log it replaced: an interested party stands between you and the proof.

## 4. The competitive question

**This corpus contains no comparison table, and that is deliberate.**

`docs/corporate/POSITIONING_AND_MESSAGING.md` §5 prohibits producing one, for a reason that survives scrutiny: asserting what another vendor's product does or does not do requires evidence about systems we cannot inspect. Getting it wrong is a credibility failure in front of the one audience that checks — and for a product whose thesis is *don't trust assertions, verify them*, publishing unverifiable assertions about third parties is self-refuting.

So the competitive asset is not a matrix. It is the **evaluation protocol below**, which a buyer runs against every vendor in the category, including this one.

### 4.1 Six questions to put to any AI gateway vendor

Aegis's answers are filled in with their locators. The other columns are for the buyer to fill from each vendor's own documentation — not from our characterisation of it.

| # | Ask every vendor | Aegis | Evidence |
|---|---|---|---|
| 1 | Is the record durable **before** the response reaches my application, or after? | Before, for admitted non-streaming calls | `CLM-043`, `CLM-003` |
| 2 | Can a third party verify one record **without trusting you and without trusting me**? | Yes — portable MMR inclusion proof, two independent verifiers | `CLM-005`, `CLM-044` |
| 3 | Who holds the evidence and the signing keys? | The customer. The licensor holds nothing | `README.md` §Security and evidence model |
| 4 | What happens to traffic when the evidence store fails? | Governed endpoints refuse; `/health` and `/metrics` stay reachable | `CLM-002` |
| 5 | Can I read the source that produces the evidence? | Yes — AGPLv3, complete | `LICENSE` |
| 6 | Where is your published list of what you do **not** claim? | `docs/institutional/UNSUPPORTED_CLAIMS.md`, 42 rows | `UC-001`–`UC-042` |

Question 6 is the one that separates the field, and it costs a vendor nothing to answer if they have one.

When a prospect asks how we compare: *"I can tell you precisely what we do and show you the code that does it. Put the same six questions to them, and compare the answers rather than the brochures."* That is a stronger position than a matrix we would have to defend.

## 5. Anti-positioning: what this is not

For this buyer, the disqualifier list is a feature. A security reviewer who finds an undisclosed limitation stops believing the disclosed ones — so the limitations lead rather than trail.

| Not | The honest statement |
|---|---|
| **Not a prompt-injection firewall** | The WAF is a finite pattern set over normalized text. It raises the cost of a known-encoding bypass and is defeated by an attacker who reads the table. Passing it establishes nothing about a payload (`UC-042`) |
| **Not a compliance certification** | No SOC 2, ISO 27001, HIPAA attestation or FedRAMP. **None in progress.** The product contributes technical inputs; the determination is the buyer's and their assessor's (`UC-021`) |
| **Not court-ready by construction** | Admissibility is a judicial determination involving custody, acquisition and procedure this software does not create (`UC-022`, `UC-034`) |
| **Not immutable** | Append-only with tamper detection. An operator with root can alter records (`UC-006`) |
| **Not non-repudiation, by default** | The default HMAC-SHA256 chain is symmetric: any key holder can forge, so it authenticates the key, not a party. `signature_assurance` reports it as `SYMMETRIC_AUTHENTICATED`, two tiers below hardware-attested. Non-repudiation needs the HSM or PQC path — configuration, not a purchase (`UC-041`, `CLM-090`) |
| **Not universal PII removal** | Deterministic patterns over specific fields. It does not protect data already sent upstream (`UC-009`, `UC-010`) |
| **Not a capacity or availability claim** | No SLO, no SLA, no throughput figure. Benchmarks are local measurements on one shared container (`CLM-051`, `UC-017`) |
| **Not cluster-ordered** | Each replica writes an independent chain. No global ordering, no multi-pod linearizability (`UC-005`, `UC-038`) |
| **Not independently assured** | No third-party audit or penetration test exists (`CR-01`) |
| **Not a substitute for legal review** | Nothing in this corpus is legal advice |

### 5.1 Who should not buy this

Stated because a pilot that should never have started costs both sides more than a fast no.

- **No statutory or contractual need for defensible records.** The mechanism is expensive in operational discipline and buys nothing without the requirement.
- **Needs a managed service.** There is none, and there is no roadmap to one.
- **Needs a certification today.** `CR-01` and `CR-02` are `NOT STARTED` (`COMMERCIAL_READINESS.md`). If the procurement gate is a SOC 2 report, this fails it now.
- **Needs prompt-injection prevention as the primary control.** Buy a different category, and read `UC-042` before believing anyone who says they sell it.
- **Cannot accept a single-maintainer dependency**, and cannot mitigate it with a pinned fork or contracted continuity.

## 6. The one-sentence position

> Aegis commits a signed, hash-linked evidence record before your AI response is observable, and issues a portable proof that a third party verifies without trusting the gateway, the vendor, or you.

Ordering, verifiability, independence. Three properties, each with a test that would falsify it. Anything longer dilutes it; anything shorter drops one.

---

**Related:** [Claim Ledger](CLAIM_LEDGER.md) · [Artifact Inventory](ARTIFACT_INVENTORY.md) · [Sales Kit](SALES_KIT/ONE_PAGER.md) · [Commercial Readiness](COMMERCIAL_READINESS.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Unsupported Claims](../institutional/UNSUPPORTED_CLAIMS.md) · [Positioning and Messaging](../corporate/POSITIONING_AND_MESSAGING.md)
