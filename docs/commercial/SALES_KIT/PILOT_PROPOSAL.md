<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Paid Pilot — Proposal Template

**Audience:** a buyer evaluating whether to run a pilot, and the founder scoping one.
**Scope:** a fixed-scope, time-boxed, paid engagement with written acceptance criteria decided before work starts.
**Boundary:** a template. `[HYPOTHESIS-UNVALIDATED]` applies to every commercial figure — no pilot has been executed, so nothing here is evidence that these terms have been accepted by anyone. Fill the bracketed fields per engagement.

---

## Why paid

A free pilot has no owner on the buyer's side. It gets assigned to whoever has time, stalls at the first integration question, and ends without a decision — which everyone reads as a negative result even though nothing was tested.

A paid pilot, even a small one, produces a budget line, an internal sponsor, and a date. **The fee is not the point; the commitment it creates is.** A buyer unwilling to fund a pilot is telling you the obligation behind the requirement is not real yet, and that is worth learning in week one.

---

## 1. Scope

| Field | Value |
|---|---|
| Customer | `[legal entity]` |
| Sponsor | `[name, title]` — must own the record-keeping obligation |
| Technical lead | `[name]` |
| Workload | **One** named workload. `[e.g. claims-triage assistant, production traffic, single region]` |
| Environments | `[e.g. one non-production + read-only shadow of production]` |
| Deployment shape | Gateway `[or]` embedded |
| Upstream provider | `[OpenAI / Anthropic / other configured endpoint]` |
| Duration | **`[4–8]` weeks**, fixed. Extensions are a new agreement |
| Fee | `[quoted per scope]` — `[HYPOTHESIS-UNVALIDATED]`; see [Pricing Guide](../ENTERPRISE_PRICING_GUIDE.md) |
| Start / end | `[date]` → `[date]` |

**One workload.** A pilot that spans three teams tests coordination, not the product, and it fails for reasons neither side learns from.

## 2. Acceptance criteria

Written here, agreed before work begins, and evaluated literally. Each is a falsifiable test — pass or fail, not an impression.

| # | Criterion | How it is judged | Passes if |
|---|---|---|---|
| 1 | Evidence precedes emission | Issue `[N]` governed non-streaming calls; for each, confirm the record is durable before the response was observable | 100%. Any exception is a failure, not a percentage |
| 2 | A third party verifies a record | Customer's auditor or security team runs the verifier against a root obtained through a channel Aegis does not touch | Verification succeeds, and an altered record fails |
| 3 | Refusals are evidence | Trigger `[N]` WAF blocks and quota rejections; confirm each is committed to the signed chain before the error returns | 100% |
| 4 | **It fails closed** | Remove the signer; fill the evidence volume; break the chain on disk. Confirm governed endpoints refuse and `/health` stays reachable | Refuses in every case. **Serving one unevidenced call is a failed pilot** |
| 5 | Streaming holds the line | Confirm `pending-terminal` until the terminal summary commits, and that the terminal marker is withheld when the commit fails | Marker never precedes its commit |
| 6 | Redaction on the customer's own corpus | Run the customer's real patterns; count what it catches and what it misses | **Measured, not passed.** The output is a number the customer owns |
| 7 | Operational load is tolerable | Record the operator time spent over the period | Customer's judgement, recorded |

**Criterion 4 is the one that matters most**, and buyers routinely skip it. An evidence system is defined by what it does when the evidence path breaks — anything can look correct while everything works. Insist on it even if the customer does not.

**Criterion 6 is deliberately not pass/fail.** Redaction is deterministic pattern matching over specific fields (`UC-009`, `UC-010`). It will miss things on a real corpus. The pilot's job is to tell the customer *how much*, in their data, so they can decide — not to produce a green tick that would be false.

## 3. What the customer gets

- A running deployment against their real ingress, storage, secrets and retention boundaries.
- Executed failure tests, with results, including the ones that did not go well.
- A redaction measurement against their own corpus.
- A written record of every acceptance criterion and its outcome.
- Direct access to the maintainer for the duration.
- **Everything learned, whether or not they proceed.** The source is AGPLv3; the pilot does not gate anything they could not run alone.

## 4. What the vendor gets

Stated plainly, because a buyer can see it anyway and pretending otherwise is a poor start:

- A validated price point. Pricing is `[HYPOTHESIS-UNVALIDATED]` until a pilot sets one.
- A reference — **named only with written permission**, and the engagement does not depend on granting it.
- Defect discovery against a real workload, which no amount of local testing substitutes for.

## 5. What is out of scope

- Any compliance determination. The pilot produces technical inputs; the determination is the customer's and their assessor's (`UC-021`).
- Certification or audit artifacts. None exist (`CR-01`, `CR-02`).
- An SLA. Response is best-effort for the duration, with the maintainer's direct attention but no contracted target (`UC-019`).
- Debugging the customer's provider, identity provider, Redis, storage or ingress.
- Custom development, unless separately scoped and quoted.
- Production cutover. That is a separate decision after the pilot's results are on the table.

## 6. Exit

**At the end date, one of three things happens, and all three are acceptable outcomes:**

1. **Proceed** — move to a commercial agreement. Note that the commercial licence template is `CR-04`, `NOT STARTED`; if the customer needs it, drafting starts now and takes 2–4 weeks.
2. **Stop** — the customer keeps everything learned and the source under AGPLv3. No renewal pressure.
3. **Extend** — a new agreement with new criteria, not a drift of this one.

A pilot that ends without a decision is a failed pilot, and the fixed end date exists to prevent it.

## 7. Signatures

| | |
|---|---|
| Customer | `[name, title, date]` |
| Vendor | `[name, date]` |

**This template is not an offer.** It becomes one when it is filled in, quoted and signed. Nothing in this repository creates a commercial commitment.

---

**Related:** [One Pager](ONE_PAGER.md) · [Objection Handling](OBJECTION_HANDLING.md) · [Discovery Call Script](DISCOVERY_CALL_SCRIPT.md) · [Pilot Playbook](../../enterprise/PILOT_PLAYBOOK.md) · [Pricing Guide](../ENTERPRISE_PRICING_GUIDE.md) · [Commercial Readiness](../COMMERCIAL_READINESS.md)
