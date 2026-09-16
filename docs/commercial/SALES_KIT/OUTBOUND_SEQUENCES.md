<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Outbound Sequences

**Audience:** the founder, doing outbound.
**Scope:** a three-touch sequence for CISO / VP Engineering / Head of Compliance at mid-market fintech and healthtech, plus the rules that keep it honest.
**Boundary:** these are templates. Every factual statement in them must hold at send time — a stale version number or an invented customer in a cold email is the same defect [Claim Ledger](../CLAIM_LEDGER.md) exists to catch, delivered straight to a prospect's inbox.

---

## Rules

1. **Lead with their problem, never with our feature list.** The first sentence is about them or the email is deleted.
2. **One verifiable thing per email.** A link they can check beats a paragraph they must believe.
3. **Never imply customers, funding, traction or certification.** There are none (`UC-028`, `UC-033`, `CR-05`).
4. **Never use a number that is not in the corpus.** No "reduces audit prep by 40%". No avoided-fine arithmetic. `COMMERCIAL.md` §Financial-claim discipline forbids it and a CISO will ask for the source.
5. **≤120 words.** Longer reads as a brochure.
6. **Three touches, then stop.** A fourth is noise, and this is a market where reputation compounds.
7. **No fake scarcity, no fake deadline, no fake referral.**

---

## Who to target

**Qualify on the obligation, not the interest** (`CR-05`). The signal is a company that has already put a language model somewhere consequential *and* owes someone a record of it.

| Good fit | Why |
|---|---|
| Mid-market fintech with LLM in credit, fraud or advice | Record-keeping obligations already exist and are already examined |
| Healthtech with LLM in triage, summarisation or coding | Audit-control requirements, and a clinical-decision record that gets questioned |
| Insurance with LLM in claims | Disputes are routine, and the record is the argument |
| Anyone who has **recently had an AI decision challenged** | The only genuinely warm cold prospect |

| Poor fit | Why |
|---|---|
| Pre-product-market-fit startups | No obligation, no budget, no deadline |
| Anyone whose gate is a SOC 2 report | We fail it today (`CR-02`) |
| Anyone wanting a managed service | There is none, and none is planned |

---

## Touch 1 — Day 0

**Subject options:**
- `Can you prove what your AI said six months ago?`
- `Your AI logs are in a database your DBAs can edit`
- `The AI record question your auditor will ask`

> Hi `[Name]`,
>
> When someone asks what your AI told a customer on a specific case six months ago, the answer comes out of a database your team can write to.
>
> That is fine until it is challenged. Then the argument stops being *what happened* and becomes *whether your records can be trusted* — and you are having it under time pressure.
>
> We built a gateway that commits a signed, hash-linked record **before** the response reaches your application, and issues a proof a third party verifies without trusting us or you.
>
> Twelve lines of Python, no call to our servers: `[link to PROVE_IT.md]`
>
> Worth fifteen minutes?
>
> `[Name]`

*(108 words)*

## Touch 2 — Day 4

Send only if Touch 1 was unanswered. Lead with the disqualifiers — it is unexpected, it is honest, and it filters hard.

**Subject:** `Re: Can you prove what your AI said` · or · `Four reasons not to talk to us`

> `[Name]` — following up, and leading with what usually ends these conversations:
>
> No SOC 2. No penetration test. Neither in progress. One maintainer. No SLA outside a signed agreement. Self-hosted only — no managed service.
>
> If any of that is a hard gate, delete this and I will not follow up again.
>
> If it is not: we publish 42 things we explicitly refuse to claim, with reasons. `[link to UNSUPPORTED_CLAIMS.md]`
>
> I have not found another vendor in this category who publishes one. Ask the ones you are already talking to for theirs.
>
> `[Name]`

*(103 words)*

## Touch 3 — Day 11

Last touch. Give something useful whether or not they reply, and close the loop explicitly.

**Subject:** `Six questions for your AI gateway vendors`

> `[Name]` — last note from me.
>
> Whether or not we ever talk, these are worth putting to any vendor in this space:
>
> 1. Is the record durable *before* the response reaches my app, or after?
> 2. Can a third party verify one record without trusting you **or** me?
> 3. Who holds the evidence and the keys?
> 4. What happens to traffic when the evidence store fails?
> 5. Can I read the source that produces the evidence?
> 6. Where is your published list of what you do *not* claim?
>
> Our answers, with locators: `[link to POSITIONING.md §4.1]`
>
> Good luck either way.
>
> `[Name]`

*(114 words)*

---

## After a reply

**Interested** → [Discovery Call Script](DISCOVERY_CALL_SCRIPT.md). Read the disqualifiers aloud in the first five minutes.

**"Send me information"** → [One Pager](ONE_PAGER.md) and [Prove It Yourself](../../PROVE_IT.md). Not a deck.

**An objection** → [Objection Handling](OBJECTION_HANDLING.md). Current truth, concrete step, timeline. In that order.

**"Not now"** → Ask what would change it, note the date, and stop. A "not now" from a qualified buyer is worth more than a "maybe" from an unqualified one.

**No reply after three** → Stop. Revisit in two quarters, or when `CR-01` or `CR-02` completes and the honest email is different.

---

## What this sequence deliberately omits

- Any customer, logo or reference. **There are none** (`CR-05`).
- Any ROI or cost-saving figure. Not evidenced (`COMMERCIAL.md` §Financial-claim discipline).
- Any competitor claim. We do not have evidence about their systems ([Positioning](../POSITIONING.md) §4).
- Any urgency device. The buyer's deadline is real or it is not; manufacturing one insults the audience most likely to notice.
- Any price. Pricing is `[HYPOTHESIS-UNVALIDATED]` and belongs in a conversation, not a cold email.

---

**Related:** [Discovery Call Script](DISCOVERY_CALL_SCRIPT.md) · [Objection Handling](OBJECTION_HANDLING.md) · [One Pager](ONE_PAGER.md) · [Positioning](../POSITIONING.md) · [Prove It Yourself](../../PROVE_IT.md) · [Unsupported Claims](../../institutional/UNSUPPORTED_CLAIMS.md)
