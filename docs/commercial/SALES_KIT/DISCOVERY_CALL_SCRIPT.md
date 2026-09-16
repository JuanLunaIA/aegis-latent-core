<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Discovery Call Script

**Audience:** whoever runs the first conversation.
**Scope:** questions that find out whether a real requirement exists, and a rule for disqualifying fast.
**Boundary:** this is a listening script. Every capability answer it maps to carries a `CLM` locator; nothing here licenses a claim that [Claims Matrix](../../CLAIMS_MATRIX.md) does not.

---

## How to run this

Talk for less than a third of the call. The purpose is not to explain the product — it is to find out whether this prospect has a problem the product solves, and to end the call quickly if they do not.

**The disqualifying question is asked in the first five minutes, not the last.** A pilot that should never have started costs the founder months, and this project has one founder.

---

## Part 1 — Is there a record, and does anyone rely on it? (5 min)

| Ask | Listen for |
|---|---|
| "Walk me through what happens today when someone asks what your AI did on a specific case six months ago." | Whether anyone has ever actually done this. If the process is hypothetical, the pain is hypothetical |
| "Who pulls that record, and out of what system?" | Postgres, Elasticsearch, Datadog, S3 — and **who has write access to it** |
| "Has that ever been challenged — by an auditor, a regulator, a customer, opposing counsel?" | A specific incident. This is the single highest-signal answer in the call |
| "What would happen if the record for that one call was missing?" | Whether the consequence is embarrassment or liability |

**If they have never been asked and cannot imagine being asked, stop qualifying and say so.** They do not need this. Tell them what would change that, and leave the door open.

## Part 2 — Where does the requirement come from? (5 min)

| Ask | Listen for |
|---|---|
| "Is there a statutory, contractual or regulatory obligation behind the record, or is it internal policy?" | A named obligation is a budget. Internal policy is a preference |
| "Who owns that obligation inside the company?" | The economic buyer. If they cannot name one, there is no budget |
| "What does your current answer to that obligation look like in an audit?" | Whether anyone has tested it |
| "Has anyone asked whether your logs could have been edited?" | If yes, the deal is qualified. If no, ask what would happen if they did |

**The qualifying pattern is a named obligation plus a named owner.** Interest in cryptography is not a buying signal; a compliance officer with a deadline is.

## Part 3 — What actually breaks today? (5 min)

| Ask | Maps to |
|---|---|
| "When your evidence store is unavailable, does traffic keep flowing?" | Fail-closed (`CLM-002`). Most systems keep serving and lose the records. Let them notice |
| "If a record and the log disagree, which one wins, and how do you tell?" | Tamper detection on read |
| "Are your AI logs written before or after you return the response to the caller?" | Commit-before-emission (`CLM-043`). Almost nobody knows. The honest answer is usually "after, asynchronously" |
| "Could you hand a regulator a single record and have them check it without taking your word for anything?" | The wedge (`CLM-005`, `CLM-044`) |

The fourth question is the one that changes the conversation. Ask it, then stop talking.

## Part 4 — The disqualifiers, said out loud (5 min)

Read these. Do not soften them. A deal that dies here was going to die in month three of an evaluation instead, having consumed the founder's quarter.

> "Before we go further, four things that disqualify us for some buyers:
>
> **There is no SOC 2 and no penetration test, and neither is in progress.** If your procurement gate requires a report, we fail it today.
>
> **It is one maintainer.** Bus factor of one. There is no on-call rotation.
>
> **There is no SLA outside an executed agreement, and the commercial licence template is not yet drafted.**
>
> **It is self-hosted. There is no managed service and no roadmap to one** — you run it, you hold the keys, you own the operations."

Then: *"Does any of that end the conversation? I would rather know now."*

A buyer who stays after that is qualified in a way no pitch achieves. A buyer who leaves has saved you both a quarter.

## Part 5 — Close to a verification, not to a demo (5 min)

The strongest close in this category is not a demo, because a demo is a thing you control.

> "Rather than me demonstrating it, let me send you the verifier and one record. It is twelve lines of Python that make no call to us. Alter a byte and it fails. If it does what I have said, that is a better basis for the next conversation than anything I could show you on a screen."

Send [Prove It Yourself](../../PROVE_IT.md) and [Unsupported Claims](../../institutional/UNSUPPORTED_CLAIMS.md) — the second one on purpose. Handing a prospect the 42-row list of things you refuse to claim is the most credible thing available, and it costs nothing because it is already public.

## The one-line qualification test

> **A named obligation, a named owner, and someone who has already been asked a question they could not answer well.**

Two out of three is a pilot worth scoping. One out of three is a conversation to revisit in two quarters. Zero is a polite no, delivered today.

---

**Related:** [One Pager](ONE_PAGER.md) · [Objection Handling](OBJECTION_HANDLING.md) · [Pilot Proposal](PILOT_PROPOSAL.md) · [Positioning](../POSITIONING.md) · [Commercial Readiness](../COMMERCIAL_READINESS.md)
