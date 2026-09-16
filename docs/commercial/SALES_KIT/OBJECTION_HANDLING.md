<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Objection Handling

**Audience:** whoever is in the room when the hard question arrives.
**Scope:** the eight objections that actually come up, each answered with the current truth, the concrete step, and a timeline where one exists.
**Boundary:** every answer states the position as of 2026-09-16. Where an item is `NOT STARTED` it says so, because [Commercial Readiness](../COMMERCIAL_READINESS.md) records it that way and a buyer will check.

---

## The rule

**Current truth → concrete step → timeline. In that order, every time.**

Never lead with the mitigation. A buyer who hears the plan before the problem concludes you were hoping they would not ask, and from that moment reads everything else as spin. A buyer who hears the problem stated plainly, with no hedging, extends credit to the rest of the conversation.

This matters more here than in most categories. **The product is evidence integrity.** An organisation that shades its own claims has demonstrated the exact failure mode the product exists to prevent, and a CISO will say so — if not to you, then internally, where you cannot answer it.

---

## 1. "You're one person. What happens when you're hit by a bus?"

**The truth:** Bus factor is one. There is no on-call rotation, no second reviewer on the critical path, and no organisational continuity commitment. Every audit of this project has raised it as `CRITICAL`.

**What actually mitigates it, today:**

- **The source is AGPLv3 and complete.** You already have the code, the right to run it, modify it and fork it. No trigger event, no agent, no release condition. That is a stronger position than most proprietary escrow arrangements deliver, and you can verify it in ten seconds.
- **The build is reproducible from the tree** — pinned Actions, hash-locked `requirements.lock`, committed `Cargo.lock`, SBOM generation.
- **Pin and vendor.** Pin an exact commit and container digest and keep a verified copy.

**What does not mitigate it, and I will not pretend otherwise:** having the source is not having a maintainer. Nothing above produces someone who can triage a security issue at 2 a.m.

**The concrete step:** escrow is `CR-03`, **`NOT STARTED`** — policy drafted (`SOFTWARE_ESCROW_POLICY.md`), no agent engaged, no deposit made, 2–4 weeks to execute once a buyer needs it. A second maintainer is `CR-06`, `NOT STARTED`, 2–4 months, and its acceptance test is real: the second engineer ships a security fix end to end without me in the loop. Anything less is bus factor one with extra headcount.

**If continuity is genuinely critical to you,** the honest recommendation is to contract a third-party engineering firm capable of maintaining the code, or build that capability internally. AGPLv3 already permits it. I would rather you do that than buy on the strength of an escrow agreement that would not save you.

## 2. "No SOC 2. No penetration test."

**The truth:** Correct. No SOC 2 Type I or II. No ISO 27001. No third-party security audit. No penetration test. **None of them is in progress.** If your procurement gate requires a report, we fail it today.

**The concrete step:** `CR-01` penetration test, 4–6 weeks, ~$15–25k. `CR-02` SOC 2 Type I, 3–6 months. Both `NOT STARTED` and both waiting on the same thing — a design partner who makes the spend rational.

**What exists in the meantime**, and it is not nothing:

- Complete source, readable and forkable — your own reviewers can do what an auditor would.
- A claims register with an evidence locator and a stated boundary for every public claim (`docs/CLAIMS_MATRIX.md`).
- A 42-row register of what is explicitly **not** claimed (`UNSUPPORTED_CLAIMS.md`).
- SBOMs, signed tags, pinned dependencies, signed container images.
- A threat model that states the operator-trust boundary rather than hiding it.

**A framing worth offering:** a SOC 2 report attests that controls were designed appropriately at a point in time. It is evidence about a process. What you can have here instead is evidence about the artifact — the source, the tests, the claims register — which is a different and in some respects more direct thing. It is not a substitute, and I am not claiming it is. But if your review can absorb a technical assessment where it expected a certificate, there is more to work with here than the missing report suggests.

**If the gate is hard:** say so now and let us both stop. I will come back when `CR-02` is done.

## 3. "Why wouldn't we just build this ourselves?"

**The truth:** you could. It is not magic — a hash chain, a Merkle Mountain Range, careful commit ordering, and a redaction pass.

**What the honest comparison looks like.** The parts that take the time are not the parts that look hard:

- Getting commit-before-emission right on the **streaming** path, where the response is already flowing while the evidence is not yet durable.
- Making a failed `fsync` fail the request rather than silently leaving bytes in a file nobody was told about.
- Rollback that costs the same at 2,000 leaves as at 20 — the naive implementation deep-copies the accumulator and gets slower as your chain grows.
- A proof format stable enough that a proof issued today still verifies in three years, including across a hash-scheme change.
- Then maintaining all of it while your actual product needs you.

**What I will not do is quote you a replacement cost.** `UC-032` blocks it: no work-breakdown estimate, no loaded rates, no independent valuation exists in this repository, so any figure I gave you would be invented. Your engineering leadership can estimate it better than I can, and they should.

**The concrete step:** read `aegis/core/crypto_audit.py` and `aegis/core/mmr.py` — 3,348 lines between them. If your team reads those and says "a sprint", believe them and build it. That is a legitimate outcome and I would rather you reach it from the code than from my assertion.

**The asymmetry worth naming:** if you build it, you own it forever, including the day a hash-scheme migration threatens every proof you have ever issued. If you adopt it and I disappear, you still have the source. The AGPL makes the downside of the second path bounded in a way the first path's maintenance burden is not.

## 4. "Our legal team will not accept AGPL."

**The truth:** this is the most common hard blocker, and it is a reasonable position. AGPLv3 §13 extends copyleft to network interaction, and many corporate policies restrict it categorically.

**The honest current state, and this is the part that must not be soft-pedalled:** a commercial licence is the intended resolution — it supersedes AGPLv3 for a covered deployment so the network obligations do not attach. **The licence text has not been drafted.** `CR-04` is `NOT STARTED`. If you asked me today to send the agreement, there is nothing to send.

**The concrete step:** `CR-04`, counsel-drafted commercial licence template, 2–4 weeks, ~$3–5k. It is gated on a buyer who wants it — drafting a licence nobody has asked for is not a good use of the money. **If you are that buyer, say so and it moves to the front.**

**What can be said about the AGPL question meanwhile:**

- Whether your specific deployment triggers §13 depends on whether you modify the software and convey it over a network to third parties. Many internal deployments do not. **That is your counsel's determination, not mine, and nothing here is legal advice.**
- The free tier is not crippled. Every engine is importable and fully functional; licence enforcement is off by default. A commercial subscription buys the licence grant, support and services — not access to withheld code.

## 5. "What's your SLA?"

**The truth:** there is none. Community support is best-effort with no commitment. The severity matrix in the pricing guide is marked `[FRAMEWORK-ONLY]` — a schedule proposed for negotiation. No rota is staffed, no service credits are contracted, and no production history supports any availability figure (`UC-019`).

I am not going to quote you a response time I cannot staff. A single maintainer who promises a one-hour critical response is promising something arithmetic does not permit.

**The concrete step:** response commitments become real inside an executed agreement, and an executed agreement is only honest once `CR-06` gives it a second person behind it.

**What to do instead:** plan on the assumption that support may be slow, and price that risk in. Pin your version. Build enough internal familiarity to patch. That is the correct posture toward any single-maintainer dependency, and I would give you the same advice about one I had no interest in.

## 6. "How do we know the evidence is real? You could have forged it."

**The best objection anyone asks, and the one the product is built to answer.**

**The truth:** with the default configuration, you are right to worry — and you should push harder than most buyers do.

The default chain is signed with HMAC-SHA256, which is **symmetric**. The verifier holds the same secret the signer does, so any key holder can produce any signature. That authenticates the key; it does not attribute the record to a party. The system reports this honestly: `signature_assurance` returns `SYMMETRIC_AUTHENTICATED`, two tiers below hardware-attested, and the ledger emits a warning at construction when configured this way (`UC-041`, `CLM-090`).

**What the inclusion proof does give you, regardless of signing tier:** whoever discloses a record cannot alter it and still produce a proof that verifies against a root you hold. Run it: [Prove It Yourself](../../PROVE_IT.md), three cases, two of which must fail.

**The load-bearing condition:** the root must reach you by a path the discloser does not control. A root supplied by the same gateway that produced the proof establishes internal consistency and nothing more (`CLM-044`).

**The concrete step for a buyer who needs attribution, not just integrity:** configure the asymmetric path — PKCS#11/HSM or an ML-DSA identity — where the signing key lives somewhere the operator cannot extract it. That is configuration, not a purchase, and it is in the deployment guide.

**And the boundary that stays:** tampering is detected, not prevented. An operator with filesystem access can destroy the chain. You would detect the break; you would not prevent it. Anyone selling you "immutable" over a filesystem is selling you a word.

## 7. "Can you send us your pricing?"

**The truth:** yes, and it comes with a label. Every figure in [Enterprise Pricing Guide](../ENTERPRISE_PRICING_GUIDE.md) is marked `[HYPOTHESIS-UNVALIDATED]`. They are published so a conversation can start from a number rather than from a silence. **No executed contract exists anywhere in this project**, so there is no average deal size, no ACV and no win rate — and `UC-028`/`UC-033` block me from implying otherwise.

**Why tell you that?** Because you will find out, and finding out later is worse. Also because it is useful information: you are early enough to shape the terms, which is rarely true.

**The concrete step:** a fixed-scope paid pilot with written acceptance criteria ([Pilot Proposal](PILOT_PROPOSAL.md)). Pilot pricing is negotiated against your scope, and the pilot is what turns the hypothesis into a price for everyone who comes after you.

## 8. "You have no customers."

**The truth:** correct. No customer references, no logos, no case studies, no revenue. `CR-05` is `NOT STARTED`. There are none to cite and I will not manufacture one.

**The concrete step:** design partners, 2–3 months to a first signature. The offer to an early buyer is a real one — direct access to the maintainer, influence over the roadmap, and pricing set before there are comparables to anchor against.

**What to weigh:** you would be taking a genuine risk, and the mitigation is not my assurance. It is that the source is yours under AGPLv3 regardless of what happens to me, and that every claim in the corpus has a locator you can check without asking permission. That is a smaller promise than a reference list and a more verifiable one.

---

## What never to say

| Never | Because |
|---|---|
| "SOC 2 is in progress" | `CR-02` is `NOT STARTED`. Saying otherwise is the one lie that ends the relationship |
| "We have other customers I can't name" | There are none |
| "It's effectively immutable" | Detection, not prevention. Use the real word |
| "That's on the roadmap for Q_" | `ROADMAP.md` carries no dates, deliberately. Inventing one here contradicts it |
| "Our pricing is market-validated" | `UC-028` blocks it |
| "It prevents prompt injection" | `UC-042`. Bounded detection over a finite pattern set |
| "Just for this one deal" | A claim in a deal is a claim. The answer is no — not "let me check" |

---

**Related:** [One Pager](ONE_PAGER.md) · [Discovery Call Script](DISCOVERY_CALL_SCRIPT.md) · [Pilot Proposal](PILOT_PROPOSAL.md) · [Commercial Readiness](../COMMERCIAL_READINESS.md) · [Unsupported Claims](../../institutional/UNSUPPORTED_CLAIMS.md) · [Prove It Yourself](../../PROVE_IT.md)
