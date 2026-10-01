# Downgrade Memo (pre-drafted, not sent)

`[COUNSEL-REVIEW-REQUIRED]` before sending, especially section 5. Send only if a trigger has fired: Gate 2 unmet at month 8 (KC-4), the CAC model dead (KC-1), the LTV model dead (KC-2), the ACV path dead (KC-3), a pen-test critical unfixed after 30 days (KC-5), or no senior hire by month 5 (KC-6). `tools/validation/kill_switch.py` writes its own factual `REPLAN_MEMO_<id>.md` when one fires, and the owner's `"SI"` in `KILL_ACK.json` is what lets work continue. This file is the letter to SAFE holders that goes with it.

Fill every `[FACT]` from recorded data. Delete this paragraph and the banner when complete.

---

**To:** `[SAFE holders]` **From:** `[founder]` **Date:** `[FACT]`
**Subject:** `[FACT: trigger id and name]` has fired. Plan downgraded.

## 1. What happened

`[FACT: the criterion, the threshold as written in the plan, the recorded number, the date. Copy the "Fact" line of REPLAN_MEMO_<id>.md.]` This was a stated condition of the round, not a surprise.

## 2. What changes

| Item | Before | After | Tag |
|---|---|---|---|
| Tranche T2 ($250,000, cap $8M) | released at Gate 2 | **not released** if KC-4 fired | M |
| Tranche T3 ($200,000, cap $10M) | released at Gate 3 | not available; cap reverts to $8M if KC-6 fired | M |
| Released capital | $300,000 | $300,000 | V once received |
| Runway on T1 alone | n/a | about 10 months at zero clients, 11 at one, 15 at three | M |
| Model base case (FY5 ARR $1.20M, H) | base | `[FACT: unchanged / bear becomes base if KC-3 fired]` | H |
| Hiring | `[FACT]` | freeze from 80% of released capital ($240,000 at T1 only) | M |

## 3. Where the money stands

Received `[FACT]`, spent `[FACT]`, remaining `[FACT]`, share spent `[FACT]` (from `RAISE_LEDGER.csv`). Alert levels for T1 only: 50% is $150,000, 80% is $240,000, 95% is $285,000.

## 4. Options, and what each costs

| Option | What it means | Model value |
|---|---|---|
| A. Continue on T1 with a hiring freeze | Founder-only operation, no second maintainer, bus-factor haircut stays | Haircut value today $6.16M, M |
| B. Re-plan the channel or the price | Only if KC-1 or KC-3 fired; new outbound batch before spending more | H |
| C. Wind down | Sell assets, return the remainder | Asset-sale floor $0.65M to $3.1M, M·A |

Founder recommendation: `[OWNER TO WRITE]`. The agent recommends none; the choice is the founder's and the investors'.

## 5. Wind-down mechanics (counsel must confirm before this is sent)

The investor pack says that at 95% spent the plan is to release the escrow deposit to design partners, run an asset sale and return the remainder pro rata. Three points are open: the escrow agreement (not signed) must define a wind-down release event; the SAFE's own dissolution priority governs distributions; and, with zero revenue, there may be no design partners. Do not repeat the pack's sentence unless counsel has confirmed each point (R-3 in [SAFE_SHEET.md](SAFE_SHEET.md)).

## 6. What we are not saying

No claim of revenue, customers, certification, audit, penetration testing or court admissibility. The repository baseline is `v5.0.2`; assurance states are in `docs/assurance/ASSURANCE_STATUS.md`.

`[Signature block: founder. Not signed by the agent.]`
