<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Validation Engine

**Audience:** the founder running the first outbound batch, the buyer interviews and the first pilot.
**Scope:** a 60-row log, the first 30 outbound touches, an interview script, a pilot generator and a kill switch that turns the D10.3 criteria into a check you can run. Prepared 2026-09-29 (Mission XVI, Phase 3).
**Boundary:** a measuring instrument. It contains no prospect, no reply, no call, no pilot and no result, and it proves nothing about demand. Every threshold below is a hypothesis taken from D10.2 and D10.3 of the investor pack and keeps its tag.

## What is here

| Asset | Path | Reproduce |
| --- | --- | --- |
| Validation log, 60 rows, blank | [`VALIDATION_LOG.csv`](VALIDATION_LOG.csv) | `python tools/validation/make_log.py --out docs/commercial/validation` |
| Pilot and contract ledgers, blank | [`PILOTS.csv`](PILOTS.csv), [`CONTRACTS.csv`](CONTRACTS.csv) | same command |
| Plan dates, blank | [`PLAN.json`](PLAN.json) | owner fills |
| Outbound batch 1 | [`OUTBOUND_BATCH_1.md`](OUTBOUND_BATCH_1.md) | `python scripts/lint_sales_copy.py docs/commercial/validation` |
| Interview script and note | [`INTERVIEW_SCRIPT.md`](INTERVIEW_SCRIPT.md) | none |
| Brevo plan | [`BREVO_PLAN.md`](BREVO_PLAN.md) | `python scripts/lint_sales_copy.py docs/commercial/validation` |
| Pilot generator | [`tools/validation/pilot_generator.py`](../../../tools/validation/pilot_generator.py) | `python tools/validation/pilot_generator.py facts.json --out pilot.md` |
| Kill switch | [`tools/validation/kill_switch.py`](../../../tools/validation/kill_switch.py) | `python tools/validation/kill_switch.py --data docs/commercial/validation` |
| Kill thresholds | [`tools/validation/kill_criteria.json`](../../../tools/validation/kill_criteria.json) | read it |

## Who does what

| Owner | Agent |
| --- | --- |
| Chooses the 30 organisations and writes them into the log | Built the log, the copy plan and the tools |
| Sends every message, one at a time | Sends nothing and holds no contact data |
| Attends the interviews and writes the notes | Wrote the script and the note template |
| Signs any pilot with a customer | Generates a draft for counsel; signs nothing |
| Answers `SI` when a kill criterion fires | Reports the trigger and writes the re-plan memo |

## The kill switch

The six criteria are those of D10.3. Each is `PENDING`, `OK` or `TRIGGERED`, from the recorded facts and the date.

| Id | Fires when | Thresholds (tag) |
| --- | --- | --- |
| `KC-1` | 30 first touches sent and fewer than 2 calls in 30 days of send number 30 | 30, 2, 30 days (`H`) |
| `KC-2` | More than 50% of concluded pilots did not convert or churned | 50% (`H`); a minimum of 3 concluded pilots is an agent choice, not in D10.3 |
| `KC-3` | The first 3 annual contracts are each below $15k | 3, $15k (`H`) |
| `KC-4` | Gate 2 unmet at month 8 of the plan | 8 (`M`) |
| `KC-5` | A pen-test critical in the evidence path is unfixed 30 days after it is found | 30 days (`M`) |
| `KC-6` | No senior hire started by month 5; the T3 cap reverts to $8M | 5, $8M (`M`) |

`KC-4` and `KC-6` stay `PENDING` until `PLAN.json` holds a plan start date, which the owner sets when the raise closes.

**When one fires** the tool exits with code 3, writes `REPLAN_MEMO_<id>.md` beside the data, and reports `HALT`. The plan continues on that criterion only when the owner records the answer `"SI"` with a date in `KILL_ACK.json`:

```json
{"KC-1": {"answer": "SI", "date": "2027-01-15"}}
```

The agent never creates that file. A trigger with `SI` still prints as `TRIGGERED`, so the history stays visible.

## Generating a pilot draft

Put the facts in a JSON file (customer, sponsor, workload, environments, `deployment_shape`, `duration_weeks`, `fee_usd`, `start`, `end`). The generator refuses more than one workload, a duration outside 4 to 8 weeks, an end date that does not match the duration, and a negative fee. The output keeps the counsel-review banner, marks the fee `[HYPOTHESIS-UNVALIDATED]` and leaves the signature rows as placeholders.

## Tag census for this phase

Every number here is copied from D10.2 or D10.3 with its tag: `H` thresholds for `KC-1` to `KC-3` (9 values), `M` for `KC-4` to `KC-6` (5 values), and one agent choice named as such. The log itself holds no measured value.

## What this phase does not do

It does not find prospects, send anything, book a call or claim demand. The result of the first batch is unknown until the owner sends it.
