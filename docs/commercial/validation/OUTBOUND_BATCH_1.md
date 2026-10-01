<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
-->

# Outbound Batch 1: 30 First Touches

**Audience:** the founder, who sends every message personally.
**Scope:** the segment plan, the opening line per segment, the send rules and the tracking for the first 30 outbound messages. The three-touch wording is in [Outbound Sequences](../SALES_KIT/OUTBOUND_SEQUENCES.md) and is not repeated here.
**Boundary:** prepared, not sent. The agent that wrote this sent nothing, holds no contact list and chose no company. Organisations, names and addresses are the owner's to enter. Every statement in a message must hold at send time (`COMMERCIAL.md`, financial-claim discipline).

## What "batch 1" is

Thirty first touches, sent by the owner, each followed by up to two more touches under the sequence rules. The count matters because it starts a clock: `KC-1` in [kill criteria](../../../tools/validation/kill_criteria.json) asks whether 30 messages yield at least 2 pilot calls in 30 days. Those thresholds are hypotheses (`H`) taken from D10.3 of the investor pack, not measured results.

| Segment | Slots | Log rows |
| --- | --- | --- |
| Fintech: LLM in credit, fraud or advice | 10 | `V-01` to `V-10` |
| Healthtech: LLM in triage, summarisation or coding | 8 | `V-11` to `V-18` |
| Insurance: LLM in claims | 7 | `V-19` to `V-25` |
| Recently had an AI decision challenged | 5 | `V-26` to `V-30` |

Rows `V-31` to `V-60` are reserved for batch 2. Nothing in them is used until batch 1's window has been read.

## Choosing the 30

Qualify on the obligation, not the interest: a company that has put a language model somewhere consequential and owes someone a record of it. The good and poor fits are in [Outbound Sequences](../SALES_KIT/OUTBOUND_SEQUENCES.md) under "Who to target". Pick organisations from public sources you can cite, address the person whose role owns the record (CISO, VP Engineering, Head of Compliance), and write the organisation and role into the log **before** sending.

## Opening line per segment

Replace the first sentence of touch 1 with the line for the segment. Each is conditional, because the sender does not know the prospect's systems.

| Segment | Opening line |
| --- | --- |
| Fintech | "If a model helps decide a credit, fraud or advice outcome at `[company]`, the record of what it was asked and said usually sits in a database your team can write to." |
| Healthtech | "If a model summarises or triages clinical or coding work at `[company]`, an auditor's question about one case comes back to logs your team can edit." |
| Insurance | "When a claim decision that a model touched is disputed, the argument turns on whether `[company]`'s record of it can be trusted." |
| Recently challenged | "I saw `[public reference]`. When an AI decision is challenged, the question that follows is whether the record is one the interested party could have changed." |

The last line may name a public event only if it is a real, cited one. If none exists, do not use the segment.

## Send rules

1. **The owner sends every message**, one at a time, from the owner's own address. The agent does not send, schedule or automate any message.
2. **Three touches, then stop.** Days 0, 4 and 11 from the first touch. A reply or an opt-out stops the sequence at once.
3. **One verifiable link per message**, and only to a page that exists: [Prove It Yourself](../../PROVE_IT.md), the [Unsupported Claims](../../institutional/UNSUPPORTED_CLAIMS.md) register (70 rows at 2026-09-29), or the [six questions](../POSITIONING.md).
4. **No customer, logo, reference, certification, ROI figure, competitor claim, price or deadline.** None of these is supported here.
5. **Honour any opt-out immediately** and note it in the log outcome.
6. **Check the law before the first send.** Rules on cold business email differ by country and by recipient type. This batch has not been reviewed for them; put the question to counsel (see [Questions for Counsel](../../legal/COUNSEL_QUESTIONS.md)) before sending.
7. Copy passes `python scripts/lint_sales_copy.py docs/commercial/validation`.

## Tracking

For each row fill, in this order: `organisation`, `role`, `lead_source` (one of `oss`, `partner`, `event`, `direct`; the model's channel CACs are hypotheses tagged by source, D10.2), then `touch1_sent`, `touch2_sent`, `touch3_sent`, `replied`, `call_date`, `cites_examiner_request`, and `outcome`. Record `founder_hours` and `expenses_usd` per row; without them the CAC hypothesis cannot be tested.

Run the kill switch after each entry:

```bash
python tools/validation/kill_switch.py --data docs/commercial/validation
```

## What a result means

Two calls in 30 days from send number 30 keeps the channel alive. Fewer than two ends this batch's channel model, and the plan halts for a re-plan memo until the owner answers `SI` (see [README](README.md)). Neither outcome is a statement about the product; both are statements about this channel, this list and this copy.
