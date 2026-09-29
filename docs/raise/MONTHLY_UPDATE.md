# Monthly Investor Update

The update is generated from recorded facts and finished by the founder. The agent does not send it.

```bash
python tools/raise/monthly_update.py --month 2026-11 --out /tmp/update_2026-11.md
```

## What the generator does

- Puts late gates and triggered kill criteria **first**, before any good news.
- Prints gate status per tranche with each condition and its reference (from `EVIDENCE.json`, `PILOTS.csv`, `PLAN.json`).
- Prints the validation funnel counts from the log: first touches, replies, calls, pilot proposals, pilots, contracts. Empty input prints zero.
- Prints all six kill criteria with status and detail.
- Computes cash received, spent, remaining and share of released capital spent from `RAISE_LEDGER.csv`, and states an alert at 50%, 80% and 95% (D5). It computes no runway; runway is a model output and is quoted from the pack only when labelled M.
- Prints every assurance item's state from `ASSURANCE_STATUS.json`.
- Leaves three sections as `[OWNER TO WRITE]`: asks, what changed, what did not work.

## Ledger format

`RAISE_LEDGER.csv` columns: `date,kind,amount_usd,note`, where `kind` is `tranche_received` or `spend`. The founder writes each row from the bank statement. The generator refuses no row, so a mistaken entry is a false update: reconcile against the bank before sending.

## Rules for the founder's narrative

1. Report every trigger and every late gate in the first paragraph.
2. Tag every figure V, M or H. A hypothesis stays a hypothesis until a signed document or a measurement backs it.
3. Do not restate assurance as more advanced than the table shows.
4. Ask for something specific (an introduction to a named kind of buyer, a reviewer for a legal draft), or say there is no ask.
5. Send it from the founder's account. Keep the sent copy and the generator output for the room.
