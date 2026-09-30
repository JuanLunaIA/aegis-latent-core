# Raise Execution (Mission Order XVI, Phase 6)

**Status: prepared, nothing sent, nothing signed, nothing filed.** These are drafts and tools for the founder. Every document carrying legal effect is marked `[COUNSEL-REVIEW-REQUIRED]` and contains no signature, no investor name and no date of signing. Securities law applies to this raise in every jurisdiction of the founder and of each investor; the agent has not reviewed any of it (see questions R-1 to R-6 in [SAFE_SHEET.md](SAFE_SHEET.md)).

Tags: **V** read back or computed from a recorded fact, **M** model assumption (investor engine, seed 42), **H** hypothesis. The amounts and caps below are **M**; they are copied from `investor_packs/aegis_investor_pack_en/data/model_outputs.json` and a test fails if they drift.

| Deliverable | File | What the founder does with it |
|---|---|---|
| Data-room index and hash manifest | [DATA_ROOM_INDEX.md](DATA_ROOM_INDEX.md), `tools/raise/data_room_manifest.py` | Load the listed files; run the tool at the commit shown to investors |
| SAFE sheet | [SAFE_SHEET.md](SAFE_SHEET.md) | Give to counsel with the YC form; no SAFE text is reproduced here |
| Tranche evidence packs | [TRANCHE_EVIDENCE_PACKS.md](TRANCHE_EVIDENCE_PACKS.md), `tools/raise/tranche_gate.py` | Fill `EVIDENCE.json` only with real dated references |
| Monthly update | [MONTHLY_UPDATE.md](MONTHLY_UPDATE.md), `tools/raise/monthly_update.py` | Generate the draft, write the narrative, send it yourself |
| Downgrade memo | [DOWNGRADE_MEMO_DRAFT.md](DOWNGRADE_MEMO_DRAFT.md) | Complete and send only if Gate 2 or another trigger fires |

Owner-written inputs, blank in the repository: `EVIDENCE.json` and `RAISE_LEDGER.csv` here, and `PILOTS.csv`, `CONTRACTS.csv`, `PLAN.json` in `docs/commercial/validation/`. The agent never fills them.

## Findings from preparing the round

1. **T1 "at signing" needs an issuer.** A SAFE is issued by a company. The pack schedules the Delaware entity in months 1 to 8 and the register targets 2027-01-31 (`REG-H09`). Until the entity exists there is nothing to sign. The gate tool therefore carries an extra T1 condition, `entity_formed`, marked as added by the agent.
2. **Tranche conditions are not standard SAFE mechanics.** A plain post-money SAFE funds once. Releasing $250k and $200k later against conditions needs either three separate SAFEs or a side letter with a funding schedule, and each later tranche depends on an investor obligation that a SAFE does not create. The pack already admits the risk: "a later tranche can fail to arrive even when its gate is met". The answer to R-2 decides whether the gates are enforceable at all.
3. **The wind-down clause promises things the current drafts do not support.** The pack says at 95% spent: release the escrow deposit to design partners, sell assets, return the remainder pro rata. The escrow term sheet defines release events for licensees, not for a wind-down, and SAFE holders rank by the instrument's own priority on a dissolution event. Both need counsel before the clause is repeated to an investor.
4. **The investor pack was refreshed on 2026-09-30.** Three verified inputs (tests, claims, test-to-source ratio) and the evidence text of seven TRL rows were updated, wording on the wind-down and on the T1 issuer was corrected, and section U (EN) / A (ES) lists every change. No TRL or model number moved. Signatures and provenance were not re-verified in that update, and counsel has not reviewed the pack.
5. **Nothing here changes a TRL, a claim or an assurance state.** [ASSURANCE_STATUS.md](../assurance/ASSURANCE_STATUS.md) still shows no item complete.

## Commands

```bash
python tools/raise/tranche_gate.py                       # gate status, exit 3 if a deadline passed unmet
python tools/raise/monthly_update.py --month 2026-11     # draft update to stdout
python tools/raise/data_room_manifest.py --out /tmp/room.md
```
