# Operating Cadence (Mission Order XVI, Phase 7)

**Status: prepared, nothing sent, nothing signed, nothing filed.** The cadence turns the facts the founder records into a weekly report, a monthly recompute and a register of stop conditions. It estimates nothing: an empty input prints as zero or "not recorded". `[COUNSEL-REVIEW-REQUIRED]` applies to [WIND_DOWN_PATH.md](WIND_DOWN_PATH.md), which touches contracts, securities and entity law.

| Rhythm | Command | Output | Owner then |
|---|---|---|---|
| Weekly, Monday | `python tools/cadence/cadence.py weekly --out-dir docs/cadence/weekly` | `weekly/WEEKLY_<iso-week>.md` | Read section 1 first; write the owner note |
| Monthly, first business day | `python tools/cadence/cadence.py monthly` | Printed report; exit 3 if the model no longer reproduces | Refresh stale inputs at the source; send the investor update ([../raise/MONTHLY_UPDATE.md](../raise/MONTHLY_UPDATE.md)) |
| On any change | `python tools/cadence/cadence.py register --out docs/cadence/KILL_SWITCH_REGISTER.md` | The register | Answer any TRIGGERED row in `KILL_ACK.json` |

The engine for `monthly` needs numpy 2.4.6 and matplotlib 3.11.2 (`investor_packs/aegis_investor_pack_en/engine/requirements.txt`); pass a Python that has them with `--engine-python`. Without them the report says `NOT_EXECUTED`, never a pass.

## What each report reads

- **Weekly:** `VALIDATION_LOG.csv` (touches, replies, calls and proposals dated inside the week), `PILOTS.csv`, `CONTRACTS.csv`, `PLAN.json`, the kill criteria, the tranche gates and `ASSURANCE_STATUS.json`. Section 1 lists triggered criteria and late gates before anything else. Section 4 lists owner actions derived by fixed rules from the state, so the same state gives the same list.
- **Monthly:** re-runs the investor engine (seed 42) and compares `model_outputs.json` and `model_tables.md` byte for byte with the committed pack; lists the input census (V, M, H); checks the one verified input it can re-measure offline (`claims_registered`); and compares recorded spend with the model's monthly operating cost once `plan_start_date` and ledger rows exist. Test counts, benchmarks and cloud prices are named as not re-measured.
- **Register:** the six kill criteria (KC-1 to KC-6), the 50, 80 and 95 percent budget alerts, and the T2 and T3 gate deadlines, each with status, the owner's answer and the recorded consequence. [KILL_SWITCH_REGISTER.md](KILL_SWITCH_REGISTER.md) is the blank-state rendering.

## Rules

1. The agent never writes `KILL_ACK.json`, `EVIDENCE.json`, `PLAN.json`, the ledger or any CSV the owner keeps.
2. A TRIGGERED row halts the plan. Work that depends on it resumes only after the owner records `"SI"` with a date.
3. Committed weekly files are generated output. The first one, `WEEKLY_2026-W40.md`, is the blank-state baseline; from then on the owner decides which weekly reports to keep in the repository. Recorded prospects, dates and results stay out of git unless the owner chooses otherwise.
4. A stale verified input is fixed at its source (rerun the check, change the pack), not by editing the report.

## First monthly finding

The 2026-09-29 run reproduced both model files byte for byte and found one stale verified input: the pack recorded 112 registered claims while `scripts/verify_claims.py` reported 113 (`CLM-113`, added in Phase 0). The pack was refreshed on 2026-09-30 (claims 113, tests 7,673, test-to-source ratio 1.26, plus new qualification evidence in seven TRL rows) and a second monthly run reproduces both files again.
