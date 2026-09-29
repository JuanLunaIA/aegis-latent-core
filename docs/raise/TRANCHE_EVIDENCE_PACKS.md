# Tranche Evidence Packs

`[COUNSEL-REVIEW-REQUIRED]` for the wording shown to an investor. Each pack lists what an investor checks before a tranche releases, where the evidence must come from, and what exists today. Conditions are copied from the investor pack and encoded in `tools/raise/terms.json`; `tools/raise/tranche_gate.py` reports them.

A condition is met only when `EVIDENCE.json` holds a real date and a reference to where the signed document is kept. A paid pilot counts only when `PILOTS.csv` shows a fee at or above $2,500 (H) with a start date **and** `EVIDENCE.json` holds a countersigned order for that pilot id. The agent never edits these files.

## T1: $300,000, cap $6,000,000 (M), at signing

| Condition | Evidence to attach | Held by | Today |
|---|---|---|---|
| T1-a SAFE countersigned | Executed SAFE (and side letter if counsel drafts one) | Founder | none |
| T1-b Issuing entity exists (agent-added) | Certificate of incorporation, IP assignment executed | Founder, counsel | drafts only (`docs/legal/IP_ASSIGNMENT_DRAFT.md`) |

Investor checks: who signs for the company, that the founder's code is assigned to it, that no earlier SAFE exists (cap table). Supporting room files: [DATA_ROOM_INDEX.md](DATA_ROOM_INDEX.md).

## T2: $250,000, cap $8,000,000 (M), Gate 2 by month 8

| Condition | Evidence to attach | Held by | Today |
|---|---|---|---|
| T2-a Paid pilot #1 | Countersigned pilot order; row in `PILOTS.csv` with fee at or above $2,500 (H); pilot agreement built from `docs/legal/PILOT_AGREEMENT_TEMPLATE.md` after counsel review | Founder | 0 pilots, 0 interviews |
| T2-b Pen-test SOW signed | SOW signed by both parties, built from `docs/assurance/PENTEST_SOW_DRAFT.md` | Founder | draft only, firm not chosen |

Also shown with this pack: validation log (funnel counts), kill-criteria output (`tools/validation/kill_switch.py`), tranche-budget status, and the two-page verify-it-yourself transcript (`tools/sales/prove_it/`). If KC-1 has triggered (fewer than 2 pilot calls from 30 messages in 30 days), the CAC model is dead and the channel is re-planned **before** T2 is spent.

## T3: $200,000, cap $10,000,000 (M), Gate 3 by month 14

| Condition | Evidence to attach | Held by | Today |
|---|---|---|---|
| T3-a Two paid design partners | Two countersigned order forms, distinct customers | Founder | none |
| T3-b Criticals remediated | Final pen-test report plus retest letter from the firm | Founder, firm | no test contracted |
| T3-c SOC 2 Type I auditor engaged | Engagement letter | Founder | readiness plan only; a single maintainer blocks CC8 and CC1 (see `docs/assurance/SOC2_READINESS.md`) |

Investor checks: the report is the firm's, not a summary; findings counts by severity; that none of the three "critical in the evidence path" cases in KC-5 (a response released without a durable commit, a forgeable receipt, a cross-tenant read) is open. If the senior hire has not started by month 5 (KC-6) the T3 cap reverts to $8M (M).

## Gate status commands

```bash
python tools/raise/tranche_gate.py --today 2027-05-31
python tools/raise/tranche_gate.py --json > gates.json
```

## What no pack may say

No pack may say the product is certified, audited, penetration-tested, SOC 2 compliant, production-ready or admissible in court unless the corresponding assurance item is `COMPLETE` with a cited artifact. Today none is.
