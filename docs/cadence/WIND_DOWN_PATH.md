# Wind-Down Path

`[COUNSEL-REVIEW-REQUIRED]` This is an operating checklist, not legal advice and not a decision. It says what happens in what order if the plan stops. The founder decides, with counsel, whether any step applies; nothing here is triggered by an agent. Figures are M (investor model) and use T1 only, since the wind-down starts before later tranches release.

## When it starts

Any of: Gate 2 unmet at month 8 (KC-4); 95% of released capital spent (BA-95, $285,000 of T1, M); or the founder, after a TRIGGERED row and an owner answer of `"SI"`, chooses to stop. The register [KILL_SWITCH_REGISTER.md](KILL_SWITCH_REGISTER.md) shows which fired. Send [../raise/DOWNGRADE_MEMO_DRAFT.md](../raise/DOWNGRADE_MEMO_DRAFT.md) first: investors hear it from the founder before anything is sold.

## Order of steps

| # | Step | Depends on | Who |
|---|---|---|---|
| 1 | Freeze new commitments: hiring, contracts, spend not already owed. Record the date in the ledger note. | Trigger acknowledged | Founder |
| 2 | Take stock of obligations: open pilot agreements, support promises, licences issued, escrow deposits, vendor contracts, payroll or contractor terms. | 1 | Founder, counsel |
| 3 | Tell each pilot and licence customer in writing, with the transition they can rely on. Offline licence tokens carry an expiry and cannot be revoked, so say what continues to work and until when. | 2 | Founder, counsel |
| 4 | Preserve the evidence base: tag the final commit, run `tools/assurance/escrow_manifest.py build`, run `tools/raise/data_room_manifest.py`, keep the signed records in `EVIDENCE.json`. | 1 | Founder |
| 5 | Decide the source's future: the repository stays under AGPLv3 regardless; whether to keep maintaining it, hand it to a community maintainer, or archive it. Published packages (PyPI, npm, GHCR) stay published; withdrawing releases needs its own decision. | 2 | Founder |
| 6 | Prepare a sale of the asset only if counsel confirms who can sell what (AI-assisted authorship, assignment status, licence model). The model's asset-sale floor is $0.65M to $3.1M (M·A, an audit-supplied range); no buyer exists. | 2, R-3 | Founder, counsel |
| 7 | Return remaining capital to SAFE holders as the instruments and law require. The pack's "pro rata" wording is not confirmed. | 6, counsel | Counsel |
| 8 | Close the entity, accounts, domains, cloud subscriptions and keys. Destroy or transfer signing keys per the key custody notes; the licence-signing private key is never deposited. | 7 | Founder, counsel |

## What must not be said

No wording may imply a customer commitment survives when it does not, that escrow guarantees continuity, that evidence produced by the product is court-admissible, or that any assurance item was completed. `docs/assurance/ASSURANCE_STATUS.md` still shows none complete.

## Open questions this path depends on

- R-3 and R-2 in [../raise/SAFE_SHEET.md](../raise/SAFE_SHEET.md): dissolution priority, pro rata return and escrow release on wind-down.
- Whether pilot agreements from `docs/legal/PILOT_AGREEMENT_TEMPLATE.md` need a termination-for-wind-down clause.
- Which customer data, if any, is held (self-hosted deployments avoid this until support needs access).
