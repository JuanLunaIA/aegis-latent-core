# SAFE Sheet

`[COUNSEL-REVIEW-REQUIRED]` This is a summary of the intended terms for counsel, not a SAFE, an offer or a solicitation. It reproduces no instrument text. Use the current published post-money SAFE form chosen by counsel and attach the side letter that counsel drafts from the conditions below. No investor is named and nothing is signed.

## Terms (all M unless marked)

| | T1 | T2 | T3 | Total |
|---|---|---|---|---|
| Amount | $300,000 | $250,000 | $200,000 | $750,000 |
| Post-money valuation cap | $6,000,000 | $8,000,000 | $10,000,000 | |
| Implied ownership if converted at the cap (amount / cap) | 5.000% | 3.125% | 2.000% | 10.125% |
| Discount | none proposed | none proposed | none proposed | |
| MFN | proposed on T1 only | none | none | |
| Release condition | issuer exists; SAFE countersigned | Gate 2 | Gate 3 | |
| Deadline (months from plan start) | signing | 8 | 14 | |

The 10.125% is a simple sum of amount over cap for each SAFE. It is not a cap table: post-money SAFEs interact, and a priced round, an option pool or conversion at a lower price changes the result. The pack states "about 10.1%" for the same sum.

Where the caps come from: T1 is the pack's haircut-now value ($6.16M, M), T2 the audit floor ($8M, M·A), T3 near the post-gate value ($10.77M, M). All three are model outputs. No investor has priced the company. The pre-money implied by the caps is $5.7M, $7.75M and $9.8M (M).

## Conditions (H: none has been tested with an investor)

- **Gate 2, by month 8:** paid pilot #1 signed at or above $2,500 (H) and a penetration-test SOW signed. Evidence: countersigned order form; signed SOW.
- **Gate 3, by month 14:** two paid design partners, pen-test criticals remediated (report plus retest letter), SOC 2 Type I auditor engaged. Evidence: two order forms; report and retest letter; engagement letter.
- If Gate 2 is unmet at month 8, T2 does not release and the plan follows [DOWNGRADE_MEMO_DRAFT.md](DOWNGRADE_MEMO_DRAFT.md). If the senior hire has not started by month 5 (KC-6), the T3 cap reverts to $8M (M).

## Use of funds, 18 months (M)

Total $560,640 of $750,000, buffer $189,360. Second maintainer 16 months $146,667; go-to-market $130,000; assurance $76,500; legal and corporate $39,500; founder salary $66,000; infrastructure, tools, insurance, accounting $35,006; recruiting $16,000; contingency $50,967. T1 alone gives about 10 months of runway at zero clients and 15 at three (M).

## What the investor is told about risk

Revenue is zero and no buyer has been interviewed (V, [validation log](../commercial/validation/VALIDATION_LOG.csv) is blank). One person maintains the code. No penetration test or SOC 2 report exists. Assurance states are in [ASSURANCE_STATUS.md](../assurance/ASSURANCE_STATUS.md). The model's base case assumes FY5 ARR of $1.20M (H); the probability-weighted figure is $1.30M (M). The bear case (p 0.45, M) exhausts released capital near month 18 and exits through the asset-sale path.

## Questions for counsel specific to the round

| # | Question | Blocks |
|---|---|---|
| R-1 | Which securities exemptions and filings apply to the company as formed and to investors in each of their jurisdictions (including Argentina and other LatAm residents), and what must be done before any solicitation? | Any conversation with an investor about terms |
| R-2 | Can staged tranches with conditions be enforced as three SAFEs, one SAFE with a funding schedule, or a side letter, and what remedy exists if an investor does not fund a met gate? | Whether Gates 2 and 3 bind anyone |
| R-3 | Does a wind-down at 95% of released capital, with escrow release to design partners and pro rata return, fit the instrument's dissolution priority and the escrow agreement? | The pack's wind-down statement |
| R-4 | How do three post-money SAFEs at different caps convert together, and what does the cap table look like at a $18M to $28M pre-money priced round? | The 10.1% figure |
| R-5 | Is MFN on T1 alone workable when later SAFEs carry higher caps? | Tranche terms |
| R-6 | What disclosure must accompany the model, and how should M and H tags be worded so that projections are not presented as promises? | Every investor document |

Record answers in the same way as [docs/legal/COUNSEL_QUESTIONS.md](../legal/COUNSEL_QUESTIONS.md).
