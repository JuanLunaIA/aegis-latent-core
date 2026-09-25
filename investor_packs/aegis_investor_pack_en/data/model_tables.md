### D3.1 Tiers [MODEL/HYPOTHESIS]
| Tier | ACV | CM | CAC | LTV @25% | LTV @40% | LTV @55% | Payback (mo) | LTV/CAC @40% |
|---|---|---|---|---|---|---|---|---|
| Blended prior | 15.0k | 90.0% | 6.4k | 54.0k | 33.8k | 24.5k | 5.7 | 5.3x |
| Mid-market | 50.0k | 90.9% | 12.5k | 181.9k | 113.7k | 82.7k | 3.3 | 9.1x |
| Enterprise | 150.0k | 90.3% | 33.8k | 541.9k | 338.7k | 246.3k | 3.0 | 10.0x |
| Pilot (one-off) | 10.0k | 75.0% | 0.0k | 7.5k | 7.5k | 7.5k | 0.0 | n/a |

### D3.2 CAC by channel [HYPOTHESIS except founder-led MODEL]
| Channel | CAC | Mix |
|---|---|---|
| founder_outbound | 6.4k | 50% |
| oss_inbound | 2.0k | 30% |
| partner_si | 9.0k | 15% |
| events_paid | 18.0k | 5% |
| Blended | 6.0k | 100% |

### D3.5 CAC stress: LTV/CAC when CAC = first-year ACV (CM 90%)
| Churn | LTV/CAC |
|---|---|
| 25% | 3.60x |
| 40% | 2.25x |
| 55% | 1.64x |

### D3.3 MGT overage (Aegis-hosted marginal cost) [VERIFIED prices, MODEL volumes]
| Band | Price/MGT | Marginal cost/MGT | Margin |
|---|---|---|---|
| 10-50M | $1,500 | $1.99 | 99.87% |
| 50-250M | $950 | $1.99 | 99.79% |
| 250M+ | $500 | $1.99 | 99.60% |

### D3.4 Sensitivity: LTV/CAC by churn x ACV (CM 90%, CAC = max($6.4k, 25% ACV))
| Churn \ ACV | 15.0k | 25.0k | 50.0k | 75.0k | 135.0k |
|---|---|---|---|---|---|
| 25% | 8.4x (LTV 54.0k) | 14.1x (LTV 90.0k) | 14.4x (LTV 180.0k) | 14.4x (LTV 270.0k) | 14.4x (LTV 486.0k) |
| 40% | 5.3x (LTV 33.8k) | 8.8x (LTV 56.2k) | 9.0x (LTV 112.5k) | 9.0x (LTV 168.8k) | 9.0x (LTV 303.8k) |
| 55% | 3.8x (LTV 24.5k) | 6.4x (LTV 40.9k) | 6.5x (LTV 81.8k) | 6.5x (LTV 122.7k) | 6.5x (LTV 220.9k) |

### D4 BEAR — P&L / cash flow / balance sheet (p=0.45)
| Line | FY1 | FY2 | FY3 | FY4 | FY5 |
|---|---|---|---|---|---|
| New customers | 0.6 | 1.2 | 1.8 | 2.4 | 3.0 |
| Customers (end) | 0.6 | 1.5 | 2.5 | 3.5 | 4.6 |
| ARR (end) | 12.0k | 35.4k | 69.9k | 115.5k | 172.0k |
| Revenue | 16.0k | 43.7k | 82.7k | 132.7k | 193.7k |
| Gross margin | 73% | 75% | 77% | 79% | 81% |
| OpEx | 361.1k | 449.3k | 385.4k | 409.2k | 433.7k |
| EBITDA | -349.4k | -416.6k | -321.6k | -304.0k | -276.6k |
| Net income | -349.4k | -416.6k | -321.6k | -304.0k | -276.6k |
| CFO | -345.4k | -408.4k | -309.2k | -287.4k | -255.9k |
| CFF (SAFE tranches) | 550.0k | 0.0k | 0.0k | 0.0k | 0.0k |
| Cash / (unfunded gap), close | 204.6k | -203.8k | -513.0k | -800.3k | -1.06M |
| AR | 2.0k | 5.4k | 10.2k | 16.4k | 23.9k |
| Deferred revenue | 6.0k | 17.7k | 35.0k | 57.7k | 86.0k |
| Equity (paid-in + retained) | 200.6k | -216.1k | -537.7k | -841.7k | -1.12M |
| Balance check (A−L−E) | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| Headcount | 3 | 3 | 2 | 2 | 2 |
| Burn multiple | 28.8 | 17.5 | 9.0 | 6.3 | 4.5 |
| Magic number (proxy) | 0.19 | 0.19 | 1.10 | 1.07 | 1.03 |

### D4 BASE — P&L / cash flow / balance sheet (p=0.40)
| Line | FY1 | FY2 | FY3 | FY4 | FY5 |
|---|---|---|---|---|---|
| New customers | 2.0 | 4.0 | 6.0 | 8.0 | 10.0 |
| Customers (end) | 2.0 | 5.2 | 9.1 | 13.5 | 18.1 |
| ARR (end) | 60.0k | 199.6k | 431.7k | 764.9k | 1.20M |
| Revenue | 70.0k | 210.4k | 437.7k | 762.7k | 1.19M |
| Gross margin | 76% | 80% | 83% | 85% | 87% |
| OpEx | 373.2k | 474.0k | 816.4k | 1.08M | 1.41M |
| EBITDA | -319.9k | -306.2k | -454.4k | -429.8k | -378.1k |
| Net income | -319.9k | -306.2k | -454.4k | -429.8k | -378.1k |
| CFO | -298.5k | -253.7k | -366.3k | -303.3k | -211.1k |
| CFF (SAFE tranches) | 550.0k | 200.0k | 0.0k | 0.0k | 0.0k |
| Cash / (unfunded gap), close | 251.5k | 197.8k | -168.6k | -471.9k | -683.0k |
| AR | 8.6k | 25.9k | 54.0k | 94.0k | 147.0k |
| Deferred revenue | 30.0k | 99.8k | 215.9k | 382.5k | 602.4k |
| Equity (paid-in + retained) | 230.1k | 123.9k | -330.5k | -760.3k | -1.14M |
| Balance check (A−L−E) | -0.00 | -0.00 | 0.00 | 0.00 | 0.00 |
| Headcount | 3 | 3 | 5 | 7 | 9 |
| Burn multiple | 5.0 | 1.8 | 1.6 | 0.9 | 0.5 |
| Magic number (proxy) | 0.82 | 0.95 | 0.78 | 0.82 | 0.76 |

### D4 BULL — P&L / cash flow / balance sheet (p=0.15)
| Line | FY1 | FY2 | FY3 | FY4 | FY5 |
|---|---|---|---|---|---|
| New customers | 3.9 | 7.8 | 11.7 | 15.6 | 19.5 |
| Customers (end) | 3.9 | 10.7 | 19.7 | 30.4 | 42.3 |
| ARR (end) | 156.0k | 608.4k | 1.48M | 2.90M | 4.95M |
| Revenue | 168.0k | 564.1k | 1.32M | 2.57M | 4.41M |
| Gross margin | 78% | 83% | 87% | 89% | 91% |
| OpEx | 391.6k | 788.2k | 1.11M | 1.49M | 1.90M |
| EBITDA | -260.0k | -319.1k | 36.5k | 798.0k | 2.09M |
| Net income | -260.0k | -319.1k | 36.5k | 598.5k | 1.57M |
| CFO | -202.7k | -141.8k | 380.4k | 1.15M | 2.37M |
| CFF (SAFE tranches) | 750.0k | 0.0k | 0.0k | 0.0k | 0.0k |
| Cash / (unfunded gap), close | 547.3k | 405.5k | 786.0k | 1.94M | 4.31M |
| AR | 20.7k | 69.6k | 163.2k | 316.6k | 543.3k |
| Deferred revenue | 78.0k | 304.2k | 741.8k | 1.45M | 2.47M |
| Equity (paid-in + retained) | 490.0k | 170.9k | 207.4k | 805.9k | 2.38M |
| Balance check (A−L−E) | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| Headcount | 3 | 5 | 7 | 9 | 11 |
| Burn multiple | 1.3 | 0.3 | — | — | — |
| Magic number (proxy) | 1.74 | 1.48 | 1.97 | 2.16 | 2.31 |

### D5.1 Pre-funding burn [MODEL: owner-supplied Azure figures]
| Item | Typical | Worst |
|---|---|---|
| Azure / month | $17.54 | $44.77 |
| Credit runway (months) | 11.4 | 4.5 |
| Cash burn while credit lasts | $100 | $100 |
| Cash burn after credit | $117.54 | $144.77 |
| Managed HSM B1 (excluded) | $2,342.40 [VERIFIED] | — |

### D5.2 Credit alert thresholds
| Alert | Spend | Month @typical | Month @worst |
|---|---|---|---|
| 50% | $100 | 5.7 | 2.2 |
| 80% | $160 | 9.1 | 3.6 |
| 95% | $190 | 10.8 | 4.2 |

### D5.3 Post-funding runway (months) [MODEL]
| Capital | 0 clients | 1 client | 3 clients |
|---|---|---|---|
| all tranches | 22 | 24 | 28 |
| T1 only | 10 | 11 | 15 |

### D7.1 Use of funds, 18 months [MODEL]
| Workstream | USD | Share |
|---|---|---|
| Engineering continuity (2nd maintainer, 16 mo) | 146.7k | 26% |
| Go-to-market (solutions engineer 12 mo + design-partner program) | 130.0k | 23% |
| Assurance (pen test + retest, SOC 2 Type I, escrow) | 76.5k | 14% |
| Legal & corporate (entity, IP, licence, regulatory, AI-authorship opinion) | 39.5k | 7% |
| Founder salary (18 mo) | 66.0k | 12% |
| Infra, tools, insurance, accounting (18 mo) | 35.0k | 6% |
| Recruiting | 16.0k | 3% |
| Contingency (10%) | 51.0k | 9% |
| Total 18 months | 560.6k | 100% |
| Raise | 750.0k |  |
| Buffer at M18 | 189.4k |  |

### D6.1 VC method (10x target, 5-yr exit, 60% stage discount) [MODEL]
| Scenario | ARR FY5 | Exit multiple | Exit EV | Post-money | Pre-money |
|---|---|---|---|---|---|
| bear | 172.0k | 4x | 687.8k | 27.5k | 0.0k |
| base | 1.20M | 8x | 9.64M | 385.6k | 0.0k |
| bull | 4.95M | 12x | 59.35M | 2.37M | 1.62M |
| Probability-weighted |  |  |  |  | 243.6k |

### D6.2 Scorecard (audit-adjusted) [MODEL]
| Factor | Weight | Score vs average | Contribution |
|---|---|---|---|
| Team | 30% | 0.60 | 0.180 |
| Opportunity size | 25% | 1.40 | 0.350 |
| Product/technology | 15% | 1.02 | 0.153 |
| Competitive environment | 10% | 0.80 | 0.080 |
| Sales channels/partnerships | 10% | 0.40 | 0.040 |
| Need for more capital | 5% | 1.10 | 0.055 |
| Other (jurisdiction, licence) | 5% | 0.80 | 0.040 |
| Factor total |  |  | 0.898 |
| Pre-money (ref $8–12M) |  |  | 7.18M – 10.78M |

### D6.3 Berkus (audit-adjusted) [MODEL]
| Element | Score (0–1) |
|---|---|
| Sound idea | 0.70 |
| Prototype (audit 51/100) | 0.51 |
| Quality team | 0.30 |
| Strategic relationships | 0.10 |
| Product rollout/sales | 0.20 |
| Value at $0.5M / $1.0M per element | 905.0k / 1.81M |

### D6.4 DCF of base FCF @25% [MODEL]
| Exit multiple on FY5 ARR | PV(FCF FY1–5) | Enterprise value |
|---|---|---|
| 6x | -782.2k | 1.59M |
| 8x | -782.2k | 2.38M |
| 10x | -782.2k | 3.17M |

### D6.5 Haircut table (reference = [AUDIT] $15M top of seed band) [MODEL]
| Haircut | Now | After gates | Gate that removes it |
|---|---|---|---|
| Bus factor 1 | −20% | −8% | second maintainer hired + escrow executed |
| AGPL friction | −7% | −4% | commercial licence counsel + one executed commercial licence |
| Zero revenue | −25% | −10% | two paid design partners |
| No third-party audit | −12% | −3% | pen test report with criticals remediated |
| Single geography | −5% | −3% | one EU or US design partner |
| FX / Argentina jurisdiction | −12% | −4% | Delaware parent + USD contracts |
| Resulting value | 6.16M | 10.77M |  |

### D2 TRL matrix
| Component | TRL now | Evidence | Gap to TRL+1 | Eng weeks | External $ | Cost to close |
|---|---|---|---|---|---|---|
| Gateway core | 6 | 7,550 tests; shipped image smoke-tested in hardened posture (CLM-109); signed 5.0.1 release | operational pilot at a design partner | 8 | $0 | $18,400 |
| WAL + group commit | 6 | commit p50 0.62 ms / p99 1.22 ms incl. fsync; 1,482 commits/s @100 threads on 4 vCPU | 30-day soak + power-loss test on target storage | 3 | $1,000 | $7,900 |
| MMR v2 proofs | 6 | Rust/Python root agreement; portable inclusion proofs (CLM-064) | third-party verification in a pilot | 2 | $0 | $4,600 |
| SDK verifiers | 6 | PyPI/npm 5.0.1 byte-identical to Release assets; provenance verified | external auditor runs aegis-sdk verify in a pilot | 2 | $0 | $4,600 |
| WAF L1/L2 | 5 | corpus-tested normalisation; finite pattern set (UC-042) | published adversarial eval + pen test coverage | 4 | $0 | $9,200 |
| Crypto-shredding | 5 | wired into commit path; keyed digests (CLM-098) | counsel review of erasure semantics + pilot | 3 | $3,000 | $9,900 |
| HA lease + global sequence | 5 | CI vs real Redis/PostgreSQL; SIGKILL failover 4.2-5.2 s (CLM-108) | partition/failover chaos tests + pilot | 6 | $2,000 | $15,800 |
| ZK circuit | 4 | preview guard; not on the request path | proving-system audit; deferred | 12 | $40,000 | $67,600 |
| Raft / consensus | 2 | orphan module; superseded by AD-17 lease design | not on roadmap | 0 | $0 | $0 |
| HSM / PQC signing | 4 | PKCS#11 path; ML-DSA-65 sign 173 us / verify 62 us; Managed HSM excluded ($2,342/mo) | Key Vault Premium HSM-backed key integration test | 4 | $500 | $9,700 |
| OTel / metrics | 6 | /metrics verified in the shipped image by the evidence collector (REG-D86) | pilot dashboards + alert runbook exercised | 1 | $0 | $2,300 |
| Azure deployment kit | 3 | deploy/azure has aks/ only; phase-0 guardrails not in repo (REG-H07) | commit phase-0 IaC + budget alerts + one real deployment readback | 2 | $540 | $5,140 |

### Monte Carlo ARR percentiles (seed 42, n=5,000)
| Percentile | FY1 | FY2 | FY3 | FY4 | FY5 |
|---|---|---|---|---|---|
| P10 | 39.7k | 132.1k | 283.9k | 502.0k | 789.6k |
| P50 | 60.8k | 202.8k | 437.2k | 774.7k | 1.22M |
| P90 | 90.3k | 301.5k | 653.4k | 1.16M | 1.83M |
