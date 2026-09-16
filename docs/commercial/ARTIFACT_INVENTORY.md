<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Revenue Artifact Inventory

**Audience:** the maintainer, and anyone auditing what this project tells a buyer.
**Scope:** every text artifact a buyer reads, or that shapes what a buyer is told.
**Boundary:** this file records *what each artifact currently claims and whether that claim is backed*. It makes no claim of its own about the product. Where it appears to permit something [Claims Matrix](../CLAIMS_MATRIX.md) does not, the matrix governs.

> **This is a pre-change snapshot, dated 2026-09-16.** It records the corpus as it stood *before* the corrections in [Claim Ledger](CLAIM_LEDGER.md) §2.1 were applied, which is what makes it useful as a baseline and what makes its `STALE` and `CONTRADICTED` markers read in the past tense. Every finding in §3 is now fixed; the ledger names the file and line for each so a reader can confirm rather than take it on trust.

**Method:** enumerated by glob, not by memory — `docs/commercial/`, root `*.md`, and a filename sweep for `PROSPECTUS|BUYER|PRODUCT_BRIEF|PRICING|SUPPORT_MODEL|ESCROW|COMMERCIAL|FAQ|ONE_PAGER`. Last-touched dates are `git log -1` per path.

---

## 1. Validation status vocabulary

| Status | Means |
|---|---|
| `BACKED` | Every load-bearing claim maps to a `CLM` row with a locator and a stated boundary, and the artifact is current. |
| `UNVALIDATED` | The artifact asserts something no evidence in this tree supports — typically price, SLA, certification, or support capacity. Not necessarily false; unevidenced, and must carry a visible status label. |
| `STALE` | Was accurate when written. A version, a count, a measurement or a registry state has since moved and the text did not. |
| `CONTRADICTED` | Two artifacts state incompatible things. The buyer who reads both catches it. |

A single artifact can be more than one. The table records the most severe.

---

## 2. Inventory

### 2.1 Root

| Path | Audience | What it currently claims | Status | Last touched |
|---|---|---|---|---|
| `README.md` | Everyone; first contact | Category, evidence model, deployment shapes, quickstart, verified metrics, boundaries | `STALE` | 2026-09-16 |
| `COMMERCIAL.md` | Procurement, legal | Licence boundary, five-package hypothesis, financial-claim discipline | `CONTRADICTED` | 2026-09-16 |
| `SUPPORT.md` | Users | Where to ask; no SLA | `BACKED` | — |
| `SECURITY.md` | Security reviewers | Disclosure process, scope | `BACKED` | — |
| `ROADMAP.md` | Everyone | Unbuilt items, no dates | `BACKED` | — |
| `INTEGRITY_SEAL.md` | Reviewers | Which commands ran on one date | `BACKED` | 2026-09-16 |
| `STATE_MANIFEST.md` | Reviewers | Current tree state | `BACKED` | 2026-09-16 |

### 2.2 `docs/commercial/`

| Path | Audience | What it currently claims | Status | Last touched |
|---|---|---|---|---|
| `ENTERPRISE_PRICING_GUIDE.md` | Procurement, finance | SKU table at **$45k / $95k / $175k / $250k–500k+**, engine add-ons, MGT tiers, services, support severities — declared "**published list prices** — offers the vendor is making" | `UNVALIDATED` + `CONTRADICTED` | 2026-09-09 |
| `SOFTWARE_ESCROW_POLICY.md` | Procurement | Deposit scope, release conditions, candidate agents — opens by stating no agent is engaged and nothing is executed | `BACKED` | 2026-09-09 |
| `COMMERCIAL_READINESS.md` | Maintainer | Six human-executable actions, all `NOT STARTED`, with procurement cost estimates | `BACKED` | 2026-09-16 |
| `CONNECTOR_ECOSYSTEM.md` | Technical buyer | What integrates with what | `UNVALIDATED` (unreviewed this pass) | 2026-09-09 |

### 2.3 `docs/` buyer-facing

| Path | Audience | What it currently claims | Status | Last touched |
|---|---|---|---|---|
| `PROSPECTUS.md` | Investor / exec | Source baseline `5.0.0`, capability summary, benchmark citations | `STALE` | 2026-09-16 |
| `PROSPECTUS_ES.md` | Investor / exec (ES) | **"Candidato de código/release: `4.1.2`… no se afirma publicación externa de `v4.1.2`"** | `STALE` + `CONTRADICTED` | 2026-09-03 |
| `BUYER_GUIDE_US.md` | Buyer, cross-functional | Role-by-role evaluation guidance | `STALE` | 2026-09-16 |
| `PRODUCT_BRIEF_US.md` | Buyer | Capability table | `STALE` | 2026-09-16 |
| `COMMERCIAL_STRATEGY_US.md` | Internal / investor | Packaging with **$10k–30k / $40k–100k / $100k–250k+** bands | `CONTRADICTED` | 2026-09-16 |
| `FAQ_PROCUREMENT.md` | Procurement | Licence, support, assurance answers | `STALE` | 2026-09-16 |

### 2.4 `docs/corporate/`, `docs/enterprise/`, `docs/institutional/`

| Path | Audience | What it currently claims | Status | Last touched |
|---|---|---|---|---|
| `corporate/POSITIONING_AND_MESSAGING.md` | Internal | Category, per-audience messaging, prohibited claims, no-competitor-matrix rule | `STALE` | — |
| `corporate/PRODUCT_ONE_PAGER.md` | Buyer | One-screen summary | `STALE` (unreviewed this pass) | 2026-09-15 |
| `corporate/EXECUTIVE_SUMMARY.md` | Exec | Problem, properties, risk table | `BACKED` (unreviewed this pass) | — |
| `corporate/CORPORATE_FAQ.md` | Exec | Company-level answers | `STALE` (unreviewed this pass) | 2026-09-02 |
| `enterprise/SUPPORT_MODEL.md` | Procurement | The actual support model | `UNVALIDATED` (unreviewed this pass) | 2026-09-15 |
| `enterprise/ENTERPRISE_READINESS.md` | Procurement | Readiness position | `UNVALIDATED` (unreviewed this pass) | — |
| `enterprise/PILOT_PLAYBOOK.md` | Buyer + founder | How a pilot runs | `UNVALIDATED` (unreviewed this pass) | — |
| `enterprise/PROCUREMENT_CHECKLIST.md` | Procurement | What to collect before quoting | `BACKED` (unreviewed this pass) | — |
| `enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md` | Security review | Pre-answered questionnaire | `UNVALIDATED` (unreviewed this pass) | — |
| `institutional/DOC-06_COMMERCIAL_PROCUREMENT.md` | Procurement | The governed procurement position | `BACKED` (unreviewed this pass) | 2026-09-09 |
| `institutional/UNSUPPORTED_CLAIMS.md` | Everyone | `UC-001`..`UC-042` — what may never be claimed | `BACKED` | 2026-09-16 |

"Unreviewed this pass" means the artifact was enumerated and its role identified, but its individual claims were not extracted line by line in Phase 1. That is stated rather than hidden: an inventory that implies a depth of review it did not perform is the same defect this file exists to find.

---

## 3. The four findings that matter

Everything above narrows to four. They are ordered by what a buyer would notice first.

### 3.1 Three incompatible price books — `CONTRADICTED`

| Source | "Enterprise" says | Declared status of the numbers |
|---|---|---|
| `docs/commercial/ENTERPRISE_PRICING_GUIDE.md` | `$95,000` | "**published list prices** — offers the vendor is making" |
| `COMMERCIAL.md` | `$100,000–250,000+` | "**not list prices**, observed ACV, or a valuation… solely as hypotheses" |
| `docs/COMMERCIAL_STRATEGY_US.md` | `$100k–250k+` | "annual hypothesis" |

The numbers disagree and **their epistemic status disagrees** — one file publishes an offer, another explicitly denies that any offer is published. A procurement reader who opens both learns that the vendor does not know what it charges. That is a worse first impression than any price.

`UC-028` and `UC-033` already block treating any of these as validated. The conflict is not that a price exists; it is that two files assign the same numbers opposite meanings.

### 3.2 A published SKU table with no validation label — `UNVALIDATED`

`ENTERPRISE_PRICING_GUIDE.md` is careful in most respects: it blocks ACV claims, labels the SLA matrix "a template for negotiation", and says plainly that no executed contract is cited. But line 10 declares the SKU prices "published list prices — offers the vendor is making", which asserts a commercial fact — that these are the terms on offer — when no pricing validation exists: no buyer interviews recorded, no cost-to-serve model, no pilot.

### 3.3 The Spanish prospectus contradicts the English one — `STALE` + `CONTRADICTED`

`docs/PROSPECTUS_ES.md` (2026-09-03) still reads *"Candidato de código/release: `4.1.2`… no se afirma publicación externa de `v4.1.2`"*. `docs/PROSPECTUS.md` reads `v5.0.0`, published 2026-09-16. A Spanish-reading buyer is served a version statement the English corpus abandoned two releases ago, and one that denies a publication which has since been read back.

### 3.4 The README shows a superseded latency figure — `STALE`

`README.md` §Verified metrics cites `p99 commit 836.35 ms`, dated 2026-08-20. That run predates the coalesced group-commit engine. `docs/CLAIMS_MATRIX.md` `CLM-034` already names the current artifacts — `evidence/backpressure_group_commit_remeasurement_2026-09-16.md` and `evidence/execution_2026-09-16/` — and six files link them. **The README is not one of them.**

The buyer reads the README first, and it shows the worse, superseded number while the claims register shows the current one. This is a case where honesty and selling point the same way: the stale figure is both wrong and unflattering.

Other stale README rows in the same table: suite counts at the `4.1.2` and `4.3.0` baselines, `mypy --strict` over 186 files, and `docker pull …:4.1.2` where GHCR carries `5.0.0`.

---

## 4. What this inventory does not establish

- It does not establish that the `BACKED` artifacts are persuasive, only that their claims are traceable.
- It does not review every line of the eleven artifacts marked "unreviewed this pass".
- It is not a competitive assessment. No claim about any other product appears in this corpus, by policy (`docs/corporate/POSITIONING_AND_MESSAGING.md` §5).
- It does not validate a single price. Nothing in this repository can; that requires buyer conversations and an executed agreement.

---

**Related:** [Claim Ledger](CLAIM_LEDGER.md) · [Positioning](POSITIONING.md) · [Enterprise Pricing Guide](ENTERPRISE_PRICING_GUIDE.md) · [Commercial Readiness](COMMERCIAL_READINESS.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Unsupported Claims](../institutional/UNSUPPORTED_CLAIMS.md)
