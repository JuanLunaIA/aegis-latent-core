# Data-Room Index

**Not a product claim.** `[COUNSEL-REVIEW-REQUIRED]` before any document is shown to an investor under a confidentiality agreement. This index lists what exists in the repository and what only the founder can supply. It is built from `tools/sales/data_room.json` (Phase 1); the public rendering is `site/data-room.html`.

Hashes are not committed here because they change with every commit. Run `python tools/raise/data_room_manifest.py --ref <commit>` and give the investor the output together with that commit id. The tool exits 2 if a path the index calls existing is missing from the tree.

## Exists in the repository

| Area | Files |
|---|---|
| Release record | `docs/RELEASE_STATUS.md`, `evidence/v5_0_1_release_readback_2026-09-24.md` |
| Claims and refusals | `docs/CLAIMS_MATRIX.md`, `docs/institutional/UNSUPPORTED_CLAIMS.md` |
| Defects and founder-only actions | `docs/REGISTRY.md`, `docs/REGISTRY_HUMAN_PACK.md` |
| Security | `SECURITY.md`, `docs/security/THREAT_MODEL.md` |
| Third-party licences | `LICENSE-THIRD-PARTY.md` |
| Audit readiness | `docs/compliance/AUDIT_READINESS.md`, `docs/compliance/COMPLIANCE_MAPPING.md` |
| Continuity | `docs/MAINTAINER_HANDBOOK.md`, `docs/assurance/ESCROW_EXECUTION_PLAN.md` |
| Licences and pricing | `LICENSE`, `COMMERCIAL.md`, `docs/commercial/ENTERPRISE_PRICING_GUIDE.md`, `docs/legal/` (drafts) |
| Benchmarks | `evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json`, `docs/BENCHMARKS.md` |
| Qualification runs | `evidence/qualification/wal_crash_soak_2026-09-29.json`, `evidence/qualification/waf_corpus_report_2026-09-29.json`, `docs/assurance/TRL_CLOSURE.md` |
| Verify-it-yourself kit | `tools/sales/prove_it/`, `docs/PROVE_IT.md` |
| Financial model | `investor_packs/*` (engine, seed 42, `model_outputs.json`, both languages) |
| Baseline and assurance status | `docs/commercial/EXEC_BASELINE.md`, `docs/assurance/ASSURANCE_STATUS.md` |

## Missing: only the founder or a third party can supply

| Document | Register | Who | Target (M) | State in the repository |
|---|---|---|---|---|
| Certificate of incorporation | `REG-H09` | Founder and counsel | 2027-01-31 | none |
| IP assignment, founder to company | `REG-H09`, `REG-H10` | Founder and counsel | 2027-01-31 | draft in `docs/legal/IP_ASSIGNMENT_DRAFT.md` |
| Cap table and any prior SAFE or note | none | Founder | before first SAFE | none; the model assumes none exist |
| Penetration-test report | `REG-H01` | Founder, then maintainer | SOW 2027-03-31, report 2027-06-30 | SOW draft only |
| SOC 2 report | `REG-H02` | Founder and auditor | engaged 2027-08-31, issued 2027-12-31 | readiness plan only |
| Escrow agreement | `REG-H03` | Founder | 2027-03-31 | term sheet and manifest tool only |
| Customer contracts, LOIs | `REG-H06` | Founder | 2027-05-31 to 2027-09-30 | templates only |
| Buyer interview notes | `REG-H06` | Founder | 2027-01-31 | blank log |
| Legal opinions (licence, AI authorship, MiFID/MAR inputs) | `REG-H04`, `REG-H10` | Counsel | 2027-01-31 | ten questions drafted |
| Financial statements, tax filings | none | Founder | after the entity exists | none |
| Insurance (cyber, E&O) | none | Founder | not scheduled | none |
| Founder's measured monthly cloud burn | `REG-H07` | Founder | not scheduled | model figure only ($17.54 typical, $44.77 worst, M) |

## Rules for what goes in the room

- Show the commit id and the manifest with every export. Do not edit a file after hashing it.
- Never place credentials, raw WAL records, customer data or the licence-signing private key in the room. `tools/assurance/escrow_manifest.py` refuses key-like paths for the same reason.
- The investor pack (both editions) was refreshed on 2026-09-30 and says so on its first page and in section U or A. Re-run the engine and the checksums before each export; the monthly recompute (`tools/cadence/cadence.py monthly`) does the model comparison.
