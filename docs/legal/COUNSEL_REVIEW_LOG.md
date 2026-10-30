<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Counsel review log

**Audience:** owner and counsel.
**Scope:** every document that needs legal review, its exact state, and the
answer that would close it.
**Boundary:** a log, not a legal opinion. A row is `REVIEWED` only when a named
lawyer has returned a dated written opinion covering that document.

> **[COUNSEL-REVIEW-REQUIRED]** This log records that review is absent. It does
> not itself provide review and is **not legal advice**.

## Status

| Document | Version / date | State | Reviewer | Date | What closes it |
| --- | --- | --- | --- | --- | --- |
| `LICENSE` (Aegis Commercial License 1.0) | v5.0.3 source, 2026-10 | `NOT REVIEWED` | — | — | counsel confirms enforceability, liability cap, governing law, and interaction with the published `5.0.2` licence |
| `COMMERCIAL.md` | 2026-10 | `NOT REVIEWED` | — | — | counsel reviews the commercial summary against `LICENSE` |
| `NOTICE` | 2026-10 | `NOT REVIEWED` | — | — | counsel confirms attribution and third-party notices |
| `docs/legal/LICENSE_TRANSITION_5.0.2.md` | 2026-10-01 | `NOT REVIEWED` | — | — | counsel confirms the right to relicense and the boundary for earlier recipients |
| `docs/legal/LICENSE_TRANSITION_5.0.3.md` | 2026-10 | `NOT REVIEWED` | — | — | counsel confirms forward-only effect and fork treatment |
| `docs/legal/TERMS_OF_SERVICE.md` | draft | `NOT REVIEWED` | — | — | counsel reviews formation, renewal, suspension, liability, and consumer terms |
| `docs/legal/PRIVACY_POLICY.md` | draft | `NOT REVIEWED` | — | — | counsel reviews against `DATA_MAP.md` and the actual schema |
| `docs/legal/DATA_PROCESSING_ADDENDUM.md` | draft | `NOT REVIEWED` | — | — | counsel reviews controller/processor roles and transfer mechanism |
| `docs/legal/SUBPROCESSORS.md` | 2026-10 | `NOT REVIEWED` | — | — | counsel confirms notice/objection mechanics |
| `docs/legal/REFUND_POLICY.md` | draft | `NOT REVIEWED` | — | — | counsel reviews automatic renewal and consumer withdrawal rights |
| `docs/legal/PILOT_AGREEMENT_TEMPLATE.md` | draft | `NOT REVIEWED` | — | — | counsel reviews scope, fees, IP, data, termination |
| `docs/legal/MSA_ORDER_FORM_TEMPLATE.md` | draft | `NOT REVIEWED` | — | — | counsel reviews order of precedence and signature blocks |
| `docs/legal/COMMERCIAL_LICENSE_TEMPLATE.md` | draft | `NOT REVIEWED` | — | — | counsel decides whether it is still needed after `5.0.3` |
| `docs/legal/ESCROW_TERM_SHEET.md` | draft | `NOT REVIEWED` | — | — | counsel and escrow agent review |
| `docs/legal/IP_ASSIGNMENT_DRAFT.md` | draft | `NOT REVIEWED` | — | — | counsel reviews after entity formation |
| `docs/legal/ENTITY_AND_TAX_MEMO.md` | 2026-10-29 | `NOT REVIEWED` | — | — | accountant and counsel answer E1–E10 |
| `docs/legal/EXPORT_AND_CRYPTO_CLASSIFICATION.md` | 2026-10-29 | `NOT REVIEWED` | — | — | export counsel classifies the cryptographic functions |
| `docs/legal/DATA_MAP.md` | 2026-10-29 | `NOT REVIEWED` | — | — | privacy counsel checks it against the schema and subprocessors |
| `docs/legal/COUNSEL_QUESTIONS.md` | 2026-10 | `OPEN` | — | — | written answers to questions 1–22 |

## Rules

1. **No self-review.** The agent that drafted a document cannot mark it
   reviewed.
2. **One document, one opinion.** A general "looks fine" email does not close
   the table row; the opinion must name the document and the version.
3. **Answers are quoted, not paraphrased.** The owner stores the written reply
   and updates the affected draft with the question number and the date.
4. **Silence is not approval.** A document sent to counsel is still
   `NOT REVIEWED` until the reply arrives.
5. **The legal gate stays closed until every row that blocks the first paid
   Order is `REVIEWED`.** The gate record is
   [`LEGAL_GATE.md`](LEGAL_GATE.md).
