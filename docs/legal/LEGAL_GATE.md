<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Legal gate record

**Audience:** owner, counsel, and any buyer asking whether the legal pack is
ready.
**Scope:** the conditions that must be true before a paid Order, a public
`5.0.3` release, or a customer-facing legal statement.
**Boundary:** a gate record. It does not provide legal advice and does not
substitute for the signed opinions in `COUNSEL_REVIEW_LOG.md`.

> **LEGAL GATE: BLOCKED**
>
> No document in `docs/legal/` has been reviewed by a lawyer. No entity has been
> formed for the product. No export classification has been obtained. The
> licence and terms are drafts.

## Why it is blocked

| Blocker | Evidence | What closes it |
| --- | --- | --- |
| No counsel review | `COUNSEL_REVIEW_LOG.md` — every row `NOT REVIEWED` or `OPEN` | dated written opinion naming document and version |
| No licensor entity | `ENTITY_AND_TAX_MEMO.md` — E1/E2 open | owner forms or selects the entity; IP assignment signed |
| No export classification | `EXPORT_AND_CRYPTO_CLASSIFICATION.md` §5 | export counsel classification for the delivered version |
| No DPA transfer mechanism | `DATA_MAP.md` §5 | counsel selects SCCs/adequacy/other and the DPA says it |
| No cookie inventory | `PRIVACY_POLICY.md` cookie section | web owner confirms only essential cookies, or adds notice |
| No merchant-of-record decision | `ENTITY_AND_TAX_MEMO.md` E6 | owner and accountant select; Stripe Tax or alternative configured |
| Insurance not bound | `INSURANCE_AND_ESCROW_DECISIONS.md` | broker quote and bound policy, or a written decision to self-insure |
| `5.0.3` not published | `docs/RELEASE_STATUS.md` | release gate, not this one |

## What may ship while blocked

- The source under the draft commercial licence may be published **only** after
  the release gate and counsel sign-off; it is not published today.
- The website may describe the product, its boundaries, and the absence of
  certifications. It may not describe the terms as reviewed, offered, or
  enforceable.
- A pilot may be discussed, but not signed, until the pilot agreement and the
  entity/tax gate are reviewed.

## What may not ship while blocked

- A statement that the licence is "legally reviewed", "enforceable", or
  "counsel approved".
- A statement that the product is "SOC 2", "ISO 27001", "HIPAA", "FedRAMP",
  "PCI DSS", "GDPR compliant", "EU AI Act compliant", or "CSRD compliant".
- An invoice from an entity that does not exist, or a Stripe checkout without a
  merchant-of-record and tax decision.
- A BAA, DPA, or SCCs that counsel has not reviewed.
- A claim that the export classification is known.

## Exit criteria

The gate moves to `OPEN` only when:

1. `COUNSEL_REVIEW_LOG.md` has a `REVIEWED` row for `LICENSE`, `TERMS`,
   `PRIVACY`, `DPA`, and `MSA_ORDER_FORM_TEMPLATE`, with named reviewer and
   date.
2. `ENTITY_AND_TAX_MEMO.md` E1–E10 are recorded.
3. `EXPORT_AND_CRYPTO_CLASSIFICATION.md` §5 is complete.
4. `DATA_MAP.md` §7 open items are closed.
5. The owner signs this record with a date.

A gate that closes because a deadline arrived is not closed.
