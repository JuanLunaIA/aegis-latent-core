<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Entity and tax memo

**Audience:** the owner, corporate counsel, and the accountant who will file.
**Scope:** the decisions that must be made before a company can issue a licence,
invoice a customer, or employ anyone.
**Boundary:** a decision memo with open fields, not a legal or tax opinion. No
entity has been formed for this product, no tax registration has been obtained
for a company, and no revenue has been recognised.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent. It is not legal
> or tax advice. Do not file, incorporate, or issue an invoice from this memo.

## 1. Current facts (verified)

| Fact | State | Evidence |
| --- | --- | --- |
| Copyright holder | Juan Luna, individual | `LICENSE`, `NOTICE` |
| Owner tax residency | Argentina | owner instruction; exact fiscal address not recorded here |
| Company | none formed for Aegis | owner instruction; no incorporation record in the repository |
| Employees | none | owner instruction |
| Contractors | none engaged | owner instruction |
| Revenue | none | no invoices, no Stripe account configured |
| Merchant of record | not configured | `aegis-cloud` billing returns `503 billing_not_configured` |
| Bank / payment account | not recorded in the repository | secrets policy |
| Accounting currency | `[OWNER INPUT REQUIRED]` | — |
| Fiscal year | `[OWNER INPUT REQUIRED]` | — |

## 2. Decisions before the first paid Order

| # | Decision | Options | Consequence | Owner input |
| --- | --- | --- | --- | --- |
| E1 | Who is the licensor? | individual / new company / existing company | a licence from the wrong party is defective | `[OWNER INPUT REQUIRED]` |
| E2 | Jurisdiction and form | Argentina SAS / SRL / SA; US LLC or C-Corp; other | tax, liability, fundraising, hiring | `[OWNER INPUT REQUIRED]` |
| E3 | IP assignment | founder assigns the repository and marks to the company | needed before a company licence | `[OWNER INPUT REQUIRED]` |
| E4 | Fiscal residence of the company | Argentina / US / other | corporate tax and treaty position | `[OWNER INPUT REQUIRED]` |
| E5 | VAT/GST registration | local regime / OSS / none yet | invoice validity and marketplace rules | `[OWNER INPUT REQUIRED]` |
| E6 | Merchant of record | Stripe direct / Paddle / other | who is liable for sales tax | `[OWNER INPUT REQUIRED]` |
| E7 | Transfer pricing between founder and company | licence royalty / assignment / salary | tax authority review | `[OWNER INPUT REQUIRED]` |
| E8 | Equity split if investors enter | founder 100% now / reserved pool | future dilution and control | `[OWNER INPUT REQUIRED]` |
| E9 | Accounting system | local accountant / cloud ledger | auditability and expense records | `[OWNER INPUT REQUIRED]` |
| E10 | Banking | business account in company name | customer KYC and payments | `[OWNER INPUT REQUIRED]` |

## 3. Tax questions that change the contract

1. If the company licenses software to a customer in the United States, is the
   income a royalty, a service fee, or business profits, and does a treaty
   apply? The answer changes withholding and the invoice wording.
2. If the customer buys through Stripe, is the owner or Stripe the merchant of
   record for VAT/GST? The current code assumes the owner is; Stripe Tax is not
   configured.
3. Are the prices in `docs/commercial/ENTERPRISE_PRICING_GUIDE.md` tax-inclusive
   or tax-exclusive? The website says USD, taxes not included; the invoice must
   match.
4. Does a paid pilot create a permanent establishment or a taxable presence in
   the customer's country? Get an answer before a multi-month on-site pilot.
5. Are crypto/security research services subject to export or services
   withholding in the customer's jurisdiction?
6. How are AI-assisted development costs treated for R&D credits or deductions,
   if the company claims any? Do not claim a credit without the records.

## 4. Documents the accountant will need

- incorporation certificate and tax ID of the company, once formed;
- founder IP assignment, signed;
- chart of accounts and fiscal year;
- invoice template with legal name, tax ID, address, and tax treatment;
- Stripe (or alternative) statements and payout reports;
- expense receipts, including cloud and domain costs;
- intercompany agreement if the founder licenses IP to the company;
- payroll or contractor agreements, if any.

## 5. Gate

The entity/tax gate is **OPEN**. A customer can be invoiced only after E1, E2,
E5, E6 and E10 are recorded by the owner and reviewed by the accountant. The
software licence can be drafted before incorporation, but it must name the
actual copyright holder and must not imply a company that does not exist.
