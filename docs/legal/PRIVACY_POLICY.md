<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Privacy Policy — Aegis Cloud

> **Draft for counsel review.** `[COUNSEL-REVIEW-REQUIRED]` This document is not legal advice and is not an offer; it is prepared for review by qualified counsel.


**Version:** 1.0-draft · **Status:** `[COUNSEL-REVIEW-REQUIRED]` · **Effective:** on the first paid Order
**Controller:** Juan Luna, [ENTITY AND ADDRESS TO BE COMPLETED], Argentina
**Contact:** privacy@aegislatent.com

This policy describes what the hosted control plane collects, why, and for how
long. It must match the schema in `aegis-cloud/app/migrations/`; when the schema
changes, this document changes in the same pull request.

## 1. What we collect

| Category | Examples | Source | Purpose |
|---|---|---|---|
| Account | email, password hash (scrypt), organisation name, role | You, at signup | Authentication and tenancy |
| Session | opaque token hash, expiry, IP address, user agent | Your request | Keep you signed in, detect abuse |
| API keys | key prefix, hash, label, creation and last-used time | You, in the dashboard | Authenticate machine calls |
| Usage metadata | organisation, request id, endpoint, status, counts, timestamps | Your API calls | Metering, quotas, invoices |
| Billing | Stripe customer and subscription identifiers, plan, invoice status | Stripe | Charge and support |
| Support and leads | name, email, message you send | You | Answer your request |
| Security logs | request id, route, status, latency | Automatic | Operate and protect the Service |

We do not collect the content of your model prompts in the control plane. The
gateway you self-host is a separate deployment and its data stays under your
control.

## 2. What we do not do

- We do not sell personal data.
- We do not use your data to train models.
- We do not run third-party advertising or cross-site trackers on the dashboard.

## 3. Legal bases (where the GDPR applies)

Performance of a contract (account, billing), legitimate interests (security,
fraud prevention, product improvement using aggregate metadata), and consent
where a feature asks for it. You may withdraw consent without affecting prior
processing.

## 4. Retention

| Data | Retention |
|---|---|
| Session records | 30 days after expiry, then deleted by the retention job |
| Rate-limit counters | One minute window, then deleted |
| Usage events | 400 days, aggregated afterwards |
| Product events (no prompt content) | 730 days |
| Billing records | As required by tax law; Stripe retains its own records |
| Application logs | 30 days in CloudWatch |
| Account after deletion | 30 days, then purged |

## 5. Subprocessors

The current list is `SUBPROCESSORS.md`: Amazon Web Services (hosting, database,
email), Stripe (payments), Vercel (website), GitHub (source hosting). We give
notice before adding one that processes personal data.

## 6. International transfers

The Service runs in `us-east-1`. Where data leaves your region, we rely on the
transfer mechanism named in the DPA (standard contractual clauses or an
adequacy decision). Counsel must confirm the mechanism for each market.

## 7. Your rights

Access, correction, deletion, portability, restriction and objection. Use
`POST /v1/account/export` and `DELETE /v1/account` in the API, or write to
privacy@aegislatent.com. We answer within 30 days. You may complain to your
supervisory authority.

## 8. Security

Passwords are hashed with scrypt; API keys are stored as hashes; sessions are
opaque and expire; the database is not publicly reachable; access to production
requires the operator's credentials. No system is perfectly secure; report a
vulnerability to security@aegislatent.com.

## 9. Children

The Service is not directed to people under 16 and we do not knowingly collect
their data.

## 10. Changes

Material changes are announced 30 days before they take effect. The current
version is recorded in this file and in `GET /v1/legal/versions` once implemented.
