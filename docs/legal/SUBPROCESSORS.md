<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Subprocessors

> **Draft for counsel review.** `[COUNSEL-REVIEW-REQUIRED]` This document is not legal advice and is not an offer; it is prepared for review by qualified counsel.


**Version:** 1.0 · **Last reviewed:** 2026-10-29
This list accompanies `PRIVACY_POLICY.md` and `DATA_PROCESSING_ADDENDUM.md`. It
names every third party that can process customer data for the hosted Service.

| Subprocessor | Purpose | Data | Location | Safeguards |
|---|---|---|---|---|
| Amazon Web Services (RDS, Lambda, S3, SES, CloudWatch) | Hosting, database, email delivery, logs | Account, session, usage, billing identifiers, email delivery events | `us-east-1` | AWS DPA, encryption at rest and in transit, private subnets |
| Stripe | Payments, invoices, subscription management | Billing name, email, payment method handled by Stripe, tax identifiers | United States / Ireland (Stripe entity) | Stripe DPA, PCI DSS scope handled by Stripe |
| Vercel | Marketing website and documentation hosting | Site visitor IP and request metadata | Global edge | Vercel DPA |
| GitHub | Source hosting, CI, release artifacts | Contributor and maintainer account data | United States | GitHub DPA |

Not subprocessors: the upstream model providers a customer configures in its own
gateway. Those calls are made by the customer's deployment, not by the hosted
control plane.

## Changes

A new subprocessor that processes personal data is announced 30 days before it
is used, with a description of the data and the safeguard. Customers may object
as described in the DPA.
