<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Data map and subprocessor truth

**Audience:** counsel, privacy reviewer, security reviewer, and any buyer
completing a vendor questionnaire.
**Scope:** what the hosted evaluation console and the self-hosted product can
process, where it goes, and which third parties are involved.
**Boundary:** a factual map of the code in this repository, not a legal
conclusion. It does not establish that a deployment is configured this way, and
it does not replace a DPA or a transfer assessment.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent. It has not been
> reviewed by a privacy lawyer and is **not legal advice**. Bracketed fields are
> open items.

## 1. Two products, two data paths

| Mode | What runs | Does Aegis receive customer AI traffic? | Operator |
| --- | --- | --- | --- |
| Self-hosted gateway | `aegis` in the customer's environment | No | Customer |
| Hosted evaluation console | `aegis-cloud` at `aegislatent.com` | No model prompts or completions; account, session and usage metadata only | Owner |

The hosted console is **not** a gateway for customer inference. A customer who
wants governed inference runs the gateway. This distinction is load-bearing for
the privacy policy and for the DPA.

## 2. Hosted console data

| Category | Examples | Purpose | Storage | Retention |
| --- | --- | --- | --- | --- |
| Account | email, name, organisation, password hash | authentication, support | PostgreSQL `accounts` | life of account; deleted on verified deletion request |
| Session | session token hash, IP address, user agent, timestamps | session integrity, abuse response | PostgreSQL `sessions` | session TTL (30 days default) and audit retention |
| API keys | key prefix and hash, label, created/last-used timestamps | tenant authentication | PostgreSQL `api_keys` | life of key; prefix retained after revocation for audit |
| Usage | request counts, token counts, plan code, period | metering and billing | PostgreSQL usage tables | billing period plus accounting retention |
| Audit | actor, action, target, timestamp, request id | security and billing traceability | PostgreSQL audit table | configured retention; not customer content |
| Billing | Stripe customer/subscription identifiers | payments | Stripe; identifiers mirrored in PostgreSQL | per Stripe and accounting policy |
| Support correspondence | emails and attachments the customer sends | support | owner mailbox | until the ticket is closed plus a stated period |

The console does **not** intentionally store model prompts, model outputs,
uploaded documents, or customer end-user identifiers. A support email can
contain them if the customer includes them; that is a customer choice, not a
product feature.

## 3. Self-hosted gateway data

The gateway processes prompts and responses in memory for policy enforcement and
writes the governed evidence record the operator configures. The record can
include request/response previews, hashes, tenant pseudonyms, policy decisions
and signatures. The operator chooses the WAL path, retention, backup target and
whether previews are enabled. Aegis the project receives none of it.

**Do not describe the gateway as "zero data" or "no PII":** previews can contain
personal data, and the operator controls whether they are on. The accurate
statement is that the gateway is self-hosted and the project has no telemetry
path to customer content.

## 4. Subprocessors

| Subprocessor | Service | Data | Region / transfer | Contract status |
| --- | --- | --- | --- | --- |
| Amazon Web Services | RDS PostgreSQL, Lambda, SES, S3 inbound, CloudWatch | account, session, usage, audit, email | `us-east-1`; transfers depend on customer location | AWS customer agreement; DPA available |
| Stripe | Checkout, subscriptions, invoices | billing contact, payment method, tax data | per Stripe configuration | Stripe services agreement; DPA available |
| Vercel | static/SSR website hosting | HTTP request metadata, no console database | global edge; check Vercel DPA | Vercel terms; DPA available |
| GitHub | source hosting, releases, CI | contributor identity, repository metadata | US | GitHub terms; DPA available |
| Cloudflare | authoritative DNS | DNS query metadata | global anycast | Cloudflare terms; DPA available |

**Not subprocessors:** an email provider used only for the owner's personal
mailbox, a local development database, and any analytics tool not listed above.
If one is added, this table and `SUBPROCESSORS.md` change before it processes
customer data.

## 5. International transfers

The hosted database and functions run in `us-east-1`. A customer in Argentina or
the EU is therefore sending account metadata to the United States. The legal
mechanism for that transfer is an open question for counsel; the repository does
not claim an adequacy decision, SCCs, or a transfer impact assessment that has
not been signed. `[COUNSEL-REVIEW-REQUIRED]`

## 6. Deletion and export

- `GET /v1/account/export` returns the authenticated account's stored records.
- `DELETE /v1/account` removes the account and its dependent rows in the
  control-plane schema, subject to records the operator must keep for tax or
  fraud prevention.
- Backups are point-in-time and age out under the RDS retention window; a
  deletion does not rewrite an existing backup. The operator must state that
  limit in the DPA.
- The self-hosted gateway deletion is entirely the operator's procedure; the
  project cannot delete a customer's WAL.

## 7. Open items

| Item | Owner | Blocks |
| --- | --- | --- |
| Confirm the actual RDS retention window and backup policy | operations | DPA Schedule B |
| Confirm whether SES stores message bodies and for how long | operations | privacy policy email section |
| Decide whether the hosted console is offered outside Argentina at launch | owner | transfer mechanism, tax |
| Add a cookie inventory if non-essential cookies are introduced | web owner | cookie notice |
| Have counsel review this map against the schema | counsel | legal gate |
