<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# MSA and Order Form template

**Audience:** counsel, then a named customer.
**Scope:** the two documents a paid customer signs: a master agreement and an
order form that supplies the commercial variables.
**Boundary:** an unfilled template. Bracketed fields are decisions, not
defaults. It has not been reviewed by counsel, offered to anyone, or signed.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent. Not legal advice.
> Do not send to a counterparty before counsel review.

## Order of precedence

1. The signed Order Form (commercial variables: plan, fees, term, support).
2. This MSA.
3. The Data Processing Addendum, if personal data is processed by the hosted
   console or by support access.
4. `LICENSE` for the software licence grant; the MSA does not broaden it.
5. The documentation at the commit or release named in the Order Form.

If documents conflict, the Order Form wins only for the variable it states. A
statement in a sales email does not amend the MSA.

## 1. Parties

| Field | Value |
| --- | --- |
| Supplier legal name | `[OWNER INPUT REQUIRED]` |
| Supplier registration / tax ID | `[OWNER INPUT REQUIRED]` |
| Supplier address | `[OWNER INPUT REQUIRED]` |
| Customer legal name | `[CUSTOMER]` |
| Customer registration / tax ID | `[CUSTOMER]` |
| Customer address | `[CUSTOMER]` |
| Effective date | `[DATE]` |

## 2. Scope

Supplier provides the software licence and, if the Order Form says so, the
hosted evaluation console and support. The software is self-hosted unless the
Order Form expressly says otherwise. The hosted console is not an inference
gateway and does not receive customer model prompts or outputs.

## 3. Fees and payment

| Field | Value |
| --- | --- |
| Plan | `[TEAM / BUSINESS / ENTERPRISE / PILOT]` |
| Fee | `[USD amount]` |
| Billing period | `[monthly / annual / one-time]` |
| Payment method | `[Stripe invoice / bank transfer]` |
| Taxes | exclusive of VAT/GST/withholding; customer bears applicable taxes |
| Late payment | `[counsel to set: suspension after notice, no penalty clause]` |
| Refund | per `docs/legal/REFUND_POLICY.md`, only where applicable law requires |

Prices are hypotheses until an Order Form is signed. The website's quote-only
model means no price is accepted by clicking a button.

## 4. Term and termination

- Initial term: `[12 months / pilot length]`.
- Renewal: `[explicit written renewal / automatic with notice]`; automatic
  renewal must comply with applicable consumer and commercial law.
- Termination for material breach: `[30 days]` cure after written notice.
- Termination for insolvency: immediate on written notice.
- Effect: customer stops using the software; the licence to the affected
  version ends as stated in `LICENSE`; payment for the elapsed term is due.
- Survival: confidentiality, IP, payment, liability, and governing law.

## 5. Licence and restrictions

The software licence is `LICENSE` (Aegis Commercial License 1.0) for the version
delivered. The MSA does not grant rights to the name, logo, or source of a later
version. Customer may not remove notices or circumvent entitlement checks.
Open-source components remain under their own licences; see
`LICENSE-THIRD-PARTY.md`.

## 6. Support

Support is `[email / named channel]`, during `[business hours]`, with
`[no SLA / response target]`. The default is **no SLA**. A response target is
not a resolution guarantee. 24/7 staffed support is not offered unless the
Order Form names the staffed rotation and the fee.

## 7. Data and privacy

If the hosted console processes account or usage data, the DPA applies. If
support accesses customer data, the DPA and a written access approval apply.
The customer is responsible for the data it puts into the self-hosted gateway,
including whether previews are enabled and how long the WAL is retained.

## 8. Confidentiality

Each party protects the other's confidential information with at least
reasonable care, uses it only for the agreement, and returns or destroys it on
request, except where law requires retention. The software's public source is
not confidential; customer data and pricing are.

## 9. IP and feedback

Supplier retains all rights in the software and marks. Customer retains all
rights in its data and its own applications. Feedback may be used without
obligation, but no customer confidential information is included.

## 10. Warranties and disclaimers

Supplier warrants that it has the right to grant the licence and that the
delivered software materially conforms to the documentation for `[30]` days.
**Except for that warranty, the software is provided "as is" to the maximum
extent permitted by law.** No warranty of fitness, non-infringement, accuracy,
or regulatory compliance. This is a draft position for counsel; consumer law
may prohibit parts of it.

## 11. Indemnity and liability

- Supplier indemnifies customer against a third-party claim that the software,
  as delivered, infringes a copyright or trade secret, subject to customer's
  prompt notice and control of the defence.
- Customer indemnifies supplier against claims arising from customer data or
  customer's use outside the documentation.
- Liability cap: `[counsel to set: fees paid in the 12 months before the claim]`.
- Excluded: indirect, incidental, special, consequential damages, lost profits,
  lost data, business interruption, except where law prohibits exclusion.
- The cap does not apply to wilful misconduct, IP indemnity, or breach of
  confidentiality, as counsel advises.

## 12. Export and sanctions

Customer complies with applicable export controls and sanctions. The software
includes cryptographic functions; an export classification is pending. Supplier
may refuse an Order from a restricted destination or party.

## 13. Governing law and forum

`[COUNSEL TO SELECT: Argentina / customer jurisdiction / arbitration]`. The
current draft points to Argentina; a customer may not accept it. Do not sign
until counsel selects and the Order Form repeats it.

## 14. Notices

Legal notices to the addresses in the Order Form, with a copy by email.
Operational notices may use the support channel.

## 15. Entire agreement

The documents listed in "Order of precedence" are the entire agreement. A
purchase order or vendor portal term is rejected unless the Order Form
expressly accepts it.

## Signature blocks

| Supplier | Customer |
| --- | --- |
| Name: `[OWNER INPUT REQUIRED]` | Name: `[CUSTOMER]` |
| Title: `[OWNER INPUT REQUIRED]` | Title: `[CUSTOMER]` |
| Signature: | Signature: |
| Date: | Date: |
