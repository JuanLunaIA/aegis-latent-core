<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Brevo Plan: What the Connector Is For

**Audience:** the founder.
**Scope:** how the Brevo connector, authorized on 2026-09-30, fits the validation work: what goes into it, what is drafted there, and what stays out.
**Boundary:** a plan, not an account state. The session that wrote this could not call Brevo (see "Status"), so nothing here was created, imported or sent in Brevo, and no Brevo behaviour is asserted beyond what the connector describes: analyse campaigns, know an audience, create drafts.

## Status

The connector reports as connected and enabled for the session, but none of its tools were exposed to it, so no list, template or draft exists in Brevo yet. The first session in which the Brevo tools load starts with read-only calls (account, senders, lists) and then creates the drafts below. Nothing is sent by the agent.

## Where it fits, and where it does not

| Use | Why |
| --- | --- |
| Double opt-in list of people who ask to hear from you (site form, interviewees who agree, pilot contacts) | Consent is recorded per contact and the list is yours to show counsel |
| Drafts of replies to "send me information" (One Pager and Prove It Yourself links) | Reuses the existing sequence rules; the owner reviews and sends |
| Read-only campaign statistics fed into the validation log | Replies and calls count; opens do not, because image-load counts are unreliable |
| **Not** batch 1 | [Outbound Batch 1](OUTBOUND_BATCH_1.md) rule 1: the owner sends each first touch personally from the owner's own address. Unsolicited first touches are the case a bulk-sending platform's terms most often restrict; read Brevo's current terms before any list that is not opted in goes near it. |
| **Not** a purchased, scraped or borrowed list | No consent basis, and it would contradict the batch-1 selection rule (public source you can cite) |

## Contact attributes

Create these attributes before any import, so every contact carries its basis:

| Attribute | Content |
| --- | --- |
| `EMAIL`, `FIRSTNAME`, `LASTNAME` | as given by the person |
| `ORGANISATION`, `ROLE` | as in the validation log row |
| `SEGMENT` | one of `fintech`, `healthtech`, `insurance`, `challenged` |
| `LEAD_SOURCE` | one of `oss`, `partner`, `event`, `direct`, as in the log |
| `LOG_ID` | the `V-nn` row |
| `CONSENT_BASIS` | how the person asked to be contacted, in words |
| `CONSENT_DATE` | ISO date |

## Drafts to create (not sent)

1. **Opt-in confirmation.** One sentence on what the list is for, the confirm link, and the sender identity block.
2. **"Send me information" reply.** [One Pager](../SALES_KIT/ONE_PAGER.md) and [Prove It Yourself](../../PROVE_IT.md) links, nothing else. Wording follows [Outbound Sequences](../SALES_KIT/OUTBOUND_SEQUENCES.md) rules 1 to 7.
3. **Investor update.** For holders who agreed to receive it, built from `python tools/raise/monthly_update.py`; the figures are the tool's, not typed by hand.

## Before the first real send

- **Sender identity.** A commercial email carries the sender's legal name and a postal address. The company is not formed, so this block is empty; fill it once it exists, or send as the individual and say so.
- **Law.** Consent and cold-email rules differ by country and recipient type; this has not been reviewed. It is question material for [Questions for Counsel](../../legal/COUNSEL_QUESTIONS.md).
- **Data role.** Brevo would process contact data on your behalf; a data processing agreement and a line in your privacy notice are counsel's to confirm.
- **Copy check.** `python scripts/lint_sales_copy.py docs/commercial/validation` before any draft is reused.
