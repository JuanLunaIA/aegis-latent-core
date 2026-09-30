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

Set up through the Brevo API on 2026-09-30, with the owner's key and after the owner authorized this environment's outgoing addresses in Brevo. Read back the same day:

| Object | State |
| --- | --- |
| Account | "Aegis Latent Core", free plan; one active sender (id 1) |
| Contact attributes added | `ORGANISATION`, `ROLE`, `SEGMENT`, `LEAD_SOURCE`, `LOG_ID`, `CONSENT_BASIS` (text), `CONSENT_DATE` (date). Names use the account's own `NOMBRE` and `APELLIDOS` |
| List | "Opted in", id 3, 0 contacts, in folder 1. The pre-existing "Su primera lista" (id 2) was not touched |
| Templates, all **inactive** | 1 "Aegis - Opt-in confirmation" (tag `optin`), 2 "Aegis - Send me information", 3 "Aegis - Investor update" |
| Campaigns | none. Nothing was scheduled or sent |

Not done by the agent: turning double opt-in on for a form (Brevo's form editor, which picks template 1), importing contacts, filling the sender's legal name and postal address, and activating any template. Each is yours. Rotate the API key used here, since it was pasted into a chat.

## The kit

| Piece | Path | What it does |
| --- | --- | --- |
| Contact sheet template | [`brevo/contacts_template.csv`](brevo/contacts_template.csv) | Header only. Copy it **outside the repository** and fill it in; it is the only place an address lives. |
| Exporter | [`tools/validation/brevo_export.py`](../../../tools/validation/brevo_export.py) | Turns that sheet into a Brevo import file. Refuses a row with no consent basis, no real past consent date, a malformed or duplicate address, or an unknown segment or source; skips anyone marked `opted_out`; reports by row and log id, never by address; refuses paths inside the repository. |
| Opt-in confirmation | [`brevo/optin_confirmation.html`](brevo/optin_confirmation.html) | Double opt-in message. |
| "Send me information" reply | [`brevo/send_me_information.html`](brevo/send_me_information.html) | Two links and the disqualifiers. |
| Investor update | [`brevo/investor_update.html`](brevo/investor_update.html) | Shell for the output of `tools/raise/monthly_update.py`. |

```bash
python tools/validation/brevo_export.py ~/contacts_private.csv --out ~/brevo_import.csv
```

Both files stay in your home directory; `.gitignore` also blocks `contacts_private*.csv` and `brevo_import*.csv` if one is ever copied into the tree.

## Steps (1 to 3 done 2026-09-30)

1. Read only: account, verified senders, existing lists and templates. Report what is already there before creating anything.
2. Create the contact attributes in the table below.
3. Create one list, "Opted in", with double opt-in on. Create the three drafts from the files above. **Do not create a campaign with a send date.**
4. Hand back the list id, the template ids and the exporter command. Import is yours: `brevo_export.py` output goes in through Brevo's import screen, so the consent columns arrive with the contacts.
5. After any real send, read campaign statistics and record replies and calls in the validation log; opens are not counted.

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
| `EMAIL`, `NOMBRE`, `APELLIDOS` | as given by the person |
| `ORGANISATION`, `ROLE` | as in the validation log row |
| `SEGMENT` | one of `fintech`, `healthtech`, `insurance`, `challenged` |
| `LEAD_SOURCE` | one of `oss`, `partner`, `event`, `direct`, as in the log |
| `LOG_ID` | the `V-nn` row |
| `CONSENT_BASIS` | how the person asked to be contacted, in words |
| `CONSENT_DATE` | ISO date |

## Drafts (not sent)

1. **Opt-in confirmation.** One sentence on what the list is for, the confirm link, and the sender identity block.
2. **"Send me information" reply.** [One Pager](../SALES_KIT/ONE_PAGER.md) and [Prove It Yourself](../../PROVE_IT.md) links, nothing else. Wording follows [Outbound Sequences](../SALES_KIT/OUTBOUND_SEQUENCES.md) rules 1 to 7.
3. **Investor update.** For holders who agreed to receive it, built from `python tools/raise/monthly_update.py --month YYYY-MM`; the figures are the tool's, not typed by hand.

The Brevo variable names in the files (`{{ contact.NOMBRE }}`, `{{ unsubscribe }}`, `{{ params.DOIurl }}`) were written from memory of Brevo's template syntax, not checked against its editor; confirm them when the drafts are created.

## Before the first real send

- **Sender identity.** A commercial email carries the sender's legal name and a postal address. The company is not formed, so this block is empty; fill it once it exists, or send as the individual and say so.
- **Law.** Consent and cold-email rules differ by country and recipient type; this has not been reviewed. It is question material for [Questions for Counsel](../../legal/COUNSEL_QUESTIONS.md).
- **Data role.** Brevo would process contact data on your behalf; a data processing agreement and a line in your privacy notice are counsel's to confirm.
- **Copy check.** `python scripts/lint_sales_copy.py docs/commercial/validation` before any draft is reused.
