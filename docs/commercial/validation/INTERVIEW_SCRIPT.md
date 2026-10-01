<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
-->

# Buyer Interview Script and Notes Template

**Audience:** the founder, running three buyer interviews (milestone `M2`, `REG-H06`).
**Scope:** a 25-minute script that tests one hypothesis without selling, and the note that each interview must leave behind.
**Boundary:** a listening script. The owner attends the interviews; the agent does not. It tests hypothesis "regulatory urgency" from D10.2, which is `H`. Its confirm and kill lines are copied from there.

## The hypothesis and the test

| | |
| --- | --- |
| Hypothesis | Compliance leads have received an examiner request for AI records (Frame A). `H` |
| Confirm | At least 2 of 3 interviewees cite an examiner request for AI records. `H` |
| Kill | 0 of 3, or all 3 already satisfied by WORM storage plus SIEM. `H` |

An interviewee "cites an examiner request" only if they name a request they or their team received, from a regulator or examiner, for records of AI use, and roughly when. A worry about being asked does not count. Record the distinction; it decides the result.

## Before the call

Say who you are, that this is research and not a sales call, and that you will not pitch. Ask permission to take notes. Do not record without consent.

## Script (25 minutes)

| Min | Ask | Listen for |
| --- | --- | --- |
| 0 to 3 | "What is your role, and what AI systems does your team answer for?" | Organisation type and the role that owns the record |
| 3 to 8 | "Has a regulator, examiner or auditor asked for records of how AI was used? What did they ask for, and when?" | A specific request, its date, who asked, what was handed over |
| 8 to 13 | "How did you answer? Where did that record come from, and who can change it?" | WORM or SIEM already covering it, or a database people can edit |
| 13 to 18 | "If that request came tomorrow for one case from six months ago, what would you do?" | Whether the answer is a process or a scramble |
| 18 to 22 | "What would make you trust a record you did not produce yourself?" | Their own bar for third-party verification, in their words |
| 22 to 25 | "Who else should I speak to? May I follow up in a few months?" | Referrals; permission, recorded |

Do not describe the product until the last five minutes, and only if asked. If asked about the disqualifiers, read them: no SOC 2, no penetration test, one maintainer, no SLA outside a signed agreement, self-hosted only.

## The note (one per interview, within 24 hours)

Save as `interview_notes_ref` in the log, for example `notes/V-11.md`. Notes contain what was said, not what was hoped.

| Field | Content |
| --- | --- |
| Log row | `V-nn` |
| Date and length | |
| Organisation type and role | Type only if the interviewee asked for anonymity |
| Cites an examiner request | `yes` / `no` / `unclear`, with the words used |
| Request date and requester | |
| How it was answered | |
| Current record store and who can write to it | |
| Trust bar in their words | |
| Follow-up permission | `yes` / `no` |
| What surprised you | |

The data room lists "Buyer interview notes" as missing until three such notes exist (`REG-H06`, `M2`).
