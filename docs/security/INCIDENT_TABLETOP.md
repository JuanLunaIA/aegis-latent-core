<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Incident-response tabletop

**Status:** scenario and evaluation sheet. **No tabletop has been run.** This
file is not evidence of incident readiness; it is the exercise that produces
such evidence when a dated record is appended.

**Audience:** owner, operator, counsel, and the person who will answer a
customer during an incident.
**Scope:** a 90-minute tabletop for the hosted evaluation console and the
self-hosted reference deployment.
**Boundary:** a plan. The account currently has no alarm delivery, no 24/7
staffed rotation, and no tested RDS restore.

## Scenario A — leaked API key and anomalous usage

**Inject at T+0:** a customer reports that a key prefix appears in a public
repository. The console shows a spike in `POST /v1/usage` from two countries.

Questions the team must answer without looking at this file:

1. Who can revoke the key, and how long does it take? (`POST /v1/keys/{id}/rotate`
   is atomic; verify the old key stops working.)
2. What evidence identifies the tenant and the time window without exposing
   another customer's data?
3. Who notifies the customer, within what time, and with what facts?
4. Is this a personal-data breach? Who decides, and on what record?
5. What is preserved for forensics, and what is deleted by rotation?
6. What is said publicly, and who approves it?

**Pass condition:** a named person performs each step, the old key is proven
dead, and the customer notification contains no unsupported cause.

## Scenario B — RDS unavailable during a paid pilot

**Inject at T+0:** `/readyz` fails; Lambda returns 5xx; the RDS console shows
`storage-full` or a failed maintenance event.

1. Who is paged? (Today: nobody. That is the finding.)
2. What is the customer-facing status, and where is it published? (No status
   page is live.)
3. What is the last verified backup, and when was a restore last executed?
   (No RDS restore has been executed.)
4. What is the RTO/RPO claim, and is it tested?
5. Who decides to fail over, and to what?
6. What is refunded or credited, under which contract?

**Pass condition:** the team discovers that the monitoring and restore paths are
not real before a customer does, and records the gap as an action.

## Scenario C — signing-key compromise

**Inject at T+0:** a WAL signature verifies under a key the operator did not
expect, or a private key file appears in a backup.

1. Which keys exist, where are they, and who can read them?
2. Can the ledger distinguish a compromised key from a rotated key?
3. What is the blast radius of re-signing? What cannot be repaired?
4. Who decides to stop the gateway, and what does the customer see?
5. Is law enforcement or a regulator involved? Who decides?
6. What is disclosed, and what is withheld under privilege?

**Pass condition:** the team can name the key inventory and the containment
step; it does not improvise a re-sign.

## Scenario D — support access to customer data

**Inject at T+0:** a support engineer asks for a copy of a customer's WAL to
debug a proof failure.

1. Is there a written access approval? Who signs?
2. What is the minimum data needed, and can it be redacted?
3. Where is the copy stored, for how long, and who can read it?
4. Does the DPA permit this access? Is the customer notified?
5. How is the copy destroyed, and is destruction recorded?

**Pass condition:** access is refused without approval, or granted with a
time-boxed, logged, minimized copy.

## Evaluation sheet

| Dimension | 0 | 1 | 2 | Notes |
| --- | --- | --- | --- | --- |
| Detection | nobody knew | a customer told us | our alarm told us | |
| Time to acknowledge | > 4 h | 1–4 h | < 1 h | |
| Roles | unclear | named but absent | named and present | |
| Customer comms | none | ad hoc | approved template | |
| Evidence | lost | partial | preserved and hashed | |
| Restore | untested | attempted | proven | |
| Decision log | none | chat | dated record | |
| Follow-up | none | list | owners and dates | |

A score below 12/16 is a finding, not a pass.

## Record

Append:

| Date | Scenario | Participants | Score | Gaps found | Owner actions | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| `[DATE]` | A/B/C/D | `[NAMES]` | `[0–16]` | `[LIST]` | `[OWNER + DATE]` | `[PATH/HASH]` |

Do not write "tabletop completed" until this row exists with a date and
participants.
