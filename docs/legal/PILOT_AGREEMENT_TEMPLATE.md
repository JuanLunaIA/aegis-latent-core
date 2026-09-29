<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Paid Pilot Agreement: Template

**Audience:** counsel and the owner turning the [pilot proposal](../commercial/SALES_KIT/PILOT_PROPOSAL.md) into a contract a customer can sign.
**Scope:** a fixed-scope, time-boxed, paid evaluation of one workload with written acceptance criteria.
**Boundary:** a template. No pilot has been executed, no customer exists and no price has been validated.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent for the owner and qualified counsel. It is not legal advice, has not been reviewed by a lawyer, has not been offered to anyone, and nobody has signed it. Bracketed fields `[●]` are open decisions, not defaults. Do not send it to a counterparty before counsel has reviewed it.

## Parties and scope

| Field | Value |
| --- | --- |
| Vendor | `[●]` (see the entity note in the [Commercial Licence Template](COMMERCIAL_LICENSE_TEMPLATE.md)) |
| Customer | `[legal entity]` |
| Sponsor | `[name, title]`, who owns the record-keeping obligation |
| Workload | **One** named workload: `[●]` |
| Environments | `[●]` |
| Deployment shape | `[gateway / embedded]` |
| Duration | `[4 to 8]` weeks, fixed. Extensions are a new agreement |
| Fee | `[●]`, `[HYPOTHESIS-UNVALIDATED]`; payable `[before start / on milestones]` |
| Dates | `[start]` to `[end]` |

## 1. Licence during the pilot

The Customer may run the Licensed Software `[tag and commit]` in the named Environments for the duration under a non-exclusive, non-transferable evaluation licence. The AGPLv3 remains available for the same source; the pilot does not gate anything the Customer could run alone.

## 2. Acceptance criteria

The criteria are those in the pilot proposal, recorded verbatim in Schedule 1 before work starts and judged literally. Criterion 6 (redaction on the Customer's corpus) is **measured and reported**, not pass or fail. A pilot with no recorded outcome for a criterion is not accepted on that criterion.

## 3. What is not promised

Compliance determinations, certification, an SLA (response is best-effort for the duration), debugging of the Customer's provider, identity provider, Redis, storage or ingress, custom development, and production cutover. The pilot produces technical inputs the Customer and its assessor evaluate.

## 4. Customer obligations

Provide the named environments and a technical lead on time; supply access under the Customer's own controls; keep any entitlement token confidential; record operator time for criterion 7.

## 5. Data

The pilot runs on the Customer's infrastructure. Vendor staff access Customer systems only through access the Customer grants and logs `[data-processing terms if any access to personal data: Schedule 2, counsel to draft]`.

## 6. References and publicity

The Vendor may name the Customer only with written permission. Granting permission is not a condition of the pilot.

## 7. Exit

At the end date exactly one of these follows, and each is an acceptable outcome: proceed to a commercial licence; stop (the Customer keeps what it learned and the AGPLv3 source); or extend under a new agreement with new criteria. A pilot without a recorded decision at the end date is a failed pilot.

## 8. Liability and general terms

Cap `[●]`; exclusions `[●]`; governing law `[●]`; forum `[●]`; confidentiality `[mutual, term ●]`. **Counsel:** keep these consistent with the commercial licence so the pilot does not set a precedent the licence must undo.

## Schedule 1: acceptance criteria

`[copy the seven criteria from the pilot proposal after the Customer and Vendor agree the values for [N]]`

## Signatures

| Party | Name, title | Date |
| --- | --- | --- |
| Vendor | `[signatory: owner action]` | `[●]` |
| Customer | `[signatory: customer action]` | `[●]` |
