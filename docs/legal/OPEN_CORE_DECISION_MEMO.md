<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Open-core Decision Memo

**Audience:** the owner, who decides, and counsel, who confirms.
**Scope:** what the gateway and the licensed modules do without a licence, and the boundary the commercial licence should draw.
**Boundary:** a memo that records facts from code and asks for a decision. It does not make the decision.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent for the owner and qualified counsel. It is not legal advice, has not been reviewed by a lawyer, has not been offered to anyone, and nobody has signed it. Bracketed fields `[●]` are open decisions, not defaults. Do not send it to a counterparty before counsel has reviewed it.

## What the code does today

| Question | Answer | Where |
| --- | --- | --- |
| Does the gateway need a licence to run? | No. It "runs unlicensed", and the licensing package changes no gateway behaviour | `aegis/licensing/__init__.py` |
| What does a token unlock? | The optional engine facades, by module name: `veracity`, `sanctum`, `agentis`, `sovereign`, and `omnia` as the wildcard for all four | `aegis/licensing/model.py`, `aegis/engines/__init__.py` |
| Who can check a token, and how? | Anyone with the vendor public key, offline. No network call | `aegis/licensing/validator.py` |
| Can a token be tied to a machine or revoked? | No. It is a bearer credential; revocation needs a root-key rotation and reissue | `aegis/licensing/validator.py` |
| Is the transaction figure enforced? | No. It is a commercial term | `aegis/licensing/validator.py` |
| Can the entitlement checks be removed? | Yes, by anyone holding the AGPLv3 source; the licence value is then contractual, not technical | follows from the AGPLv3 grant |

## A correction to the register

`REG-H04` says "no feature is withheld by a runtime check". That is true of the **gateway** and false of the **engine facades**, which a token gates. The register should say so. Either the sentence changes, or the facades stop being gated. This memo asks the owner which.

## Options

| Option | What it means | Consequence |
| --- | --- | --- |
| A. Keep facades gated | Commercial value is the four engine modules plus the right to avoid AGPL obligations | Consistent with the code. The gate is trivially removable from source, so the contract must carry the weight |
| B. Ungate facades, sell only the licence and support | Nothing is withheld by a check | Simplest to explain. Revenue depends wholly on AGPL avoidance, support and assurance |
| C. Move some facades to a separate proprietary package | A hard technical boundary | Needs a separate repository and release pipeline, and splits the AGPL story. Larger work than A or B |

## Recommendation

Option A for the first customers, because it matches the shipped code and needs no change. State the boundary plainly in the licence (clauses 2.2 and 6 of the [template](COMMERCIAL_LICENSE_TEMPLATE.md)) rather than implying a technical enforcement the software does not have. Revisit after the first pilot shows which modules a buyer actually values.

## Decision record

| Field | Value |
| --- | --- |
| Decision | `[A / B / C]` |
| Decided by | `[owner: owner action]` |
| Date | `[●]` |
| Counsel confirmation | `[●]` |
