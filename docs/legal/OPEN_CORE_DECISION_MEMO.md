<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
-->

# Open-core Decision Memo

**Audience:** the owner, who decides, and counsel, who confirms.
**Scope:** what the gateway and the engine modules do without an entitlement token, and the boundary a paid offering could draw.
**Boundary:** a memo that records facts from code and asks for a decision. It does not make the decision.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent for the owner and qualified counsel. It is not legal advice, has not been reviewed by a lawyer, has not been offered to anyone, and nobody has signed it. Bracketed fields `[●]` are open decisions, not defaults. Do not send it to a counterparty before counsel has reviewed it.

> **[SUPERSEDED-IN-PART — 5.0.2]** The memo's options assumed the right to avoid AGPL obligations was a commercial asset. That right no longer exists for the `5.0.2` source, which is Apache-2.0; the owner must decide the open-core boundary again. See [Licence Transition 5.0.2](LICENSE_TRANSITION_5.0.2.md).

## What the code does today

| Question | Answer | Where |
| --- | --- | --- |
| Does the gateway need a licence to run? | No. It "runs unlicensed", and the licensing package changes no gateway behaviour | `aegis/licensing/__init__.py` |
| What does a token unlock? | The optional engine facades, by module name: `veracity`, `sanctum`, `agentis`, `sovereign`, and `omnia` as the wildcard for all four | `aegis/licensing/model.py`, `aegis/engines/__init__.py` |
| Who can check a token, and how? | Anyone with the vendor public key, offline. No network call | `aegis/licensing/validator.py` |
| Can a token be tied to a machine or revoked? | No. It is a bearer credential; revocation needs a root-key rotation and reissue | `aegis/licensing/validator.py` |
| Is the transaction figure enforced? | No. It is a commercial term | `aegis/licensing/validator.py` |
| Can the entitlement checks be removed? | Yes, by anyone holding the source (Apache-2.0 from `5.0.2`, AGPLv3 for the published releases up to `5.0.1`); the entitlement value is then contractual, not technical | follows from either grant |

## A correction to the register

`REG-H04` says "no feature is withheld by a runtime check". That is true of the **gateway** and false of the **engine facades**, which a token gates. The register should say so. Either the sentence changes, or the facades stop being gated. This memo asks the owner which.

## Options

| Option | What it means | Consequence |
| --- | --- | --- |
| A. Keep facades gated | Commercial value is the four engine modules as an entitlement signal (the right to avoid AGPL obligations no longer exists for `5.0.2`) | Consistent with the code. The gate is trivially removable from source, so the contract must carry the weight |
| B. Ungate facades, sell only support and assurance | Nothing is withheld by a check | Simplest to explain, and the shipped default. Revenue depends wholly on support, indemnification and assurance |
| C. Move some facades to a separate proprietary package | A hard technical boundary | Needs a separate repository and release pipeline, and splits the Apache-2.0 story. Larger work than A or B |

## Recommendation

Recorded before the relicence: Option A for the first customers, because it matched the shipped code and needed no change, stating the boundary plainly in the agreement (clauses 2.2 and 6 of the [template](COMMERCIAL_LICENSE_TEMPLATE.md)) rather than implying a technical enforcement the software does not have. **That recommendation is superseded:** its premise, the right to avoid AGPL obligations, no longer exists for the `5.0.2` source, and under Apache-2.0 the gate stays trivially removable. The shipped code keeps the opt-in gate as an entitlement signal. This memo does not make the new decision; the owner does, after a pilot shows which modules a buyer values.

## Decision record

| Field | Value |
| --- | --- |
| Decision | `[A / B / C]` |
| Decided by | `[owner: owner action]` |
| Date | `[●]` |
| Counsel confirmation | `[●]` |
