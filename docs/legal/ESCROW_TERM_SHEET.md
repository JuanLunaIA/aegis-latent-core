<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Escrow Term Sheet

**Audience:** the owner choosing an escrow agent, and counsel drafting the tri-party agreement.
**Scope:** the terms the vendor is prepared to propose. It turns the [Software Escrow and Continuity Policy](../commercial/SOFTWARE_ESCROW_POLICY.md) into an agenda for an agent and a buyer.
**Boundary:** no agent is engaged, no agreement exists and no deposit has been made. Escrow reduces artifact risk; it does not reduce key-person risk.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent for the owner and qualified counsel. It is not legal advice, has not been reviewed by a lawyer, has not been offered to anyone, and nobody has signed it. Bracketed fields `[●]` are open decisions, not defaults. Do not send it to a counterparty before counsel has reviewed it.

## Proposed terms

| Term | Proposal | Open point |
| --- | --- | --- |
| Parties | Vendor, Beneficiary (buyer), Escrow Agent | Agent `[●]`; neither candidate named in the policy has been engaged |
| Deposit | Full source at each released tag; build pipeline definitions; private packaging repository configuration; deployment manifests and Helm charts; architecture and operations documentation; the licence-signing key **custody procedure** | Update cadence `[on each release / quarterly]` |
| Never deposited | The Ed25519 licence-signing private key; customer key material; secrets | None. A key that mints entitlements for every customer is a larger risk than the one escrow addresses |
| Verification | The agent independently rebuilds a working artifact from the deposit and reports the result | Level `[●]`; a deposit that was never rebuilt is not evidence |
| Release conditions | Vendor ceases business; vendor becomes insolvent; vendor fails contracted support, uncured after notice; vendor discontinues without a migration path | Notice period `[●]`; condition 3 needs Schedule A of the licence to set support targets |
| Licence on release | Right to use, modify and maintain the deposited materials for the Beneficiary's internal use | Whether it survives beyond the licence Term `[●]` |
| Fees | `[●]`, payer `[Vendor / Beneficiary]` | The register carries a cost range only as a planning input |
| Governing law and forum | `[●]` | Agent's standard terms usually decide this |

## Sequence

1. The owner selects an agent. No agent has reviewed this sheet.
2. The agent's standard tri-party agreement is compared to this sheet by counsel.
3. The first deposit is made and verified before any buyer relies on it.
4. Each licence that includes escrow references the executed agreement in its Schedule D.

## What a buyer should insist on

The executed agreement; dated evidence of deposit with the agent's verification report; the release-condition wording read by the buyer's counsel; a post-release maintenance plan naming who would run the code.

## Closing the register item

`REG-H03` closes only when a tri-party agreement is signed and a verified deposit exists. This sheet does neither.
