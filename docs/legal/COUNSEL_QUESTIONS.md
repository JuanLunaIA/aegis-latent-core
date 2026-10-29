<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Questions for Counsel

**Audience:** qualified software-licensing, corporate and regulatory counsel.
**Scope:** the questions the drafts cannot answer and should not guess.
**Boundary:** questions, not positions. Answers belong in writing from counsel, dated, and are then reflected in the drafts.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent for the owner and qualified counsel. It is not legal advice, has not been reviewed by a lawyer, has not been offered to anyone, and nobody has signed it. Bracketed fields `[●]` are open decisions, not defaults. Do not send it to a counterparty before counsel has reviewed it.

| # | Question | Why it matters | Blocks |
| --- | --- | --- | --- |
| 1 | Part of the code was produced with AI-assisted tooling operated by the founder. In the relevant jurisdictions, what copyright subsists, who owns it, and what may the licensor warrant or indemnify? | Every licence grants rights and may warrant ownership | IP indemnity, ownership warranty, the assignment (`REG-H10`, `REG-H04`) |
| 2 | For a recipient of a release up to `5.0.1` published under the AGPLv3, which network-use and source obligations still apply once `5.0.2` is Apache-2.0, and what, if anything, is owed to them? | Decides what earlier recipients are told | Release notes and the support-agreement story |
| 3 | Is the offline bearer-token design (no revocation, no binding, expiry by host clock) adequate to support the contractual reporting and audit clauses? | Enforcement is contractual | Clauses 2.2 and 6 |
| 4 | Is the DCO plus lightweight CLA in `CONTRIBUTING.md` enough to relicense future contributions, or is an assignment or broader licence needed, now that inbound and outbound are both Apache-2.0? | Decides whether the CLA stays | Accepting outside contributions |
| 5 | What should the copyright notice and licensor name be after the company is formed, and what is the correct order for assignment and first licence? | Avoids a licence issued by the wrong party | First signature |
| 6 | Export classification and any filing for the cryptographic functions, including post-quantum signatures | Affects delivery to some countries | Clause 10 |
| 7 | Do the MiFID II and MAR input modules and the reference to the senior managers regime create regulatory-adjacent statements that need review before sale? | Buyers in financial services will ask | `REG-H10` |
| 8 | What governing law, forum and liability structure suit a sole-founder company selling to regulated buyers? | Sets the caps and the forum | Licence and pilot general terms |
| 9 | When do support staff access to customer data require a data-processing agreement, and what should Schedule C contain? | Self-hosted deployments avoid it until support needs access | Support terms |
| 10 | Is a single form of company (jurisdiction, type) preferable for a seed round that uses SAFE instruments? | Affects formation and investor documents | `REG-H09` |
| 11 | **Relicence confirmation.** Does the owner hold the right to relicense the whole tree to Apache-2.0 for `5.0.2`, given automation-authored commits (Dependabot version bumps and four commits by an automated code assistant account that touched generated files) and AI-assisted material? What happens to any commercial agreement already executed? | Publishing `5.0.2` asserts a licence the owner may not be able to grant | Publication of `5.0.2` (`docs/legal/LICENSE_TRANSITION_5.0.2.md`) |

## How answers are recorded

Counsel replies in writing. The owner saves each reply in the data room, and the affected draft is updated with a note naming the question number and the date. A draft is ready to offer only when every question that blocks it has a recorded answer.

## v5.0.3 — commercial licence questions

Added when the source moved from Apache-2.0 to the Aegis Commercial License 1.0.
These block the public v5.0.3 release; the earlier list remains open for the
historical record.

| # | Question | Why it matters | Blocks |
| --- | --- | --- | --- |
| 12 | Is the production-use restriction in `LICENSE` §2 enforceable against a recipient who also holds the Apache-2.0 `5.0.2` copy? | The forward-only boundary must survive contact with a fork | `docs/legal/LICENSE_TRANSITION_5.0.3.md` §4, release notes |
| 13 | Is the "no competing managed service" clause (§3b) enforceable in the target markets, and does it cover a customer that hosts the software for its own customers? | It is the main commercial lever after the code is public | `LICENSE`, sales terms |
| 14 | Does `CLA.md` §5 grant the right to relicense inbound contributions from Apache-2.0 to proprietary? | Without it, an outside contribution can block the model | Accepting any outside contribution |
| 15 | Is the liability cap in §8 enforceable against small businesses and consumers in AR, EU and US? | Sets the insurance and contract structure | First paid Order |
| 16 | Which governing law and forum should replace the draft (Argentina, Rosario)? | A forum the buyer does not accept stalls procurement | `LICENSE` §11 |
| 17 | What must the privacy policy say about IP addresses and user agents stored with sessions (`app/repos/sessions.py`) and about Stripe/SES as subprocessors? | The policy must match the schema, not an aspiration | `docs/legal/PRIVACY_POLICY.md`, DPA |
| 18 | Are automatic renewal and the refund terms compliant in each market? | Consumer law varies; a wrong clause is void | `docs/legal/REFUND_POLICY.md` |
| 19 | Is an export classification required for the cryptographic functions and the PQC path? | Delivery to some countries | `LICENSE` §10, sales |
| 20 | May the repository stay public under a proprietary licence without implying an open-source grant, and what wording is required? | The owner wants the repo public | `README.md`, `COMMERCIAL.md` |
| 21 | Who is the merchant of record for VAT/GST, and does Stripe Tax cover the target markets? | Tax exposure on every subscription | Payment configuration |
| 22 | What copyright notice and licensor name apply before and after a company is formed? | A licence from the wrong party is defective | First signature |

