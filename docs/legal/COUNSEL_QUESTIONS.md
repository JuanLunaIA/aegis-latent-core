<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
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
