<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# AI-assisted contributions

> **Draft for counsel review.** `[COUNSEL-REVIEW-REQUIRED]` This document is not legal advice and is not an offer; it is prepared for review by qualified counsel.


**Status:** factual record for counsel. Not a legal opinion.

## What the history shows

`git log --format='%ae'` in `aegis-latent-core` records commits authored by
automation accounts (`noreply@anthropic.com`, `qwenlm-intl@service.alibaba.com`)
and by the owner (`127159163+JuanLunaIA@users.noreply.github.com`). Those commits
were produced by agents running on the owner's instruction, in the owner's
repository, against the owner's specification.

## What that means, and what it does not

- The owner directed the work and owns the repository and the contractual
  relationship with the tooling providers.
- Whether AI-generated expression is copyrightable, and who owns it, varies by
  jurisdiction. The repository does not assert an answer.
- The CLA (`CLA.md`) covers human contributors. It does not retroactively assign
  anything from an agent.
- If counsel concludes that a jurisdiction requires human authorship for a
  portion of the code, the remedy is a jurisdiction-specific review of that
  portion, not a silent rewrite of history.

## What is verified

```bash
git -C aegis-latent-core log --format='%ae' | sort | uniq -c | sort -rn
```

The output is the record. No commit message or file claims authorship beyond it.

## Open question for counsel

Does the current `CLA.md` and `AUTHORS` combination give the owner sufficient
rights to license v5.0.3 commercially in the target markets, or is a separate
assignment or opinion required for agent-assisted material?
