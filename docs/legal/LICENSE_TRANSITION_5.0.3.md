<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Licence transition: Apache-2.0 to Aegis Commercial License 1.0 (v5.0.3)

**Audience:** owner, counsel, procurement reviewers, and anyone deciding which
terms apply to a given copy of Aegis Latent Core.
**Scope:** what changes from v5.0.3, which published copies keep which terms, what
was modified in the repository, and what only counsel can decide.
**Boundary:** a factual record and a list of open questions. It is not a legal
opinion and it is not evidence that v5.0.3 is published.

> **COUNSEL-REVIEW-REQUIRED.** Prepared by the owner with agent assistance. It
> has not been reviewed by a lawyer. The relicensing authority rests on the
> owner's instruction, on `CLA.md`, and on the repository's own statements.

## 1. The position in one table

| Artifact | Licence | Basis |
|---|---|---|
| Source from v5.0.3 forward | Aegis Commercial License 1.0 (`LicenseRef-Aegis-Commercial-1.0`) | `LICENSE`, `NOTICE`, per-file headers, package metadata |
| Published release `5.0.2` | Apache License, Version 2.0 | Published 2026-10-01; GitHub Release, PyPI and npm read back; cannot be revoked |
| Releases up to and including `5.0.1` | AGPLv3 or a separate commercial agreement, as published | Those artifacts shipped with the licence current when they were built |
| `sdk/python`, `sdk/typescript`, `examples/` | Apache License, Version 2.0 | Deliberate: client integration without a licence review |
| Third-party components | Their own licences | `LICENSE-THIRD-PARTY.md`, SBOM |

## 2. What changed in the repository

| Surface | Change |
|---|---|
| `LICENSE` | Replaced by the Aegis Commercial License 1.0; SHA-256 pinned in `docs/legal/LICENSE.sha256` and checked by `tests/test_license_policy.py` |
| `NOTICE` | States the commercial terms, the SDK exception, and the v5.0.2 boundary |
| Per-file headers | `scripts/apply_license_headers.py` writes the commercial profile outside `sdk/` and `examples/`, and the Apache profile inside them; `--check` fails on any mismatch |
| Package metadata | `pyproject.toml` (core and cloud), `dashboard/package.json`, both `Cargo.toml` files: `LicenseRef-Aegis-Commercial-1.0`; SDKs unchanged at `Apache-2.0` |
| Tests | `tests/test_license_files.py` (Apache pin) replaced by `tests/test_license_policy.py` (commercial pin, SDK exception, documentation sweep) |
| Documentation | Current surfaces stop calling the product Apache-2.0; historical records (`evidence/`, `investor_packs/`, `CHANGELOG.md`, `RELEASE_STATUS.md`, the 5.0.2 transition) keep the terms of their date |
| Releases | Not published yet. v5.0.3 becomes real when the tag, release, registries and images are read back |

## 3. Why the owner can relicense, and what is not established

The repository records a sole copyright holder (`AUTHORS`), and `CLA.md` grants
the Maintainer the right to publish future versions under other terms. That is
the basis. It is not proof that every line is free of third-party rights.

Not established by this document:

- whether AI-assisted material is copyrightable in every jurisdiction, and who
  owns it (`docs/legal/AI_CONTRIBUTIONS.md`);
- that no contributor outside the CLA ever landed code (the git history shows
  agent-authored commits under the owner's direction);
- that a restriction on production use or hosted competition is enforceable in
  every target market;
- that the governing-law and liability clauses survive review.

## 4. What cannot be undone

Anyone holding a copy of `5.0.2` may continue to use, modify, redistribute and
sell it under Apache-2.0. A fork of `5.0.2` can compete legally. This document
says so plainly because a commercial plan built on the opposite assumption is
built on a false premise.

## 5. Boundary commit and tag

- Boundary commit: the commit that introduces this file (`git log -1 --format=%H -- docs/legal/LICENSE_TRANSITION_5.0.3.md`).
- Release tag: `v5.0.3`, created only after the release gates pass.
- Publication: recorded in `docs/RELEASE_STATUS.md` only after readback.

## 6. Counsel questions

See `docs/legal/COUNSEL_QUESTIONS.md`. The blocking ones are jurisdiction,
liability cap, enforceability of the production and hosting restrictions,
trademark policy, and the status of AI-assisted contributions.
