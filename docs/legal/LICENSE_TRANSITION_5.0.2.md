<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
-->

# Licence Transition: AGPLv3-or-commercial to Apache-2.0 (5.0.2)

**Audience:** the owner, counsel, procurement reviewers and anyone deciding which terms apply to which copy of Aegis Latent Core.
**Scope:** what changed when the `5.0.2` source line moved to the Apache License, Version 2.0; which published copies keep which terms; what was changed in the repository; and what only the owner or counsel can decide.
**Boundary:** a factual record of a repository change and a list of open questions. It is not a legal opinion, not a relicensing instrument, and not evidence that `5.0.2` is published.

> **[COUNSEL-REVIEW-REQUIRED]** Prepared by an AI agent for the owner and qualified counsel. It is not legal advice, has not been reviewed by a lawyer, has not been offered to anyone, and nobody has signed it. The relicensing authority described below rests on the owner's written instruction and on the repository's own statements; counsel has not confirmed it.

## 1. The position in one table

| Artifact | Licence | Basis |
| --- | --- | --- |
| Published release `5.0.2` | Apache License, Version 2.0 | Owner instruction; `LICENSE`, `NOTICE`, per-file headers, package metadata |
| Any published release up to and including `5.0.1` (tags, GitHub Releases, PyPI, npm, GHCR images) | GNU Affero General Public License v3, or the separate commercial licence, **as published** | Those artifacts shipped with the licence text current when they were built; this change does not rewrite them |
| Any commercial licence or other agreement already executed | Its own terms | A repository edit cannot amend a signed agreement. No such agreement is recorded in this repository |

**`5.0.2` is published.** The GitHub Release, PyPI core/SDK and npm publication were read back on 2026-10-01. GHCR was not readable from this environment. Apache-2.0 attaches to the published `5.0.2` copies; earlier releases up to `5.0.1` keep the terms under which they shipped.

## 2. What changed in the repository

| Surface | Change |
| --- | --- |
| `LICENSE` | Replaced with the verbatim Apache License 2.0 text (SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`), pinned by `tests/test_license_files.py` |
| `NOTICE` | Rewritten for Apache-2.0 Section 4(d): copyright, licence pointer, third-party pointer, trademark reservation |
| Per-file headers | Three lines on every Python, Rust, TOML, shell, workflow and Dockerfile source: copyright, `SPDX-License-Identifier: Apache-2.0`, pointer to `LICENSE` and `NOTICE`. Applied and checked by `scripts/apply_license_headers.py` and the CI "License Headers" job |
| Package metadata | `license = "Apache-2.0"` (PEP 639) with `license-files` for the gateway and the Python SDK; `Apache-2.0` for `aegis-rust`, both Cargo crates, the TypeScript SDK and the dashboard lockfile; the `License ::` AGPL classifier is removed |
| Distribution (Apache-2.0 Section 4(a)) | `LICENSE` and `NOTICE` are copied into `sdk/python/` and `sdk/typescript/` (and listed in the npm `files`), and into `/licenses/` in the gateway, air-gap and dashboard images; the OCI `licenses` label reads `Apache-2.0` |
| Dependency policy | `scripts/license/license_scan.py` checks components against one Apache-2.0 tier. A strong-copyleft (GPL, AGPL) component is **blocking** for an Apache-2.0 artifact unless it is not distributed with it |
| `COMMERCIAL.md`, `CONTRIBUTING.md`, `AUTHORS`, docs, site | Reworded: no second licence tier; what is sold is services, not a licence |
| Licence-entitlement engine (`aegis/licensing`, `AEGIS_LICENSE_ENFORCEMENT`) | **Kept, unchanged in behaviour** (off by default; the public-API compatibility tests pin it). Documented as an entitlement signal, not a legal licence grant |
| `evidence/` and `investor_packs/` | Historical records; **not rewritten**. The investor packs (EN and ES) were built on the dual-licence model: their "AGPL friction" valuation haircut (7% now, 4% after remediation) and their "AGPL scares enterprise buyers" answer no longer describe the `5.0.2` licence. They were left as dated snapshots because re-deriving a valuation input is the owner's decision, not a wording fix |
| `site/` | Regenerated from `tools/sales/build_site.py` (footer licence line and one data-room row); the generator and `tests/test_sales_surface.py` keep them in step |

## 3. Why the owner can relicense, and what is not established

Stated from the repository, not from a legal review:

- `CONTRIBUTING.md` section 1 records that, to the maintainer's knowledge, there are no third-party **human** contributions, and that the maintainer is the sole copyright holder. Section 3.2 already reserved the right to relicense contributions.
- The commit history contains commits by automation, not by outside authors: Dependabot version bumps to workflow files and four commits by an automated code assistant account that touched generated files. Whether any of those carries independently copyrightable material, and whether the owner's licence covers it, is **not established here**.
- A large share of the history was authored with AI-assisted tooling operated by the owner. Whether copyright subsists in that material, and in whom, is an open counsel question already recorded as question 1 in `COUNSEL_QUESTIONS.md`.

## 4. What only the owner or counsel can do

1. **Confirm the right to relicense** (section 3) in writing before `5.0.2` is published.
2. **Decide the fate of any executed commercial agreement.** None is recorded in this repository. If one exists, its terms govern that customer, and a customer holding `5.0.1` or earlier under AGPLv3 or a commercial licence keeps that grant.
3. **Review whether to keep the CLA** in `CONTRIBUTING.md` section 3 (it lets the maintainer relicense future releases) now that inbound and outbound are both Apache-2.0 (Section 5 of the License).
4. **Re-derive the commercial model.** The pricing guide and the investor packs were built on a dual-licence assumption, including an "AGPL friction" input that no longer applies and a commercial-licence market (willingness to pay to avoid AGPL obligations) that Apache-2.0 removes for the `5.0.2` source. Under Apache-2.0 only support, pilots, hardening and assurance work remain sellable as such. Every figure stays `[HYPOTHESIS-UNVALIDATED]`; regenerate the packs through their single engine only after the owner has re-derived the inputs.
5. **Re-run the dependency licence scan in a release-representative environment.** `docs/compliance/LICENSE_AUDIT.md` still records the inventory observed on 2026-09-09 (384 distributed components); only its compatibility matrix was reworded for Apache-2.0. A scan run on 2026-10-01 in a development environment inventoried 462 distributed components with 0 `STRONG_COPYLEFT`, 15 `WEAK_COPYLEFT` and 1 `UNKNOWN`: `spartan2 0.9.0` (optional `zk-spartan` feature) declares `license-file` rather than `license`, the file it ships reads as an MIT licence, and the scanner reads only the `license` field and does not infer. That scan was not committed, because its environment is not the one that produced the committed audit; treat it as a lead for counsel, not a result.
6. **Decide the trademark position.** Section 6 grants no right to the name or marks; whether any mark is registered is outside this repository.
7. **Maintain the `5.0.2` publication record** by reading back each surface and recording any missing OCI or attestation evidence. The agent did not create or sign the release.

## 5. Statements this record does not support

- That every `5.0.2` surface, including GHCR and attestations, has been independently verified from this environment.
- That any earlier release was ever Apache-2.0.
- That relicensing is legally effective, or that the owner's title is clean of third-party or AI-origin claims.
- That a dependency set is compatible with Apache-2.0 beyond the identifiers upstream projects declare (`docs/compliance/LICENSE_AUDIT.md`).
- That Apache-2.0 changes any security, compliance or certification claim. It does not; `docs/CLAIMS_MATRIX.md` controls those.

## Related documents

- [`LICENSE`](../../LICENSE) and [`NOTICE`](../../NOTICE)
- [`COMMERCIAL.md`](../../COMMERCIAL.md)
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
- [`COUNSEL_QUESTIONS.md`](COUNSEL_QUESTIONS.md)
- [`docs/RELEASE_STATUS.md`](../RELEASE_STATUS.md)
- [`docs/compliance/LICENSE_AUDIT.md`](../compliance/LICENSE_AUDIT.md)
- [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
