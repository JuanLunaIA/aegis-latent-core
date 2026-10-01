# Aegis Latent Core — Commercial Use and Licensing

This document summarizes the licence and the commercial-offering boundary, and the current packaging hypothesis, for Aegis Latent Core. It is for procurement, legal, commercial and technical buyers. It is not legal advice, a binding offer, a warranty, a support SLA or a regulatory representation.

**Last verified:** 2026-09-16 UTC
**Release baseline:** `5.0.1` source line — published 2026-09-24 on every surface (PyPI `aegis-latent-core` `5.0.1` followed on 2026-09-26) (`docs/RELEASE_STATUS.md` §1.0a); `5.0.0` is the previous release; see §1.0 for what was read back on each surface
**Source baseline:** `5.0.2` with fourteen synchronized anchors — the published Apache-2.0 release; the most recent published release is `5.0.1`, **published 2026-09-24 on every surface (PyPI `aegis-latent-core` `5.0.1` followed on 2026-09-26)**, read back the same day (`docs/RELEASE_STATUS.md` §1.0a). The previous release is `v5.0.0`, published 2026-09-16 on every surface except PyPI `aegis-latent-core` (see `docs/RELEASE_STATUS.md` §1.0); `v4.1.2` was the last version published on every surface before `5.0.1` completed the set on 2026-09-26, whose publication was read back on 2026-09-04 and is recorded in `docs/RELEASE_STATUS.md` §1.1
**Historical external baseline:** signed annotated `v4.0.2` tag at `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`, with GitHub Release and GHCR gateway/dashboard images read back on 2026-09-02; before it, lightweight `v4.0.1` at `6469904380218584ae0b5221334bc9a46500f5ba` with failed tag workflows; PyPI/npm observed at `4.0.0` without attributed provenance
**License source:** [`LICENSE`](LICENSE)
**Commercial strategy:** [`docs/COMMERCIAL_STRATEGY_US.md`](docs/COMMERCIAL_STRATEGY_US.md)

## License structure

**From `5.0.2` the source is licensed under the Apache License, Version 2.0** ([`LICENSE`](LICENSE), with attributions in [`NOTICE`](NOTICE)), for every use, commercial or not. There is no second licence tier and no licence fee: Apache-2.0 permits use, modification, redistribution and commercial use, including in closed-source products, subject to its conditions (a copy of the License and the NOTICE with every distribution, a statement of changes in modified files, preserved notices, and the patent-termination clause in Section 3). Section 6 of the License grants **no** right to use the project's name or marks, and Section 7 provides the software **AS IS**.

**Earlier releases keep the terms they were published under.** Releases up to and including `5.0.1` were published under the GNU Affero General Public License v3 or a separate commercial agreement; the Apache-2.0 relicence is a property of the `5.0.2` source line forward and does not retroactively change a copy a recipient already holds under those terms. See [`docs/legal/LICENSE_TRANSITION_5.0.2.md`](docs/legal/LICENSE_TRANSITION_5.0.2.md). **`5.0.2` is a source target: no tag, GitHub Release, registry package or image has been published for it**, and nothing here is evidence otherwise (`docs/RELEASE_STATUS.md`).

What is sold, if anything, is therefore **services, not a licence**: support, pilots, hardening and assurance work, described below. A licence-entitlement token (`aegis/licensing`, `AEGIS_LICENSE_ENFORCEMENT`) is an opt-in signal for a deployment that wants entitlement checks; it is off by default and is not a legal licence grant. This file does not determine a customer's regulatory duties, whether a specific agreement signed against an earlier version is affected, or the enforceability of any term. Customer counsel must review the actual deployment, modifications, distribution model and any executed contract.

## Product baseline for commercial review

The current source line is **5.0.2** with fourteen synchronized anchors — the published Apache-2.0 release; the most recent published release is `5.0.1`, published 2026-09-24 on every surface (PyPI `aegis-latent-core` `5.0.1` followed on 2026-09-26), read back the same day (`docs/RELEASE_STATUS.md` §1.0a); the previous release is **5.0.0**, published 2026-09-16 on every surface except PyPI `aegis-latent-core`, and **4.1.2** was the last version published on every surface before `5.0.1` completed the set on 2026-09-26. **No publication is claimed here that was not read back**, and version metadata is never treated as evidence of release. It adds bounded SSE with `pending-terminal` evidence, native Anthropic `POST /v1/messages`, Python drop-in and TypeScript provider-native SDK integration, portable MMR proofs, a read-only forensic dashboard, bounded JCS/DAG-CBOR/CIDv1/PDF/`VERIFY.sh` ZIP exports, and an auxiliary `RustWal` streaming segment. External publication is claimed only from readback. On 2026-09-16 the `v5.0.0` signed annotated tag, the GitHub Release with 31 uploaded assets, PyPI `aegis-latent-sdk` `5.0.0`, npm `aegis-latent-sdk` `5.0.0`, and both GHCR images with cosign signature objects present were read back. **`cosign verify` and `gh attestation verify` were not run, and a signature object resolving is not verification** — it establishes that an object was pushed, not that it validates or who signed it.

**One gap, stated rather than glossed:** PyPI `aegis-latent-core` — the gateway distribution — was never published at `5.0.0`; `5.0.1` reached it on 2026-09-26 (`docs/RELEASE_STATUS.md` §1.0b), so a `pip install` now gives `5.0.1` unless a version is pinned. A commercial scope must still name the exact commit or the published artifact it covers: the PyPI files, the GitHub Release assets or `ghcr.io/juanlunaia/aegis-latent-core:5.0.1`.

The `v4.0.2` release objects, the prior public `v4.0.1` lightweight tag, and the observed `4.0.0` registry objects are historical external baselines, not provenance for this line.

For non-streaming calls, durable evidence and MMR proof headers are available after commit. For streams, initial headers remain `pending-terminal`; the terminal record is committed before the protocol terminal marker and proof retrieval occurs after termination.

## Commercial packaging hypothesis

| Package | Intended use | Included boundary | Commercial status |
|---|---|---|---|
| Community / OSS | Any use, including commercial and closed-source, under Apache-2.0 | Source, tests, public documentation and public issue tracking | Free; no support or SLA promise |
| Team / Pilot | Time-bounded evaluation of one defined workload | Pilot plan, evidence replay, deployment checklist, bounded engineering support and written acceptance criteria | Paid fixed-scope engagement; price quoted after scope |
| Production | Self-hosted deployment with a support relationship | Support agreement (no licence is sold), release updates, deployment guidance and defined support window | Annual terms sized by topology, request tier, environments and support |
| Enterprise | Multiple environments or procurement-heavy deployment | Negotiated support, security-review assistance, architecture guidance, procurement artifacts and response targets | Custom annual agreement subject to staffing and legal review |
| Sovereign / OEM | Air-gapped, embedded, redistribution, escrow or dedicated assurance | Separate redistribution, support, assurance and custody terms | Future/custom only; not a default promise |

The project does not publish a permanent one-time price, lifetime update promise, unlimited feature entitlement, round-the-clock support commitment or sovereign assurance claim. Those require an executed agreement, an accountable support organization and legal review.

**The packaging hypothesis predates the relicence.** It and the pricing guide were written when the project offered AGPLv3 or a commercial licence; under Apache-2.0 only the services components (support, pilots, hardening, assurance) remain sellable as such, and any figure that assumed a licence fee or an AGPL-avoidance premium no longer has a basis. Treat every tier as `[HYPOTHESIS-UNVALIDATED]` until re-derived.

**Pricing lives in one place.** [`docs/commercial/ENTERPRISE_PRICING_GUIDE.md`](docs/commercial/ENTERPRISE_PRICING_GUIDE.md) is the single source of truth, and every figure in it is labelled `[HYPOTHESIS-UNVALIDATED]` with the five gates that would have to close before any of it could be stated as firm. **No figure is repeated here**, deliberately: this file previously carried a competing set of bands, which meant the corpus quoted two different numbers for the same tier under two opposite descriptions of what those numbers were. One source, one label, no restatement.

This repository contains no evidence-backed vertical ACV, no observed contract value and no startup/IP valuation (`UC-032`, `UC-033`).

## Financial-claim discipline

The figures in the pricing guide are planning inputs held by the project, not offers, quotes, or market observations. To keep that boundary enforceable rather than aspirational, the following rules apply to every document, deck, and conversation derived from this file.

| Rule | Reason |
|---|---|
| A range may never be restated as a list price, a quote, or an observed contract value. | The ranges are unvalidated hypotheses; no executed commercial agreement is recorded in this repository. |
| A quote must name the legal entity, term, environments, scope, assumptions, exclusions, and validity period. | A tier label without a named environment and scope cannot be costed or accepted. |
| Unit-economics ratios may not be published until their inputs are measured. | Customer acquisition cost, lifetime value, gross margin, and payback are undefined here; the model skeleton and its input register are in [`docs/COMMERCIAL_STRATEGY_US.md`](docs/COMMERCIAL_STRATEGY_US.md). |
| Return-on-investment material must be customer-specific and buyer-owned. | Avoided fines, avoided incidents, and fixed risk-reduction percentages are not evidenced and must not be asserted. |
| No customer count, logo, reference, or valuation may be implied. | None exists. Absence of a reference list is a fact to state plainly, not to soften. |

A buyer or investor encountering a figure that does not satisfy these rules should treat it as unsupported and request its measurement source.

## What a paid engagement can provide

A defined engagement may include release provenance, SBOM and dependency reports, evidence-replay assistance, deployment hardening review, key-rotation planning, backpressure testing, WAF corpus review, rollback planning and a documented support matrix. The exact scope must identify environments, request volume, retention, provider topology, data handling, support hours, response targets, exclusions and customer-owned controls.

## What is not automatically included

A paid agreement does not automatically provide SOC 2, HIPAA, FedRAMP, EU AI Act conformity, GDPR compliance, FIPS 140 validation, court admissibility, penetration-test completion, external cryptographic review, production SLOs, customer references or regulatory representation. Those are separate organizational, contractual or independent-assurance matters.

The release also does not approve a constant-time ML-DSA verify claim. The retained timing experiment returned `p=0.0` for `verify`.

## Procurement inputs

Before quoting a production or enterprise engagement, collect the target topology, number of environments, expected request volume, upstream providers, retention and residency requirements, ingress termination, storage provider, secret manager or HSM, support hours, incident escalation, rollback owner, required security questionnaires and legal entity information. A quote that omits these inputs is not an enterprise-ready quote.

## Support boundary

Community use receives no contractual support. Pilot support is time-boxed and scoped. Production and enterprise support require a named owner, supported-version policy, maintenance cadence, response targets, escalation path and exclusions. No document should imply 24/7 or mission-critical coverage until the project can staff and measure it.

## Counsel review points

Counsel should review the right to relicense (including any contribution by anyone other than the copyright holder and the status of AI-assisted material), the treatment of agreements already executed against a version published under AGPLv3 or a commercial licence, the Apache-2.0 patent grant and its termination clause, NOTICE and trademark handling, the AS-IS disclaimer against any support-contract warranty, indemnity, limitation of liability, privacy/data-processing language, retention and deletion, export controls, tax, procurement representations and any statement about certification or regulatory alignment.

## Contact and next step

The practical next step is a bounded evaluation against the buyer's actual ingress, storage, secret-management, provider and retention boundaries. Start with [`docs/PRODUCT_BRIEF_US.md`](docs/PRODUCT_BRIEF_US.md), [`docs/BUYER_GUIDE_US.md`](docs/BUYER_GUIDE_US.md), [`docs/FAQ_PROCUREMENT.md`](docs/FAQ_PROCUREMENT.md) and [`docs/COMMERCIAL_STRATEGY_US.md`](docs/COMMERCIAL_STRATEGY_US.md). Support and services terms require a separate written agreement; this repository does not collect personal registration data or expose private contact details as part of the source tree.

## Related documents

- [`README.md`](README.md)
- [`LICENSE`](LICENSE)
- [`NOTICE`](NOTICE)
- [`docs/legal/LICENSE_TRANSITION_5.0.2.md`](docs/legal/LICENSE_TRANSITION_5.0.2.md)
- [`docs/PRODUCT_BRIEF_US.md`](docs/PRODUCT_BRIEF_US.md)
- [`docs/BUYER_GUIDE_US.md`](docs/BUYER_GUIDE_US.md)
- [`docs/FAQ_PROCUREMENT.md`](docs/FAQ_PROCUREMENT.md)
- [`docs/COMMERCIAL_STRATEGY_US.md`](docs/COMMERCIAL_STRATEGY_US.md)
- [`docs/institutional/DOC-06_COMMERCIAL_PROCUREMENT.md`](docs/institutional/DOC-06_COMMERCIAL_PROCUREMENT.md)

## Copyright

Copyright (c) 2026 Juan Luna. Licensed under the Apache License, Version 2.0 from `5.0.2` (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)); earlier releases keep the terms they were published under. Nothing in this summary waives a license condition or creates a warranty.
