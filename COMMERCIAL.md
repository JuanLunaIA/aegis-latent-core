# Aegis Latent Core — Commercial Use and Licensing

This document summarizes the open-source and commercial licensing boundary and the current packaging hypothesis for Aegis Latent Core. It is for procurement, legal, commercial and technical buyers. It is not legal advice, a binding offer, a warranty, a support SLA or a regulatory representation.

**Last verified:** 2026-08-27 UTC
**Release baseline:** current source/release candidate
**Source/release candidate:** `4.0.2` with fourteen synchronized anchors; external `v4.0.2` publication is not claimed before readback
**Historical external baseline:** lightweight `v4.0.1` tag at `6469904380218584ae0b5221334bc9a46500f5ba` with failed tag workflows; PyPI/npm observed at `4.0.0` without attributed provenance
**License source:** [`LICENSE`](LICENSE)
**Commercial strategy:** [`docs/COMMERCIAL_STRATEGY_US.md`](docs/COMMERCIAL_STRATEGY_US.md)

## License structure

Aegis Latent Core is available under the GNU Affero General Public License v3 as described in [`LICENSE`](LICENSE). A separate commercial agreement may be available for organizations that need terms different from the open-source license, subject to an executed agreement and applicable legal review.

This file does not determine whether a specific use triggers AGPL obligations, whether an exemption applies, whether future versions are included, or whether a customer has a regulatory duty. Customer counsel must review the actual deployment, modifications, distribution model and executed contract.

## Product baseline for commercial review

The current source/release candidate is **4.0.2** with fourteen synchronized anchors. It adds bounded SSE with `pending-terminal` evidence, native Anthropic `POST /v1/messages`, Python drop-in and TypeScript provider-native SDK integration, portable MMR proofs, a read-only forensic dashboard, bounded JCS/DAG-CBOR/CIDv1/PDF/`VERIFY.sh` ZIP exports, and an auxiliary `RustWal` streaming segment. No external `v4.0.2` tag, GitHub Release, PyPI/npm package, or OCI image is claimed until successful readback. The prior public `v4.0.1` lightweight tag and observed `4.0.0` registry objects are historical external baselines, not provenance for this candidate; a commercial scope must name the exact commit or a future published release.

For non-streaming calls, durable evidence and MMR proof headers are available after commit. For streams, initial headers remain `pending-terminal`; the terminal record is committed before the protocol terminal marker and proof retrieval occurs after termination.

## Commercial packaging hypothesis

| Package | Intended use | Included boundary | Commercial status |
|---|---|---|---|
| Community / OSS | Evaluation, development and self-hosted use under AGPLv3 | Source, tests, public documentation and public issue tracking | Free; no support or SLA promise |
| Team / Pilot | Time-bounded evaluation of one defined workload | Pilot plan, evidence replay, deployment checklist, bounded engineering support and written acceptance criteria | Paid fixed-scope engagement; price quoted after scope |
| Production | Commercial self-hosted deployment | Commercial license terms, release updates, deployment guidance and defined support window | Annual terms sized by topology, request tier, environments and support |
| Enterprise | Multiple environments or procurement-heavy deployment | Negotiated support, security-review assistance, architecture guidance, procurement artifacts and response targets | Custom annual agreement subject to staffing and legal review |
| Sovereign / OEM | Air-gapped, embedded, redistribution, escrow or dedicated assurance | Separate redistribution, support, assurance and custody terms | Future/custom only; not a default promise |

The project does not publish a permanent one-time price, lifetime update promise, automatic AGPL exemption, unlimited feature entitlement, 24/7 support commitment or sovereign assurance claim. Internal planning retains Team/Pilot USD 10,000–30,000, Production USD 40,000–100,000, and Enterprise USD 100,000–250,000+ solely as hypotheses. They are **not list prices, observed ACV, or a valuation**, and this repository contains no evidence-backed vertical ACV or startup/IP valuation. Those commitments require an executed agreement, an accountable support organization and legal review.

## What a commercial engagement can provide

A defined engagement may include release provenance, SBOM and dependency reports, evidence-replay assistance, deployment hardening review, key-rotation planning, backpressure testing, WAF corpus review, rollback planning and a documented support matrix. The exact scope must identify environments, request volume, retention, provider topology, data handling, support hours, response targets, exclusions and customer-owned controls.

## What is not automatically included

A commercial agreement does not automatically provide SOC 2, HIPAA, FedRAMP, EU AI Act conformity, GDPR compliance, FIPS 140 validation, court admissibility, penetration-test completion, external cryptographic review, production SLOs, customer references or regulatory representation. Those are separate organizational, contractual or independent-assurance matters.

The release also does not approve a constant-time ML-DSA verify claim. The retained timing experiment returned `p=0.0` for `verify`.

## Procurement inputs

Before quoting a production or enterprise engagement, collect the target topology, number of environments, expected request volume, upstream providers, retention and residency requirements, ingress termination, storage provider, secret manager or HSM, support hours, incident escalation, rollback owner, required security questionnaires and legal entity information. A quote that omits these inputs is not an enterprise-ready quote.

## Support boundary

Community use receives no contractual support. Pilot support is time-boxed and scoped. Production and enterprise support require a named owner, supported-version policy, maintenance cadence, response targets, escalation path and exclusions. No document should imply 24/7 or mission-critical coverage until the project can staff and measure it.

## Counsel review points

Counsel should review AGPL network-use implications, modification and distribution obligations, commercial exemption wording, future-version rights, warranty and indemnity, limitation of liability, privacy/data-processing language, retention and deletion, export controls, tax, procurement representations and any statement about certification or regulatory alignment.

## Contact and next step

The practical next step is a bounded evaluation against the buyer's actual ingress, storage, secret-management, provider and retention boundaries. Start with [`docs/PRODUCT_BRIEF_US.md`](docs/PRODUCT_BRIEF_US.md), [`docs/BUYER_GUIDE_US.md`](docs/BUYER_GUIDE_US.md), [`docs/FAQ_PROCUREMENT.md`](docs/FAQ_PROCUREMENT.md) and [`docs/COMMERCIAL_STRATEGY_US.md`](docs/COMMERCIAL_STRATEGY_US.md). Commercial terms require a separate written agreement; this repository does not collect personal registration data or expose private contact details as part of the source tree.

## Related documents

- [`README.md`](README.md)
- [`LICENSE`](LICENSE)
- [`docs/PRODUCT_BRIEF_US.md`](docs/PRODUCT_BRIEF_US.md)
- [`docs/BUYER_GUIDE_US.md`](docs/BUYER_GUIDE_US.md)
- [`docs/FAQ_PROCUREMENT.md`](docs/FAQ_PROCUREMENT.md)
- [`docs/COMMERCIAL_STRATEGY_US.md`](docs/COMMERCIAL_STRATEGY_US.md)

## Copyright

Copyright and licensing notices remain subject to the repository license files and any executed agreement. Nothing in this summary waives a license condition or creates a warranty.
