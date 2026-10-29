# Aegis Latent Core — Commercial Use and Licensing

This document states the licence boundary and what is sold from v5.0.3 forward.
It is for procurement, legal, commercial and technical buyers. It is not legal
advice, a binding offer, a warranty, a support SLA or a regulatory representation.

**Effective:** v5.0.3 · **Status:** draft for counsel review (`docs/legal/COUNSEL_QUESTIONS.md`)
**Last verified:** 2026-10-29 UTC
**Release baseline:** `v5.0.3` prepared, **not published**; `v5.0.2` remains the latest published release
**Licence source:** [`LICENSE`](LICENSE) · **Attribution:** [`NOTICE`](NOTICE)
**Transition record:** [`docs/legal/LICENSE_TRANSITION_5.0.3.md`](docs/legal/LICENSE_TRANSITION_5.0.3.md)

## 1. What the licence grants

From v5.0.3 the gateway, the control plane and the dashboard are licensed under
the **Aegis Commercial License 1.0**: source-available, read and evaluated for
thirty days at no cost, and usable in production only under a paid Order. The
full terms are in [`LICENSE`](LICENSE). In short:

| Use | Without a paid Order | With a paid Order |
|---|---|---|
| Read, compile and run for evaluation (30 days) | Yes | Yes |
| Production use inside your organisation | No | Yes, within the Order's scope |
| Modify for internal use | Yes, not distributed | Yes, not distributed |
| Redistribute, resell or host for third parties | No | Only if the Order says so |
| Remove notices or bypass entitlement checks | No | No |

## 2. What stays Apache-2.0

The client SDKs in [`sdk/python`](sdk/python) and [`sdk/typescript`](sdk/typescript)
remain under the Apache License, Version 2.0, so a customer can integrate them
without a licence review. The examples in [`examples/`](examples) do the same.
They ship their own `LICENSE` and `NOTICE`.

## 3. What was already published cannot be revoked

`v5.0.2` was published on 2026-10-01 (GitHub Release, PyPI and npm read back)
under Apache-2.0. Anyone who received it may keep using, modifying and
redistributing it under those terms, forever. Releases up to `5.0.1` were
published under AGPLv3 or a separate commercial agreement and keep those terms.
No file in this repository changes that. What the commercial licence governs is
v5.0.3 and later.

A fork of `v5.0.2` can therefore compete legally. The commercial defence is the
service, the trademark, the support relationship and the work added after
`v5.0.2` — not a claim over the published source.

## 4. What is sold

| Package | Intended use | Included | Commercial status |
|---|---|---|---|
| Evaluation | Thirty days, one environment, non-production | Source, documentation, issue tracker | Free, no support promise |
| Team | One production environment | Production licence for the Order's scope, release updates, written support window | Paid annual subscription |
| Business | Several environments, quarterly review | Adds procurement artefacts, review calls, priority fixes | Paid annual subscription |
| Enterprise / OEM | Redistribution, air-gap, escrow, assurance | Separate written terms; requires legal review | Custom agreement |

Prices, taxes, refunds and payment terms live in the Order and in the published
price list; this file repeats no figures. The pricing guide remains planning
input, labelled `[HYPOTHESIS-UNVALIDATED]`, until an Order exists.

## 5. What a paid agreement does not include

A paid agreement does not by itself provide SOC 2, HIPAA, FedRAMP, EU AI Act
conformity, GDPR compliance, FIPS 140 validation, court admissibility, a
penetration-test attestation, external cryptographic review, customer references
or regulatory representation. Those are separate organisational, contractual or
independent-assurance matters.

The release also does not approve a constant-time ML-DSA verify claim. The
retained timing experiment returned `p=0.0` for `verify`.

## 6. Support boundary

Evaluation receives no contractual support. Team and Business support require a
named owner, a supported-version policy, a maintenance cadence, response targets,
an escalation path and exclusions. No document should imply 24/7 or
mission-critical coverage until the project can staff and measure it.

## 7. Financial-claim discipline

The figures in the pricing guide are planning inputs, not offers, quotes or
observed contract values. A range may never be restated as a list price. A quote
must name the legal entity, term, environments, scope, assumptions, exclusions
and validity period. Unit-economics ratios may not be published until their
inputs are measured. No customer count, logo, reference or valuation may be
implied: none exists.

## 8. Counsel review points

Counsel should review the right to relicense (including AI-assisted material and
any contribution by anyone other than the copyright holder), the treatment of
agreements already executed against earlier versions, the enforceability of the
production restriction and the anti-hosting clause, the trademark policy, the
AS-IS disclaimer against any support warranty, indemnity, limitation of
liability, privacy and data-processing language, retention and deletion, export
controls, tax, and the governing-law clause. The open list is maintained in
[`docs/legal/COUNSEL_QUESTIONS.md`](docs/legal/COUNSEL_QUESTIONS.md).

## 9. Contact and next step

The practical next step is a bounded evaluation against the buyer's actual
ingress, storage, secret-management, provider and retention boundaries. Start
with [`docs/PRODUCT_BRIEF_US.md`](docs/PRODUCT_BRIEF_US.md),
[`docs/BUYER_GUIDE_US.md`](docs/BUYER_GUIDE_US.md) and
[`docs/FAQ_PROCUREMENT.md`](docs/FAQ_PROCUREMENT.md). Support and services terms
require a separate written agreement.

## Related documents

- [`README.md`](README.md)
- [`LICENSE`](LICENSE)
- [`NOTICE`](NOTICE)
- [`docs/legal/LICENSE_TRANSITION_5.0.3.md`](docs/legal/LICENSE_TRANSITION_5.0.3.md)
- [`docs/legal/TERMS_OF_SERVICE.md`](docs/legal/TERMS_OF_SERVICE.md)
- [`docs/legal/PRIVACY_POLICY.md`](docs/legal/PRIVACY_POLICY.md)
- [`docs/PRODUCT_BRIEF_US.md`](docs/PRODUCT_BRIEF_US.md)
- [`docs/BUYER_GUIDE_US.md`](docs/BUYER_GUIDE_US.md)
- [`docs/COMMERCIAL_STRATEGY_US.md`](docs/COMMERCIAL_STRATEGY_US.md)

## Copyright

Copyright (c) 2026 Juan Luna. All rights reserved. Licensed under the Aegis
Commercial License 1.0 from v5.0.3; earlier releases keep the terms they were
published under. Nothing in this summary waives a licence condition or creates a
warranty.
