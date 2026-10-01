<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
-->

# Commercial Licence: Template

**Audience:** counsel adapting a licence drafted to sit beside the AGPLv3 grant of releases up to `5.0.1`, and the owner deciding its open terms.
**Scope:** a licence for one licensee to use a release of Aegis Latent Core published under the AGPLv3 (up to `5.0.1`) on terms other than the AGPLv3. Superseded in part for the Apache-2.0 `5.0.2` source (see the note below).
**Boundary:** a template with open fields. It is not an offer until counsel finalises it, the fields are filled and the licensor signs.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent for the owner and qualified counsel. It is not legal advice, has not been reviewed by a lawyer, has not been offered to anyone, and nobody has signed it. Bracketed fields `[●]` are open decisions, not defaults. Do not send it to a counterparty before counsel has reviewed it.

> **[SUPERSEDED-IN-PART — 5.0.2]** This template was drafted to sit beside the AGPLv3 grant. From `5.0.2` the source is Apache-2.0, so a licence "without the obligations the AGPLv3 places on a licensee" has nothing to supersede for that source. The template remains useful for an agreement made against a release up to `5.0.1` and as a starting point for a support/services agreement (term, fees, liability, general terms); clause 1 would be replaced. See [Licence Transition 5.0.2](LICENSE_TRANSITION_5.0.2.md).

## How to read this draft

Text in plain type is proposed wording. Notes marked **Counsel** state the decision or risk behind a clause. Nothing in the clauses restates a product capability as a promise: where a clause touches a capability it incorporates the claims register instead.

## Parties and artifact

| Field | Value |
| --- | --- |
| Licensor | `[●]`. **Counsel:** today the sole copyright holder is an individual (`NOTICE`, `CONTRIBUTING.md` §1). The licensor should be the company once the IP assignment is signed; do not issue a licence from the individual and then assign |
| Licensee | `[legal entity, registered address]` |
| Licensed Software | Aegis Latent Core at `[exact release tag and commit, or named published artifact]`. A licence that says only "the software" cannot be costed or audited |
| Distribution channels covered | `[PyPI files / GitHub Release assets / GHCR image]` |
| Licensed Modules | `[veracity, sanctum, agentis, sovereign, or omnia for all four]` (`aegis/licensing/model.py`) |
| Environments | `[named environments and topology]` |
| Term | `[●]` from `[date]` |
| Fees | `[●]`. Planning ranges are `[HYPOTHESIS-UNVALIDATED]` and may not be restated as a quote (`COMMERCIAL.md`) |

## 1. Grant

1.1 The Licensor grants the Licensee a non-exclusive, non-transferable licence during the Term to install, run and, for its own internal use, modify the Licensed Software in the named Environments, without the obligations the AGPLv3 places on a licensee who conveys or offers network access to a modified version (a version published under the AGPLv3).

1.2 The licence does not cover: redistribution or sublicensing `[unless Schedule B: OEM]`; use in environments not named; versions after the Licensed Software unless the Licensor supplies them under this agreement.

**Counsel:** decide whether a licensee that never modifies the software needs this licence at all, and how the AGPLv3 network-use clause applies to a gateway that other services call. See question 2 in [Questions for Counsel](COUNSEL_QUESTIONS.md).

1.3 The Licensor keeps all rights not granted. The licence the same source was published under (the AGPLv3 for a release up to `5.0.1`; Apache-2.0 for `5.0.2`) remains available to anyone, including the Licensee; this agreement does not withdraw it.

## 2. Entitlement token

2.1 The Licensor may issue an Ed25519-signed entitlement token naming the Licensee, tier, Licensed Modules, a transaction figure and an expiry. The token unlocks the optional engine facades only; the gateway itself runs without one.

2.2 The Licensee acknowledges how the token works, so neither side is surprised later:

- it is a **bearer credential**: whoever holds a copy holds the entitlement, and the Licensee must protect it;
- it is verified **offline**, and expiry is checked against the host's own clock, which nothing in the software can prove honest;
- the transaction figure is a **commercial term, not a runtime quota**: the software does not count or enforce it, so compliance with it is by the reporting and audit provisions in clause 6;
- there is **no revocation** before expiry. Ending an entitlement early means rotating the Licensor's root key and reissuing every token, which is a Licensor process and not a code path.

(`aegis/licensing/validator.py`.)

**Counsel:** because enforcement is contractual, clauses 2.2 and 6 carry weight that a technical control would otherwise carry. Confirm they are enforceable in the governing law.

## 3. Product boundaries incorporated

3.1 The Licensee's use is subject to the statements and refusals in `docs/CLAIMS_MATRIX.md` and `docs/institutional/UNSUPPORTED_CLAIMS.md` at the Licensed Software's tag. The Licensor makes no statement about the software beyond those documents.

3.2 Without limiting 3.1, the Licensor does not represent that the software or any output of it: is certified; satisfies any law, regulation or standard; is admissible in any proceeding; is fit for production at any load; or prevents tampering (it makes some tampering detectable). Whether an obligation is met is for the Licensee and its assessors.

3.3 The default signing mode is symmetric (HMAC-SHA256); it authenticates a key, not a party, and gives no non-repudiation. The Licensee chooses its signing path.

## 4. Support and updates

4.1 Support is as stated in Schedule A `[●]`: channel, hours, response targets and named contacts. If Schedule A is empty, no support obligation exists and none may be implied.

4.2 Updates: `[versions and cadence included]`. Security fixes: `[policy per SECURITY.md]`.

**Counsel:** the escrow release condition "material failure to meet contracted support" is measurable only if Schedule A sets targets (see the [Escrow Term Sheet](ESCROW_TERM_SHEET.md)).

## 5. Ownership, third-party components, contributions

5.1 The Licensor owns the Licensed Software. The Licensee owns its data, prompts, outputs and records; the Licensor does not receive them under a self-hosted deployment.

5.2 Third-party components keep their own licences (`LICENSE-THIRD-PARTY.md`).

5.3 Licensee modifications remain the Licensee's; `[grant-back: none / feedback licence / contributions under the DCO and CLA in CONTRIBUTING.md]`.

**Counsel:** the origin of the code includes AI-assisted authoring (`CONTRIBUTING.md` §1). Decide what, if anything, the Licensor may warrant about ownership. See question 1.

## 6. Reporting and audit

6.1 Once per `[period]` the Licensee reports its deployed environments and, if the fee depends on it, its annual transaction figure. The Licensor may audit on `[notice]` no more than `[once per year]`, at its cost unless the audit shows an underpayment above `[●]`.

## 7. Warranties and liability

7.1 Warranties: `[●]`. **Counsel:** propose the narrowest set: authority to license; software delivered as built from the named tag. No warranty of results.

7.2 Liability cap `[●]`; excluded losses `[●]`; IP indemnity `[none / capped / excluded]`. **Counsel:** the IP indemnity is the clause most exposed to the authorship question; do not offer it before question 1 is answered.

## 8. Term and termination

8.1 Ends at expiry, or on notice for uncured material breach after `[●]` days. On end, the Licensee stops using the Licensed Software under this agreement; the licence the version was published under remains available for versions the Licensee may lawfully use under it.

## 9. Data and security

9.1 A self-hosted deployment sends nothing to the Licensor. If the Licensor's staff access Licensee systems or data for support, a data-processing agreement is required first `[Schedule C, to be drafted by counsel]`.

## 10. Export and sanctions

10.1 The software contains cryptographic functions, including post-quantum signatures. Each party complies with the export and sanctions laws that apply to it. **Counsel:** confirm classification and any filing.

## 11. General

Governing law `[●]`; forum `[●]`; notices `[●]`; entire agreement; assignment `[●]`; order of precedence: this agreement, then Schedules, then the claims register at the named tag.

## Schedules

| Schedule | Content |
| --- | --- |
| A | Support and updates |
| B | OEM or redistribution terms `[only if agreed]` |
| C | Data-processing terms `[only if support involves data access]` |
| D | Escrow: reference to the executed tri-party agreement `[if any]` |

## Signatures

| Party | Name, title | Date |
| --- | --- | --- |
| Licensor | `[signatory: owner action]` | `[●]` |
| Licensee | `[signatory: licensee action]` | `[●]` |
