<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Software Escrow and Continuity Policy

**Status: this is a policy template, not an executed arrangement.**
No escrow agent is engaged, no agreement is signed, and no deposit has been made. Everything below describes terms the vendor is prepared to enter into. A buyer relying on continuity protection needs an executed tri-party agreement, and until one exists this document grants nothing.

That statement is first because a procurement team scanning for it should not have to find it in a footnote.

## The risk this addresses

Aegis is maintained by one engineer. Enterprise procurement calls this key-person or "bus factor" risk, and treats it as a disqualifier for infrastructure that sits on a critical path. The concern is legitimate and this document does not argue otherwise.

What can honestly be said about it:

**Mitigations that already exist**, and can be verified in this repository today:

- The source is **AGPLv3**. A licensee already has the code, the right to run and modify it, and the right to fork. That is a stronger continuity position than most proprietary escrow arrangements deliver, and it does not depend on a trigger event or an agent.
- The build is reproducible from the tree: pinned Actions, a hash-locked `requirements.lock`, a committed `Cargo.lock`, and SBOM generation.
- Release provenance is published — signed tags, uploaded assets, and container images with signature objects present.

**What those do not solve**, and should not be presented as solving:

- Ongoing maintenance, security patching and vulnerability response.
- Support responsiveness.
- Roadmap continuity.

Having the source is not having a maintainer. An escrow arrangement addresses the *artifacts*; it does not manufacture engineering capacity, and no escrow agreement ever has.

## Proposed deposit scope

| Deposited | Why |
|---|---|
| Full source at each released tag | The buildable artifact |
| Build pipeline definitions | Source alone does not reproduce a release |
| Private packaging repository configuration | Needed to rebuild distributables |
| Deployment manifests and Helm charts | Needed to run what is rebuilt |
| Architecture and operations documentation | Needed to understand it |
| Licence-signing key custody procedure | Rebuild without token issuance is not a working system |

**Explicitly not deposited: the Ed25519 licence-signing private key and any customer key material.** Depositing a key that mints entitlements for every customer would create a larger risk than the one escrow addresses. The custody *procedure* is deposited; the key is not.

## Proposed release conditions

Standard triggers, to be defined precisely in the executed agreement:

1. Vendor ceases business operations.
2. Vendor enters insolvency or an equivalent proceeding.
3. Vendor materially fails to meet contracted support obligations, uncured after a defined notice period.
4. Vendor discontinues the product without a migration path.

Condition 3 depends on the support terms actually being contracted. Without an executed support agreement, there is no obligation for a failure to be measured against — a point a buyer should push on rather than accept.

## Candidate escrow agents

Escrow London and NCC Group are the agents customarily used for this kind of arrangement in the UK and EU market. **Naming them here is not a relationship**: neither has been engaged, neither has reviewed this policy, and neither has any obligation to any Aegis customer. A buyer with an incumbent agent should expect that agent to be used instead.

## What a buyer should actually verify

Rather than accepting this document, ask for:

1. The **executed** tri-party agreement — vendor, buyer, agent.
2. **Evidence of deposit**, dated, with a verification report from the agent.
3. A **verification exercise**: did the agent independently rebuild a working artifact from the deposit? An unverified deposit is a box of files, and unverified deposits are the normal failure mode of software escrow.
4. The **release-condition wording**, read by the buyer's counsel rather than summarised by the vendor.
5. A **maintenance plan for the post-release period** — who would operate the code, and under what terms.

Item 3 is the one most often skipped and the one that most often makes an escrow worthless.

## Honest positioning

Escrow reduces artifact risk. It does not reduce key-person risk. A buyer for whom maintainer continuity is genuinely critical should weigh:

- A support agreement with a third-party engineering firm capable of maintaining the code.
- Internal capability to maintain their own fork, which AGPLv3 already permits.
- Contractual transition-assistance terms.

Presenting escrow as a solution to the underlying concern would be overselling it, and a procurement team that has bought escrow before will know that.

## Related

- [`COMMERCIAL.md`](../../COMMERCIAL.md)
- [`docs/commercial/ENTERPRISE_PRICING_GUIDE.md`](ENTERPRISE_PRICING_GUIDE.md)
- [`docs/institutional/DOC-06_COMMERCIAL_PROCUREMENT.md`](../institutional/DOC-06_COMMERCIAL_PROCUREMENT.md)
- [`docs/institutional/UNSUPPORTED_CLAIMS.md`](../institutional/UNSUPPORTED_CLAIMS.md) — `UC-019`, `UC-028`, `UC-033`
