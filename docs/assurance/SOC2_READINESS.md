<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# SOC 2 Readiness for the Vendor

**Audience:** the owner planning a SOC 2 Type I, and the auditor who will scope it.
**Scope:** what the company that sells Aegis would need for a Type I report, what the repository already evidences, and what it does not. It serves `REG-H02` and milestones `M7` (auditor engaged) and `M11` (report issued).
**Boundary:** a readiness assessment, not an audit and not a pre-audit by an auditor. No platform, policy set or auditor exists. It is different from [Audit Readiness](../compliance/AUDIT_READINESS.md), which maps the gateway's controls to a **customer's** audit; this page is about the **vendor's own** report.

## What the report would cover

Aegis is self-hosted, so the vendor operates no production service that holds customer data. The system a Type I report would describe is therefore the vendor's **software development and release system**: source control, review, CI, signing, publication, vulnerability handling and support access. The Security category (common criteria) is the natural starting point; Availability and Confidentiality would add little for a vendor that hosts nothing. The scope is a decision for the auditor and the owner.

A Type I report says controls were **designed** appropriately at a point in time. A Type II report says they **operated** over a period and cannot come first (`REG-H02`).

## Criteria groups against the repository

| Group | Repository evidence today | Missing | Owner action |
| --- | --- | --- | --- |
| CC1 control environment | None: one maintainer, no board, no code of conduct for staff | Governance, roles, accountability, background checks | Adopt a governance statement; define roles |
| CC2 communication | `SECURITY.md`, `docs/security/VULNERABILITY_DISCLOSURE.md`, public claims register | Internal communication of responsibilities; customer commitments in contracts | Policy plus signed contracts |
| CC3 risk assessment | `docs/security/THREAT_MODEL.md` (product threats) | A company risk assessment and register | Run and record one |
| CC4 monitoring | CI on every change; scheduled security scans | Management review of control results | Periodic review record |
| CC5 control activities | Documented gates (`docs/DOCUMENTATION_GOVERNANCE.md`) | Written control descriptions mapped to criteria | Write the control matrix |
| CC6 logical access | Signed tags via a keyless workflow identity; branch and environment gates in workflows | Access reviews for GitHub, registries and cloud accounts; MFA evidence; offboarding | Review and record quarterly |
| CC7 system operations | Tamper-evident evidence chain for the product; incident runbook (`docs/security/INCIDENT_RESPONSE.md`) | An incident log, tested response, vendor monitoring | Run a tabletop; keep records |
| CC8 change management | CI gates, signed and attested releases, review of every change | A second reviewer (`REG-H05`): today the author approves | Second maintainer |
| CC9 risk mitigation and vendors | SBOM, dependency audits (`docs/security/DEPENDENCY_RISK_REGISTER.md`) | A list of vendors with reviewed risk (GitHub, PyPI, npm, cloud) | Vendor register |

## The blocking item

`CC8` and `CC1` assume more than one person. A single maintainer who writes, reviews and releases every change is a design finding for a Type I report: the control can be described but has no segregation of duties. The second maintainer (`REG-H05`, milestone `M3`, 2027-02-28) comes before the auditor is engaged (`M7`, 2027-08-31) for this reason.

## Sequence

1. **Platform first, auditor second** (`REG-H02`): choose a compliance platform, connect source control, cloud and identity, and let it show which controls have evidence.
2. Write the policy set the platform lists (information security, access control, change management, incident response, risk assessment, vendor management, business continuity, HR).
3. Run one tabletop incident and one access review, and keep the records.
4. Engage the auditor with a fieldwork date (`M7`).
5. Report issued with no qualified opinion (`M11`, 2027-12-31, `M`).

## Cost and time

The register gives $20k to $80k per year for platform plus audit and 3 to 6 months (`REG-H02`); the model carries $35k for the engagement (`M`). These are planning inputs, not quotes.

## What stays true until the report exists

No document may say the product or the company is SOC 2 compliant, certified or attested. `docs/institutional/UNSUPPORTED_CLAIMS.md` and the claims register hold that line, and [Assurance Status](ASSURANCE_STATUS.md) records the state.
