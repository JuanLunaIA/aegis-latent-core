# Assurance Roadmap

**Audience:** procurement, security reviewers, anyone asking "when will you be certified?"
**Scope:** what independent assurance would require, in what order, and what exists today.
**Boundary:** **no independent assurance exists.** No audit, no penetration test, no certification, no third-party review. This document describes what such work would involve. Publishing a roadmap is not progress toward it, and nothing here is a commitment or a date.

---

## 1. Current state

| Assurance type | State |
| --- | --- |
| SOC 2 Type I or II | None. Not in progress. |
| ISO 27001 | None. |
| Independent penetration test | None. |
| Third-party code audit | None. |
| Cryptographic review by an external party | None. |
| Formal certification of any kind | None. |
| Customer-conducted assessments shared back | None available. |

**"Not in progress" is accurate and deliberate.** Saying "in progress" or "planned for next year" without an engaged assessor, a defined scope and a budget would be the kind of claim this project exists to avoid making.

## 2. What exists instead

Self-produced evidence. Useful, and categorically different from independent assurance — the distinction is that everything below was produced by the party being assessed.

| Artifact | What it establishes |
| --- | --- |
| [Claims Matrix](../CLAIMS_MATRIX.md) | Every public claim, its state, evidence locator and boundary |
| [Threat Model](../security/THREAT_MODEL.md) | Documented threats, mitigations and residual risk |
| [Security Controls](../security/SECURITY_CONTROLS.md) | Control inventory with per-control boundaries |
| Test suite | Behaviour under the conditions the tests exercise |
| Formal artifacts | Bounded model checking via Z3, Lean and TLA+/TLC |
| CI security scanning | CodeQL, Bandit, pip-audit, Trivy, OSV, cargo-audit |
| SBOMs and build attestations | What the build consumed and produced |
| Signed tags and images | Provenance of the release |
| [Evidence Index](../../evidence/INDEX.md) | Dated records of what was observed |

A reviewer can verify all of it independently. That is the point: the documents are structured so you do not have to take the project's word for anything.

## 3. What assurance would require, in order

Ordered by dependency. Skipping ahead produces an assessment that fails on prerequisites.

### Stage 1 — Organisational prerequisites

Most certifications assess an **organisation's controls over time**, not a codebase. Before any assessor is engaged:

- A legal entity with defined scope.
- Documented policies: access, change, incident, vendor, business continuity, risk.
- Personnel controls, which in a single-maintainer project raises separation-of-duties questions an assessor will ask about immediately.
- An operating history — typically 3–12 months of evidence for a Type II.

**This stage is the binding constraint, not the technical work.** A well-engineered codebase with no operating organisation cannot be SOC 2 audited, and no amount of code quality changes that.

### Stage 2 — Independent technical review

Achievable without full organisational maturity, and higher value per unit cost for most buyers:

- **Penetration test** against a representative deployment, with a defined scope, a report, and remediation evidence.
- **Cryptographic review** of the chain construction, MMR implementation, canonical hashing and signing paths by a reviewer with relevant expertise.
- **Code audit** of the evidence path: `crypto_audit.py`, `mmr.py`, `streaming.py`, and the auth surface.

A buyer who needs external validation sooner should ask for these rather than for a certification, because they are attainable and they address the actual technical risk.

### Stage 3 — Formal certification

- Scope definition and gap assessment.
- Remediation.
- Evidence collection over the observation period.
- Audit fieldwork.
- Report.

Realistically 12–24 months from a standing start with an operating organisation, and requiring sustained funding. **No such programme is underway.**

## 4. What a buyer can do today

Independent assurance you can obtain without waiting for anyone:

1. **Conduct your own security review.** The source is available; the threat model and control inventory tell you where to look and what is claimed.
2. **Commission your own penetration test** against your deployment. That is more relevant to your risk than a generic test of someone else's.
3. **Spot-check the claims register.** Pick three rows and verify their evidence locators. If a locator does not support its claim, that is a material finding about the whole register — and it is a cheap test.
4. **Run the pilot** in [Pilot Playbook](../enterprise/PILOT_PLAYBOOK.md), especially the failure tests. Fail-closed behaviour under load is the property that matters most and is the easiest to verify yourself.
5. **Verify the supply chain.** Check signatures, attestations and SBOMs with the commands in [Release Status §2](../RELEASE_STATUS.md#2-readback-commands).
6. **Assess the maintainer-capacity risk** explicitly, and document your mitigation. See [Support Model §4](../enterprise/SUPPORT_MODEL.md#4-the-maintainer-capacity-risk).

## 5. What would change this document

It changes when an assessor is engaged, a scope is agreed, and work begins — not before, and not on intent. Any future state will be recorded here with the assessor named, the scope stated, the report referenced, and the limitations of that report stated as plainly as its conclusions.

Until then, this document says "none exists", and that is the accurate answer to give a security team asking.

---

**Related:** [Audit Evidence Index](AUDIT_EVIDENCE_INDEX.md) · [Control to Evidence Matrix](CONTROL_TO_EVIDENCE_MATRIX.md) · [Enterprise Readiness](../enterprise/ENTERPRISE_READINESS.md) · [Vendor Security Questionnaire](../enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md)
