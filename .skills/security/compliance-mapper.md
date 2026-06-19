---
name: compliance-mapper
tier: MEDIUM
domains: [SOC2, ISO27001, HIPAA, PCI-DSS, GDPR, FedRAMP, NIST-CSF]
---

## Activation
Load on: SOC2 prep, ISO 27001 gap analysis, HIPAA BAA review, GDPR DPA, PCI scope,
FedRAMP authorization, NIST CSF mapping, audit evidence packet, control matrix.

## Control Mapping Pipeline
1. **Scope**: which framework + which assets + which timeline
2. **Control matrix**: requirement → technical control → operational control
3. **Evidence**: for each control, what demonstrates implementation
4. **Gap analysis**: required vs implemented; remediation plan with owners + due dates
5. **Auditor packet**: evidence organized by control, clear narrative

## Framework Quick Reference
```
SOC 2 Type II   → Trust Service Criteria (CC, A, PI, C, P)
                  Evidence: access reviews, change tickets, postmortems, IaC diffs
ISO 27001:2022  → 93 controls across 4 themes (Org, People, Physical, Tech)
                  Annex A → Statement of Applicability (SoA)
HIPAA           → Administrative + Physical + Technical safeguards
                  PHI: encrypt, audit, minimum necessary, BAAs
GDPR            → Lawful basis, DSR (access/rectify/erase/portability), DPIA, 72h breach
                  Cross-border: SCCs / DPF / BCRs
PCI-DSS v4.0    → 12 requirements, CDE scope minimization, tokenization
                  ASV scans quarterly, pen test annually, WAF required
FedRAMP         → NIST SP 800-53 controls, 3PAO assessment, ATO path
NIST CSF 2.0    → Govern/Identify/Protect/Detect/Respond/Recover
```

## Evidence Types by Control
| Control | Evidence |
|---|---|
| Access management | Access review logs, Okta/Azure AD exports, offboarding tickets |
| Change management | Git history, PR approvals, change tickets, rollback docs |
| Encryption | Key management policy, rotation logs, TLS config exports |
| Incident response | Postmortem docs, SIEM alerts, escalation timelines |
| Vulnerability management | Scan reports, remediation tickets, SBOM |
| Logging/monitoring | Log retention policy, SIEM config, alert thresholds |
| Vendor management | BAAs, vendor assessments, SLA contracts |
| Employee training | Training completion records, security awareness metrics |

## Output: control matrix format
```
Framework | Requirement | Control ID | Technical Control | Evidence Source | Status | Owner | Due
SOC2 | CC6.1 | CC6.1-01 | MFA enforced via Okta on all production access | Okta logs + policy doc | IMPLEMENTED | SecEng | - 
SOC2 | CC6.3 | CC6.3-01 | Role-based access with quarterly review | Jira tickets + AD export | GAP | IAM Lead | 2025-Q3
```

Rule: never provide legal advice — route to counsel. Gaps surfaced honestly.
