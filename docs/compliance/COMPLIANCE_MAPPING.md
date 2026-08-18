# Compliance Contribution Map — Aegis Latent Core v3.1.0

This document explains which **implemented technical behaviors** may contribute evidence to a customer security, privacy, AI-governance, or audit program. It is written for compliance officers, security reviewers, procurement teams, and counsel. It does **not** determine compliance, certification, authorization, legal admissibility, or contractual sufficiency.

**Last verified:** 2026-08-18 UTC
**Release baseline:** `v3.1.0`
**Owner:** Release owner and qualified customer reviewer
**Canonical claim control:** [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)

> **Boundary.** Aegis is a technical gateway and evidence component. The deploying organization remains responsible for scope, lawful basis, policies, identity, access, retention, incident response, physical safeguards, personnel, vendor contracts, independent assessment, and jurisdiction-specific decisions.

## Status vocabulary

| Status | Meaning |
|---|---|
| `IMPLEMENTED` | The repository contains the behavior and a named test or implementation path. |
| `MEASURED` | A retained artifact measures the behavior under a named workload and boundary. |
| `CONFIGURATION-DEPENDENT` | The behavior requires a declared storage, signer, kernel, network, secret-manager, or topology control. |
| `CUSTOMER-ASSESSMENT` | The behavior may contribute evidence, but the customer must assess scope, applicability, and operating effectiveness. |
| `NOT_EVIDENCED` | The repository does not contain enough evidence to make the statement. |

## Control contribution summary

| Control area | Aegis behavior | Repository evidence | Status | Customer boundary |
|---|---|---|---|---|
| Governed request lifecycle | Authenticated request, bounded body read, policy/WAF checks, upstream call, durable evidence commit, then governed response | `aegis/proxy/`, `aegis_server/main.py`, `aegis/core/crypto_audit.py`, `tests/test_enterprise_durable_evidence.py` | `IMPLEMENTED` | Customer must validate ingress, identity, provider contract, and deployment topology. |
| Evidence integrity | Canonical hashes, predecessor linkage, Merkle metadata, signature metadata, WAL append and `fsync` path | `aegis/core/crypto_audit.py`, integrity tests, `verify_integrity()` | `IMPLEMENTED` | Tamper detection is not immutable external storage, WORM media, or protection from a privileged host administrator. |
| Signing and key rotation | Versioned HMAC keyring, atomic replacement, active/overlap verification, expiry and non-secret `key_id` metadata | `aegis_server/crypto/keyring.py`, `tests/test_keyring_rotation.py`, `key_rotation_report_v2.json` | `MEASURED` / local scope | Secret-manager custody, replica propagation, clock discipline, backup, destruction and orchestration require customer evidence. HMAC is symmetric and classical. |
| WAF and normalization | Application-layer normalization and pinned local corpus regression | `aegis/proxy/waf.py`, `tests/data/waf_corpus_v1.json`, `tools/security/run_waf_corpus.py`, `waf_corpus_report_v1_candidate.json` | `MEASURED` / local corpus | HTTP/2 frame parsing, proxy translation, pseudo-header ordering, H2C, continuation fragments and ingress differentials remain outside this artifact. |
| Egress control | Canonical endpoint validation and application allowlist | `aegis/proxy/egress_guard.py`, egress tests | `IMPLEMENTED` | Network firewall, namespace isolation, cloud IAM, Kubernetes NetworkPolicy and provider-side controls remain required. |
| Rate limiting | Distributed Redis limiter can fail closed when backend is unavailable; in-memory mode is development-only | `aegis/core/ratelimiter.py`, rate-limit tests, `DEPLOYMENT_GUIDE.md` | `CONFIGURATION-DEPENDENT` | Redis TLS, HA, credentials, capacity, failure recovery and fairness require environment testing. |
| Kernel posture | Strict configuration can require Seccomp and AppArmor/SELinux checks | `aegis/core/seccomp_guard.py`, `aegis/core/lsm_guard.py`, deployment tests | `CONFIGURATION-DEPENDENT` | Startup checks are point-in-time assertions. They do not prove indefinite host integrity or kernel hardening. |
| Backpressure | Injected 2 ms `fsync` delay under 10k offered requests preserved 10k durable records with valid chain | `tools/benchmarks/run_backpressure_stall.py`, `backpressure_stall_10k_report.json` | `MEASURED` / injected seam | p99 commit latency was 1,189.89 ms. This is not production capacity, a storage SLO, or `dm-delay` equivalence. |
| Privacy minimization | Request and response bodies are represented by hashes in the WAL under the declared implementation path; tenant/session identifiers remain a configurable PII risk | `docs/privacy/DATA_RETENTION.md`, `aegis/core/crypto_audit.py`, configuration and tests | `CONFIGURATION-DEPENDENT` | Hashes can remain personal data in context. Customer must define purpose, lawful basis, retention, access, deletion/hold, transfer and subject-rights procedures. |
| Export and replay | Exported bundles preserve evidence metadata and signing key ID; integrity can be checked offline under the named verifier | `aegis_server/compliance/exporter.py`, exporter tests | `IMPLEMENTED` | Offline verification does not establish authorship, legal admissibility, or the truth of upstream content. |
| Incident evidence | WAL and retained JSON artifacts can support an incident record and replay workflow | `docs/operations/`, `docs/security/THREAT_MODEL.md`, NIST SP 800-61/800-86 references | `CUSTOMER-ASSESSMENT` | Customer must own incident handling, legal hold, acquisition, notification, chain of custody, and qualified review. |

## Framework-specific contribution map

### NIST AI RMF and Generative AI Profile

NIST describes AI RMF as a voluntary framework for incorporating trustworthiness considerations into AI design, development, use, and evaluation. The Generative AI Profile is a companion resource for generative-AI risk management. [1] [2]

| NIST function | Potential Aegis contribution | Evidence boundary |
|---|---|---|
| GOVERN | Claim matrix, release gates, human review owner, security policy, incident and commercial boundaries | Aegis does not supply the organization's AI policy, accountability structure, or risk appetite. |
| MAP | Request lifecycle, trust boundaries, provider and storage dependencies, threat model | The map covers the gateway boundary, not every customer model, data source, downstream decision, or impact. |
| MEASURE | WAF corpus, timing experiment, backpressure run, test suite, integrity verification | Measures are local and bounded; they do not establish enterprise-wide model quality, fairness, availability, or misuse resistance. |
| MANAGE | Fail-closed paths, durable error evidence, rollback and runbooks | Operating effectiveness, incident response, corrective action and residual-risk acceptance remain customer responsibilities. |

**Allowed wording:** “Aegis provides technical controls and evidence paths that may support a customer AI risk-management program.”
**Blocked wording:** “Aegis is NIST AI RMF compliant” or “Aegis implements the NIST GenAI Profile.”

### NIST CSF 2.0 and NIST SP 800-53

NIST CSF 2.0 provides a taxonomy for managing cybersecurity risk and publishes informative references and profiles. NIST warns that mappings are not always one-to-one and can be subjective. [11] [18]

| CSF 2.0 function | Contribution | Required customer evidence |
|---|---|---|
| Govern | Claims matrix, owner fields, security policy, release gates | Governance charter, risk acceptance, supplier governance and review records |
| Identify | Asset/data/trust-boundary descriptions and dependency tables | Complete enterprise asset inventory and data-flow inventory |
| Protect | Authentication, request bounds, egress validation, signer policy, kernel prerequisites | IAM, secrets, TLS, firewall, workload identity, storage and hardening evidence |
| Detect | Integrity verification, WAF alerts, commit failures and telemetry recommendations | Central monitoring, alert tuning, response ownership and detection validation |
| Respond | Failure-path evidence, incident runbooks, rollback criteria | NIST SP 800-61 lifecycle, incident team, communications and legal process |
| Recover | WAL backup/restore and release rollback guidance | Restore tests, recovery objectives, backup immutability and business continuity |

**No one-to-one equivalence is claimed.** A customer or assessor must select the applicable controls and evaluate implementation and operating effectiveness.

### ISO/IEC 42001 and ISO/IEC 27001

ISO/IEC 42001 specifies requirements for establishing, implementing, maintaining and continually improving an Artificial Intelligence Management System. ISO's public page describes traceability, transparency and reliability as benefits. [14] ISO/IEC 27001 defines requirements for an Information Security Management System. [15]

Aegis can provide **technical evidence inputs** for an AIMS or ISMS, such as request lifecycle records, change/release evidence, integrity verification, and documented control boundaries. The repository does not establish the customer's management-system scope, risk treatment, internal audit, management review, competence, supplier controls, or certification.

**Allowed wording:** “Selected Aegis controls may support an ISO/IEC 42001 or ISO/IEC 27001 evidence package.”
**Blocked wording:** “ISO certified,” “ISO compliant,” or “Aegis satisfies Clause X” without a customer-specific control assessment and qualified review.

### SOC 2

AICPA Trust Services Criteria cover Security, Availability, Processing Integrity, Confidentiality and Privacy for attestation or consulting engagements. [16]

| Trust Services Criteria area | Possible evidence input | Missing organizational evidence |
|---|---|---|
| Security | Authentication, access boundaries, key handling, secure release gates | Entity-wide security program, personnel, change management, vendor management and testing |
| Availability | Failure semantics, telemetry, backup/restore guidance | Availability design, capacity, SLOs, incident history, recovery testing and auditor opinion |
| Processing integrity | Durable evidence gate, canonicalization and chain verification | End-to-end processing criteria, completeness population, auditor sampling and management assertion |
| Confidentiality / Privacy | Hash-only WAL design under declared path, retention guidance | Data inventory, legal basis, contracts, retention/deletion processes, access reviews and privacy program |

Aegis is not a SOC 2 report and does not imply one.

### HIPAA Security Rule

HHS publishes a crosswalk between NIST CSF and the HIPAA Security Rule and states that using NIST CSF does not guarantee HIPAA compliance. [12]

Aegis may provide evidence relevant to selected technical safeguards such as audit controls under 45 CFR §164.312(b), integrity controls under §164.312(c), and transmission controls under §164.312(e), when configured and operated in the customer's environment. That statement does not decide whether a customer is a covered entity or business associate, whether a BAA is required, whether a dataset is PHI, or whether the complete Security Rule is satisfied.

A customer must assess administrative, physical and technical safeguards, risk analysis, workforce controls, access procedures, contingency planning, breach response, BAAs and state-law requirements. Hashing a payload does not remove all privacy obligations because identifiers, timing, metadata and derived data can remain personal or regulated information.

### FedRAMP and federal environments

Aegis has **no FedRAMP authorization** and no IL5/IL6 authorization. The historical FedRAMP RFC-0004 page found during research explicitly states that it is closed historical material and must not be applied. [17]

For a federal deployment, the customer must define the authorization boundary, system security plan, data flows, inherited controls, external connections, customer responsibilities, assessment path and agency authorization. Aegis can be evaluated as one component inside that boundary, but a local release artifact does not establish an ATO.

### EU AI Act and GDPR

The EU AI Act is a jurisdiction-specific regulation whose applicability depends on system role, use, geography and relevant obligations. [16] GDPR analysis likewise depends on controller/processor role, purpose, lawful basis, data categories, transfers and rights. Aegis documentation can support a customer inventory, technical documentation and data-flow review. It does not establish conformity, legal basis, DPIA completion or a lawful transfer mechanism.

## Evidence wording rules

Use the following vocabulary in customer-facing documents:

| Prefer | Do not use |
|---|---|
| “contributes technical evidence to” | “satisfies compliance” |
| “mapped to selected control objectives” | “certified” |
| “customer assessment required” | “HIPAA compliant” |
| “no FedRAMP authorization claimed” | “FedRAMP-ready” |
| “may support an auditor evidence request” | “audit-proof” |
| “offline integrity verification under the named verifier” | “court-admissible” |
| “HMAC is symmetric and classical” | “non-repudiation” for HMAC |

## Reviewer checklist

A qualified reviewer should confirm the deployment scope, legal role, data categories, identity and access controls, secret-manager custody, storage immutability, retention and deletion process, backup/restore, incident response, provider terms, network boundary, customer configuration, and independent assessment requirements. This document supplies a starting map, not a legal conclusion.

## Related documents

- [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
- [`docs/privacy/DATA_RETENTION.md`](../privacy/DATA_RETENTION.md)
- [`docs/security/THREAT_MODEL.md`](../security/THREAT_MODEL.md)
- [`docs/BUYER_GUIDE_US.md`](../BUYER_GUIDE_US.md)
- [`DEPLOYMENT_GUIDE.md`](../../DEPLOYMENT_GUIDE.md)

## References

[1]: https://www.nist.gov/itl/ai-risk-management-framework "NIST AI Risk Management Framework"
[2]: https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence "NIST AI RMF Generative AI Profile"
[11]: https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final "NIST CSF 2.0"
[12]: https://www.hhs.gov/hipaa/for-professionals/security/nist-security-hipaa-crosswalk/index.html "HHS/NIST HIPAA Security Rule crosswalk"
[14]: https://www.iso.org/standard/42001 "ISO/IEC 42001:2023"
[15]: https://www.iso.org/standard/27001 "ISO/IEC 27001:2022"
[16]: https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 "AICPA Trust Services Criteria"
[17]: https://www.fedramp.gov/rfcs/0004/ "FedRAMP RFC-0004 historical page"
[18]: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final "NIST SP 800-53 Rev. 5"
