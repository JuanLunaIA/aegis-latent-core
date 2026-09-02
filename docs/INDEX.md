# Documentation Index

**Audience:** everyone. This is the entry point to the documentation corpus.
**Scope:** every maintained document, grouped by who needs it.
**Boundary:** documents describe the checked-out source. They do not establish publication, deployment, or external acceptance — see [Release Status](RELEASE_STATUS.md).

---

## Start here

| If you are | Read, in order |
| --- | --- |
| Evaluating the project | [README](../README.md) → [Boundaries](BOUNDARIES.md) → [Claims Matrix](CLAIMS_MATRIX.md) → [Release Status](RELEASE_STATUS.md) |
| Building against it | [Developer Quickstart](DEVELOPER_QUICKSTART.md) → [Integrations Guide](DEVELOPER_INTEGRATIONS_GUIDE.md) → [MMR Proof v1](api/MMR_PROOF_V1.md) |
| Reviewing its security | [Security Policy](../SECURITY.md) → [Threat Model](security/THREAT_MODEL.md) → [Security Controls](security/SECURITY_CONTROLS.md) → [Security Architecture](security/SECURITY_ARCHITECTURE.md) |
| Deploying it | [Deployment Guide](../DEPLOYMENT_GUIDE.md) → [Deployment Profiles](operations/DEPLOYMENT_PROFILES.md) → [Storage Requirements](operations/STORAGE_REQUIREMENTS.md) → [Monitoring and Alerting](operations/MONITORING_ALERTING.md) |
| Running procurement | [Executive Summary](corporate/EXECUTIVE_SUMMARY.md) → [Procurement Checklist](enterprise/PROCUREMENT_CHECKLIST.md) → [Vendor Security Questionnaire](enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md) → [Claims Matrix](CLAIMS_MATRIX.md) |
| Assessing regulatory fit | [Compliance Mapping](compliance/COMPLIANCE_MAPPING.md) → the relevant technical-input document → [Boundaries](BOUNDARIES.md) |
| Contributing | [Contributing](../CONTRIBUTING.md) → [Governance](../GOVERNANCE.md) → [Style Guide](STYLE_GUIDE.md) → [Documentation Governance](DOCUMENTATION_GOVERNANCE.md) |

**Read [Boundaries](BOUNDARIES.md) before quoting anything from this corpus in an external document.**

---

## Claim control

The documents that decide what may be said, and on what evidence.

| Document | Purpose |
| --- | --- |
| [Claims Matrix](CLAIMS_MATRIX.md) | The public claims register: claim, state, evidence locator, boundary, owner. |
| [Boundaries](BOUNDARIES.md) | Consolidated product and evidence boundaries. |
| [Release Status](RELEASE_STATUS.md) | The only place publication state is stated. Readback commands included. |
| [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md) | Claims that must not be made, and why. |
| [Style Guide](STYLE_GUIDE.md) | How to write documentation here, including prohibited language. |
| [Documentation Governance](DOCUMENTATION_GOVERNANCE.md) | How documentation changes are reviewed and gated. |
| [Evidence Governance](institutional/EVIDENCE_GOVERNANCE.md) | How dated evidence records are produced and frozen. |

## Developer

| Document | Purpose |
| --- | --- |
| [Developer Quickstart](DEVELOPER_QUICKSTART.md) | Run the gateway from source and inspect evidence. |
| [Integrations Guide](DEVELOPER_INTEGRATIONS_GUIDE.md) | OpenAI and Anthropic paths, SDK usage, proof verification, streaming semantics. |
| [SDK Guide](DEVELOPER_SDK_GUIDE.md) | Python and TypeScript SDK detail. |
| [Repository Map](REPOSITORY_MAP.md) | Where things live. |
| [Technical FAQ](FAQ_TECHNICAL.md) | Common technical questions. |
| [Rust Build](RUST_BUILD.md) | Building the native extension. |

## API

| Document | Purpose |
| --- | --- |
| [MMR Proof v1](api/MMR_PROOF_V1.md) | The `aegis-mmr-inclusion-v1` proof schema and verification rules. |
| [Audit Endpoints](api/AUDIT_ENDPOINTS.md) | The `/v1/audit` surface, scopes, and response shapes. |
| [Forensic Export](api/FORENSIC_EXPORT.md) | The bounded evidence bundle: contents, verification, and limits. |

## Architecture

| Document | Purpose |
| --- | --- |
| [Architecture](architecture/ARCHITECTURE.md) | Components, request lifecycle, evidence lifecycle. |
| [Failure Semantics](architecture/FAILURE_SEMANTICS.md) | What happens on every failure path, and what the client observes. |
| [Decisions](architecture/DECISIONS.md) | Architecture decision records and their consequences. |
| [Deep Dive](architecture/DEEP_DIVE.md) | Extended implementation detail. |
| [ADR-001](architecture/ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md) | The founding decision record. |

## Security

| Document | Purpose |
| --- | --- |
| [Security Policy](../SECURITY.md) | Reporting path, supported versions, scope. |
| [Threat Model](security/THREAT_MODEL.md) | System model, trust boundaries, threats, mitigations, residual risk. |
| [Security Controls](security/SECURITY_CONTROLS.md) | Control-by-control status, evidence, boundary, and who configures it. |
| [Security Architecture](security/SECURITY_ARCHITECTURE.md) | How the controls fit together across trust boundaries. |
| [Incident Response](security/INCIDENT_RESPONSE.md) | Detection, containment, evidence preservation, recovery. |
| [Vulnerability Disclosure](security/VULNERABILITY_DISCLOSURE.md) | Private reporting, triage, coordination. |
| [WAF Testing](security/WAF_TESTING.md) | The pinned corpus and what its result means. |
| [PQC Constant Time](security/PQC_CONSTANT_TIME.md) | Post-quantum signer timing boundary. |

## Operations

| Document | Purpose |
| --- | --- |
| [Deployment Profiles](operations/DEPLOYMENT_PROFILES.md) | Local, single-node hardened, Kubernetes, air-gapped. |
| [Storage Requirements](operations/STORAGE_REQUIREMENTS.md) | Durability, `fsync`, single-writer, capacity. |
| [Monitoring and Alerting](operations/MONITORING_ALERTING.md) | Metrics, logs policy, alert rules. |
| [Backup and Restore](operations/BACKUP_RESTORE.md) | Scope, integrity checks, restore drill. |
| [Key Rotation Runbook](operations/KEY_ROTATION_RUNBOOK.md) | Signer and trusted-root rotation. |
| [Rollback Runbook](operations/ROLLBACK_RUNBOOK.md) | Release and configuration rollback under evidence constraints. |
| [Backpressure Runbook](operations/BACKPRESSURE_RUNBOOK.md) | SSE queue saturation and upstream slowdown. |
| [Operations Playbook](institutional/DOC-04_OPERATIONS_PLAYBOOK.md) | The full institutional operations volume. |
| [Scaling Guide](performance/SCALING_GUIDE.md) | Scaling boundaries and what they do not establish. |

## Compliance and privacy

| Document | Purpose |
| --- | --- |
| [Compliance Mapping](compliance/COMPLIANCE_MAPPING.md) | Framework-by-framework technical contribution and prohibited claim. |
| [EU AI Act Technical Inputs](compliance/EU_AI_ACT_TECHNICAL_INPUTS.md) | Article 12 record-keeping contribution. |
| [HIPAA Technical Inputs](compliance/HIPAA_TECHNICAL_INPUTS.md) | Safe Harbor-inspired redaction contribution. |
| [MiFID II Technical Inputs](compliance/MIFID_II_TECHNICAL_INPUTS.md) | Record-keeping helper contribution. |
| [ISO/IEC 27037 Technical Inputs](compliance/ISO_27037_TECHNICAL_INPUTS.md) | Evidence handling contribution. |
| [Data Retention](privacy/DATA_RETENTION.md) | What is retained, for how long, under whose control. |
| [PII Redaction Boundaries](privacy/PII_REDACTION_BOUNDARIES.md) | What redaction does and does not catch. |
| [Data Processing Checklist](privacy/DATA_PROCESSING_CHECKLIST.md) | Questions to answer before processing personal data. |

## Formal verification and measurement

| Document | Purpose |
| --- | --- |
| [Formal Verification](formal/FORMAL_VERIFICATION.md) | Z3, Lean, and TLA+/TLC artifacts and the CI gate. |
| [Formal Verification Limits](formal/FORMAL_VERIFICATION_LIMITS.md) | What the models do not prove. |
| [Benchmark Results](benchmarks/BENCHMARK_RESULTS.md) | Measured numbers with environment and date. |
| [Benchmark Method](benchmarks/BENCHMARK_METHOD.md) | How measurements are taken and what they exclude. |
| [Benchmarks](BENCHMARKS.md) | The v3.1.0 measurement record. |

## Enterprise and procurement

| Document | Purpose |
| --- | --- |
| [Enterprise Readiness](enterprise/ENTERPRISE_READINESS.md) | Deployment models, controls, and current limitations. |
| [Pilot Playbook](enterprise/PILOT_PLAYBOOK.md) | Running an evaluation pilot with acceptance criteria. |
| [Procurement Checklist](enterprise/PROCUREMENT_CHECKLIST.md) | What to evaluate and in what order. |
| [Vendor Security Questionnaire](enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md) | Answer templates grounded in repository evidence. |
| [Support Model](enterprise/SUPPORT_MODEL.md) | Community versus commercial support boundary. |
| [Buyer Guide](BUYER_GUIDE_US.md) | Evaluation framing by role. |
| [Procurement FAQ](FAQ_PROCUREMENT.md) | Common procurement questions. |
| [Security FAQ](FAQ_SECURITY.md) | Common security-review questions. |

## Assurance

| Document | Purpose |
| --- | --- |
| [Assurance Roadmap](assurance/ASSURANCE_ROADMAP.md) | What independent assurance would require. None exists today. |
| [Audit Evidence Index](assurance/AUDIT_EVIDENCE_INDEX.md) | Where an auditor finds each artifact. |
| [Control to Evidence Matrix](assurance/CONTROL_TO_EVIDENCE_MATRIX.md) | Control-by-control evidence mapping. |
| [Evidence Index](../evidence/INDEX.md) | The dated evidence catalog. |

## Corporate

| Document | Purpose |
| --- | --- |
| [Executive Summary](corporate/EXECUTIVE_SUMMARY.md) | What this is, what problem it addresses, what it does not establish. |
| [Product One-Pager](corporate/PRODUCT_ONE_PAGER.md) | Condensed capability and limitation summary. |
| [Corporate FAQ](corporate/CORPORATE_FAQ.md) | The eight questions every evaluator asks. |
| [Positioning and Messaging](corporate/POSITIONING_AND_MESSAGING.md) | **Internal.** Category, audiences, prohibited claims. |
| [Commercial](../COMMERCIAL.md) | Licensing and commercial path. |
| [Commercial Strategy](COMMERCIAL_STRATEGY_US.md) | **Internal.** Commercial hypotheses. |

## Institutional volumes

Long-form volumes for institutional review. Each is self-contained and carries its own claim ledger.

| Volume | Subject |
| --- | --- |
| [DOC-01](institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md) | Enterprise architecture |
| [DOC-02](institutional/DOC-02_CRYPTOGRAPHIC_FORENSIC_BLUEPRINT.md) | Cryptographic and forensic blueprint |
| [DOC-03](institutional/DOC-03_THREAT_MODEL.md) | Threat model |
| [DOC-04](institutional/DOC-04_OPERATIONS_PLAYBOOK.md) | Operations playbook |
| [DOC-05](institutional/DOC-05_REGULATORY_DOSSIER.md) | Regulatory dossier |
| [DOC-06](institutional/DOC-06_COMMERCIAL_PROCUREMENT.md) | Commercial and procurement |
| [Document Control](institutional/DOCUMENT_CONTROL.md) | Volume control record |
| [Claim Evidence Graph](institutional/CLAIM_EVIDENCE_GRAPH.md) | Claim-to-evidence relationships |

---

**Related:** [README](../README.md) · [Boundaries](BOUNDARIES.md) · [Claims Matrix](CLAIMS_MATRIX.md) · [Governance](../GOVERNANCE.md)
