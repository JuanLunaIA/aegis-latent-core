# Documentation Index

**Audience:** everyone. This is the entry point to the documentation corpus.
**Scope:** every maintained document, grouped by who needs it.
**Boundary:** documents describe the checked-out source. They do not establish publication, deployment, or external acceptance — see [Release Status](RELEASE_STATUS.md).

---

## Start here

| If you are | Read, in order |
| --- | --- |
| Evaluating the project | [README](../README.md) → [Boundaries](BOUNDARIES.md) → [Claims Matrix](CLAIMS_MATRIX.md) → [Release Status](RELEASE_STATUS.md) |
| Building against it | [Developer Quickstart](DEVELOPER_QUICKSTART.md) → [Usage Examples](USAGE_EXAMPLES.md) → [Integrations Guide](DEVELOPER_INTEGRATIONS_GUIDE.md) → [MMR Proof v1](api/MMR_PROOF_V1.md) |
| Reviewing its security | [Security Policy](../SECURITY.md) → [Threat Model](security/THREAT_MODEL.md) → [Security Controls](security/SECURITY_CONTROLS.md) → [Security Architecture](security/SECURITY_ARCHITECTURE.md) |
| Deploying it | [Deployment Guide](../DEPLOYMENT_GUIDE.md) → [Deployment Profiles](operations/DEPLOYMENT_PROFILES.md) → [Storage Requirements](operations/STORAGE_REQUIREMENTS.md) → [Monitoring and Alerting](operations/MONITORING_ALERTING.md) |
| Running procurement | [Executive Summary](corporate/EXECUTIVE_SUMMARY.md) → [Procurement Checklist](enterprise/PROCUREMENT_CHECKLIST.md) → [Vendor Security Questionnaire](enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md) → [Claims Matrix](CLAIMS_MATRIX.md) |
| Assessing regulatory fit | [Audit Readiness](compliance/AUDIT_READINESS.md) → [Compliance Mapping](compliance/COMPLIANCE_MAPPING.md) → the relevant technical-input document → [Boundaries](BOUNDARIES.md) |
| Contributing | [Contributing](../CONTRIBUTING.md) → [Governance](../GOVERNANCE.md) → [Style Guide](STYLE_GUIDE.md) → [Documentation Governance](DOCUMENTATION_GOVERNANCE.md) |
| Maintaining or succeeding the maintainer | [Maintainer Handbook](MAINTAINER_HANDBOOK.md) → [Registry](REGISTRY.md) → [Release Status](RELEASE_STATUS.md) |

**Read [Boundaries](BOUNDARIES.md) before quoting anything from this corpus in an external document.**

**Section indexes:** [docs/README.md](README.md) · [architecture](architecture/README.md) · [benchmarks](benchmarks/README.md) · [institutional](institutional/README.md) · [security](security/SECURITY_CONTROLS.md)

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

| [Master Defect and Debt Registry](REGISTRY.md) | Every defect, debt and audit row with its terminal state, evidence and boundary. |
| [Registry — Human Handoff Pack](REGISTRY_HUMAN_PACK.md) | The rows that need a human decision, split out of the registry. |
| [Roadmap](ROADMAP.md) | Audit backlog and engineering tickets, with severity, root cause and proposed solution. |
| [Release Epistemic Statement](RELEASE_EPISTEMIC_STATEMENT.md) | What a release does and does not establish, surface by surface. |
## Developer

| Document | Purpose |
| --- | --- |
| [Developer Quickstart](DEVELOPER_QUICKSTART.md) | Run the gateway from source and inspect evidence. |
| [Integrations Guide](DEVELOPER_INTEGRATIONS_GUIDE.md) | OpenAI and Anthropic paths, SDK usage, proof verification, streaming semantics. |
| [Usage Examples](USAGE_EXAMPLES.md) | Runnable examples for every mode, with real transcripts. |
| [SDK Guide](DEVELOPER_SDK_GUIDE.md) | Python and TypeScript SDK detail. |
| [Repository Map](REPOSITORY_MAP.md) | Where things live. |
| [Module Inventory](MODULE_INVENTORY.md) | Generated per-file inventory: purpose, reachability status, tests, owner — and every open ticket's owner and unblock path. |
| [Technical FAQ](FAQ_TECHNICAL.md) | Common technical questions. |
| [Rust Build](RUST_BUILD.md) | Building the native extension. |

| [Upgrading to 5.0.0](UPGRADING.md) | The 4.x → 5.0.0 path, including the breaking public JSON API change. |
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

| [Platform Compatibility Matrix](PLATFORM_COMPATIBILITY.md) | Supported platforms, kernels and filesystems, with the review date. |
| [Architecture Index](architecture/README.md) | Index to the architecture corpus. |
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

| [Build-script Attestation](security/BUILD_SCRIPT_ATTESTATION.md) | Which crates run a build script and what that means for provenance. |
| [Dependency Risk Register](security/DEPENDENCY_RISK_REGISTER.md) | Per-dependency disposition for risky components. |
| [Dependency Triage](security/DEPENDENCY_TRIAGE.md) | Generated dependency triage output. |
| [WAL Hardening — 2026-08-20](security/WAL_HARDENING_2026-08-20.md) | The diagnosed native WAL race and its regression results. |
## Operations

| Document | Purpose |
| --- | --- |
| [Deployment Profiles](operations/DEPLOYMENT_PROFILES.md) | Local, single-node hardened, Kubernetes, air-gapped. |
| [Storage Requirements](operations/STORAGE_REQUIREMENTS.md) | Durability, `fsync`, single-writer, capacity. |
| [Azure Quickstart](operations/AZURE_QUICKSTART.md) | Empty subscription to a running strict-mode gateway on one VM, and back. |
| [Azure Install Options](operations/AZURE_INSTALL_OPTIONS.md) | VM kit, AKS, Helm, Container Apps: advantages, disadvantages, costs. |
| [Azure Kit Creator](operations/AZURE_KIT_CREATOR.md) | `doctor`, `estimate`, `create`, `verify`, and what a generated kit contains. |
| [Monitoring and Alerting](operations/MONITORING_ALERTING.md) | Metrics, logs policy, alert rules. |
| [Backup and Restore](operations/BACKUP_RESTORE.md) | Scope, integrity checks, restore drill. |
| [Key Rotation Runbook](operations/KEY_ROTATION_RUNBOOK.md) | Signer and trusted-root rotation. |
| [Rollback Runbook](operations/ROLLBACK_RUNBOOK.md) | Release and configuration rollback under evidence constraints. |
| [Backpressure Runbook](operations/BACKPRESSURE_RUNBOOK.md) | SSE queue saturation and upstream slowdown. |
| [High Availability](operations/HIGH_AVAILABILITY.md) | Active-passive failover, active-active replicas with one global sequence, multi-team boundary. |
| [Operations Playbook](institutional/DOC-04_OPERATIONS_PLAYBOOK.md) | The full institutional operations volume. |
| [Scaling Guide](performance/SCALING_GUIDE.md) | Scaling boundaries and what they do not establish. |

| [Platform Operator Guide](PLATFORM_OPERATOR_GUIDE.md) | Day-2 operations for SRE and platform teams: deployment, evidence handling, limits. |
## Compliance and privacy

| Document | Purpose |
| --- | --- |
| [Audit Readiness](compliance/AUDIT_READINESS.md) | Assessor procedure and control matrices: SOC 2, HIPAA §164.312, ISO/IEC 27001 Annex A, EU AI Act, MiFID II; the evidence collector. |
| [Compliance Mapping](compliance/COMPLIANCE_MAPPING.md) | Framework-by-framework technical contribution and prohibited claim. |
| [EU AI Act Technical Inputs](compliance/EU_AI_ACT_TECHNICAL_INPUTS.md) | Article 12 record-keeping contribution. |
| [HIPAA Technical Inputs](compliance/HIPAA_TECHNICAL_INPUTS.md) | Safe Harbor-inspired redaction contribution. |
| [MiFID II Technical Inputs](compliance/MIFID_II_TECHNICAL_INPUTS.md) | Record-keeping helper contribution. |
| [ISO/IEC 27037 Technical Inputs](compliance/ISO_27037_TECHNICAL_INPUTS.md) | Evidence handling contribution. |
| [Data Retention](privacy/DATA_RETENTION.md) | What is retained, for how long, under whose control. |
| [PII Redaction Boundaries](privacy/PII_REDACTION_BOUNDARIES.md) | What redaction does and does not catch. |
| [Data Processing Checklist](privacy/DATA_PROCESSING_CHECKLIST.md) | Questions to answer before processing personal data. |

| [License Audit](compliance/LICENSE_AUDIT.md) | Generated license inventory for the dependency set. |
## Formal verification and measurement

| Document | Purpose |
| --- | --- |
| [Formal Verification](formal/FORMAL_VERIFICATION.md) | Z3, Lean, and TLA+/TLC artifacts and the CI gate. |
| [Formal Verification Limits](formal/FORMAL_VERIFICATION_LIMITS.md) | What the models do not prove. |
| [Benchmark Results](benchmarks/BENCHMARK_RESULTS.md) | Measured numbers with environment and date. |
| [Benchmark Method](benchmarks/BENCHMARK_METHOD.md) | How measurements are taken and what they exclude. |
| [Azure Benchmarks](benchmarks/AZURE_BENCHMARKS.md) | Disk and gateway measurements on one Azure VM, 2026-09-26. |
| [Benchmarks](BENCHMARKS.md) | The v3.1.0 measurement record. |

| [Prove It Yourself](PROVE_IT.md) | Reproduce the evidence on your own machine, command by command. |
| [Benchmark Methodology and Index](benchmarks/README.md) | How to read benchmark results, and the retained v3.1.0 measurements. |
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

| [Commercial Readiness](commercial/COMMERCIAL_READINESS.md) | What stands between this repository and an enterprise sale. |
| [Revenue Artifact Inventory](commercial/ARTIFACT_INVENTORY.md) | Inventory of the commercial artifacts and their state. |
| [Sales Claim Ledger](commercial/CLAIM_LEDGER.md) | Claims sales may and may not make, with their evidence. |
| [Connector Ecosystem](commercial/CONNECTOR_ECOSYSTEM.md) | The connector surfaces and their boundaries. |
| [Enterprise Pricing Guide](commercial/ENTERPRISE_PRICING_GUIDE.md) | Pricing structure and what it does not include. |
| [Positioning](commercial/POSITIONING.md) | Category, audience and prohibited claims. |
| [Software Escrow and Continuity Policy](commercial/SOFTWARE_ESCROW_POLICY.md) | Escrow terms and continuity commitments. |
| [Sales Kit — Discovery Call Script](commercial/SALES_KIT/DISCOVERY_CALL_SCRIPT.md) | Discovery questions that keep claims inside the ledger. |
| [Sales Kit — Objection Handling](commercial/SALES_KIT/OBJECTION_HANDLING.md) | Prepared answers to the objections buyers raise. |
| [Sales Kit — One Pager](commercial/SALES_KIT/ONE_PAGER.md) | Buyer-facing one-page summary. |
| [Sales Kit — Outbound Sequences](commercial/SALES_KIT/OUTBOUND_SEQUENCES.md) | Outreach sequences constrained by the claim ledger. |
| [Sales Kit — Pilot Proposal](commercial/SALES_KIT/PILOT_PROPOSAL.md) | Paid pilot proposal template. |
## Assurance

| Document | Purpose |
| --- | --- |
| [Assurance Roadmap](assurance/ASSURANCE_ROADMAP.md) | What independent assurance would require. None exists today. |
| [Audit Evidence Index](assurance/AUDIT_EVIDENCE_INDEX.md) | Where an auditor finds each artifact. |
| [Control to Evidence Matrix](assurance/CONTROL_TO_EVIDENCE_MATRIX.md) | Control-by-control evidence mapping. |
| [Evidence Index](../evidence/INDEX.md) | The dated evidence catalog. |

| [Security Assurance Roadmap](SECURITY_ASSURANCE_ROADMAP.md) | Repository evidence versus deployment acceptance and independent assurance. |
## Corporate

| Document | Purpose |
| --- | --- |
| [Executive Summary](corporate/EXECUTIVE_SUMMARY.md) | What this is, what problem it addresses, what it does not establish. |
| [Product One-Pager](corporate/PRODUCT_ONE_PAGER.md) | Condensed capability and limitation summary. |
| [Corporate FAQ](corporate/CORPORATE_FAQ.md) | The eight questions every evaluator asks. |
| [Positioning and Messaging](corporate/POSITIONING_AND_MESSAGING.md) | **Internal.** Category, audiences, prohibited claims. |
| [Commercial](../COMMERCIAL.md) | Licensing and commercial path. |
| [Commercial Strategy](COMMERCIAL_STRATEGY_US.md) | **Internal.** Commercial hypotheses. |

| [Product Brief (US)](PRODUCT_BRIEF_US.md) | Executive sponsor and economic buyer brief. |
| [Prospectus](PROSPECTUS.md) | Full US enterprise prospectus. |
| [Prospectus (ES)](PROSPECTUS_ES.md) | Prospectus, Spanish edition. |
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
| [DOC-08 — Zero-Knowledge Inclusion Proof](institutional/DOC-08_ZERO_KNOWLEDGE_INCLUSION.md) | Construction and epistemic boundary of the inclusion proof. |
| [Institutional Suite Index](institutional/README.md) | Index to the institutional volumes. |
