# Aegis Institutional Documentation Suite

**Suite version:** 1.0
**Evidence cutoff:** 2026-08-22 UTC
**Release baseline:** published `v3.1.0`
**Current-main review baseline:** post-PR #99, commit `45d95188d40792639fdd654369765a7233bef09a`
**Language:** US English
**Status:** Review candidate; publication is controlled by `docs/CLAIMS_MATRIX.md`

## Purpose

This directory is the canonical institutional review suite for the published Aegis Latent Core v3.1.0 baseline and the explicitly identified current-main changes after PR #99. It reconciles architecture, cryptography, security, operations, regulatory, and commercial claims against production code, tests, retained evidence, and authoritative external sources. Current-main capabilities are not retroactively attributed to the v3.1.0 tag. The suite does not convert a technical feature into a certification, legal opinion, contractual commitment, production authorization, or independent assurance report.

## Volumes

| ID | Canonical document | Primary audience | Accountable reviewers |
|---|---|---|---|
| DOC-01 | [Enterprise Architecture and Mechanistic Lifecycle Specification](DOC-01_ENTERPRISE_ARCHITECTURE.md) | Architects, platform engineers, formal-methods reviewers | Architecture, storage, SRE, formal methods |
| DOC-02 | [Zero-Trust Post-Quantum Cryptographic and Forensic Blueprint](DOC-02_CRYPTOGRAPHIC_FORENSIC_BLUEPRINT.md) | Cryptography, security architecture, evidence engineering | Cryptography, security, evidence custody |
| DOC-03 | [Threat Model and Adversarial Defense Framework](DOC-03_THREAT_MODEL.md) | CISO, AppSec, AI red team, platform security | Application security, AI security, platform security |
| DOC-04 | [Operational Engineering Playbook and High-Availability Runbooks](DOC-04_OPERATIONS_PLAYBOOK.md) | SRE, incident command, release engineering | SRE, release, security, evidence custody |
| DOC-05 | [Institutional Regulatory Compliance and Statutory Audit Dossier](DOC-05_REGULATORY_DOSSIER.md) | Compliance, audit, quality, counsel | Qualified counsel, assessor, quality unit, privacy/security officers |
| DOC-06 | [Commercial Strategy, C-Suite Buyer Dossier, and Procurement Package](DOC-06_COMMERCIAL_PROCUREMENT.md) | Executives, procurement, product, finance | Executive commercial owner, finance, security, counsel |

Supporting controls are [Claim-Evidence Graph](CLAIM_EVIDENCE_GRAPH.md), [Unsupported Claims and Contradictions](UNSUPPORTED_CLAIMS.md), and [Document Control](DOCUMENT_CONTROL.md).

## Canonical source and supersession map

The six volumes consolidate overlapping explanatory material. Existing files remain useful as focused guides and history, but any material conflict is resolved in this order: applicable law and executed terms; `docs/CLAIMS_MATRIX.md`; production code and tests; retained evidence; this suite; focused legacy documentation; samples and marketing material.

| Existing document family | Canonical institutional destination | Retention rule |
|---|---|---|
| `docs/architecture/*`, architecture sections in `README.md` and `DEPLOYMENT_GUIDE.md` | DOC-01 | Retain for implementation detail; resolve conflicting assurance language through DOC-01. |
| `docs/security/PQC_CONSTANT_TIME.md`, forensic/PQC sections in FAQs and prospectus | DOC-02 | Retain measurements and focused guidance; DOC-02 controls cross-domain claims. |
| `docs/security/THREAT_MODEL.md`, `docs/security/WAF_TESTING.md`, security FAQs | DOC-03 | Retain focused procedures; DOC-03 controls attack-surface and mitigation status. |
| `docs/operations/*`, `docs/PLATFORM_OPERATOR_GUIDE.md`, `docs/performance/SCALING_GUIDE.md` | DOC-04 | Retain executable runbooks; DOC-04 controls production-readiness and HA language. |
| `docs/compliance/COMPLIANCE_MAPPING.md`, privacy and regulatory feature prose | DOC-05 | Retain contribution maps; DOC-05 controls legal and assurance interpretations. |
| `docs/COMMERCIAL_STRATEGY_US.md`, `docs/BUYER_GUIDE_US.md`, product/FAQ/prospectus files | DOC-06 | Retain buyer detail and historical hypotheses; DOC-06 controls current offers and promises. |
| `Samples/` | None | Demonstration only; never runtime, customer, capacity, or assurance evidence. |

## Claim status contract

Every material claim uses one status: `IMPLEMENTED`, `MEASURED`, `CONFIGURATION-DEPENDENT`, `ROADMAP`, or `LEGAL-REVIEW-REQUIRED`. A claim is blocked if its source changes, its test or artifact fails, an assumption changes, a named reviewer rejects it, or customer-facing wording becomes stronger than the claims matrix.

`[PROVEN_FORMAL]` is permitted only for the exact Lean theorem, Z3 formula, and finite TLC configurations recorded in `docs/formal/FORMAL_VERIFICATION.md`. It does not apply to this documentation suite, the implementation, storage hardware, deployment topology, legal status, or commercial outcome.

## Reproduction and validation

```bash
python scripts/audit_documentation_corpus.py \
  --output-dir "evidence/documentation_audit_$(date -u +%F)"
python tools/docs/verify_documentation.py
python -m ruff check aegis aegis_server tests scripts/audit_documentation_corpus.py
python -m pytest -q --tb=short
bash scripts/verify_formal_artifacts.sh
```

The documentation audit must report no placeholders in `docs/institutional/`, the repository documentation verifier must pass, and `git diff --check` must be clean. External regulatory citations require periodic freshness review and qualified interpretation.

## Approval and release

No volume is an external promise until its accountable owners approve the exact revision. Regulatory and evidentiary conclusions require counsel or a qualified assessor. Production operation requires target-environment acceptance. Commercial terms require an executed agreement. Rollback is a Git revert plus withdrawal or correction of any externally distributed claim.
