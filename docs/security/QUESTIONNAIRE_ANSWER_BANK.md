<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Security questionnaire answer bank

**Audience:** anyone answering a customer's vendor-security questionnaire.
**Scope:** the questions that recur in enterprise procurement, with the only
answer the current evidence supports.
**Boundary:** an answer bank, not a certification. "No" is a valid answer and
must not be softened. Every "yes" points to an artifact or a test; if it does
not, it is not ready to send.

> **[COUNSEL-REVIEW-REQUIRED]** Legal, privacy and contractual answers must be
> reviewed before they are sent. This bank does not create a DPA, BAA, SLA or
> certification.

## Company and product

| # | Question | Answer | Evidence / boundary |
| --- | --- | --- | --- |
| 1 | What does the product do? | An OpenAI-compatible AI governance and evidence gateway: policy enforcement plus a durable signed evidence ledger for admitted outcomes. | `README.md`, `docs/CLAIMS_MATRIX.md` |
| 2 | Is it SaaS? | The gateway is self-hosted. A separate hosted evaluation console exists at `aegislatent.com` and does not receive customer model prompts or outputs. | `docs/legal/DATA_MAP.md` |
| 3 | Where is data processed? | Self-hosted: in the customer's environment. Hosted console metadata: AWS `us-east-1`. | `DATA_MAP.md` §1–2 |
| 4 | Do you train models on customer data? | No. The project does not operate a model-training pipeline on customer data. | code boundary; no training service |
| 5 | Do you use customer data for analytics? | The hosted console records account, session and usage metadata for authentication, metering and abuse response; not prompts or completions. | `DATA_MAP.md` §2 |

## Certifications and assurance

| # | Question | Answer | Evidence / boundary |
| --- | --- | --- | --- |
| 6 | SOC 2 Type II? | **No.** No audit, report, or auditor. | `ASSURANCE_STATUS.md` |
| 7 | ISO/IEC 27001? | **No.** No certificate or certification body. | `ASSURANCE_STATUS.md` |
| 8 | ISO/IEC 42001? | **No.** No AI management-system certificate. | `ASSURANCE_STATUS.md` |
| 9 | HIPAA / BAA? | **No BAA is offered.** The product is not represented as HIPAA compliant. | `ASSURANCE_STATUS.md` |
| 10 | FedRAMP / IL5 / IL6? | **No.** No authorization or 3PAO assessment. | `ASSURANCE_STATUS.md` |
| 11 | PCI DSS? | **No.** No QSA assessment; the product is not a payment processor. | `ASSURANCE_STATUS.md` |
| 12 | Independent penetration test? | **No completed third-party test.** The SOW is a draft. | `docs/assurance/PENTEST_SOW_DRAFT.md` |
| 13 | Can you provide a security questionnaire? | Yes, this bank, with the "no" answers intact. | this file |

## Architecture and encryption

| # | Question | Answer | Evidence / boundary |
| --- | --- | --- | --- |
| 14 | Encryption in transit? | TLS is supported and required by the reference deployment; RDS TLS is **not yet proven** with `pg_stat_ssl`. | `aegis-cloud/deploy/aws/RDS_TLS.md` |
| 15 | Encryption at rest? | The self-hosted operator chooses and must verify the volume. The reference EC2 kit used encrypted EBS; RDS storage encryption is **not asserted here** until re-read from the live instance. | deployment profiles; `aws rds describe-db-instances` |
| 16 | Key management? | Ed25519 and ML-DSA signing keys are operator-controlled. The project does not escrow them. HSM/PKCS#11 is optional and deployment-dependent. | `docs/operations/KEY_ROTATION_RUNBOOK.md` |
| 17 | Is the cryptography FIPS validated? | **No.** The implementations are not FIPS 140-3 validated. | `docs/CLAIMS_MATRIX.md` CLM-019 |
| 18 | Multi-tenant isolation? | Tenant principals are derived from authenticated keys/OIDC/mTLS; the hosted console uses account-scoped queries. A formal isolation test is pending. | `docs/security/SECURITY_CONTROLS.md` |
| 19 | High availability? | Single-node reference; active/passive HA is configuration-dependent. No multi-region failover. | `docs/operations/HIGH_AVAILABILITY.md` |

## Access and operations

| # | Question | Answer | Evidence / boundary |
| --- | --- | --- | --- |
| 20 | Who has production access? | The owner, currently via the AWS root account. A scoped MFA operator role is drafted but **not deployed**. | `aegis-cloud/deploy/aws/OPERATOR_ROLE.md` |
| 21 | Is MFA enforced? | Not yet for AWS operations. The drafted role requires MFA; root MFA status must be verified before relying on it. | `OPERATOR_ROLE.md` |
| 22 | Logging and monitoring? | Application JSON logs and EMF metrics exist; CloudWatch alarms are **not deployed** (0 alarms). | `aegis-cloud/deploy/aws/OBSERVABILITY.md` |
| 23 | Incident response? | A written plan and disclosure policy exist; no 24/7 staffed on-call. A tabletop is pending. | `docs/security/INCIDENT_RESPONSE.md`, `VULNERABILITY_DISCLOSURE.md` |
| 24 | Backup and restore? | RDS automated backups/PITR were reported as configured in an earlier readback; **no RDS restore has been executed** in this record. Re-read before answering a customer. | `docs/operations/BACKUP_RESTORE.md` |
| 25 | Business continuity / DR? | A plan exists with RTO/RPO as targets, not tested commitments. | `docs/operations/` |
| 26 | Change management? | Branch protection, CI gates and signed releases exist for the public repo; the private control plane uses a local gate because remote CI is blocked by billing. | `docs/RELEASE_STATUS.md`, `aegis-cloud/verify.sh` |

## Data handling and legal

| # | Question | Answer | Evidence / boundary |
| --- | --- | --- | --- |
| 27 | DPA available? | A draft DPA exists; it is **not reviewed by counsel** and not offered as executed. | `docs/legal/DATA_PROCESSING_ADDENDUM.md` |
| 28 | Subprocessors? | AWS, Stripe, Vercel, GitHub, Cloudflare, as listed. | `docs/legal/SUBPROCESSORS.md` |
| 29 | Data retention? | Configured by the deployment for the gateway; hosted console retains account/session/usage metadata as described. | `DATA_MAP.md` §2 |
| 30 | Can we export/delete data? | Yes for the hosted console account via `/v1/account/export` and `DELETE /v1/account`, subject to tax/fraud retention and backups. | `aegis-cloud/app/routers/me.py` |
| 31 | Where is the company incorporated? | **No company is formed for the product.** The copyright holder is an individual. | `docs/legal/ENTITY_AND_TAX_MEMO.md` |
| 32 | Insurance? | **No policy is bound.** | `docs/legal/INSURANCE_AND_ESCROW_DECISIONS.md` |
| 33 | Export classification? | **Not obtained.** | `docs/legal/EXPORT_AND_CRYPTO_CLASSIFICATION.md` |
| 34 | Source code escrow? | **Not signed.** A term sheet is a draft. | `docs/legal/ESCROW_TERM_SHEET.md` |
| 35 | SLA? | **No SLA.** Support is email, no staffed 24/7 rotation. | `docs/enterprise/SUPPORT_MODEL.md` |

## How to answer a question not in this bank

1. Find the canonical source in `docs/truth/PUBLIC_SURFACE_MAP.md`.
2. If the source says "not implemented", answer "no" and state the boundary.
3. If no source exists, answer "we do not have evidence for that today" and add
   the question to `docs/truth/PUBLIC_SURFACE_MAP.md` before answering again.
4. Never convert a roadmap item into a "yes" because a customer needs it.
