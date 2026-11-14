# ISO/IEC Standards Register

**Audience:** security reviewers, procurement, auditors, and anyone answering an RFP that lists ISO/IEC standards.
**Scope:** for each ISO or ISO/IEC standard a buyer is likely to name, what certificate exists and who receives it, what this gateway contributes technically, and what it does not.
**Boundary:** `LEGAL-REVIEW-REQUIRED`. The register classifies public standards. It is not a conformity assessment, an auditor's opinion, or legal advice, and no certification body has reviewed it. It uses the classes defined in [Certification Scope](CERTIFICATION_SCOPE.md) §2 and the status vocabulary of [Compliance Mapping](COMPLIANCE_MAPPING.md). Claim row: `CLM-129`.

---

## 1. Reading the register

Software cannot hold an ISO/IEC 27001, 42001 or 27701 certificate. Those standards certify an **organisation's management system**, audited by an accredited certification body. A product contributes technical controls and evidence to that system; it is never the certified party.

| Class | Meaning for this register |
|---|---|
| O | A certificate or attestation exists, and it is issued to an **organisation**. The gateway contributes evidence inputs; the organisation holds the certificate. |
| P | The **product or its cryptographic module** must be validated or evaluated by a laboratory. Nothing in this repository is validated or evaluated. |
| F | No certificate exists. The standard is guidance, a vocabulary, a framework or a format specification. The function statement in the row is the claim. |

A status describes this repository's source. `IMPLEMENTED` never means "conforms to the standard": it means the repository contains the named behaviour and a test or implementation path for it.

## 2. AI governance and AI systems

| Standard | Class | Gateway contribution | Evidence | Status |
|---|---|---|---|---|
| ISO/IEC 42001:2023 (AI management system) | O | Annex A A.6.2.8 (AI system recording of event logs): one signed, hash-linked evidence record per governed call, committed before the response is released. A.6.2.6 (operation and monitoring): posture and rejection counters on `/metrics`. A.10.3 (suppliers): the egress allowlist limits which upstream providers the gateway can reach | `aegis/core/crypto_audit.py`; `aegis/core/observability.py`; `aegis/proxy/egress_guard.py` | `IMPLEMENTED` for the mechanisms; `CUSTOMER-ASSESSMENT` for the controls |
| ISO/IEC 23894:2023 (AI risk management) | F | Refusals (WAF, egress, body bounds, unavailable evidence) are recorded and countable, which an organisation may cite as risk-treatment records. There is no per-route or per-tenant risk-tier field | `aegis/proxy/app.py` rejection paths; `X-Aegis-Rejection-ID` | `CUSTOMER-ASSESSMENT` |
| ISO/IEC 42005:2025 (AI system impact assessment) | F | Evidence records can be sampled as inputs to an assessment. No impact-assessment export preset exists | `docs/api/FORENSIC_EXPORT.md` | `NOT_EVIDENCED` for any preset |
| ISO/IEC 42006:2025 (requirements for AIMS certification bodies) | — | Applies to certification bodies, not products. The offline verifier lets an auditor check a sample of records without trusting the gateway | `sdk/` verifiers; `aegis/core/mmr.py` | Not applicable to the product |
| ISO/IEC 5338:2023 (AI system life cycle processes) | F | Operation stage only: each record carries the model name the request named and the configured provider | `aegis/core/crypto_audit.py` | `IMPLEMENTED` (operation stage) |
| ISO/IEC 12792:2025 (transparency taxonomy) | F | Response headers state evidence and proof status (`X-Aegis-Evidence-Status`, `X-Aegis-Proof-Status`, `X-Aegis-MMR-*`). There is no provider or model disclosure header and no synthetic-output flag | `aegis/proxy/app.py` | `IMPLEMENTED` (evidence headers only) |
| ISO/IEC 22989:2022, 23053:2022, TR 24027:2021, TR 24028:2020, 24029-1/-2, 25059:2023, 38507:2022 | F | Vocabulary, frameworks, bias, robustness, quality and governance guidance. The gateway does not train, evaluate or score models. Adversarial-input refusals are local regression results, not a robustness assessment of any model | `tests/data/waf_corpus_v1.json` | No contribution claimed |

## 3. Digital evidence and records

| Standard | Class | Gateway contribution | Evidence | Status |
|---|---|---|---|---|
| ISO/IEC 27037:2012 (identification, collection, acquisition, preservation) | F | See [ISO/IEC 27037 Technical Inputs](ISO_27037_TECHNICAL_INPUTS.md). The gateway produces artifacts; people perform the process | that document | `LEGAL-REVIEW-REQUIRED` |
| ISO/IEC 27041:2015 (suitability of investigative methods) | F | Assuring an investigative method is the practitioner's. The offline verifiers are reproducible and tested, which a practitioner may cite | `sdk/` | `CUSTOMER-ASSESSMENT` |
| ISO/IEC 27042:2015, 27043:2015 (analysis; incident investigation) | F | Practitioner process. A broken chain makes the gateway refuse governed traffic with 503 until repaired, which preserves the state an investigator examines | `aegis/proxy/app.py` (`_require_intact_ledger`) | `CUSTOMER-ASSESSMENT` |
| ISO/IEC 27050 series (electronic discovery) | F | `/v1/audit/proofs/{state_id}` returns an O(log n) inclusion proof for one disclosed record against a separately trusted root, so one record can be produced without the others | `aegis/proxy/audit_api.py`; `aegis/core/mmr.py` | `IMPLEMENTED` |
| ISO 14721 (OAIS archival) | F | Forensic bundles are signed and verifiable offline. The register does not map them to OAIS information packages | `aegis/core/forensic_bundle.py` | No contribution claimed |
| ISO 14533 series (long-term signature profiles) | F | RFC 3161 timestamp tokens when a TSA is configured; a strict gateway with the seccomp filter refuses that path (`REG-D105`). No long-term signature profile is produced | `aegis/core/rfc3161_timestamper.py` | `NOT_EVIDENCED` |

## 4. Information security and cloud

| Standard | Class | Gateway contribution | Evidence | Status |
|---|---|---|---|---|
| ISO/IEC 27001:2022 (ISMS) | O | Annex A, control by control: [Audit Readiness](AUDIT_READINESS.md) §4.3 | that table | `CUSTOMER-ASSESSMENT` |
| ISO/IEC 27002:2022 (control guidance) | F | The same controls, implementation level. CI gates on every change contribute evidence to 8.25, 8.28 and 8.29; the secure-development process and its operating effectiveness are the organisation's | `.github/workflows/ci.yml` | `IMPLEMENTED` (CI gates); `CUSTOMER-ASSESSMENT` (controls) |
| ISO/IEC 27005:2022 (security risk management) | F | Organisational process | — | No contribution claimed |
| ISO/IEC 27017:2015 (cloud controls) | F, used inside a 27001 scope | Applies to a cloud service provider and its customers. Self-hosted, the deployer is the provider. Tenant separation is logical, never physical | `aegis/auth/principal.py`; tenant-isolation tests | `CUSTOMER-ASSESSMENT` |
| ISO/IEC 27018:2025 (PII in public clouds, replaces 2019) | F, used inside a 27001 scope | Applies to a public-cloud PII processor. The gateway keeps request and response bodies as digests in the WAL, and cryptographic shredding can make a subject's sealed payload unreadable | `aegis/core/crypto_shredder.py`; [Data Retention](../privacy/DATA_RETENTION.md) | `CONFIGURATION-DEPENDENT` |
| ISO/IEC 27034 series (application security) | F | Typed configuration with strict-mode refusals, bounded parsing, CI static analysis and property-based tests | `aegis/config.py`; `.github/workflows/ci.yml` | `IMPLEMENTED` |
| ISO/IEC 27035 series (incident management) | F | Integrity failure, egress refusal and ledger faults are visible on `/v1/audit/integrity` and `/metrics`; the procedure is the organisation's | [Incident Response](../security/INCIDENT_RESPONSE.md) | `CUSTOMER-ASSESSMENT` |
| ISO/IEC 27036 series (supplier relationships) | F | Egress allowlist of upstream providers | `aegis/proxy/egress_guard.py` | `IMPLEMENTED` |
| ISO/IEC 27040:2024 (storage security) | F | Each record is fsynced before the response is released; AES-256-GCM sealing; shredding | `aegis/core/group_commit.py`; `aegis/core/crypto_shredder.py` | `IMPLEMENTED` |
| ISO/IEC 27032:2023, ISO/IEC 20000-1:2018, ISO 22301:2019, ISO 31000:2018, ISO 9001:2015 | O or F | Organisational. For continuity, the gateway's own backup and HA procedures exist; no recovery point or recovery time objective is measured | [Backup and Restore](../operations/BACKUP_RESTORE.md); [High Availability](../operations/HIGH_AVAILABILITY.md) | No objective claimed |

## 5. Privacy and de-identification

| Standard | Class | Gateway contribution | Evidence | Status |
|---|---|---|---|---|
| ISO/IEC 27701:2025 (PIMS; standalone since October 2025, replaces 2019) | O | Evidence inputs for minimisation and erasure: digests instead of bodies, redaction before egress, shredding | [PII Redaction Boundaries](../privacy/PII_REDACTION_BOUNDARIES.md) | `CUSTOMER-ASSESSMENT` |
| ISO/IEC 29100 (privacy framework) | F | Data minimisation at the gateway: bodies are hashed in the evidence record, and PII can be redacted before the upstream call | same | `CONFIGURATION-DEPENDENT` |
| ISO/IEC 29101:2018 (privacy architecture) | F | Hash-linked records hold digests; per-subject sealed payloads are stored separately and can be shredded | `aegis/core/crypto_shredder.py` | `IMPLEMENTED` |
| ISO/IEC 20889:2018 (de-identification terminology) | F | In its terms, redaction is **masking** and the PII vault is **pseudonymisation**: the vault keeps the mapping so the response can be restored. Neither is anonymisation | `aegis/core/phi_deidentifier.py`; `CLM-124` | `IMPLEMENTED` |
| ISO/IEC 27559:2022, 27557:2022 | F | Re-identification and privacy risk assessment are the organisation's | — | No contribution claimed |

## 6. Cryptography and authentication

| Standard | Class | Gateway contribution | Evidence | Status |
|---|---|---|---|---|
| ISO/IEC 19790 (cryptographic module requirements) | P | **Not validated.** The gateway has no module of its own; see [Certification Scope](CERTIFICATION_SCOPE.md) §5 | that section | None |
| ISO/IEC 18033-3, 10118-3, 14888-3 (block ciphers, hash functions, signatures) | F | The gateway uses AES-256-GCM, SHA-256 and HMAC-SHA256 from the Python `cryptography` library, and ECDSA or RSA through a PKCS#11 token. ML-DSA-65 is NIST FIPS 204; this register cites no ISO/IEC standard for it | `aegis/core/crypto_audit.py`; `aegis/core/pqc_signer.py` | `IMPLEMENTED` (algorithm use, not validation) |
| ISO/IEC 11770 series (key management) | F | Versioned keyring with rotation and overlap; PKCS#11 and HSM signing tiers | `aegis/core/hsm.py`; [Compliance Mapping](COMPLIANCE_MAPPING.md) "Signing and key rotation" | `CONFIGURATION-DEPENDENT` |
| ISO/IEC 18031 (random bit generation) | F | The gateway implements no generator. Keys, nonces and identifiers come from the operating system through Python's `secrets` and `os.urandom` and the `cryptography` library | `aegis/core/` | `IMPLEMENTED` (delegated) |
| ISO/IEC 29115:2013 (entity authentication assurance) | F | Each record's signer reference names the authentication method (`api_key`, OIDC, mTLS). No assurance level is mapped | `aegis/config.py` (`principal_signer_ref`) | `IMPLEMENTED` (method only) |
| ISO/IEC 18367 (conformance testing of cryptographic algorithms and mechanisms) | F | Known-answer tests pin SHA-256, HMAC-SHA256, AES-256-GCM and Ed25519 to their published vectors, through the gateway's own digest and HMAC functions. ML-DSA-65 has no known-answer test. This is testing, not a laboratory's conformance evaluation | `tests/test_known_answer_vectors.py` | `IMPLEMENTED` (four primitives) |
| ISO/IEC 15408 (Common Criteria), ISO/IEC 18045 | P | No evaluation | — | None |

## 7. Software supply chain and the web surface

| Standard | Class | Gateway contribution | Evidence | Status |
|---|---|---|---|---|
| ISO/IEC 5230:2020 (OpenChain licence compliance) | O, self-certification available | Licence headers are checked in CI, and a licence audit is kept. No OpenChain programme has been declared | [License Audit](LICENSE_AUDIT.md); CI `License Headers` | `NOT_EVIDENCED` for conformance |
| ISO/IEC 18974:2023 (OpenChain security assurance) | O, self-certification available | Dependency, OSV, Trivy, cargo and CodeQL scans in CI; hash-pinned lock files. No programme has been declared | `.github/workflows/` | `NOT_EVIDENCED` for conformance |
| ISO/IEC 5962:2021 (SPDX) | F, format specification | CI emits an SPDX JSON SBOM (`sbom.spdx.json`, Syft) for main and release builds. ISO/IEC 5962:2021 standardises SPDX 2.2.1; the SBOM uses the version Syft emits (SPDX 2.3 for the pinned Syft 1.0.0). `scripts/generate_sbom.sh` writes the same format locally (`aegis-sbom.spdx.json`) | `.github/workflows/ci.yml` (`sbom` job); `scripts/generate_sbom.sh` | `IMPLEMENTED`; a release asset needs its own readback |
| ISO/IEC 25010:2023 (product quality model) | F | Benchmarks are measured locally under named conditions | [Benchmarks](../BENCHMARKS.md) | `MEASURED` / local scope |
| ISO/IEC 40500:2025 (WCAG 2.2) | F | The dashboard has not been assessed against WCAG 2.2 | `dashboard/` | `NOT_EVIDENCED` |

## 8. Sector standards

| Standard | Class | Gateway contribution | Status |
|---|---|---|---|
| ISO 27799 (health informatics security) | F, used inside a 27001 scope | See [HIPAA Technical Inputs](HIPAA_TECHNICAL_INPUTS.md) | `CUSTOMER-ASSESSMENT` |
| IEC 81001-5-1:2021 (health software security) | P when the product is health software | The gateway's intended use is not a medical purpose; see [Certification Scope](CERTIFICATION_SCOPE.md) §5 | `LEGAL-REVIEW-REQUIRED` |
| ISO 20022 (financial messaging) | F | The gateway neither emits nor parses ISO 20022 messages | Not applicable |

## 9. Mappings this register rejects

These appear in circulated mappings and are wrong or unsupported:

- **ISO/IEC 42001 A.8.4 is "Communication of incidents"**, not event logging. Event logging is A.6.2.8. A.9.3 is "Objectives for responsible use of AI system", not human oversight.
- **Writing ISO control identifiers into evidence records.** A signed record cannot be corrected. A wrong clause number would become permanent evidence, and every verifier would need a schema change. Mappings stay in documents like this one, versioned and correctable.
- **"ISO 42001", "ISO 27001" or "ISO 27701" badges** on a product page. They read as certification. Allowed wording is in [Compliance Mapping](COMPLIANCE_MAPPING.md) "ISO/IEC 42001 and ISO/IEC 27001".
- **ISO/IEC 27701:2019 and 27018:2019** as current editions. Both were replaced in 2025.
- **Features the gateway does not have**, presented as ISO mappings: provider and model disclosure headers, risk-tier fields, impact-assessment presets, Roughtime anchoring, customer-managed key services, multi-region replication, a recovery point objective of zero, and known-answer vectors for ML-DSA-65.

## 10. Related documents

- [Certification Scope](CERTIFICATION_SCOPE.md)
- [Compliance Mapping](COMPLIANCE_MAPPING.md)
- [Audit Readiness](AUDIT_READINESS.md)
- [Assurance Status](../assurance/ASSURANCE_STATUS.md)
- [Claims Matrix](../CLAIMS_MATRIX.md)
