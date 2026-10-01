# Certification Scope: Function Versus External Attestation

**Audience:** sales, procurement reviewers, and buyers in healthcare, legal, government, banking and engineering. Also anyone about to write "not certified" or "certified" about this product.
**Scope:** for each framework a buyer names, three things. Does any certification or attestation exist for it? If so, who receives it? And what does the gateway itself do for the function the framework asks for, with the evidence that shows it?
**Boundary:** `LEGAL-REVIEW-REQUIRED` (`CLM-120`). This is a classification of public schemes as read on 2026-09-30. It is not legal advice, a compliance determination, or an assessor's opinion. [Assurance Status](../assurance/ASSURANCE_STATUS.md) holds the independent-assurance state, which is none, and this document does not change it. Claims are governed by the [Claims Matrix](../CLAIMS_MATRIX.md).

---

## 1. Why this document exists

Several documents in the corpus say "not certified" next to HIPAA, GDPR and the EU AI Act. For those laws the sentence is true but misleading. **No certification exists that any software product could hold.** A buyer reads "not certified" as a missing step. There is no such step: HHS states that it does not recognise private HIPAA "certifications" [1], GDPR certification applies to a controller's or processor's processing operations and is voluntary [2], and a gateway is not what the EU AI Act assesses [3].

For those frameworks the accurate statement is a **function statement**: what the gateway does, which clause the function serves, and which test shows it. A function statement can be complete. Where the gateway fully supplies a function, this document says so without qualification. Where it does not, it says which part is missing and whose it is.

Other frameworks do have a certificate, and nothing replaces it. FIPS 140-3 module validation and Common Criteria evaluation certify a product or module. SOC 2 and ISO/IEC 27001 attest an organisation. For those, "none" stays "none" until the certificate exists.

## 2. Three classes

| Class | Meaning | What the product can say |
| --- | --- | --- |
| **F — function only** | No certification scheme applies to a software component. The law or framework places its obligations on an organisation, and the component supplies functions that organisation uses. | The function statement. "Not certified" is not written, because no certificate exists to lack. "Compliant" is not written either, because compliance is the organisation's. |
| **O — organisational attestation** | A certificate or report exists, but it attests an **organisation**: the vendor, if it runs a hosted service, or the deploying organisation. | "The gateway supplies controls X, Y, Z to your programme." The vendor's own attestation state is stated as it is: none ([Assurance Status](../assurance/ASSURANCE_STATUS.md)). |
| **P — product validation** | A third party must test the product or its cryptographic module, and the claim cannot be made without the certificate. | "Not validated" and "not evaluated" remain accurate and required. Only the algorithms in use may be named. |

## 3. Class F — no certificate exists; the function is the claim

"Provided" means the gateway supplies the whole function as the clause states it, in the configuration named, with the evidence linked. "Partial" names the missing part. "Deployer" means the obligation cannot be met by software.

### 3.1 HIPAA Security Rule, 45 CFR §164.312 (healthcare, US)

No HIPAA certification exists for products or organisations: "HHS does not endorse or otherwise recognize private organizations' 'certifications' regarding the Security Rule" [1].

| Clause | Function | Gateway | Evidence |
| --- | --- | --- | --- |
| (b) audit controls | Record and examine activity in systems that contain ePHI | **Provided** for every governed call: a hash-linked record, durable before the response, signed under the configured key. The reported assurance tier says which signature a chain carries (`CLM-090`) | `aegis/core/crypto_audit.py`; [Audit Readiness](AUDIT_READINESS.md) §3.4 |
| (c)(1) integrity; (c)(2) mechanism to authenticate ePHI | Detect improper alteration | **Provided** for the records the gateway writes: tamper detection on read, inclusion proofs, offline verifier | `/v1/audit/integrity`; `aegis-sdk verify`; `CLM-090` |
| (d) person or entity authentication | Verify who is seeking access | **Provided** at the gateway: API keys compared in constant time, per-key principal grants looked up by an HMAC digest of the key rather than the key itself (`AEGIS_API_KEY_PRINCIPALS_JSON`), OIDC with pinned algorithms, and mTLS | `aegis/auth/apikey.py`; `aegis/auth/principal.py`; `aegis/auth/oidc.py`; `aegis/auth/mtls.py` |
| (e)(1) transmission security | Guard ePHI in transit | **Provided** on the gateway's two hops when TLS is configured on both: a TLS or mTLS listener, and TLS upstream with a pinned CA | [Audit Readiness](AUDIT_READINESS.md) §4.2 |
| (a)(2)(i) unique user identification | One identity per user | **Partial**: one principal per credential; issuing one credential per person is the organisation's | `aegis/auth/principal.py` |
| (a)(2)(iv) encryption and decryption | Encrypt ePHI | **Partial**: with shredding on, per-subject AES-256-GCM sealing, and digests rather than bodies in the WAL; storage encryption at rest is the host's | `aegis/core/crypto_shredder.py`; `CLM-068` |
| (a)(2)(ii) emergency access procedure | Break-glass access | **Deployer**: no break-glass path exists in the gateway | — |
| §164.308 administrative safeguards, BAAs | Risk analysis, workforce, contracts | **Deployer** | — |

**What may be said:** "Aegis provides the audit-control, integrity, authentication and transmission-security functions of 45 CFR §164.312(b), (c), (d) and (e)(1) for the calls it governs. No HIPAA certification exists for any product."
**What may not be said:** "HIPAA compliant", "HIPAA certified", "HIPAA ready" as a status. PHI redaction is pattern-based and is not de-identification under §164.514 ([HIPAA inputs](HIPAA_TECHNICAL_INPUTS.md)).

### 3.2 GDPR, Regulation (EU) 2016/679 (every sector, EU)

Article 42 certification is voluntary and certifies **processing operations by controllers and processors**. It "shall not reduce the responsibility of the controller or the processor" [2]. No certificate is issued to a software product.

| Article | Function | Gateway | Evidence |
| --- | --- | --- | --- |
| 5(1)(c) data minimisation (records) | Keep no more personal data than needed | **Provided** in the evidence record: request and response bodies are recorded as digests, or as per-subject ciphertext when shredding is on, never as text. Tenant and session identifiers are configurable and can be personal data | [Data Retention](../privacy/DATA_RETENTION.md) |
| 5(1)(f), 32(1)(b) integrity of processing | Detect alteration | **Provided** for the evidence record | `CLM-090` |
| 17 erasure, with the record kept intact | Make personal data unrecoverable without breaking the audit chain | **Provided** for records committed while shredding is on: destroying a subject's key leaves ciphertext only, and the MMR root and earlier proofs do not change. Records committed before shredding was turned on keep plain digests (`CLM-068`) | `CLM-068`; `aegis/core/crypto_shredder.py` |
| 32(1)(a) encryption | Encrypt personal data | **Partial**: payload sealing under shredding; transport TLS; storage at rest is the host's | as above |
| 6 lawful basis; 30 records of processing; 35 DPIA; 28 processor contracts | Organisational duties | **Deployer** | — |

**What may be said:** "Aegis keeps digests rather than bodies in its evidence record, and, with shredding enabled, can erase a data subject's payloads without invalidating the chain. GDPR certifies processing operations, not software."
**What may not be said:** "GDPR compliant", "GDPR certified".

### 3.3 EU AI Act, Regulation (EU) 2024/1689 (every sector, EU)

Conformity assessment (Article 43) applies to **high-risk AI systems**, and the system's provider carries it out. Whether a system is high-risk follows from its intended purpose (Article 6, Annex III). The gateway governs and records calls to a model. That purpose is not an Annex III use, so the gateway is a component that a provider or deployer uses, not the system the Act assesses. Whether this holds for a particular product that embeds the gateway is a legal question (`LEGAL-REVIEW-REQUIRED`).

| Article | Function | Gateway | Evidence |
| --- | --- | --- | --- |
| 12(1) record-keeping | "automatic recording of events (logs) over the lifetime of the system" [3] | **Provided** for the calls the gateway governs: automatic, per-call, tamper-evident, and committed before the response | [EU AI Act inputs](EU_AI_ACT_TECHNICAL_INPUTS.md) |
| 19, 26(6) keep logs for at least six months | Retention | **Provided** as configuration: WAL rotation plus an object-locked archive with a set retention period | `AEGIS_S3_ARCHIVE_RETENTION_DAYS`; [Data Retention](../privacy/DATA_RETENTION.md) |
| 15 cybersecurity | Resilience against manipulation | **Partial**: injection filtering with its stated evasions (`CLM-117`), kernel confinement, and fail-closed evidence. The model's robustness is not evaluated | `CLM-117`, `CLM-119` |
| 9, 11, 14, 17, 43 | Risk management, documentation, human oversight, QMS, conformity assessment | **Deployer or provider** | — |

**What may be said:** "Aegis records every governed model call automatically and tamper-evidently, and keeps the records for a configurable period. These are the logging functions Articles 12 and 26(6) ask of high-risk systems."
**What may not be said:** "EU AI Act compliant", "AI Act certified", "conformity-assessed".

### 3.4 Legal evidence and admissibility (legal, every jurisdiction)

No certificate makes a record admissible; a court decides. US Federal Rule of Evidence 902(14) lets a copy of data self-authenticate "if authenticated by a process of digital identification". The rule requires a certification by a **qualified person**, and the committee note names comparison of hash values as the usual process [4].

| Function | Gateway | Evidence |
| --- | --- | --- |
| A digital identification process for each record | **Provided**: SHA-256 digests, hash linkage, and a signature per node | `aegis/core/crypto_audit.py` |
| Independent verification of a copy | **Provided**: offline verification of an exported bundle, and inclusion proofs against a separately trusted root | `aegis-sdk verify`; `aegis/core/mmr.py`; [MMR claim boundary](../../AGENTS.md) |
| Trusted time | **Not provided in the hardened posture**: the host clock. A strict gateway refuses RFC 3161 anchoring (`REG-D105`) | [Audit Readiness](AUDIT_READINESS.md) §5 |
| The certification itself | **Deployer**: a qualified person certifies | — |

**What may be said:** "Aegis produces the hash-based digital identification and offline verification that a Rule 902(14) certification relies on."
**What may not be said:** "court-admissible", "legally admissible", "legal-grade evidence". Signatures are HMAC-SHA256, ML-DSA-65, or RSA-PSS or ECDSA through a PKCS#11 token; an ephemeral Ed25519 fallback is reported as `COMPROMISED_EPHEMERAL` (`CLM-090`). None of them is a qualified electronic signature or seal under eIDAS. Qualified status requires a qualified trust service provider on an EU trusted list [5], and the gateway is not one.

### 3.5 Financial-sector record-keeping (banking and investment)

| Rule | Who carries it | Gateway function | What may not be said |
| --- | --- | --- | --- |
| MiFID II Article 16(6)/(7); MiFIR Article 25(1) | The investment firm | Per-call records with retention classes ([MiFID II inputs](MIFID_II_TECHNICAL_INPUTS.md); citation under legal review, `REG-D77`) | "MiFID II compliant" |
| SEC Rule 17a-4(f) (US broker-dealers) | The broker-dealer. The 2022 amendments allow a non-rewriteable, non-erasable format **or** a complete time-stamped audit trail [6] | The archive writes segments under S3 Object Lock, `COMPLIANCE` mode by default (`AEGIS_S3_ARCHIVE_LOCK_MODE`). Whether a given bucket and its configuration meet Rule 17a-4(f) is the broker-dealer's determination. The chain is append-only and detects a rewrite; its timestamps come from the host clock | "17a-4 compliant", "SEC approved". The SEC approves no product |

### 3.6 Voluntary frameworks and catalogues (government, engineering, every sector)

| Framework | Certificate? | Gateway function | Evidence |
| --- | --- | --- | --- |
| NIST AI RMF 1.0 and Generative AI Profile | None; voluntary [7] | Records, measurement artifacts and fail-closed paths that support MAP, MEASURE and MANAGE | [Compliance Mapping](COMPLIANCE_MAPPING.md) |
| NIST CSF 2.0 | None | Detect, protect and recover functions at the gateway boundary | [Compliance Mapping](COMPLIANCE_MAPPING.md) |
| NIST SP 800-53 Rev. 5 | None for products. An agency's authorising official authorises the **system** | AU-2, AU-3 and AU-12 event logging; AU-9 protection of audit information; AU-10 non-repudiation with asymmetric signing configured; IA-2; SC-8 | [Audit Readiness](AUDIT_READINESS.md) §4 |
| OWASP Top 10 for LLM Applications (2025) | None; an awareness list | LLM01 prompt injection: filtered with stated evasions (`CLM-117`, `UC-042`); LLM02 sensitive-information disclosure: redaction (`CLM-047`) | `tests/test_waf_redteam_d94_d101.py` |
| ISO/IEC 27037 (digital evidence handling) | None; guidance | Identification, preservation and verification functions for the gateway's records | [ISO/IEC 27037 inputs](ISO_27037_TECHNICAL_INPUTS.md) |

## 4. Class O — the certificate attests an organisation

| Scheme | Who receives it | When a buyer needs it from this vendor | State |
| --- | --- | --- | --- |
| SOC 2 Type I or II | A service organisation, via a CPA firm's report | Only if the vendor **operates** the gateway as a hosted service. For self-hosted software, the deployment falls inside the buyer's own SOC 2 scope | None ([Assurance Status](../assurance/ASSURANCE_STATUS.md), `REG-H02`) |
| ISO/IEC 27001:2022 | An organisation's ISMS | When a buyer's vendor policy requires it of the supplier organisation | None |
| ISO/IEC 42001:2023 | An organisation's AI management system | Same | None |
| HITRUST | An organisation's assessed environment | Healthcare buyers whose policy asks for it | None |
| PCI DSS v4.x | The entity that stores, processes or transmits card data | The gateway sits inside the buyer's assessed environment. PCI's software programmes cover payment software, which this is not | Not applicable to the product |
| FedRAMP | A **cloud service offering** used by US federal agencies [8] | Only if the vendor offers the gateway as a cloud service to a federal agency. Self-hosted software falls under the agency's own authorisation | Not applicable while the product is self-hosted |

## 5. Class P — the product or module must be validated

| Scheme | What it certifies | Who requires it | State and allowed wording |
| --- | --- | --- | --- |
| FIPS 140-3 (NIST CMVP) | A cryptographic module | US federal agencies and their contractors whenever cryptography protects sensitive information: "if cryptography is required, then it must be validated" [9] | **Not validated.** The gateway has no module of its own. It uses the Python `cryptography` library (OpenSSL) and the Rust `ml-dsa` crate. A host whose OpenSSL FIPS provider is validated validates that provider, not the gateway; the `ml-dsa` crate is not validated. Allowed: "uses FIPS-approved algorithms", naming those configured: SHA-256, HMAC-SHA256, AES-256-GCM, ML-DSA-65 (FIPS 204), and RSA-PSS or ECDSA through a PKCS#11 token. No known-answer test against NIST vectors is in the repository |
| NIST CAVP / ACVP | An algorithm implementation | Buyers who ask for algorithm certificates | None |
| Common Criteria (NIAP in the US) | A product against a protection profile | US national security systems (CNSSP 11) and some government buyers | None |
| FDA device clearance (SaMD) / EU MDR | Software with a medical intended purpose | Only if the product is **marketed for a medical purpose** | The gateway's intended use, governing and recording model calls, is not a medical purpose. `clinical_claim_detector.py` and `dosage_hallucination.py` flag model text. Presenting them as clinical decision support would change this analysis (`LEGAL-REVIEW-REQUIRED`) |

## 6. Replacing "not certified" in the corpus

| Where the text says | Write instead |
| --- | --- |
| "Not HIPAA certified" | "No HIPAA certification exists for any product. Aegis provides the §164.312(b), (c), (d) and (e)(1) functions for governed calls (see Certification Scope §3.1)." |
| "Not GDPR certified" | "GDPR certification applies to processing operations, not software. Aegis minimises and can erase what it records (§3.2)." |
| "Not EU AI Act certified" | "Aegis supplies the automatic logging Article 12 asks of high-risk systems; conformity assessment is the system provider's (§3.3)." |
| "Not court-certified" / "not legally admissible" | "Admissibility is decided by a court. Aegis produces the hash-based identification a Rule 902(14) certification relies on (§3.4)." |
| "Not SOC 2 certified" | Unchanged: "No SOC 2 report exists." This is class O and the statement is the state. |
| "Not FIPS certified" | "Not FIPS 140-3 validated. Uses FIPS-approved algorithms." This is class P. |

## 7. References

1. U.S. Department of Health and Human Services, HIPAA FAQ, "Are we required to 'certify' our organization's compliance with the standards of the Security Rule?" <https://www.hhs.gov/hipaa/for-professionals/faq/are-we-required-to-certify-our-organizations-compliance-with-the-standards/index.html>
2. Regulation (EU) 2016/679, Article 42(1), (3) and (4). <https://eur-lex.europa.eu/eli/reg/2016/679/oj>
3. Regulation (EU) 2024/1689, Articles 6, 12, 26 and 43, and Annex III. <https://eur-lex.europa.eu/eli/reg/2024/1689/oj>
4. Federal Rules of Evidence, Rule 902(14) and the 2017 committee note. <https://www.law.cornell.edu/rules/fre/rule_902>
5. Regulation (EU) No 910/2014 (eIDAS), as amended by Regulation (EU) 2024/1183: qualified trust services and trusted lists. <https://eur-lex.europa.eu/eli/reg/2014/910/oj>
6. U.S. SEC, "Amendments to Electronic Recordkeeping Requirements for Broker-Dealers" (2022): the audit-trail alternative to the WORM requirement. <https://www.sec.gov/investment/amendments-electronic-recordkeeping-requirements-broker-dealers>
7. NIST, AI Risk Management Framework (AI RMF 1.0) and NIST AI 600-1. <https://www.nist.gov/itl/ai-risk-management-framework>
8. FedRAMP, "Scope of FedRAMP" (OMB M-24-15). <https://www.fedramp.gov/2026/scope/>
9. NIST CSRC, Cryptographic Module Validation Program. <https://csrc.nist.gov/projects/cryptographic-module-validation-program>

<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
-->
