# DOC-05 — Institutional Regulatory Compliance and Statutory Audit Dossier

**Document ID:** `DOC-05`
**Canonical language:** US English
**Review date:** 2026-08-20 UTC
**Source boundary:** checked-out source metadata is synchronized at `v4.0.2`; source metadata does not prove external tag, release, registry, OCI, deployment, compliance, or acceptance state
**Historical evidence scope:** the technical and regulatory mapping reviewed on 2026-08-20 remains a `v3.1.0`-era record unless explicitly revalidated against the current source
**Status:** Technical control-contribution dossier; not legal advice, certification, attestation, authorization, or conformity assessment
**Primary owners:** Customer compliance owner, qualified counsel, independent assessor, evidence custodian, security owner, and release owner
**Normative claim control:** [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)

## 1. Purpose and decision boundary

This dossier maps selected Aegis technical behaviors to regulatory, assurance, and evidentiary topics requested by institutional reviewers. It does not determine whether a law, rule, standard, or contractual obligation applies to a customer. It does not establish operating effectiveness in a target environment, replace management assertions, qualify a computerized system, create a SOC 2 report, establish HIPAA de-identification, satisfy broker-dealer recordkeeping, prove EU AI Act conformity, or authenticate evidence under a court rule.

The legal and assurance result depends on facts outside the repository: organizational role, jurisdiction, regulated activity, record population, data categories, intended use, system boundary, policies, workforce controls, contracts, storage topology, retention, incident response, examiner competence, independent testing, and the operation of controls over time. Aegis can produce technical records that a qualified reviewer may use as evidence; it cannot issue the reviewer's conclusion.

Material claims use the repository vocabulary:

| Status | Meaning |
|---|---|
| `IMPLEMENTED` | Production code and named tests implement the stated behavior under the declared boundary. |
| `MEASURED` | A retained artifact records an observation for a named workload and environment. |
| `CONFIGURATION-DEPENDENT` | The result requires deployment-specific identity, storage, network, key-custody, retention, or operational controls. |
| `ROADMAP` | Required capability, validation, population test, integration, or independent evidence is absent or incomplete. |
| `LEGAL-REVIEW-REQUIRED` | Applicability, sufficiency, conformity, admissibility, certification, or contractual interpretation requires a qualified human decision. |

## 2. Source hierarchy and currency

The source hierarchy is: applicable enacted law and authoritative regulator text; executed customer agreements and policies; authoritative standards and licensed guidance; production code and tests; retained execution evidence; the claims matrix; and explanatory repository prose. A module name or docstring that uses terms such as `compliant`, `admissible`, `Safe Harbor`, `WORM`, `Part 11`, or `ISO 27037` is an implementation label, not a regulatory conclusion.

The following primary or institutional sources were checked on 2026-08-20:

| Topic | Source and scope |
|---|---|
| AICPA Trust Services Criteria | AICPA describes the 2017 Trust Services Criteria, revised points of focus 2022, as criteria for attestation or consulting engagements over security, availability, processing integrity, confidentiality, or privacy.[1] |
| HIPAA Security Rule | HHS states that regulated entities must implement access control, audit controls, integrity, authentication, and transmission-security safeguards for ePHI.[2] |
| HIPAA de-identification | HHS describes Expert Determination and Safe Harbor under 45 CFR 164.514(b), including removal of the enumerated identifiers and the actual-knowledge condition.[3] |
| SEC Rule 17a-4 | SEC's 2022 amendments permit either WORM or an audit-trail alternative; the alternative must preserve a complete time-stamped trail sufficient to recreate an original record after modification or deletion.[4] |
| FINRA Rule 4511 | FINRA requires members to make and preserve books and records under applicable rules, uses at least six years where no period is otherwise specified, and requires compliant media and format under SEA Rule 17a-4.[5] |
| 21 CFR Part 11 | FDA guidance explains that Part 11 applies to electronic records maintained or submitted under predicate-rule requirements and remains subject to scope, enforcement-discretion, and predicate-rule analysis.[6] |
| GAMP 5 | ISPE's GAMP 5 Second Edition is industry guidance for a risk-based approach to compliant GxP computerized systems; it is not itself a statute or an Aegis qualification result.[7] |
| EU AI Act | Regulation (EU) 2024/1689 Articles 13 and 14 address transparency/instructions for high-risk systems and human oversight. Applicability depends on role, classification, intended purpose, geography, and effective-date rules.[8] |
| ISO/IEC 27037 | ISO describes the standard as guidance for identification, collection, acquisition, and preservation of potential digital evidence.[9] |
| Federal Rule of Evidence 902(13)/(14) | The Federal Judicial Center describes certification-based self-authentication for qualifying electronic-process records and copied electronic data. Authentication is not a determination of relevance, hearsay, weight, custody completeness, or ultimate admissibility.[10] |

## 3. Applicability gate

No framework mapping may be used until the accountable organization records:

1. the legal entity and organizational role;
2. jurisdictions, regulated activities, contracts, and relevant dates;
3. the system and service boundary, including model provider and storage services;
4. record classes, data categories, data subjects, and retention obligations;
5. whether Aegis is authoritative, supplemental, or merely observational;
6. the target release, configuration, image digest, signer, topology, and evidence path;
7. the population from which control evidence will be sampled;
8. named control owners, reviewers, escalation paths, and approval authority; and
9. the independent assessor, counsel, qualified person, or tribunal process that will interpret the evidence.

If any item is missing, the mapping remains `LEGAL-REVIEW-REQUIRED` or `CONFIGURATION-DEPENDENT` and cannot be presented as compliance.

## 4. Master control-contribution matrix

| Framework or rule | Selected requirement or review lens | Potential Aegis technical evidence | Status | Missing evidence and decision owner |
|---|---|---|---|---|
| SOC 2 Trust Services Criteria | Security, availability, processing integrity, confidentiality, and privacy criteria selected for an engagement | Authentication and strict configuration; WAF and egress controls; signed evidence metadata; failure paths; backup/restore guidance; bounded test and benchmark artifacts | `LEGAL-REVIEW-REQUIRED` | Management's system description and assertion, complete control design, operating-period samples, vendor/workforce/change controls, auditor procedures, exceptions, and opinion. Owner: management and licensed CPA firm. |
| HIPAA Security Rule, 45 CFR 164.312 | Access, audit controls, integrity, person/entity authentication, and transmission security | API-key and optional mTLS paths; event records; chain verification; request/response hashes; configurable TLS/egress/deployment controls | `CONFIGURATION-DEPENDENT` | Covered-entity/business-associate status, risk analysis, BAAs, full administrative/physical/technical safeguards, access reviews, contingency plans, transmission architecture, operating effectiveness, and state law. Owner: privacy/security officers and counsel. |
| HIPAA Privacy Rule, 45 CFR 164.514(b) | Expert Determination or Safe Harbor de-identification | `PHIDeidentifier` performs best-effort regex replacement for selected textual forms and emits category/count metadata | `ROADMAP` | Complete identifier handling across structured/free-text/multimedia data; ZIP/date/age rules; actual-knowledge review; quality evaluation; expert determination where used; production wiring; re-identification controls. Owner: privacy officer and qualified expert. |
| SEC Rule 17a-4(f) | WORM or complete time-stamped audit-trail alternative, retention, access, recreation, and production | Append records, predecessor linkage, hashes/signatures, timestamps, local WAL and export functions | `LEGAL-REVIEW-REQUIRED` | Broker-dealer applicability; complete regulated record population; modifications/deletions trail; original-record recreation; required retention; independent access; undertakings; usable production; target recordkeeping-system validation. Owner: broker-dealer compliance, counsel, records principal, and examiner. |
| FINRA Rule 4511 | Make/preserve required books and records; duration and Rule 17a-4 media/format | Technical record export and retention inputs | `LEGAL-REVIEW-REQUIRED` | FINRA-member status, applicable books/records, retention schedule, supervision, production procedures, and compliant system determination. Owner: member firm's records/compliance principals and counsel. |
| 21 CFR Part 11 | Electronic records/signatures within predicate-rule scope; closed/open system controls | Signature metadata, change records, trace links, HMAC integrity tags, deployment decision records, qualification-result structures | `LEGAL-REVIEW-REQUIRED` | Predicate-rule scope, intended use, validated state, requirements, risk assessment, IQ/OQ/PQ, access/authority/device checks, durable audit trail, signature attribution, record retention/copies, SOPs, training, and quality approval. Owner: regulated company quality unit and FDA counsel. |
| ISPE GAMP 5 Second Edition | Risk-based computerized-system lifecycle and validation guidance | Change-control objects, trace matrix, performance-qualification record type, vendor-package structure | `CONFIGURATION-DEPENDENT` | Approved lifecycle, supplier assessment, intended use, category/risk rationale, specifications, test evidence, deviations, quality approvals, periodic review, retirement, and licensed-guide interpretation. Owner: quality unit and validation lead. |
| EU AI Act Articles 13/14 | Transparency/instructions and human oversight for applicable high-risk systems | Gateway documentation, request/evidence records, claim boundaries, configurable human-review and monitoring inputs | `LEGAL-REVIEW-REQUIRED` | Provider/deployer/importer/distributor role, high-risk classification, intended purpose, instructions for use, performance/limitations, oversight design, competence/authority, conformity process, post-market monitoring, incident process, and effective-date analysis. Owner: EU regulatory counsel and conformity/governance owners. |
| ISO/IEC 27037:2012 | Identification, collection, acquisition, and preservation guidance | Acquisition metadata, custody-event structures, hashes, evidence-node export, package seal, custody-transfer helpers | `LEGAL-REVIEW-REQUIRED` | Qualified digital-evidence first responder, complete custody record, original source preservation, validated acquisition method, time synchronization, tool validation, secure transport/storage, jurisdictional procedure, and independent verification. Owner: evidence custodian and qualified examiner. |
| FRE 902(13)/(14) | Certification-based authentication of qualifying electronic-process records or copied data | Hashes, process metadata, export records, and reproducible verification may support a declaration | `LEGAL-REVIEW-REQUIRED` | Proper certification, notice, qualified declarant, process/system foundation, matching copied-data digest, case-specific rules, objections, hearsay/relevance analysis, and court determination. Owner: litigation counsel and declarant. |

## 5. Framework-specific analysis

### 5.1 SOC 2

`[LEGAL-REVIEW-REQUIRED]` A SOC 2 engagement is an attestation over a service organization's system and selected Trust Services Criteria, not a source-code feature checklist. Aegis may contribute evidence for selected controls, but the repository does not define the complete system description, control population, period of operation, management assertion, complementary user-entity controls, subservice-organization treatment, or auditor opinion.

Potential inputs include strict-startup gates (`aegis/config.py`, `aegis/proxy/app.py`), keyring controls (`aegis_server/crypto/keyring.py`), change and release records, failure-path tests, `verify_integrity()`, and bounded evidence in `evidence/execution_2026-08-20/`. The absence of a finding in unit tests does not establish operating effectiveness over a SOC 2 examination period.

**Falsification:** any representation that Aegis is “SOC 2 compliant,” “SOC 2 certified,” or covered by a report without the report, system boundary, period, auditor, and opinion.

### 5.2 HIPAA Security Rule

`[CONFIGURATION-DEPENDENT]` HHS's technical safeguards include audit controls and integrity, but HIPAA compliance is organizational and risk-based. Aegis evidence records may help record and examine activity, and chain verification may help detect certain modifications. API-key and mTLS options may contribute to authentication and access control. Transmission security remains dependent on ingress, TLS, provider links, networks, secrets, and configuration.

`PHIDeidentifier` does not complete Safe Harbor. Its finite regex set does not enumerate every person name, geography, date/age condition, biometric/image, unique characteristic, code, structured field, or contextual re-identification path. HHS also requires the covered entity not to have actual knowledge that remaining information could identify an individual. The module's `method = "safe_harbor_regex"` value is a software label and must not be used as a regulatory determination.

**Required test:** a customer-approved data inventory and representative corpus, false-negative and false-positive evaluation, structured and unstructured field coverage, actual-knowledge review, expert review where selected, and proof that every relevant production path invokes the approved method.

### 5.3 SEC Rule 17a-4 and FINRA Rule 4511

`[LEGAL-REVIEW-REQUIRED]` SEC no longer requires WORM exclusively; its audit-trail alternative requires enough history to recreate an original record after modification or deletion, including complete time-stamped actions and identity where applicable. The Aegis local WAL is append-oriented and tamper-evident under its verifier, but local files remain mutable or deletable by privileged actors. Rotation applies permissions, not regulatory WORM. The repository does not prove that every required broker-dealer record, modification, deletion, actor identity, retention period, undertaking, independent-access path, or production request is captured.

FINRA Rule 4511 links required records to the Exchange Act and applicable rules, sets at least six years where no period is specified under FINRA rules, and requires Rule 17a-4-compliant media/format. A generic five- or seven-year class in code cannot determine the applicable period for a real record.

**Kill criterion:** block “17a-4 compliant,” “FINRA compliant,” or “WORM” language unless a qualified records principal and counsel approve the exact recordkeeping-system architecture and acceptance evidence.

### 5.4 21 CFR Part 11 and GAMP 5

`[LEGAL-REVIEW-REQUIRED]` Part 11 applicability begins with predicate-rule and electronic-record facts. `gxp_qualification.py` supplies in-memory change records, an exact-version deployment gate, trace-link structures, and HMAC-sealed qualification records. These are support objects, not a validated computerized system. The HMAC is symmetric and does not independently attribute an approval to a person. The in-memory registry does not itself provide durable audit trails, account lifecycle, identity proofing, signature manifestation controls, record retention, or copies.

GAMP 5 is risk-based industry guidance. A usable customer package needs intended use, system inventory, supplier assessment, risk assessment, requirements, configuration/design, test strategy, deviations, traceability, quality-unit approval, data-integrity controls, periodic review, change control, incident/CAPA linkage, backup/restore, business continuity, and retirement. Repository objects may populate a subset of that package only after validated integration.

**Falsification:** a production authorization is denied if the exact deployed version lacks approved change evidence, trace links, executed qualification evidence, deviation disposition, quality approval, and a retained record set under the customer's controlled process.

### 5.5 EU AI Act Articles 6, 9, 12, 13 and 14

`[LEGAL-REVIEW-REQUIRED]` High-risk classification analysis belongs under Article 6 together with the applicable Annex I or Annex III category and exceptions. Article 9 governs the risk-management system for high-risk systems and is not itself the classification basis. Article 12 addresses automatic event logging for applicable high-risk systems; Articles 13 and 14 address transparency/instructions and human oversight. Aegis is a gateway component and is not automatically the provider of the upstream AI system. Its documentation and records may contribute technical inputs, but do not establish classification, required log content or retention, conformity assessment, or division of obligations.

The target package must identify provider and deployer roles, intended purpose, foreseeable misuse, performance characteristics, limitations, input specifications, changes, logs, monitoring, human authority, competence, ability to interpret and override outputs, incident escalation, and effective dates. A gateway log cannot substitute for provider instructions or prove that a human can understand and control a model-dependent decision.

**Required review:** EU counsel and the accountable AI-governance owner must approve the role/classification analysis and verify that target instructions and oversight measures address the specific high-risk system.

### 5.6 ISO/IEC 27037 and FRE 902(13)/(14)

`[LEGAL-REVIEW-REQUIRED]` `iso27037_evidence.py` creates useful acquisition metadata, custody-event fields, evidence nodes, and a package digest. Those fields may support a broader evidence-handling process. They do not establish identification of all sources, forensically sound acquisition, preservation of originals, examiner competence, calibrated time, validated tools, or complete custody.

The code historically used `Admissible`, `Conditional`, and `Compromised` labels. These are operator-supplied technical classifications, not legal outcomes. A local integrity result cannot determine admissibility. Likewise, `dfir_export.py` creates a CMS envelope using an ephemeral private key and self-signed certificate; that certificate has no external identity trust by default. Its E01-like container requires independent interoperability and forensic-tool testing before a compatibility claim.

FRE 902(13)/(14) can permit authentication by certification, but case-specific certification, notice, declarant qualification, process foundation, objections, and other evidence rules remain necessary. A cryptographic hash can support sameness; it does not prove truth, authorship, lawful acquisition, relevance, or absence of hearsay.

## 6. Material claim register

| Claim ID | Status | Controlled claim | Repository locator | Falsification or acceptance test | Human owner |
|---|---|---|---|---|---|
| `DOC05-C001` | `IMPLEMENTED` | Aegis can generate event records containing request/response hashes, predecessor linkage, timestamps, signature metadata, and model/tenant fields under the declared ledger path. | `aegis/core/crypto_audit.py`; ledger tests | Named tests fail, required fields disappear, or an accepted governed path bypasses the ledger boundary. | Release and evidence owners |
| `DOC05-C002` | `CONFIGURATION-DEPENDENT` | These records may contribute to HIPAA audit-control and integrity evidence. | `aegis/core/crypto_audit.py`; `docs/privacy/DATA_RETENTION.md` | Target risk analysis, identity, transmission, retention, monitoring, and operating-effectiveness evidence are absent. | HIPAA security/privacy officers |
| `DOC05-C003` | `ROADMAP` | Regex redaction is not a complete Safe Harbor or Expert Determination implementation. | `aegis/core/phi_deidentifier.py`; `tests/test_phi_deidentifier.py` | Promotion requires complete method criteria, representative evaluation, production wiring, and qualified approval. | Privacy officer and expert |
| `DOC05-C004` | `LEGAL-REVIEW-REQUIRED` | Local WAL and hash-chain controls do not establish Rule 17a-4 compliance or regulatory WORM. | `aegis/core/crypto_audit.py`; rotation and backup code | Qualified review confirms record population, audit-trail/WORM path, retention, access, recreation, undertakings, and production. | Records principal and counsel |
| `DOC05-C005` | `IMPLEMENTED` | GxP-oriented support objects enforce selected in-memory workflow conditions, including requester/approver separation and exact-version change approval. | `aegis/core/gxp_qualification.py`; `tests/test_gxp_qualification.py` | Unit regressions fail or deployed use bypasses these objects. | Quality-system engineering owner |
| `DOC05-C006` | `LEGAL-REVIEW-REQUIRED` | GxP support objects do not establish Part 11 compliance, a validated state, or GAMP qualification. | Same as `DOC05-C005` | Customer qualification package and quality-unit approval are absent. | Quality unit and counsel |
| `DOC05-C007` | `IMPLEMENTED` | The evidence package can include acquisition metadata, custody-event fields, evidence nodes, and a SHA-256 package seal. | `aegis/core/iso27037_evidence.py`; `tests/test_iso27037_evidence.py` | Seal verification or field regressions fail. | Evidence engineering owner |
| `DOC05-C008` | `LEGAL-REVIEW-REQUIRED` | Package fields do not establish ISO conformity or legal admissibility. | `aegis/core/iso27037_evidence.py`; `aegis/core/custody_transfer.py` | Qualified examiner, complete custody, source preservation, tool validation, and legal process are absent. | Evidence custodian and counsel |
| `DOC05-C009` | `CONFIGURATION-DEPENDENT` | Aegis records and documentation may contribute to Article 13/14 implementation for an applicable deployment. | Institutional architecture, threat, and operations volumes | Role, classification, instructions, oversight, monitoring, and conformity evidence are missing. | EU regulatory and AI-governance owners |
| `DOC05-C010` | `LEGAL-REVIEW-REQUIRED` | Repository evidence may be supplied to a SOC 2 auditor but is not a report or opinion. | `docs/compliance/COMPLIANCE_MAPPING.md`; retained evidence | No executed engagement, system description, management assertion, period sample, or auditor opinion exists. | Management and licensed auditor |
| `DOC05-C011` | `IMPLEMENTED` | The 2026-08-20 local gates retained bounded formal, test, WAF, stall, key-rotation, and manifest evidence. | `AEGIS_EXECUTION_REPORT_2026-08-20.md`; `evidence/execution_2026-08-20/` | Hash, schema, solver, or reproduction checks fail. | Release owner |
| `DOC05-C012` | `LEGAL-REVIEW-REQUIRED` | Local engineering evidence does not by itself prove operating effectiveness in a customer environment. | All repository evidence | An external claim omits environment, period, population, reviewer, exceptions, or scope. | Customer control owner and assessor |

## 7. Corrected overclaims and contradictions

| Uncontrolled wording | Required correction |
|---|---|
| “NIST SP 800-188 Safe Harbor” | NIST SP 800-188 and HIPAA Safe Harbor are distinct authorities. Describe the module as best-effort identifier redaction unless the complete selected method is validated. |
| “ISO/IEC 27037 compliant package” | “ISO/IEC 27037-oriented package fields that may support a customer evidence-handling process.” |
| “Admissible” based on chain integrity | “Technical integrity classification; legal admissibility requires case-specific qualified review.” |
| “Court-ready PKCS#7” | “Self-signed CMS envelope with no external identity trust unless a reviewed custody and PKI process establishes it.” |
| “E01 compatible” | “E01-oriented output; compatibility requires retained testing with named independent tools and versions.” |
| “Part 11 compliant signatures” | “Signature metadata and HMAC-sealed records that may contribute to a customer Part 11 assessment.” |
| “SEC 17a-4 WORM ledger” | “Append-oriented application ledger; target WORM or audit-trail compliance is not established.” |
| “EU AI Act compliant” | “Technical records may support selected obligations after role, classification, and conformity analysis.” |
| “SOC 2 automated bundle” | “Evidence export that a licensed auditor may assess within an engagement.” |

## 8. Customer evidence package checklist

| Evidence family | Required content |
|---|---|
| Applicability | Entity, role, jurisdiction, regulated activity, record/data class, intended use, legal citations, effective date, and counsel decision |
| System boundary | Architecture, data flows, dependencies, provider, identity, network, secrets, storage, backups, external services, and complementary controls |
| Release identity | Commit, tag, image/wheel digest, SBOM, provenance, configuration, migrations, and approved change record |
| Design evidence | Requirements, threat/risk assessment, control design, failure semantics, segregation of duties, retention and deletion design |
| Test evidence | Unit/integration/system/negative/fault/recovery/security tests; population and sample methods; environment; exceptions and remediation |
| Operations | Access reviews, monitoring, incidents, changes, backups/restores, key rotations, retention, legal holds, training, vendor management, and periodic review |
| Forensics | Source identification, acquisition method, originals, hashes, time source, tools/versions, operator identity, custody transfers, storage, verification, and declarations |
| Independent review | Reviewer qualifications, scope, procedures, findings, limitations, management response, approval, and report/opinion where applicable |

## 9. Release and communication gates

Block release or customer communication if any of the following occurs:

- a customer-facing document uses `compliant`, `certified`, `admissible`, `WORM`, `Safe Harbor`, `non-repudiation`, `validated`, or `court-ready` without the approved scope and reviewer;
- a source locator changes without claim review;
- a required test or retained artifact fails;
- target topology, signer, storage, ingress, or legal role changes without reassessment;
- a control is represented as operating effectively without period evidence;
- an example or software label is presented as a legal conclusion; or
- counsel, assessor, quality unit, evidence custodian, or security owner rejects the claim.

Rollback is a Git revert of the documentation/control change and withdrawal of the affected external material. If the statement has already been distributed, the release owner must preserve the prior text, recipients, correction, approval, and UTC timestamps.

## 10. Residual risk and next action

The principal residual risk is **semantic claim drift**: technically useful modules carry regulatory names that can be copied into marketing, audit, or litigation material as if they were formal outcomes. The next action is a qualified review of each module label and external statement, followed by target-environment acceptance tests and a controlled evidence population. No framework status should move beyond `LEGAL-REVIEW-REQUIRED` or `CONFIGURATION-DEPENDENT` solely because this dossier exists.

## References

[1]: https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022 "AICPA Trust Services Criteria"
[2]: https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html "HHS Summary of the HIPAA Security Rule"
[3]: https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html "HHS Guidance Regarding Methods for De-identification of PHI"
[4]: https://www.sec.gov/investment/amendments-electronic-recordkeeping-requirements-broker-dealers "SEC amendments to electronic recordkeeping requirements"
[5]: https://www.finra.org/rules-guidance/rulebooks/finra-rules/4511 "FINRA Rule 4511"
[6]: https://www.fda.gov/regulatory-information/search-fda-guidance-documents/part-11-electronic-records-electronic-signatures-scope-and-application "FDA Part 11 Scope and Application"
[7]: https://ispe.org/publications/guidance-documents/gamp-5-guide-2nd-edition "ISPE GAMP 5 Second Edition"
[8]: https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng "Regulation (EU) 2024/1689"
[9]: https://www.iso.org/standard/44381.html "ISO/IEC 27037:2012"
[10]: https://www.fjc.gov/content/325216/amendments-federal-rules-practice-and-procedure-evidence-2017-self-authenticating "Federal Judicial Center, FRE 902(13)/(14)"
