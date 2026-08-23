# Data Retention and Privacy Boundaries — Aegis Latent Core v3.1.0

This document describes what Aegis may persist, what remains in memory, and which retention and privacy decisions belong to the deploying organization. It is for privacy engineers, security reviewers, platform operators, and counsel. It is not a GDPR or HIPAA determination, a records-of-processing notice, or legal advice.

**Last verified:** 2026-08-22 UTC
**Release baseline:** `v3.1.0`
**Owner:** Deployment owner with privacy and legal review
**Related claim control:** [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)

> **Key boundary.** A hash is not automatically anonymous. A tenant identifier, request timing, model name, endpoint, or linkage metadata can remain personal, confidential, regulated, or commercially sensitive information in context.

## Data-flow summary

Aegis receives a client request, applies configured controls, forwards an admitted request to an upstream provider, computes canonical evidence metadata, signs and commits the record to the configured WAL, and may enqueue bounded response enrichment. The exact fields depend on the active route and configuration. Operators must validate the deployed code path and configuration before making a retention decision.

| Data class | Typical location | Persistence claim | Primary risk |
|---|---|---|---|
| Request body | Request memory and upstream transport | Not intended as a plaintext WAL field under the documented path | Prompt content, secrets, PHI, personal data and provider-sensitive information |
| Response body | Response memory and enrichment path | Not intended as a plaintext WAL field under the documented path | Completion content, personal data, regulated data and retention exposure |
| Evidence metadata | WAL JSONL record and exports | Durable when the evidence commit succeeds | Linkability, timing, model/provider metadata, identifiers and retention obligations |
| Signing material | Protected configuration, keyring or signer service | Must not be written to WAL or source control | Key compromise, unauthorized signing and rotation failure |
| Logs and telemetry | Process logs, metrics, traces and operator systems | Deployment-dependent | Accidental payload or secret leakage, broad access and retention drift |

## WAL fields and risk

The active implementation and export paths are authoritative. The following table describes the fields documented for the v3.1.0 evidence model; a deployment should confirm the exact schema before relying on it.

| Field | Purpose | Data classification concern |
|---|---|---|
| `state_id` | Request-scoped identifier | Usually low risk, but linkable across systems if reused |
| `timestamp` | Commit or event timing | May reveal user activity, workload or incident timing |
| `tenant_id` | Session, tenant or user-derived identifier | Potential personal or confidential identifier |
| `sampling_params` | Model and sampling configuration | Provider, product or trade-secret metadata |
| `prev_hash` and `merkle_root` | Chain linkage and integrity metadata | Usually non-content metadata; linkability remains possible |
| `signature`, `signature_scheme`, `signing_key_id` | Integrity and signer metadata | Key material must never appear; key IDs can reveal rotation events |
| `request_hash` and `response_hash` | Content commitments | A hash can remain personal data when it can be linked to the source content or person |
| `model` and `endpoint` | Provider route metadata | May expose usage patterns or contractual information |
| `token_trail_count` | Analysis metadata | May reveal response size or workload characteristics |
| `is_fallback` | Signer-path metadata | Useful for release and security review; it can expose a degraded path |

## What the documented WAL path does not claim

The documentation does not claim that every deployment stores no plaintext payload anywhere. Reverse proxies, upstream providers, tracing systems, crash dumps, debug logs, object stores, backups, and operator tooling can persist data outside the WAL. A customer must inventory those systems.

The documentation also does not claim that pseudonymization removes all privacy obligations. `AEGIS_PII_REDACT_TENANT_ID=true` can reduce direct identifier exposure for the configured field, but it does not remove other identifiers, linkability, singling-out risk, lawful-basis requirements, or subject rights.

## Tenant and session identifiers

A tenant or session identifier may originate from a request header, a request field, or a generated UUID. If a caller supplies an email, account number, persistent user ID, or a stable pseudonymous value, the resulting evidence metadata may be personal or confidential data.

When the deployment enables `AEGIS_PII_REDACT_TENANT_ID=true`, the implementation derives a truncated hash for the stored tenant identifier under the documented path. This reduces direct exposure but does not produce an anonymity guarantee. Operators must validate collisions, linkage, access control and downstream exports for their data model.

## Retention decision table

Retention is an operator policy. Aegis does not select a universally correct period for a vertical, regulation, customer contract, or legal hold.

| Decision | Required owner | Evidence to retain |
|---|---|---|
| Purpose and lawful basis | Privacy/legal owner | Record of purpose, role, lawful basis and data categories |
| Active WAL period | Platform and records owner | Configuration, change record, rotation logs and approval |
| Archive period | Records/legal owner | Retention schedule, legal hold handling and access reviews |
| Deletion or disposal | Records owner and security | Deletion evidence, key destruction if applicable, chain implications and exception log |
| Backup period | SRE and records owner | Backup policy, encryption, immutability, restore test and expiry |
| Export retention | Compliance/security owner | Recipients, access scope, integrity hashes, revocation and disposal |

Do not copy an example period from this document into a production policy without a customer-specific review. Financial, healthcare, government, litigation, employment and cross-border contexts can impose different requirements.

## GDPR reference boundary

For GDPR-oriented review, **Article 5(1)(c)** addresses data minimisation, **Article 5(1)(e)** addresses storage limitation, **Article 25** addresses data protection by design and by default, and **Article 32** addresses security of processing. These are related but non-interchangeable obligations. Hash-only evidence fields may reduce plaintext retention for a declared path; rotation guidance may support a storage-limitation process; design defaults and technical safeguards may support Articles 25 and 32. None of those implementation facts establishes anonymisation, lawful basis, a retention schedule, or GDPR compliance. [3]

## Privacy control mapping without legal conclusion

| Topic | Technical contribution | Boundary |
|---|---|---|
| Data minimization | Hash-based evidence fields can reduce plaintext prompt/response persistence in the WAL path | Hashes and metadata can remain sensitive; external systems may still store content |
| Integrity and confidentiality | Owner-only WAL permissions, signing metadata and configured transport/security controls | Filesystem, host, backup, key custody and network controls require acceptance testing |
| Purpose limitation | Repository documents evidence and governance purposes | Customer must prevent secondary use and define permitted processing |
| Storage limitation | WAL rotation and archive procedures can be operated externally | Aegis does not select retention, legal hold or deletion policy automatically |
| Data subject rights | Export and retention processes can provide inputs to customer procedures | Append-only evidence, legal holds and integrity continuity require legal/process design |
| Access control | API keys, audit keys and deployment controls exist in configured paths | Enterprise IAM, least privilege, access review, break-glass and personnel controls remain customer-owned |

## Deployment requirements

Operators should store signing keys in a secret manager or protected signer service, keep keys separate from upstream provider credentials, restrict WAL access, encrypt storage according to the customer threat model, avoid raw payload logging, scrub crash and trace channels, and test restore and disposal procedures. The keyring file is not a secret manager by itself.

A customer processing regulated data should perform a data protection impact assessment or equivalent risk analysis when required, execute applicable vendor agreements, define controller/processor or covered-entity/business-associate roles, and verify cross-border transfer requirements. Aegis documentation cannot complete those decisions.

## Incident and legal-hold handling

When evidence integrity, unauthorized access, or accidental payload persistence is suspected, preserve the original WAL and relevant metadata read-only, record the operator and UTC time, calculate hashes with the repository or customer-approved tool, and follow the customer's incident and legal-hold process. Do not rewrite a retained WAL in place to satisfy a deletion request without an approved evidence-continuity procedure and qualified review.

## Verification commands

The following commands verify repository behavior, not customer legal compliance:

```bash
pytest -q tests/test_p0_release_gates.py
pytest -q tests/test_enterprise_durable_evidence.py
pytest -q tests/test_keyring_rotation.py
python -m compileall -q aegis aegis_server
```

Before a pilot, add an environment-specific test that confirms no raw payload reaches logs, traces, backups, provider request logging, or crash artifacts. That test is not present in the repository-wide release artifact unless a customer adds and retains it.

## Review status

| Item | Status |
|---|---|
| Plaintext prompt/response WAL claim | Allowed only for the documented code path and declared schema |
| Pseudonymization | Configuration-dependent and not anonymization |
| GDPR applicability or lawful basis | `CUSTOMER-ASSESSMENT` |
| HIPAA applicability or BAA requirement | `CUSTOMER-ASSESSMENT` |
| Universal retention periods | Not provided |
| Deletion/legal-hold semantics | Requires customer procedure and qualified review |

## Related documents

- [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
- [`docs/compliance/COMPLIANCE_MAPPING.md`](../compliance/COMPLIANCE_MAPPING.md)
- [`docs/security/THREAT_MODEL.md`](../security/THREAT_MODEL.md)
- [`docs/operations/ROLLBACK_RUNBOOK.md`](../operations/ROLLBACK_RUNBOOK.md)
- [`DEPLOYMENT_GUIDE.md`](../../DEPLOYMENT_GUIDE.md)

## References

[1]: https://www.nist.gov/itl/ai-risk-management-framework "NIST AI Risk Management Framework"
[2]: https://www.hhs.gov/hipaa/for-professionals/security/nist-security-hipaa-crosswalk/index.html "HHS/NIST HIPAA Security Rule crosswalk"
[3]: https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng "GDPR, EUR-Lex"
