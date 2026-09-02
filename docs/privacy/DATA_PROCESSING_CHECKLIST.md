# Data Processing Checklist

**Audience:** privacy officers, procurement, platform engineers preparing a deployment.
**Scope:** the questions to answer before this gateway processes personal data, and where in the repository each answer comes from.
**Boundary:** this is a preparation checklist, not legal advice and not a Data Processing Agreement. It does not draft contractual terms, does not determine your lawful basis, and does not tell you whether a transfer is permitted. Those are determinations for you and your counsel.

---

## How to use this

Work through each section and record an answer. An unanswered item is a finding, not a blank. Where the repository cannot supply an answer, the checklist says so rather than implying one exists.

Nothing here substitutes for a Data Protection Impact Assessment where one is required.

---

## 1. Data inventory

- [ ] **What personal data can appear in a governed request?** Prompts are free text; assume anything a user can type can appear.
- [ ] **What appears in a governed response?** Model output may contain personal data whether or not the request did.
- [ ] **What metadata is attached?** Tenant, principal pseudonym, timestamps, request IDs, model identifiers.
- [ ] **Which payload fields does your integration populate?** Redaction visits `content`, `system` and `text` only. Personal data in any other field is not scrubbed. See [PII Redaction Boundaries §3](PII_REDACTION_BOUNDARIES.md#3-what-redaction-does-not-catch).
- [ ] **Are special categories involved?** Health, biometric, or similar data raises the bar under most regimes.

## 2. The upstream provider

This section is first for a reason: it is where most of the exposure is, and it is the part the gateway does not control.

- [ ] **Which provider receives the data?** `AEGIS_BACKEND_URL`.
- [ ] **Do you have an agreement with them covering this processing?** The gateway forwards; it does not create or enforce a provider agreement.
- [ ] **Where do they process it?** Relevant if cross-border transfer rules apply to you.
- [ ] **Do they retain prompts, and for how long?** Their policy, not yours.
- [ ] **Do they train on your data?** Their terms decide this.
- [ ] **Do you understand that redaction does not protect the provider?** The request reaches them as sent. Redaction changes the evidence record only. See [PII Redaction Boundaries §4](PII_REDACTION_BOUNDARIES.md#4-the-limit-that-surprises-people).

If your privacy position depends on the provider not receiving personal data, you need filtering **before** the gateway. This gateway is not that control.

## 3. Redaction

- [ ] **Is `AEGIS_PHI_DEIDENTIFY` enabled?** Off by default.
- [ ] **Is `AEGIS_PCI_SCRUB` enabled?** Off by default.
- [ ] **Have you tested coverage against your traffic shape, using synthetic data?** Do not assume coverage; the seventeen implemented categories may not match your identifiers.
- [ ] **Have you recorded the measured coverage, dated?** The repository has no such measurement for any corpus.
- [ ] **Do you understand that records written before redaction was enabled remain unredacted permanently?** The chain is append-only; enabling the control does not scrub history.

## 4. Retention

- [ ] **How long will WAL records be retained?** An operator decision. The gateway has no retention enforcement and deletes nothing on a schedule.
- [ ] **What is the basis for that period?** See [Data Retention](DATA_RETENTION.md).
- [ ] **How will deletion happen when the period expires?** Deleting from an append-only hash-linked chain truncates it. Decide the mechanism before you need it.
- [ ] **Are retired signing keys retained at least as long as the records they signed?** Otherwise those records become unverifiable.
- [ ] **Are archived segments in scope?** S3 Object Lock archival, if configured, may make deletion harder by design.

**The tension to resolve explicitly:** an append-only evidence chain and a right-to-erasure obligation pull in opposite directions. This repository does not resolve that for you and does not claim to. Decide, document, and have counsel review it.

## 5. Access control

- [ ] **Who holds `audit:read`?** They can read governed content.
- [ ] **Who holds `audit:export`?** They can bulk-export evidence. Grant separately from `audit:read`.
- [ ] **Who has filesystem access to the WAL volume?** They read everything, bypassing every scope. This is the largest access-control gap in the design; see [Security Architecture §2](../security/SECURITY_ARCHITECTURE.md#2-trust-boundaries).
- [ ] **Who can reach the dashboard?** It renders ledger and evidence views. Browser-facing authentication is your responsibility.
- [ ] **Is tenant isolation sufficient for your model?** It is logical isolation within one process, not separate deployments.

## 6. Logging and telemetry

- [ ] **Confirm payloads are not logged.** Default is not to log them; confirm nothing in your stack re-enables it.
- [ ] **Is `AEGIS_LOG_LEVEL` set to `INFO` or higher in production?** `DEBUG` may surface request detail.
- [ ] **Where do logs go, and who reads them?**
- [ ] **If SIEM export is configured, what does the collector retain?** The exported schema excludes content and raw identity values; downstream retention is yours.
- [ ] **Do metrics carry identifiers?** They should not — metrics are content-free by design. Verify no custom label reintroduces one.

## 7. Transfers and residency

- [ ] **Where does the gateway run?**
- [ ] **Where is the WAL stored?**
- [ ] **Where is any archive stored?**
- [ ] **Where does the provider process?**
- [ ] **Where does the SIEM collector sit?**
- [ ] **Do any of those cross a border that matters for you?** The repository makes no determination about transfer legality.

## 8. Subject rights

- [ ] **Can you locate all records for one data subject?** Records are indexed by tenant and node hash, not by data subject. There is no subject-lookup capability, and building one is your work.
- [ ] **What is your response to an access request?** Forensic export is bounded and time-limited to the retained window.
- [ ] **What is your response to an erasure request?** See §4. This is the hard one.
- [ ] **Can you produce a processing record?** The evidence chain contributes; it is not itself a complete record of processing.

## 9. Security controls

- [ ] **Is the deployment in strict mode?** Verify with `aegis_security_enforcement_mode == 1`, not by reading a config file.
- [ ] **Is TLS terminated appropriately?** Not provided by the gateway by default.
- [ ] **Is the WAL volume encrypted at rest?** Your storage layer's job; the gateway does not encrypt it.
- [ ] **Is signing key custody documented?**
- [ ] **Are backups covered by the same controls as production?** A backup of personal data is personal data.

Full control inventory: [Security Controls](../security/SECURITY_CONTROLS.md).

## 10. Incident readiness

- [ ] **Do you have a breach notification process?** This repository does not provide one.
- [ ] **Do you know how to preserve evidence without destroying it?** See [Incident Response](../security/INCIDENT_RESPONSE.md).
- [ ] **Do you know which records fall in an exposure window if a key is compromised?**
- [ ] **Have you rehearsed a restore?** See [Backup and Restore](../operations/BACKUP_RESTORE.md).

---

## What this checklist does not do

- **Not a DPA.** No contractual terms are drafted here.
- **Not a lawful-basis determination.**
- **Not a DPIA.** It may inform one.
- **Not a transfer-mechanism assessment.**
- **Not a compliance statement** for GDPR, HIPAA, or any other regime. See [Compliance Mapping](../compliance/COMPLIANCE_MAPPING.md).
- **Not legal advice.** Route these answers to qualified counsel.

---

**Related:** [Data Retention](DATA_RETENTION.md) · [PII Redaction Boundaries](PII_REDACTION_BOUNDARIES.md) · [Compliance Mapping](../compliance/COMPLIANCE_MAPPING.md) · [Security Controls](../security/SECURITY_CONTROLS.md) · [Procurement Checklist](../enterprise/PROCUREMENT_CHECKLIST.md) · [Boundaries](../BOUNDARIES.md)
