# EU AI Act — Technical Inputs

**Audience:** compliance officers, legal counsel, security reviewers, procurement.
**Scope:** the technical capabilities this gateway can contribute to an EU AI Act record-keeping assessment, and the boundary of that contribution.
**Boundary:** `LEGAL-REVIEW-REQUIRED`. This document describes software behaviour. It makes no determination about whether any system is subject to the Regulation, how it is classified, or whether any obligation is met. Those determinations require qualified legal review of your specific deployment, use case, and role.

---

## 1. What this document is not

Read this first, because the failure mode here is expensive.

- **Not a compliance statement.** No conformity assessment has been performed on this software.
- **Not a classification.** Whether your system is high-risk, limited-risk, or out of scope depends on your use case, not on this gateway.
- **Not a role determination.** Whether you are a provider, deployer, importer or distributor is a legal question about you.
- **Not a substitute for technical documentation.** Article 11 documentation is about *your* AI system. This is a component.
- **Not certified, assessed, or notified-body reviewed.**

Using this gateway does not make an AI system compliant, and no configuration of it does.

## 2. The relevant obligation

Article 12 concerns automatic recording of events (logs) over the lifetime of a high-risk AI system, to a degree appropriate to its intended purpose, supporting traceability of functioning.

**The gateway can contribute to the record-keeping element.** It contributes nothing to risk management, data governance, human oversight design, accuracy specification, robustness, or conformity assessment — those are properties of your system and your organisation.

## 3. What the gateway can technically contribute

| Capability | What it produces | Evidence locator |
| --- | --- | --- |
| Per-call evidence records | A hash-linked, signed record of each governed request and response, committed before the response returns | `aegis/core/crypto_audit.py`; `tests/test_enterprise_durable_evidence.py` |
| Tamper detection | `verify_integrity()` detects chain-link and signature changes on read | `aegis/core/crypto_audit.py`; `GET /v1/audit/integrity` |
| Portable inclusion proofs | A third party can verify a disclosed record was included under a root they trust independently | `aegis/core/mmr.py`; [MMR Proof v1](../api/MMR_PROOF_V1.md) |
| Streaming coverage | An exact-byte terminal summary committed before the terminal marker | `aegis/proxy/streaming.py` |
| Bounded export | A ZIP extract with manifest, records, proofs and a digest checker | [Forensic Export](../api/FORENSIC_EXPORT.md) |
| Identity binding | Records bound to an authenticated principal, never a client-supplied header | `aegis/auth/principal.py` |
| Model and parameter capture | The model identifier and request parameters as forwarded | `aegis/proxy/app.py` |
| Optional timestamping | RFC 3161 exchanges persisted after nonce and imprint checks | `aegis/anchoring/rfc3161.py` |

## 4. What the gateway does not determine

| Not determined | Why |
| --- | --- |
| Whether Article 12 applies to you | Depends on classification and role |
| Whether your logs are "appropriate to the intended purpose" | A judgement about your system, made by you and your assessor |
| The lifetime over which records must be kept | A retention decision with legal input; the gateway enforces no retention |
| Whether traceability is sufficient | Sufficiency is assessed against your system's risk profile |
| Anything about the model itself | The gateway governs the transaction, not the model |
| Post-market monitoring, incident reporting, registration | Organisational obligations |

## 5. Boundaries a reviewer must record

These are the limits most likely to matter in an assessment, stated so they are not discovered late.

**Scope of the record.** Records cover calls that traverse this gateway. Any path that bypasses it produces no record, and the gateway cannot detect that it was bypassed.

**Retained window.** The in-memory chain is bounded by `AEGIS_MAX_MEMORY_NODES`. `GET /v1/audit/integrity` reports `full_history_retained`; when false, a `valid` result covers the retained window only. Long-horizon retention needs archived segments and a separate integrity story.

**No cross-replica ordering.** Each replica produces an independent chain. There is no single global timeline. A multi-replica deployment produces N independently verifiable bundles and any merge across them is your process, which you must justify. See [DOC-01 §8](../institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md).

**Operator trust.** The chain detects tampering on read; it does not prevent an operator with filesystem access from altering or deleting records. Every integrity claim terminates at that boundary. See [Security Architecture §2](../security/SECURITY_ARCHITECTURE.md#2-trust-boundaries).

**Time is not attested by default.** Record timestamps come from the host clock. Without RFC 3161 anchoring — which is optional, off by default, and requires an accepted TSA — there is no independent evidence of when a record was created.

**Signature semantics.** With the default HMAC signer, the signature is symmetric: anyone holding the key could produce it. That is authenticity relative to key custody, not third-party non-repudiation. An asymmetric or HSM signer changes this and should be specified if your assessment depends on it.

**Redaction interacts with record completeness.** Enabling PHI or PCI scrubbing means the record holds the scrubbed form. If your assessment requires the original input, redaction reduces record fidelity. That trade-off is yours to make explicitly.

## 6. What you must assess

- [ ] Whether the Regulation applies, and your role under it.
- [ ] Your system's classification.
- [ ] Whether gateway records satisfy your Article 12 obligation in scope, granularity and retention.
- [ ] Whether every relevant call path traverses the gateway.
- [ ] Retention period and deletion mechanism, reconciled against an append-only chain.
- [ ] Whether time attestation is needed, and if so, an accepted TSA.
- [ ] Whether HMAC signing is sufficient, or an asymmetric signer is required.
- [ ] How multi-replica evidence is reconciled.
- [ ] Custody controls around operator access.
- [ ] Human oversight, risk management, data governance, accuracy and robustness — none of which this component addresses.

## 7. Prohibited phrasing

Never state, in any material:

- "EU AI Act compliant" or "Article 12 compliant"
- "Conformity assessed" or "CE marked"
- "Satisfies EU AI Act record-keeping requirements"
- "Certified for high-risk AI systems"

Acceptable phrasing:

> Aegis Latent Core produces per-call cryptographic evidence records that an organisation may evaluate as a technical input to an EU AI Act Article 12 record-keeping assessment. Whether that obligation applies, and whether it is met, is a determination for the organisation and its assessor.

---

**Related:** [Compliance Mapping](COMPLIANCE_MAPPING.md) · [Audit Endpoints](../api/AUDIT_ENDPOINTS.md) · [Forensic Export](../api/FORENSIC_EXPORT.md) · [Data Retention](../privacy/DATA_RETENTION.md) · [Boundaries](../BOUNDARIES.md) · [Claims Matrix](../CLAIMS_MATRIX.md)
