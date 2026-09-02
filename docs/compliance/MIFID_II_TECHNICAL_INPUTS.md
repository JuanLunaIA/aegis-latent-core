# MiFID II — Technical Inputs

**Audience:** compliance officers, legal counsel, procurement in regulated financial services.
**Scope:** the technical capabilities this gateway can contribute to a MiFID II record-keeping assessment, and the boundary of that contribution.
**Boundary:** `LEGAL-REVIEW-REQUIRED`. This document describes software behaviour. It makes no determination about whether MiFID II applies to you, which obligations attach, or whether any of them is met. Those determinations require qualified legal review.

---

## 1. What this document is not

- **Not a MiFID II compliance statement.**
- **Not a determination that any record satisfies a regulatory record-keeping obligation.**
- **Not an order-record-keeping system.** This gateway records AI inference calls, not orders, transactions, or client communications as such.
- **Not a transaction reporting system.**

## 2. Scope correction worth making early

MiFID II record-keeping obligations are frequently cited imprecisely. Two distinct things are often conflated:

- **RTS 24** concerns record-keeping of orders in financial instruments.
- **RTS 25** concerns clock synchronisation for reportable events.

If your concern is order record-keeping, RTS 24 is the relevant instrument, and this gateway does not record orders. If your concern is timestamp accuracy, RTS 25 is relevant, and this gateway's position on time is stated in §5.

Getting this distinction right in an assessment matters more than any capability listed below.

## 3. What the gateway can technically contribute

Where an investment firm uses an AI system in a process subject to record-keeping, the gateway can produce durable records **of the AI interaction**:

| Capability | Contribution | Evidence locator |
| --- | --- | --- |
| Durable per-call records | Hash-linked, signed record of each governed request and response, committed before the response returns | `aegis/core/crypto_audit.py` |
| Ordered within one process | Chain linkage establishes order within a single writer's WAL | `aegis/core/crypto_audit.py` |
| Tamper detection | `verify_integrity()` detects link or signature changes on read | `GET /v1/audit/integrity` |
| Identity binding | Records bound to an authenticated principal, never a client-supplied header | `aegis/auth/principal.py` |
| Third-party verifiable proofs | MMR inclusion proofs verifiable against an independently trusted root | [MMR Proof v1](../api/MMR_PROOF_V1.md) |
| Bounded export | Extract for regulator or internal review | [Forensic Export](../api/FORENSIC_EXPORT.md) |
| Optional timestamp anchoring | RFC 3161 exchanges persisted after nonce and imprint verification | `aegis/anchoring/rfc3161.py` |

The gateway records that a governed AI call occurred, under which identity, with what input and output, and produces evidence that the record has not been altered. Whether that is a record you are required to keep is your determination.

## 4. What the gateway does not determine

| Not determined | Why |
| --- | --- |
| Whether MiFID II applies to you | A legal question about your activities |
| Which records you must keep, and for how long | Depends on the obligation and your role |
| Whether an AI interaction is a reportable event | A regulatory characterisation |
| Whether records are sufficient for a regulator | Sufficiency is assessed by the regulator |
| Anything about orders, transactions or trade reporting | Out of scope entirely |
| Whether your clock meets RTS 25 divergence limits | See §5 |

## 5. Time — the boundary that matters most here

For any obligation with a timestamp-accuracy requirement, read this carefully.

**Record timestamps come from the host clock.** The gateway does not:

- synchronise the host clock,
- measure divergence from UTC,
- attest traceability to a reference time source,
- detect clock drift or a backwards step,
- prevent an operator from changing the clock.

RFC 3161 anchoring is available, optional, and off by default. When configured, an obtained response is persisted after nonce and imprint checks and OpenSSL verification against an explicit trust store. **An obtained timestamp response is not a trusted timestamp**: TSA selection, certificate and revocation lifecycle, renewal, egress, and independent time trust all require acceptance in your target environment.

If your obligation carries a maximum divergence from UTC, satisfying it is a host and infrastructure matter — time synchronisation, monitoring, and traceability records — and the gateway contributes nothing to it. **Do not present gateway timestamps as evidence of clock accuracy.**

## 6. Further boundaries a reviewer must record

**No cross-replica ordering.** Chain linkage orders records within one writer's WAL. Across replicas there is no global order. A deployment with N replicas produces N independent sequences; interleaving them into one timeline is your process to define and justify. See [DOC-01 §8](../institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md).

**Retention is not enforced.** The gateway deletes nothing on a schedule and implements no retention policy. Multi-year retention needs archived segments, an archive integrity story, and retained signing keys for the whole period.

**Operator trust.** Tampering is detected on read, not prevented. Records are alterable by anyone with filesystem access.

**Signature semantics.** With HMAC, the signature is symmetric — authenticity relative to key custody, not third-party non-repudiation. If your assessment needs records attributable to a party that could not have forged them, specify an asymmetric or HSM signer.

**Immutability is not claimed.** Rotation applies owner-only permissions and renames; that is access restriction. The S3 Object Lock adapter can target a configured bucket but does not configure, enforce or attest its retention policy, and does not establish a regulatory WORM status.

**Completeness.** Records cover calls traversing this gateway. A path that bypasses it produces no record and the gateway cannot detect the bypass.

## 7. What you must assess

- [ ] Whether MiFID II applies, and which obligations.
- [ ] Whether AI interaction records fall within a record-keeping obligation at all.
- [ ] Retention period, archival integrity, and signing-key retention across it.
- [ ] Clock synchronisation and traceability, independently of this gateway.
- [ ] Whether HMAC signing is sufficient, or an asymmetric signer is required.
- [ ] How multi-replica records are reconciled into a defensible sequence.
- [ ] Custody controls around operator access.
- [ ] Whether every relevant call path traverses the gateway.
- [ ] Regulator expectations about format and accessibility.

## 8. Prohibited phrasing

Never state:

- "MiFID II compliant" or "RTS 24 compliant" or "RTS 25 compliant"
- "Meets regulatory record-keeping requirements"
- "Regulator-approved records"
- "Timestamp accuracy guaranteed" or "traceable to UTC"

Acceptable phrasing:

> Aegis Latent Core produces durable, tamper-evident records of governed AI interactions that an investment firm may evaluate as a technical input to its own record-keeping assessment. It does not record orders or transactions, does not establish clock traceability, and makes no compliance determination.

---

**Related:** [Compliance Mapping](COMPLIANCE_MAPPING.md) · [Audit Endpoints](../api/AUDIT_ENDPOINTS.md) · [Forensic Export](../api/FORENSIC_EXPORT.md) · [Data Retention](../privacy/DATA_RETENTION.md) · [DOC-05](../institutional/DOC-05_REGULATORY_DOSSIER.md) · [Boundaries](../BOUNDARIES.md)
