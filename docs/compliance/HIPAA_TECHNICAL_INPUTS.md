# HIPAA — Technical Inputs

**Audience:** privacy officers, security officers, legal counsel, procurement.
**Scope:** the technical capabilities this gateway can contribute to a HIPAA assessment, and the boundary of that contribution.
**Boundary:** `LEGAL-REVIEW-REQUIRED`. This document describes software behaviour. It makes no determination about covered-entity or business-associate status, about whether de-identification has been achieved, or about whether any Rule is satisfied. Those determinations require qualified legal review.

---

## 1. What this document is not

- **Not a HIPAA compliance statement.** No assessment of this software has been performed.
- **Not an implementation of Safe Harbor.** The scrubber's own module docstring says it "does not implement or establish the complete 45 CFR 164.514(b)(2) Safe Harbor method, Expert Determination, or NIST SP 800-188 de-identification process."
- **Not a de-identification determination.** Scrubbed output is text with matched patterns removed. It is not de-identified data.
- **Not a Business Associate Agreement**, and not a statement that the licensor will enter one.
- **Not a substitute for a Security Rule risk analysis.**

**Using this gateway does not make a system HIPAA compliant. Enabling redaction does not de-identify PHI.**

## 2. What the gateway can technically contribute

### Toward the Privacy Rule

| Capability | Contribution | Evidence locator |
| --- | --- | --- |
| Pattern-based scrubbing across seventeen Safe Harbor-associated categories | Reduces PHI written into the evidence record | `aegis/core/phi_deidentifier.py` |
| Scrub audit record | Per-category hit counts, confidence scores and a UTC timestamp, containing **no PHI** — only category metadata | `ScrubAuditRecord` in the same module |
| Minimum-necessary support | Scope separation between `audit:read` and `audit:export` | `aegis/proxy/audit_api.py` |

The seventeen categories: `ACCOUNT`, `ADDRESS`, `BIOMETRIC`, `DATE`, `DEVICE_ID`, `EMAIL`, `HEALTH_PLAN_ID`, `IP_ADDRESS`, `LICENSE`, `MRN`, `NAME`, `NPI`, `PHONE`, `SSN`, `URL`, `VIN`, `ZIP`.

### Toward the Security Rule

| Safeguard area | Capability | Evidence locator |
| --- | --- | --- |
| Access control | Authenticated principals, scopes, tenant-scoped visibility | `aegis/auth/`; `aegis/proxy/dependencies.py` |
| Audit controls | Hash-linked signed records of governed access, committed before response | `aegis/core/crypto_audit.py` |
| Integrity | Tamper detection on read; portable inclusion proofs | `verify_integrity()`; `aegis/core/mmr.py` |
| Transmission security | mTLS and OIDC paths | `aegis/auth/mtls.py`, `aegis/auth/oidc.py` |
| Person authentication | Immutable principal derivation from the credential | `aegis/auth/principal.py` |

These are technical inputs to safeguard implementation. They are not the safeguards themselves, which include administrative and physical requirements this software does not touch.

## 3. What the gateway does not determine

| Not determined | Why |
| --- | --- |
| Whether you are a covered entity or business associate | A legal characterisation of you |
| Whether data is PHI | Depends on context and origin, not on pattern shape |
| Whether Safe Harbor is met | Requires all eighteen identifier categories removed **and** no actual knowledge of residual identifiability — a determination, not a regex result |
| Whether Expert Determination applies | Requires a qualified expert |
| Whether a breach occurred, or is notifiable | A legal determination |
| Adequacy of your risk analysis | An organisational obligation |

## 4. The Safe Harbor gap, stated precisely

Safe Harbor under 45 CFR 164.514(b)(2) requires removal of eighteen specified identifier categories **and** that the covered entity has no actual knowledge that residual information could identify the individual.

The scrubber implements pattern matching associated with seventeen category labels. Two things follow, and both matter:

1. **Category-label coverage is not statutory coverage.** A label named `NAME` matching some name-shaped strings is not "all names removed". Free-text disclosure, paraphrase, unusual formats and non-English forms are not detected. See [PII Redaction Boundaries §3](../privacy/PII_REDACTION_BOUNDARIES.md#3-what-redaction-does-not-catch).
2. **The actual-knowledge condition is not a software property.** No regex can establish that residual data does not identify someone. That is a judgement made by a person.

So: pattern removal is a contribution toward a Safe Harbor effort. It is not Safe Harbor, and describing it as such would be a misstatement with real consequences.

## 5. Boundaries a reviewer must record

**PHI reaches the provider unscrubbed.** The request goes upstream as sent; redaction changes the evidence record only. If PHI must not reach your model provider, you need filtering before the gateway, plus a Business Associate Agreement with the provider. See [PII Redaction Boundaries §4](../privacy/PII_REDACTION_BOUNDARIES.md#4-the-limit-that-surprises-people).

**Only three payload fields are visited.** `content`, `system`, `text`. PHI elsewhere is not scrubbed.

**Records written before redaction was enabled remain unscrubbed permanently.** The chain is append-only.

**Retention conflicts with erasure.** An append-only hash-linked chain and a deletion obligation pull against each other. Deleting from the chain truncates it. Resolve this deliberately; the repository does not resolve it for you.

**Operator access bypasses every scope.** Anyone with filesystem access to the WAL volume reads all records regardless of `audit:read`.

**Encryption at rest is not provided.** The WAL is a file. Encrypting the volume is your storage layer's responsibility.

**Coverage against your data is unmeasured.** `[UNKNOWN_MISSING_PRIMARY_SOURCE]` — no recall measurement exists in this repository for any corpus. Measure it yourself with synthetic data.

## 6. What you must assess

- [ ] Your status and your obligations.
- [ ] Whether PHI may appear in prompts or responses at all.
- [ ] Whether a BAA is in place with your model provider — and whether the licensor is willing to enter one, which is a commercial question, not a technical one.
- [ ] Measured redaction coverage against your traffic, using synthetic data.
- [ ] Which payload fields your integration populates.
- [ ] Retention period, and the deletion mechanism against an append-only chain.
- [ ] Encryption at rest and in transit.
- [ ] Who holds `audit:read`, `audit:export`, and filesystem access.
- [ ] Whether HMAC signing is sufficient for your audit-control requirement.
- [ ] Administrative and physical safeguards — outside this software entirely.

## 7. Prohibited phrasing

Never state:

- "HIPAA compliant"
- "Safe Harbor compliant" or "Safe Harbor de-identification"
- "PHI is removed" or "de-identifies PHI"
- "Satisfies the Security Rule"
- "HIPAA certified" — no such certification exists for anyone

Acceptable phrasing:

> Aegis Latent Core provides deterministic pattern-based redaction targeting textual forms associated with HIPAA Safe Harbor identifier categories, and produces cryptographic audit records that an organisation may evaluate as technical inputs to a HIPAA assessment. It does not implement the Safe Harbor method, does not de-identify data, and makes no compliance determination.

---

**Related:** [Compliance Mapping](COMPLIANCE_MAPPING.md) · [PII Redaction Boundaries](../privacy/PII_REDACTION_BOUNDARIES.md) · [Data Retention](../privacy/DATA_RETENTION.md) · [Data Processing Checklist](../privacy/DATA_PROCESSING_CHECKLIST.md) · [Security Controls](../security/SECURITY_CONTROLS.md) · [Boundaries](../BOUNDARIES.md)
