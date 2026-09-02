# ISO/IEC 27037 — Technical Inputs

**Audience:** forensic practitioners, incident responders, legal counsel, security reviewers.
**Scope:** how this gateway's evidence handling relates to the identification, collection, acquisition and preservation guidance in ISO/IEC 27037, and where the gaps are.
**Boundary:** `LEGAL-REVIEW-REQUIRED`. ISO/IEC 27037 is guidance for people handling digital evidence. This software is not a party to that process. It produces artifacts a practitioner may handle; it does not perform identification, collection, acquisition or preservation as the standard means them, and it establishes no chain of custody.

---

## 1. The distinction that governs everything below

ISO/IEC 27037 addresses **what a person does** with potential digital evidence: how they identify it, collect or acquire it, preserve it, and document what they did.

This gateway **produces artifacts**. It does not act as a Digital Evidence First Responder or a Digital Evidence Specialist, and no software can. Every role and responsibility in the standard belongs to a person.

So the contribution is narrow and specific: the artifacts have properties — integrity verifiability, defined boundaries, reproducible checking — that make a practitioner's job easier and their documentation stronger. That is worth something. It is not the standard being met.

## 2. What the gateway can technically contribute

| Standard concern | Contribution | Evidence locator |
| --- | --- | --- |
| Integrity verification | Hash-linked chain plus per-node signature; `verify_integrity()` detects alteration on read | `aegis/core/crypto_audit.py` |
| Reproducible verification | Deterministic canonical hashing; the same input yields the same digest | `aegis/core/normalization.py`; `tests/test_determinism.py` |
| Third-party verification | MMR inclusion proofs verifiable against an independently trusted root, without the gateway | `aegis/core/mmr.py`; [MMR Proof v1](../api/MMR_PROOF_V1.md) |
| Bounded acquisition | Export produces a defined extract with a manifest recording the bounds requested | [Forensic Export](../api/FORENSIC_EXPORT.md) |
| Offline checking | `VERIFY.sh` recomputes embedded digests without network access — subject to §4 | `aegis/core/forensic_bundle.py` |
| Minimising handling | Export reads without modifying the source records | `aegis/proxy/audit_api.py` |
| Access records | Audit endpoint access is authenticated and scoped | `aegis/auth/`; `aegis/proxy/dependencies.py` |

## 3. What the gateway does not do

| Not provided | Consequence |
| --- | --- |
| **Chain of custody** | No custody record is created, maintained, or attached to any artifact. Custody documentation is entirely the practitioner's. |
| Identification of potential evidence | A person decides what is relevant. |
| Forensic imaging | Export is a logical extract, not a bit-level image of the storage device. |
| Write-blocking | No hardware or software write-blocking is provided or implied. |
| Practitioner competence | A role requirement, not a software feature. |
| Contemporaneous notes | The practitioner's documentation. |
| Legal admissibility | A judicial determination. |

## 4. The `VERIFY.sh` blind spot

A practitioner relying on the bundle checker must understand its limit, because relying on it incorrectly would be worse than not using it.

`VERIFY.sh` compares file bytes against digest literals **embedded in the same unauthenticated archive**. An actor able to modify a record can also modify the digest describing it, and the script reports success.

A passing check therefore establishes that the bundle is internally self-consistent and undamaged in transit. It does **not** establish that the bundle reflects what the gateway recorded.

Detecting co-tampering requires the MMR inclusion proofs verified against a root obtained through a channel independent of the bundle and of the gateway. That is a separate step the script does not perform, and a practitioner who reports "verified" on the basis of `VERIFY.sh` alone has overstated their result.

## 5. Boundaries a practitioner must document

**Operator trust.** The chain detects tampering on read; it does not prevent it. Anyone with filesystem access to the WAL volume can alter or delete records. Every integrity property terminates at that boundary.

**Retained window.** Export covers records the process still retains, bounded by `AEGIS_MAX_MEMORY_NODES`. **Absence of a record is not evidence that it never existed.** Note the window and its bound when documenting an extract.

**Time.** Timestamps come from the host clock. Without RFC 3161 anchoring — optional, off by default, requiring an accepted TSA — there is no independent evidence of when a record was created. The gateway does not detect clock changes.

**Authorship.** Records bind to an authenticated principal. That establishes which credential was used, not who used it.

**Signature semantics.** With HMAC the signature is symmetric: authenticity relative to key custody, not attribution to a party that could not have forged it.

**No cross-replica ordering.** Each replica is an independent sequence. Interleaving them is the practitioner's reasoning, which must be stated.

**Trusted root independence.** A proof verified against a root supplied by the gateway under examination establishes internal consistency only. Obtain the root separately or the verification is circular.

## 6. Suggested practitioner procedure

The gateway's contribution is strongest when the practitioner's handling is disciplined. In outline:

1. **Before anything else, snapshot the WAL and rotated segments**, preserving mode and timestamps, and digest the snapshot. See [Incident Response §3](../security/INCIDENT_RESPONSE.md#3-containment).
2. **Record who, when, from where, and under what authority.** This is the start of the custody chain; nothing in the software creates it.
3. **Obtain the trusted MMR root through an independent channel** and record how.
4. **Export with explicit bounds**, and record the bounds. A later export with different bounds is a different extract.
5. **Verify twice:** `VERIFY.sh` for internal consistency, then proofs against the independent root.
6. **Record the retained-window bound** at the time of export.
7. **Record what could not be established** — time, authorship, completeness — rather than leaving it implied.

Step 7 is the one that distinguishes a defensible report from an overstated one.

## 7. Prohibited phrasing

Never state:

- "ISO/IEC 27037 compliant" or "27037 certified"
- "Forensically sound" without naming the specific process and its limits
- "Chain of custody maintained" — none is created
- "Court-admissible" or "legally admissible"
- "Forensic image" for what is a logical extract

Acceptable phrasing:

> Aegis Latent Core produces tamper-evident records and bounded, verifiable extracts whose integrity properties a practitioner may rely on when handling digital evidence under ISO/IEC 27037 guidance. The gateway establishes no chain of custody, performs no acquisition in the sense of the standard, and makes no admissibility determination.

---

**Related:** [Compliance Mapping](COMPLIANCE_MAPPING.md) · [Forensic Export](../api/FORENSIC_EXPORT.md) · [Incident Response](../security/INCIDENT_RESPONSE.md) · [MMR Proof v1](../api/MMR_PROOF_V1.md) · [DOC-02](../institutional/DOC-02_CRYPTOGRAPHIC_FORENSIC_BLUEPRINT.md) · [Boundaries](../BOUNDARIES.md)
