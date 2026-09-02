# Corporate FAQ

**Audience:** executives, procurement, legal, security reviewers.
**Scope:** direct answers to the questions every evaluator asks.
**Boundary:** answers describe the software. They do not describe any organisation operating it, and none is certified.

---

## Is Aegis compliant?

**No — and no software component can be.**

Compliance is a property of an organisation and its processes, assessed against a specific framework by someone qualified to assess it. A component contributes technical inputs; it cannot be compliant on its own, and a vendor claiming otherwise is telling you something that is not true of any product.

What Aegis contributes: per-call cryptographic evidence records, tamper detection, third-party-verifiable inclusion proofs, pattern-based redaction, scope-controlled access, and bounded export. An organisation may evaluate those as technical inputs to an assessment under the EU AI Act, HIPAA, MiFID II, or ISO/IEC 27037.

What it does not do: determine whether a framework applies to you, whether your obligations are met, or whether your controls are sufficient.

See [Compliance Mapping](../compliance/COMPLIANCE_MAPPING.md).

---

## Is the evidence legally admissible?

**Not established, and not something this project can establish.**

Admissibility is a determination made by a court applying its own rules of evidence, in a specific jurisdiction, in a specific proceeding. It depends on relevance, authentication, custody, and the court's judgement — not on the cryptographic properties of a file.

What the system produces is **technical integrity evidence**: records whose alteration is detectable, with proofs a third party can verify against an independently obtained root. That may support an authentication argument. It is not the argument, and it is not a conclusion.

Two things weaken any admissibility argument and should be understood before relying on one:

- **No chain of custody is created.** Nothing in the software records who handled evidence, when, or under what authority. That documentation is entirely the practitioner's.
- **With the default HMAC signer the signature is symmetric.** Anyone holding the key could have produced it, so it is authenticity relative to key custody, not attribution to a party that could not have forged it.

Route this to counsel. See [ISO/IEC 27037 Technical Inputs](../compliance/ISO_27037_TECHNICAL_INPUTS.md).

---

## Is the evidence immutable?

**No.**

The chain is append-only within the process and **detects** tampering on read through hash linkage and per-node signatures. It does not **prevent** tampering. An operator with filesystem access can alter or delete records, and no control in this repository stops them.

Segment rotation applies owner-only file permissions and renames the file. That is access restriction, not immutability.

An S3 Object Lock adapter can target a bucket you configure, verifying checksum, version, lock mode and retention on upload. It does not configure, enforce or attest the bucket's retention policy, and whether your target satisfies a regulatory write-once definition is a determination for you and your assessor.

**Operator trust is the largest residual assumption in the design.** Every integrity, custody and non-repudiation statement about this system terminates there. See [Security Architecture §2](../security/SECURITY_ARCHITECTURE.md#2-trust-boundaries).

---

## Does it prevent prompt injection?

**No, and nobody's product does.**

Prompt injection is an open research problem. The gateway applies bounded heuristic detection over a pinned corpus — pattern matching plus session-cumulative and crescendo signals — and blocks what it recognises. It does not generalise to unseen attack classes and it does not certify that a model cannot be manipulated.

What it does instead, and what is actually useful: **it records what was sent and what came back.** If an injection succeeds, there is durable, verifiable evidence of the interaction. Detection is best-effort; the record is the product.

The measured result of the pinned WAF corpus is zero observed bypasses and zero false positives across 15 malicious and 8 benign local cases. That is a small sample with a wide confidence interval, and it is not a coverage claim. See [WAF Testing](../security/WAF_TESTING.md).

---

## Does it remove all PII?

**No.**

Redaction is deterministic pattern matching across seventeen categories, applied to three payload fields (`content`, `system`, `text`). It does not detect free-text disclosure, paraphrase, indirect identifiers, novel formats, or non-English identifiers. Coverage against your traffic is unmeasured — no such measurement exists in this repository for any corpus.

**The limit that surprises people:** redaction runs before the evidence record is written, but *after* the request has already gone to your model provider. Redaction protects the record. It does not protect the provider, and it cannot recall data already sent.

If your privacy position depends on the provider not receiving personal data, you need filtering before the gateway. This is not that control.

Records written before redaction was enabled remain unredacted permanently, because the chain is append-only.

See [PII Redaction Boundaries](../privacy/PII_REDACTION_BOUNDARIES.md).

---

## Is it production-ready?

**That phrase is not used here, because it means different things to different buyers.** The useful answer is component-by-component:

| Dimension | State |
| --- | --- |
| Implemented and tested in source | Yes, with a test suite and CI gates |
| Documented operational procedures | Yes, and none validated against a production deployment |
| Independent security assurance | None |
| Production-scale measurement | None. Benchmarks are local. |
| Defined SLO, RPO or RTO | None |
| Deployed and accepted in a named target environment | None known to this project |

An organisation with platform engineering capacity that runs its own pilot, including the failure tests, and accepts the documented gaps can reach a defensible deployment decision. An organisation expecting a certified, vendor-supported, capacity-proven product should not adopt this today.

See [Enterprise Readiness](../enterprise/ENTERPRISE_READINESS.md) and [Pilot Playbook](../enterprise/PILOT_PLAYBOOK.md).

---

## What is the licence?

**Dual: AGPLv3, or a commercial licence.**

The AGPL is copyleft with a network clause: if you modify the software and let third parties interact with it over a network, you must offer them the corresponding source. That clause is the practical decision point for most organisations. Internal use without modification, or without third-party network exposure, generally does not trigger it — but confirm with counsel for your specific case.

A commercial licence exists for organisations where the AGPL terms do not fit. See [COMMERCIAL.md](../../COMMERCIAL.md).

Dependency licences are enumerated in the SPDX SBOMs published as release assets.

---

## How is support handled?

**Community support is best-effort and unpaid. There is no SLA in the open-source project.**

Stated intent: triage within about a week, security reports faster. Neither is a commitment. There is no on-call rotation and no escalation path. An unanswered issue is a normal outcome.

Commercial support terms exist only inside an executed agreement.

**The fact worth weighing:** this is a single-maintainer project. The bus factor is one. A commercial agreement can change response commitments; it does not change how many people understand the codebase. Reasonable mitigations are to pin and vendor the source, build internal capability to patch the evidence path, negotiate continuity terms, or accept the risk explicitly and document it.

See [Support Model](../enterprise/SUPPORT_MODEL.md).

---

## Two more worth asking

**What is the largest security assumption?**
That the operator of the deployment is trusted. Tampering is detected on read, not prevented.

**What would change your mind about a claim here?**
Every row in [Claims Matrix](../CLAIMS_MATRIX.md) carries a falsification condition. Spot-check three rows against their evidence locators — if a locator does not support its claim, that is a material finding about the whole register, and it is a cheap test to run.

---

**Related:** [Executive Summary](EXECUTIVE_SUMMARY.md) · [Product One-Pager](PRODUCT_ONE_PAGER.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md) · [Unsupported Claims](../institutional/UNSUPPORTED_CLAIMS.md) · [Procurement FAQ](../FAQ_PROCUREMENT.md)
