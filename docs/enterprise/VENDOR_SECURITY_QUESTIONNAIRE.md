# Vendor Security Questionnaire — Response Templates

**Audience:** anyone completing a security questionnaire about this software.
**Scope:** prepared answers to common questions, each grounded in repository evidence or explicitly marked unknown.
**Boundary:** these are technical answers about the software. They are not answers about any organisation operating it, and they are not certified. Where a question asks about an operating organisation, the answer depends on who is deploying — you, in a self-hosted model.

---

## Rules for using these answers

1. **Do not edit an answer to sound better.** If an answer is inconvenient, the honest response is to say so, not to soften it.
2. **`[UNKNOWN_MISSING_PRIMARY_SOURCE]` means answer it yourself or leave it unanswered.** Do not substitute a plausible value.
3. **Never claim a certification.** None exists. "In progress" would also be false.
4. **Distinguish software from operator.** In a self-hosted deployment most organisational controls are the customer's, and saying so is accurate rather than evasive.

---

## Architecture and hosting

**Q: Describe the architecture.**

> A self-hosted gateway that sits between a client application and an upstream model provider. It applies admission controls, forwards the request, redacts configured patterns, and commits a hash-linked signed evidence record to a local write-ahead log before returning the response. Streaming emits sanitized events incrementally and commits one exact-byte terminal summary before the terminal marker. See `docs/architecture/ARCHITECTURE.md` and `docs/security/SECURITY_ARCHITECTURE.md`.

**Q: Is this SaaS or self-hosted?**

> Self-hosted only. No hosted service, managed offering, or vendor-operated infrastructure exists, and none is on the roadmap. The customer runs it in their own environment.

**Q: Does the vendor have access to customer data or systems?**

> No. The licensor has no operational access to any customer deployment, holds no customer evidence, keys or payloads, and has no ability to reach a customer environment.

**Q: What third parties are involved in processing?**

> The customer's chosen upstream model provider receives the governed request. That relationship is between the customer and the provider; the gateway forwards to a configured endpoint and does not create, mediate or enforce a provider agreement.

## Data custody

**Q: Where is customer data stored?**

> In the customer's infrastructure. Evidence records are written to a JSONL write-ahead log on customer storage. The gateway holds a bounded in-memory window governed by `AEGIS_MAX_MEMORY_NODES`.

**Q: Is data encrypted at rest?**

> The gateway does not encrypt the write-ahead log. Encryption at rest is the customer's storage-layer responsibility. Rotated segments receive owner-only file permissions, which is access restriction and not encryption.

**Q: Is data encrypted in transit?**

> The gateway supports TLS termination and mutual TLS with explicit client-certificate pinning. TLS is not enabled by default and is a deployment configuration. Upstream connections use HTTPS where the configured endpoint provides it.

**Q: How is data segregated between tenants?**

> Logically, within a single process: principals are derived from the authenticated credential and never from a client-supplied header, and audit reads are filtered by tenant. This is not equivalent to separate deployments — an operator with filesystem access to the volume can read all records regardless of scope.

## Cryptography

**Q: What cryptographic algorithms are used?**

> SHA-256 for canonical hashing and chain linkage. HMAC-SHA256 for node signing by default. Optional PKCS#11/HSM signing, and optional ML-DSA-65 when the native Rust extension is present. No primitive is implemented in-house; hashing and HMAC come from Python's standard library, asymmetric operations from the `cryptography` package.

**Q: Does signing provide non-repudiation?**

> Not with the default HMAC signer. HMAC is symmetric: anyone holding the key can produce a valid signature, so it provides authenticity relative to key custody, not third-party non-repudiation. An asymmetric or HSM signer changes this and must be configured deliberately.

**Q: How are keys managed?**

> Key custody is the customer's. The gateway reads a signing key from configuration, or uses a PKCS#11 backend. In strict mode it refuses to start without one and refuses to fall back from a configured but unavailable HSM. Rotation guidance is in `docs/operations/KEY_ROTATION_RUNBOOK.md`. The gateway does not generate, escrow, distribute or destroy keys.

**Q: Are records immutable?**

> No. The chain is append-only within the process and detects tampering on read. It does not prevent an operator with filesystem access from altering or deleting records. No write-once storage guarantee is claimed. An S3 Object Lock adapter can target a bucket the customer configures, but does not configure, enforce or attest its retention policy.

## Access control

**Q: What authentication methods are supported?**

> API keys with per-key principal mapping, OIDC with strict claim validation, and mutual TLS with explicit leaf pinning. In strict mode, API-key mode requires an explicit principal mapping for every key.

**Q: How is authorization enforced?**

> Scope-based. `audit:read` gates audit reads; `audit:export` gates forensic export and is granted separately because export is a bulk sensitive-data operation.

**Q: Is there role-based access control?**

> Scope-based rather than role-based. Scopes attach to authenticated principals. There is no role hierarchy, no delegation model, and no administrative console.

**Q: How is privileged access controlled?**

> Within the software, by scope. Host-level privileged access is entirely the customer's control domain, and it is the largest residual assumption in the design: an operator with root can alter or delete evidence.

## Audit and logging

**Q: What audit logging exists?**

> Every governed call produces a hash-linked, signed evidence record committed before the response returns. Records bind to an authenticated principal, the model identifier, request parameters, and hashes covering exact response bytes. Verification is available at `GET /v1/audit/integrity`.

**Q: Can audit logs be tampered with?**

> Tampering is detectable, not prevented. Chain linkage and per-node signatures make alteration detectable on read. A privileged operator can still alter or delete the underlying file.

**Q: How long are audit records retained?**

> Retention is entirely the customer's decision. The gateway enforces no retention policy and deletes nothing on a schedule.

**Q: Are payloads logged?**

> Not by default, and enabling payload logging is contraindicated. Evidence records are the record of governed content; application logs carry request IDs, principal pseudonyms, status codes and control decisions. Metrics are content-free.

## Vulnerability management

**Q: How are vulnerabilities reported?**

> Through GitHub Private Vulnerability Reporting. Public issues for security findings are not accepted. See `docs/security/VULNERABILITY_DISCLOSURE.md`.

**Q: What are your remediation SLAs?**

> None in the open-source project. Stated targets — acknowledgement within seven days, assessment within fourteen — are intent, not commitment. Binding timelines exist only under an executed commercial agreement.

**Q: Do you perform penetration testing?**

> No independent penetration test has been performed. Automated scanning runs in CI: CodeQL, Bandit, pip-audit, Trivy, OSV-Scanner and cargo-audit.

**Q: Do you have a bug bounty?**

> No.

## Dependency and supply chain

**Q: How are dependencies managed?**

> Python dependencies are hash-pinned in `requirements.lock` and installed with `--require-hashes`. GitHub Actions are pinned by commit SHA and verified by `scripts/verify_github_action_pins.py`. Rust dependencies are locked in `Cargo.lock`.

**Q: Do you produce an SBOM?**

> Yes. SPDX JSON SBOMs are generated in CI and published as release assets with digest sidecars.

**Q: Are releases signed?**

> The release tag is signed with Sigstore keyless signing. Container images are signed with cosign. Release artifacts carry build provenance attestations and a `SHA256SUMS` file; they do not carry detached signatures, so verification uses `gh attestation verify` and `sha256sum`, not `cosign verify-blob`. Note that GitHub displays the tag as unverified with reason `bad_cert`, which is the expected result for a Sigstore short-lived certificate — see `docs/RELEASE_STATUS.md`.

## Compliance and certification

**Q: Are you SOC 2 certified?** → **No.** No SOC 2 examination has been performed, and none is in progress.

**Q: Are you ISO 27001 certified?** → **No.**

**Q: Are you HIPAA compliant?** → **No.** The software provides pattern-based redaction and audit records that an organisation may evaluate as technical inputs. Compliance is an organisational determination. See `docs/compliance/HIPAA_TECHNICAL_INPUTS.md`.

**Q: Are you GDPR compliant?** → Compliance is a determination about a controller or processor, not about a software component. The software is self-hosted, so the customer is the controller of data in their deployment. See `docs/privacy/DATA_PROCESSING_CHECKLIST.md`.

**Q: Are you FedRAMP authorized?** → **No.**

**Q: Will you sign a BAA / DPA?** → `[UNKNOWN_MISSING_PRIMARY_SOURCE]` — a commercial question for the licensor, not a property of the software. See `COMMERCIAL.md`.

## Business continuity

**Q: What is your RTO/RPO?**

> None is defined for the software. In a self-hosted model these are properties of the customer's deployment and their backup and restore configuration.

**Q: Do you have a disaster recovery plan?**

> Not for a customer's deployment; there is no vendor-operated infrastructure. Backup and restore procedures are documented in `docs/operations/BACKUP_RESTORE.md` and have not been validated against a production deployment.

**Q: What is your uptime history?**

> Not applicable. No hosted service exists.

## Organisation

Answers in this section depend on the operating organisation and are not properties of the software.

| Question | Answer |
| --- | --- |
| Employee background checks | `[UNKNOWN_MISSING_PRIMARY_SOURCE]` |
| Security awareness training | `[UNKNOWN_MISSING_PRIMARY_SOURCE]` |
| Cyber insurance | `[UNKNOWN_MISSING_PRIMARY_SOURCE]` |
| Financial statements | `[UNKNOWN_MISSING_PRIMARY_SOURCE]` |
| Number of engineers | Single maintainer. Bus factor is one, and a reviewer should weigh that explicitly. |
| Sub-processors | None, for the software. The customer's model provider is the customer's sub-processor. |

## The question worth asking that questionnaires usually miss

**Q: What is the largest security assumption in this design?**

> That the operator of the deployment is trusted. The evidence chain detects tampering on read; it does not prevent an operator with root from altering or deleting records. Every integrity, custody and non-repudiation statement about this system terminates at that boundary. A reviewer should decide whether their control environment makes that assumption acceptable.

---

**Related:** [Enterprise Readiness](ENTERPRISE_READINESS.md) · [Procurement Checklist](PROCUREMENT_CHECKLIST.md) · [Security Controls](../security/SECURITY_CONTROLS.md) · [Threat Model](../security/THREAT_MODEL.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md)
