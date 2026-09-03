# Procurement Checklist

**Audience:** procurement, vendor management, legal, security review.
**Scope:** what to evaluate before adopting this software, in the order that surfaces disqualifiers earliest.
**Boundary:** this checklist is supplied by the project being evaluated. Treat it as a starting structure, not as independent verification. Every item marked "verify yourself" means exactly that.

---

## 0. Disqualifiers first

Four questions that end the evaluation early if the answer is wrong for you. Ask them before spending review time.

| Question | Answer |
| --- | --- |
| Do you require a vendor-operated SaaS? | Then stop. This is self-hosted only, and a hosted service is not on the roadmap. |
| Do you require certification (SOC 2, ISO 27001) before deployment? | Then stop, or plan to accept a documented gap. None exists, and none is in progress. |
| Do you require a contractual SLA from the open-source project? | Then stop. Support is best-effort unless a commercial agreement is executed. |
| Do you require a single global evidence timeline across replicas? | Then stop. Each replica is an independent chain. This is not configurable. |

Publishing these costs some evaluations and saves everyone the ones that were going to fail in month three.

## 1. Fix the artifact under evaluation

Version ambiguity invalidates everything downstream. Pin it before anything else.

- [ ] **Exact commit SHA or tag.** Not "latest", not "main".
- [ ] **Note that `v4.0.2` targets `a6eb58d`, and the default branch has moved past it.** Evaluating the branch head is evaluating different source.
- [ ] **If evaluating a container, pin the digest**, not the tag.
- [ ] **If evaluating an SDK from a registry, confirm the version.** PyPI and npm carry `4.0.0` while source is `4.1.0`. Installing from a registry gets you different code from the documentation.

Verify yourself with the readback commands in [Release Status §2](../RELEASE_STATUS.md#2-readback-commands). Do not accept the table in that document as evidence; run the commands.

## 2. Licence

- [ ] **AGPLv3 or a commercial licence.** Decide which applies to you.
- [ ] **AGPL §13 network clause:** if you modify the software and let third parties interact with it over a network, you must offer them the corresponding source. Confirm with counsel whether your intended use triggers it.
- [ ] **Dependency licences.** SBOMs are published as release assets; review them.
- [ ] **Commercial terms** if AGPL does not fit: see [COMMERCIAL.md](../../COMMERCIAL.md).

## 3. Security review

- [ ] Read [Threat Model](../security/THREAT_MODEL.md), including the out-of-scope section.
- [ ] Read [Security Controls](../security/SECURITY_CONTROLS.md) and note every row whose owner is "You".
- [ ] Read [Security Architecture §2](../security/SECURITY_ARCHITECTURE.md#2-trust-boundaries) and accept or reject the operator-trust assumption. **Every integrity claim in this system terminates there.**
- [ ] Confirm no independent audit or penetration test exists — because none does.
- [ ] Review the CI security posture: hash-pinned dependencies, SHA-pinned actions, least-privilege tokens, SAST and dependency scanning.
- [ ] Run your own SAST and dependency scan. Do not rely on the project's.
- [ ] Review [Vulnerability Disclosure](../security/VULNERABILITY_DISCLOSURE.md) and decide whether best-effort timelines are acceptable.

## 4. Claims verification

This is where an evaluation of this project differs from most.

- [ ] Read [Claims Matrix](../CLAIMS_MATRIX.md). Every public claim has a state, a locator and a boundary.
- [ ] **Spot-check three claims against their evidence locators.** If a claim's cited test does not exist or does not test what the row says, that is a material finding about the whole register.
- [ ] Read [Unsupported Claims](../institutional/UNSUPPORTED_CLAIMS.md) — what the project refuses to say.
- [ ] Read [Boundaries](../BOUNDARIES.md).
- [ ] Check whether any sales or marketing statement you have been given exceeds a matrix row. If so, the matrix governs.

## 5. Deployment environment

- [ ] Choose a profile: [Deployment Profiles](../operations/DEPLOYMENT_PROFILES.md).
- [ ] **Confirm storage power-loss protection with your vendor.** `fsync` success is not power-loss durability, and this is the most common gap between documented and actual durability.
- [ ] Confirm Redis availability for distributed rate limiting; strict mode requires it.
- [ ] Confirm your CNI enforces NetworkPolicy — verify, do not assume.
- [ ] Decide TLS termination.
- [ ] Decide signing: HMAC, HSM/PKCS#11, or post-quantum. Note that HMAC is symmetric and is not third-party non-repudiation.
- [ ] Plan key custody and rotation.
- [ ] Size storage against measured WAL growth from your pilot.

## 6. Data handling

- [ ] Work through [Data Processing Checklist](../privacy/DATA_PROCESSING_CHECKLIST.md).
- [ ] **Confirm your model provider agreement covers what you send.** Redaction does not protect the provider; the request reaches them as sent.
- [ ] Measure redaction coverage against your traffic shape, with synthetic data.
- [ ] Confirm which payload fields your integration populates — only `content`, `system` and `text` are scrubbed.
- [ ] Decide encryption at rest; the gateway does not provide it.

## 7. Retention and deletion

- [ ] Decide the retention period and its basis.
- [ ] **Resolve the append-only versus erasure tension explicitly.** Deleting from a hash-linked chain truncates it. The repository does not resolve this for you.
- [ ] Confirm retired signing keys will be retained at least as long as the records they signed.
- [ ] Decide archival: S3 Object Lock is available and configuration-dependent, and is not a WORM guarantee.

## 8. Operations

- [ ] Confirm you have platform capacity to run a stateful service.
- [ ] Rehearse restore, rollback, and key rotation during the pilot. See [Pilot Playbook](PILOT_PLAYBOOK.md).
- [ ] Configure alerting per [Monitoring and Alerting](../operations/MONITORING_ALERTING.md), noting that no threshold is tuned.
- [ ] Define your own RPO and RTO. None is defined here.
- [ ] Assign incident ownership; see [Incident Response](../security/INCIDENT_RESPONSE.md).

## 9. Support and escalation

- [ ] Read [Support Model](SUPPORT_MODEL.md).
- [ ] Accept that community support is best-effort with no guaranteed response.
- [ ] **Assess the single-maintainer risk.** Bus factor is one. Decide your mitigation: internal capability to maintain a fork, a commercial agreement, or accepting the risk.
- [ ] If you need commitments, negotiate them into an agreement. Nothing in the repository creates one.

## 10. Evidence package to request

Available from the repository or a release:

| Artifact | Where |
| --- | --- |
| Source at a pinned commit | Git |
| SBOM (SPDX) | Release assets |
| Build provenance attestations | `gh attestation verify` |
| Signed tag | `gitsign verify` |
| Signed container images | `cosign verify` |
| Claims register | [Claims Matrix](../CLAIMS_MATRIX.md) |
| Threat model and control inventory | `docs/security/` |
| Test results | Run the suite yourself |
| Dated evidence records | [`evidence/INDEX.md`](../../evidence/INDEX.md) |

Not available, and will not be produced on request:

| Artifact | Status |
| --- | --- |
| SOC 2 / ISO 27001 report | Does not exist |
| Penetration test report | Does not exist |
| Customer references | None to offer |
| Uptime history | No hosted service exists |
| Insurance certificate | `[UNKNOWN_MISSING_PRIMARY_SOURCE]` |
| Financial statements | `[UNKNOWN_MISSING_PRIMARY_SOURCE]` |

## 11. Language check

Pause the purchase if any proposal, from any source, uses "compliant", "certified", "court-admissible", "immutable", "WORM", "production-ready", "guaranteed", or "24/7" without a named artifact, a defined scope, a reviewer, and a falsification condition.

That test applies to material from this project as much as to anyone's.

---

**Related:** [Enterprise Readiness](ENTERPRISE_READINESS.md) · [Pilot Playbook](PILOT_PLAYBOOK.md) · [Vendor Security Questionnaire](VENDOR_SECURITY_QUESTIONNAIRE.md) · [Support Model](SUPPORT_MODEL.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Release Status](../RELEASE_STATUS.md) · [Boundaries](../BOUNDARIES.md)
