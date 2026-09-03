# Support Model

**Audience:** procurement, vendor management, operators planning for production.
**Scope:** the boundary between community and commercial support, and what each does and does not include.
**Boundary:** **the open-source project provides no service level agreement.** Every response target below is stated intent from a single maintainer. Binding commitments exist only inside an executed commercial agreement, and nothing in this repository creates one.

---

## 1. Two tiers

| | Community | Commercial |
| --- | --- | --- |
| Cost | Free | Per agreement |
| Channel | GitHub issues, discussions | Per agreement |
| Response target | Intent only, non-binding | Per agreement |
| Escalation | None | Per agreement |
| Named contact | No | Per agreement |
| Guaranteed fix | No | Per agreement |
| Deployment assistance | No | Per agreement |
| Assurance artifacts | None exist | None exist — see §5 |

The right-hand column says "per agreement" rather than listing terms because listing terms that are not offered would be marketing. What a commercial agreement contains is negotiated; see [COMMERCIAL.md](../../COMMERCIAL.md).

## 2. Community support

**What it is:** maintainers and contributors answering when they have time.

**What it covers:** bug reports with reproductions, documentation errors, usage questions already grounded in the documentation, security reports through the private channel.

**Response intent** — triage within about a week, faster for security reports. Neither is a commitment. **An unanswered issue is a normal outcome, not a failure state.** Plan on that basis rather than on the intent.

**What makes a report answerable:** the exact commit or tag, Python version and OS, whether the Rust extension is present, `AEGIS_SECURITY_ENFORCEMENT_MODE`, a minimal reproduction, and the relevant logs with secrets removed. A failing test beats a description.

**Never include** a credential, customer payload, raw WAL record, or real personal data in a public issue.

Channels and routing: [SUPPORT.md](../../SUPPORT.md).

## 3. What no tier covers

Neither community nor commercial support includes:

- Debugging your upstream model provider, identity provider, Redis, storage, or ingress.
- Operating your deployment.
- Determining whether your deployment satisfies a regulation. That is yours and your assessor's. See [Compliance Mapping](../compliance/COMPLIANCE_MAPPING.md).
- Legal opinions about evidence admissibility.
- Producing certifications, audit reports, or penetration test results.
- Reviewing your private fork.
- Custom development, unless separately agreed.

## 4. The maintainer-capacity risk

Stated directly, because it belongs in a procurement assessment rather than in a footnote.

**This is a single-maintainer project. The bus factor is one.** There is no on-call rotation, no second reviewer on the critical path, and no organisational continuity commitment.

A commercial agreement can change response commitments. It does not change the number of people who understand the codebase.

Reasonable mitigations, in rough order of cost:

1. **Pin and vendor.** Pin an exact commit and container digest, and keep a verified copy. The AGPL guarantees your right to the source.
2. **Build internal capability.** Have someone on your side able to read `aegis/core/crypto_audit.py`, `aegis/core/mmr.py` and `aegis/proxy/streaming.py` well enough to patch them.
3. **Negotiate escrow or continuity terms** in a commercial agreement.
4. **Accept the risk explicitly**, documented, with a review date.

Choosing (4) is legitimate. Choosing it without writing it down is not.

## 5. Assurance artifacts

Requests for the following will be answered "does not exist", not "available on request":

| Artifact | Status |
| --- | --- |
| SOC 2 Type I or II | Does not exist; none in progress |
| ISO 27001 certificate | Does not exist |
| Penetration test report | Does not exist |
| Third-party security audit | Does not exist |
| Customer references | None to offer |
| Uptime history | Not applicable; no hosted service |

What does exist: source, SBOMs, build attestations, signed tags and images, a claims register with evidence locators, a threat model, and a control inventory. See [Audit Evidence Index](../assurance/AUDIT_EVIDENCE_INDEX.md).

The path to independent assurance, if it is ever pursued, is described in [Assurance Roadmap](../assurance/ASSURANCE_ROADMAP.md). Publishing that document is not the same as having the evidence, and it should not be read as a commitment.

## 6. Security reports

Security reports follow their own path and are prioritised ahead of feature work regardless of tier. Report privately: [Vulnerability Disclosure](../security/VULNERABILITY_DISCLOSURE.md).

Stated intent: acknowledgement within seven days, assessment within fourteen. Non-binding, for the reasons in §4.

## 7. Version support

Fixes target the versions listed in [SECURITY.md](../../SECURITY.md). Older versions receive nothing.

**Check which artifact you are actually running.** The gateway ships from source and from the GHCR tag `4.1.1`; the SDK on PyPI is `4.1.1`, but the SDK on npm is still `4.0.0`. A support question about an npm-installed SDK may concern code that the current documentation does not describe. See [Release Status](../RELEASE_STATUS.md).

---

**Related:** [SUPPORT.md](../../SUPPORT.md) · [COMMERCIAL.md](../../COMMERCIAL.md) · [Enterprise Readiness](ENTERPRISE_READINESS.md) · [Procurement Checklist](PROCUREMENT_CHECKLIST.md) · [Vulnerability Disclosure](../security/VULNERABILITY_DISCLOSURE.md) · [Assurance Roadmap](../assurance/ASSURANCE_ROADMAP.md)
