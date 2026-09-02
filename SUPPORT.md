# Support

**Audience:** users, evaluators, operators, and prospective customers.
**Scope:** where to get help, what response you can expect, and what is out of scope.
**Boundary:** nothing in this document is a service level agreement. Response targets are stated as intent, not commitment, and are non-binding unless an executed commercial agreement says otherwise.

---

## 1. Choose the right channel

| You have | Use | Do not use |
| --- | --- | --- |
| A security vulnerability | [Private vulnerability reporting](https://github.com/JuanLunaIA/aegis-latent-core/security/advisories/new) — see [SECURITY.md](SECURITY.md) | A public issue |
| A bug with a reproduction | [Bug report issue](https://github.com/JuanLunaIA/aegis-latent-core/issues/new?template=bug_report.md) | Email |
| A documentation error | [Documentation issue](https://github.com/JuanLunaIA/aegis-latent-core/issues/new?template=documentation_issue.md) | A pull request with no issue, for anything larger than a typo |
| A feature idea | [Feature request issue](https://github.com/JuanLunaIA/aegis-latent-core/issues/new?template=feature_request.md) | A pull request implementing it before discussion |
| A usage question | [GitHub Discussions](https://github.com/JuanLunaIA/aegis-latent-core/discussions) | The issue tracker |
| A procurement or commercial question | See [COMMERCIAL.md](COMMERCIAL.md) | The issue tracker |

**Never put a credential, an API key, a customer payload, a raw WAL record, or real personal data in a public issue.** If a reproduction needs one, say so and a maintainer will move the conversation private.

## 2. Community support

Community support is best-effort and unpaid. It is provided by maintainers and contributors when they have time.

**What helps you get an answer:**

- The exact commit or tag you are running, not "latest".
- Your Python version, OS, and whether the Rust extension is present.
- `AEGIS_SECURITY_ENFORCEMENT_MODE` and whether you are in a strict or development configuration.
- A minimal reproduction. A failing test is better than a description.
- What you expected, what happened, and the relevant log lines with secrets removed.

**Response intent, not commitment:** maintainers aim to triage new issues within a week and security reports faster, per [SECURITY.md](SECURITY.md). There is no guarantee, no on-call rotation, and no escalation path in the community channel. An unanswered issue is not an error condition.

## 3. Self-service first

Most questions are answered by existing documentation. Before opening an issue:

| Question | Document |
| --- | --- |
| How do I run it? | [Developer Quickstart](docs/DEVELOPER_QUICKSTART.md) |
| How do I deploy it? | [Deployment Guide](DEPLOYMENT_GUIDE.md) · [Deployment Profiles](docs/operations/DEPLOYMENT_PROFILES.md) |
| What version is actually published? | [Release Status](docs/RELEASE_STATUS.md) |
| Can I claim X about this system? | [Claims Matrix](docs/CLAIMS_MATRIX.md) · [Boundaries](docs/BOUNDARIES.md) |
| What does it not do? | [Boundaries](docs/BOUNDARIES.md) · [Unsupported Claims](docs/institutional/UNSUPPORTED_CLAIMS.md) |
| Why is my WAL refusing to open? | [Storage Requirements](docs/operations/STORAGE_REQUIREMENTS.md) |
| Is it compliant with <framework>? | [Compliance Mapping](docs/compliance/COMPLIANCE_MAPPING.md) — read the boundary section first |
| Something is on fire | [Incident Response](docs/security/INCIDENT_RESPONSE.md) |

## 4. Commercial support

The project is dual-licensed. A commercial agreement may include support terms; the open-source distribution does not.

**The open-source project provides no SLA, no guaranteed response time, no dedicated contact, no uptime commitment, and no assurance artifacts.** Any response target, escalation path, or remediation window exists only if it appears in an executed agreement between you and the licensor.

See [COMMERCIAL.md](COMMERCIAL.md) for licensing, and [Support Model](docs/enterprise/SUPPORT_MODEL.md) for the boundary between community and commercial support in more detail.

## 5. Out of scope

Support does not cover:

- Debugging your upstream model provider, your identity provider, your Redis, your storage, or your ingress.
- Deployment work on your infrastructure.
- Determining whether your deployment satisfies a regulation. That is a determination for you and your assessor; see [Compliance Mapping](docs/compliance/COMPLIANCE_MAPPING.md).
- Legal questions about evidence admissibility. See [Boundaries](docs/BOUNDARIES.md).
- Producing assurance artifacts such as audit reports, penetration test results, or certifications. None exist; see [Assurance Roadmap](docs/assurance/ASSURANCE_ROADMAP.md).
- Reviewing your private fork.

## 6. Supported versions

Security fixes target the versions listed in [SECURITY.md](SECURITY.md). Older versions receive no fixes and no support.

The gateway ships from source. SDK registry versions may lag the source baseline — check [Release Status](docs/RELEASE_STATUS.md) before reporting a version-specific issue, because the version you installed from a registry may not be the version the source documents describe.

---

**Related:** [Security Policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Governance](GOVERNANCE.md) · [Commercial](COMMERCIAL.md) · [Support Model](docs/enterprise/SUPPORT_MODEL.md)
