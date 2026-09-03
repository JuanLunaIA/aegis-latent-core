# Enterprise Readiness

**Audience:** platform engineering leads, security reviewers, procurement.
**Scope:** an honest assessment of what is ready for enterprise deployment, what is configuration-dependent, and what is not ready.
**Boundary:** "readiness" here means the repository provides the capability and its tests. It does not mean any deployment has been accepted, audited, or run at scale. No independent assurance exists. See [Assurance Roadmap](../assurance/ASSURANCE_ROADMAP.md).

---

## 1. Summary for a reviewer in a hurry

| Dimension | Position |
| --- | --- |
| Deployment model | Self-hosted only. No SaaS, no hosted service, no vendor-operated infrastructure. |
| Evidence custody | Entirely yours. The licensor never holds your evidence, keys, or payloads. |
| Security controls | Implemented and tested; most require target configuration to be effective. |
| Operational readiness | Runbooks exist. None is validated against a production deployment. |
| Independent assurance | None. No audit, no penetration test, no certification. |
| Support | Community best-effort. Commercial terms only under an executed agreement. |
| Scale evidence | Local measurements only. No capacity claim of any kind. |
| Maintainer capacity | Single maintainer. Bus factor of one. |

**The two facts most likely to matter to your risk assessment are the last two.** They are stated here rather than buried because a reviewer will find them anyway, and finding them late is worse.

## 2. Deployment models

| Model | Available | Notes |
| --- | --- | --- |
| Self-hosted from source | Yes | The supported path. See [Deployment Profiles](../operations/DEPLOYMENT_PROFILES.md). |
| Self-hosted container | Yes | `ghcr.io/juanlunaia/aegis-latent-core:4.0.2` — the most recent published tag, digest-pinnable, cosign-signed. No `4.1.1` image is published. |
| Kubernetes via Helm | Yes | `StatefulSet`, per-replica WAL volumes, default-deny NetworkPolicy. |
| Air-gapped | Yes | With documented capability loss; no external anchoring. |
| Vendor-hosted SaaS | No | Does not exist and is not on the roadmap. |
| Managed service | No | Does not exist. |

**You run it. You hold the data. The licensor has no operational access to your deployment and no ability to reach your evidence.** For many buyers that is the point; for buyers expecting a vendor-operated service, it is a disqualifier they should learn early.

## 3. Evidence custody

| Property | Position |
| --- | --- |
| Where evidence lives | Your storage, under your control |
| Who can read it | Your principals, plus anyone with filesystem access to the volume |
| Who holds signing keys | You |
| Vendor access | None |
| Third-party verifiability | Via MMR proofs against a root you obtain independently |
| Cross-replica ordering | Does not exist. Each replica is an independent chain. |
| External immutability | Not established. Rotation applies access restriction, not immutability. |

The operator-trust boundary is the largest residual assumption in the design: an operator with root can alter or delete records. The chain detects tampering on read; it does not prevent it. See [Security Architecture §2](../security/SECURITY_ARCHITECTURE.md#2-trust-boundaries).

## 4. Security controls

Full inventory with per-control boundaries: [Security Controls](../security/SECURITY_CONTROLS.md).

**Implemented and tested in source:** authenticated principals with scope enforcement, immutable tenant binding, request and streaming bounds, WAF detection over a pinned corpus, hash-linked signed evidence with commit-before-emission, single-writer WAL enforcement, portable inclusion proofs, hash-pinned dependencies, SHA-pinned actions, least-privilege CI tokens, SAST and dependency scanning, SBOM and build attestation.

**Requires your configuration to be effective:** OIDC, mTLS, distributed rate limiting via Redis, HSM signing, kernel controls, TLS termination, NetworkPolicy enforcement by your CNI, storage with power-loss protection, encryption at rest.

**Not provided:** encryption of the WAL at rest, prevention of operator tampering, network-layer DoS absorption, protection of data already sent to your model provider.

## 5. Operational readiness

| Capability | State |
| --- | --- |
| Health and readiness endpoints | Implemented |
| Prometheus metrics | Implemented behind an optional extra |
| Alert rules | Documented starting points, untuned |
| Runbooks: backpressure, key rotation, rollback, backup/restore, incident | Written |
| Runbooks validated against a production deployment | No |
| Defined RPO or RTO | No |
| Disaster recovery plan | No |
| On-call or escalation | No |

Runbooks are written from the source's actual behaviour, not invented. They have not been exercised at scale, and that gap should be closed by your own rehearsal during a pilot; see [Pilot Playbook](PILOT_PLAYBOOK.md).

## 6. Integration readiness

| Surface | State |
| --- | --- |
| OpenAI-compatible gateway | Implemented |
| Anthropic path | Implemented, bounded by SDK test coverage |
| Python SDK | Implemented; registry version lags source — see [Release Status](../RELEASE_STATUS.md) |
| TypeScript SDK | Implemented; same registry caveat |
| Proof verification in both SDKs | Implemented |
| Forensic dashboard | Implemented; browser-facing authentication is yours |
| Orchestration framework integrations | Not implemented |
| OpenTelemetry span model | Partial; hooks exist, a tested model does not |

Provider compatibility is bounded by what the SDK tests exercise. It is not a claim of compatibility with every provider version or endpoint.

## 7. What is not ready

Stated plainly, because a readiness document that omits these is not useful.

| Gap | Consequence |
| --- | --- |
| **No independent assurance** | No SOC 2, ISO 27001, penetration test, or third-party audit. Nothing to hand a security team that they did not derive themselves. |
| **No production-scale evidence** | Benchmarks are local. No capacity, throughput, or latency claim survives contact with a target environment without your own measurement. |
| **No cross-replica ordering** | A requirement for one global timeline cannot be met today. |
| **Registry lag** | SDKs are published at `4.0.0` while source is `4.1.2`. Installing from a registry gets you different code from the documentation. |
| **Single maintainer** | Bus factor of one. No independent second approver on the critical path. |
| **No SLA** | Response targets are intent, not commitment, absent an executed agreement. |
| **Untested runbooks at scale** | Procedures are written; rehearsal is yours. |
| **No customer references** | None exist to offer. |

## 8. Procurement readiness

| Artifact | Available |
| --- | --- |
| Source code under AGPLv3 or commercial licence | Yes |
| SBOM (SPDX) | Yes, as release assets |
| Build provenance attestations | Yes |
| Signed release tag and signed images | Yes, verified per [Release Status](../RELEASE_STATUS.md) |
| Claims register with evidence locators | Yes — [Claims Matrix](../CLAIMS_MATRIX.md) |
| Threat model | Yes |
| Security control inventory | Yes |
| Vendor security questionnaire responses | Yes — [Vendor Security Questionnaire](VENDOR_SECURITY_QUESTIONNAIRE.md) |
| Audit report | No |
| Penetration test report | No |
| Certification | No |
| Insurance certificate | `[UNKNOWN_MISSING_PRIMARY_SOURCE]` |
| Financial statements | `[UNKNOWN_MISSING_PRIMARY_SOURCE]` |

## 9. Who this fits, and who it does not

**Fits:** an organisation that wants evidence custody in its own infrastructure, has platform engineering capacity to run it, can perform its own security assessment, and values a documented boundary over a marketed one.

**Does not fit:** an organisation that requires a vendor-operated service, needs certification before deployment, requires a contractual SLA from the open-source project, needs cross-replica global ordering today, or has no capacity to operate a stateful service.

Saying the second list out loud costs a few prospects and saves everyone a failed evaluation.

---

**Related:** [Pilot Playbook](PILOT_PLAYBOOK.md) · [Procurement Checklist](PROCUREMENT_CHECKLIST.md) · [Vendor Security Questionnaire](VENDOR_SECURITY_QUESTIONNAIRE.md) · [Support Model](SUPPORT_MODEL.md) · [Security Controls](../security/SECURITY_CONTROLS.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md)
