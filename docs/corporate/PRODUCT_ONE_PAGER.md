# Aegis Latent Core — Product One-Pager

**Audience:** anyone needing the shortest accurate description.
**Boundary:** every claim here has a row in [Claims Matrix](../CLAIMS_MATRIX.md). No independent assurance exists.

---

## What it is

An **AI Governance and Cryptographic Evidence Gateway**. It sits between an application and a model provider, applies policy to each call, and commits a hash-linked, signed evidence record to a durable log before the response reaches the caller. Each record can be verified by a third party through a portable inclusion proof, without trusting the gateway that produced it. It is self-hosted: the organisation running it holds its own evidence, keys and data.

---

## Five capabilities

| | |
| --- | --- |
| **Commit before emission** | For admitted non-streaming calls the evidence record is durable before the response is observable. For streaming, the terminal marker is withheld until the terminal summary commits. |
| **Portable inclusion proofs** | Merkle Mountain Range proofs verifiable by the Python and TypeScript SDKs against a root obtained independently of the gateway. |
| **Provider independence** | OpenAI-compatible surface; the upstream provider is a configured endpoint. |
| **Fail-closed operation** | Refuses to start or to serve rather than producing unevidenced traffic — no signer, no distributed limiter, no durable storage means no service. |
| **Governed claims** | A public claims register with evidence locators and boundaries, enforced by CI checks that reject unsupported assurance language. |

---

## Deployment

Self-hosted only. Source, container image, or Helm chart on Kubernetes. Air-gapped supported with documented capability loss.

No SaaS. No managed service. No vendor access to any deployment.

---

## Evidence model

| Property | Position |
| --- | --- |
| Storage | Your infrastructure, single-writer JSONL write-ahead log |
| Integrity | Hash-linked chain plus per-node signature; tampering detected on read |
| Third-party verification | MMR inclusion proof against an independently obtained root |
| Signing | HMAC-SHA256 by default; PKCS#11/HSM and ML-DSA-65 available |
| Ordering | Within one process. **No cross-replica global ordering exists.** |
| Custody | Entirely yours. The licensor holds nothing. |

---

## Limitations

| | |
| --- | --- |
| Certification | None. No SOC 2, ISO 27001, HIPAA attestation, or FedRAMP. None in progress. |
| Compliance | Produces technical inputs only. Determinations belong to you and your assessor. |
| Legal admissibility | Not established. A judicial determination. |
| Immutability | Not claimed. Tampering is detected, not prevented; an operator with root can alter records. |
| PII removal | Deterministic pattern matching over three payload fields. Not universal, and it does not protect data already sent to your provider. |
| Service levels | No SLO, no SLA, no capacity claim. Benchmarks are local measurements. |
| Cross-replica ordering | Does not exist. |
| Assurance | No independent audit or penetration test. |
| Maintainer capacity | Single maintainer; bus factor of one. |
| Registry state | SDKs published at `4.0.0`; source baseline is `4.1.0`. |

---

## Licence

AGPLv3 **or** a commercial licence. The AGPL network clause applies if you modify the software and expose it to third parties over a network. See [COMMERCIAL.md](../../COMMERCIAL.md).

---

## Next step

1. **Evaluate the source** at a pinned commit — [Developer Quickstart](../DEVELOPER_QUICKSTART.md)
2. **Review the claims** and spot-check three against their locators — [Claims Matrix](../CLAIMS_MATRIX.md)
3. **Run a pilot**, including the failure tests — [Pilot Playbook](../enterprise/PILOT_PLAYBOOK.md)

---

**Related:** [Executive Summary](EXECUTIVE_SUMMARY.md) · [Corporate FAQ](CORPORATE_FAQ.md) · [Boundaries](../BOUNDARIES.md) · [Enterprise Readiness](../enterprise/ENTERPRISE_READINESS.md)
