<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — One Page

**AI Governance and Cryptographic Evidence Gateway.** Self-hosted.

---

## The problem

Your AI decisions are logged to a database your administrators can edit. When a regulator, a counterparty or an internal investigation asks what the model was told and what it said, you answer from records the interested party could have changed.

Nobody has to act in bad faith for this to fail. A retention job, a migration, an incident script — the record is gone and nobody can prove which.

## What it costs

The argument stops being *what happened* and becomes *whether your records can be trusted*. You have that argument under time pressure, in front of the one audience that will not accept "our internal controls" as an answer.

## What Aegis does

| | |
|---|---|
| **Commits before it answers** | For an admitted non-streaming call the record is written, flushed and `fsync`-ed **before the response is observable**. Not queued. Not probably-durable. (`CLM-043`) |
| **Chains and signs every record** | Hash-linked append-only log; tampering detected on read. |
| **Issues a portable proof** | A third party verifies one disclosed record against a root they obtained independently — **without trusting the gateway, the vendor, or you**. (`CLM-005`, `CLM-044`) |
| **Holds nothing** | Self-hosted. No SaaS, no telemetry, no vendor access. Your evidence, your keys, your data. |
| **Fails closed** | No signer, no durable storage, no limiter → no service. A broken chain refuses governed traffic at ingress rather than serving unevidenced calls. (`CLM-002`) |

## The proof, in 60 seconds

Don't take the claim. Run it:

```python
pip install aegis-latent-sdk

from aegis_sdk.proof import InclusionProof, verify_inclusion_hash
proof = InclusionProof.from_mapping(record["mmr_proof"])
verify_inclusion_hash(record["mmr_leaf_hash"], proof, trusted_root)   # -> True
```

Twelve lines, two languages, **no call to us** — alter one byte of the record and it returns `False`. Supply a root we gave you and it is circular; that condition is stated every time the capability is. Worked transcript, including the two cases that must fail: [Prove It Yourself](../../PROVE_IT.md).

## What it is not

**No SOC 2, ISO 27001, HIPAA attestation or FedRAMP — none in progress.** No independent penetration test. No SLA. Tampering is detected, not prevented; an operator with root can alter records. The WAF is bounded detection, not an injection boundary. Single maintainer; bus factor of one.

Full list: [Unsupported Claims](../../institutional/UNSUPPORTED_CLAIMS.md), 42 rows. Ask any other vendor for theirs.

## Commercial status

| | |
|---|---|
| Core | **Free**, AGPLv3, complete. No feature is withheld by a runtime check |
| Commercial licence | `[FRAMEWORK-ONLY]` — supersedes AGPLv3 §13 for a covered deployment. **The template is not yet drafted** (`CR-04`) |
| Pricing | `[HYPOTHESIS-UNVALIDATED]` — published so a conversation can start, not validated by any executed contract. [Pricing Guide](../ENTERPRISE_PRICING_GUIDE.md) |
| Support | Community best-effort, no SLA. Commercial terms per agreement (`[FRAMEWORK-ONLY]`) |

## Next step

A paid pilot against your real ingress, storage and retention boundaries — including the failure tests, which is where an evidence product is actually judged. [Pilot Proposal](PILOT_PROPOSAL.md).

---

**Related:** [Positioning](../POSITIONING.md) · [Objection Handling](OBJECTION_HANDLING.md) · [Claims Matrix](../../CLAIMS_MATRIX.md) · [README](../../../README.md)
