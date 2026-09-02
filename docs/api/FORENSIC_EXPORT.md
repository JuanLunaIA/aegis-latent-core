# Forensic Export

**Audience:** developers, investigators, auditors receiving an exported bundle.
**Scope:** what `POST /v1/audit/forensics/export` produces, how to check it, and the precise limits of what a checked bundle establishes.
**Boundary:** a forensic bundle is a bounded extract from one gateway's retained window. It is not authenticated, not complete, and not a custody record. The included checker has a specific and important blind spot, described in §4.

---

## 1. Producing a bundle

```bash
curl -X POST \
  -H "Authorization: Bearer $AUDIT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "acme", "limit": 500}' \
  --output bundle.zip \
  localhost:8080/v1/audit/forensics/export
```

Requires the `audit:export` scope, which is separate from `audit:read` because export is a bulk sensitive-data operation and should be granted separately.

**The request must be bounded.** Empty or unbounded requests are rejected. This is deliberate: an unbounded export is a data-exfiltration primitive.

**Export is time-sensitive.** It covers records the supplying process still retains. Once the bounded in-memory deque rolls over, those records are no longer exportable through this path. For an incident, export early — see [Incident Response](../security/INCIDENT_RESPONSE.md).

## 2. Bundle contents

| Entry | What it is |
| --- | --- |
| `manifest.json` | Contract-defined manifest: what was exported, the bounds requested, and per-file digests |
| Record files | The retained evidence records inside the requested bounds |
| Portable proofs | `aegis-mmr-inclusion-v1` proofs, where available for the exported records |
| Technical PDF | Human-readable summary of the extract |
| `VERIFY.sh` | Offline checker for the embedded file digests |

Source: `aegis/core/forensic_bundle.py`, `aegis/proxy/audit_api.py`. Tests: `tests/test_forensic_bundle.py`, `tests/test_audit_api_new.py::test_forensic_export_returns_verifiable_zip`.

Not every record has a proof. Records predating portable-proof support have none, and a stream that never reached terminal commit has none. Their absence is expected and is not evidence of tampering.

## 3. Checking a bundle

```bash
unzip bundle.zip -d ./bundle
cd bundle
bash VERIFY.sh
```

`VERIFY.sh` recomputes each file's digest and compares it against the digest literals embedded in the bundle.

**Then verify the proofs separately, against a root you obtained independently:**

```python
from aegis_sdk.proof import verify_inclusion_proof
import json

proof = json.load(open("proofs/<state_id>.json"))
ok = verify_inclusion_proof(proof, trusted_root="<root from an independent channel>")
print("inclusion verified:", ok)
```

Do not use a root taken from the bundle itself. See §4.

## 4. What `VERIFY.sh` does not detect

This is the most important section in the document.

`VERIFY.sh` compares file bytes against digest literals **embedded in the same unauthenticated archive**. An actor who can modify a record file can also modify the digest literal that describes it, and the script will report success.

```
┌──────────────── bundle.zip (unauthenticated) ─────────────────┐
│                                                                │
│   record.json  ◄──── digest compared ────►  VERIFY.sh          │
│        ▲                                        ▲              │
│        └────────── both modifiable by the same actor ──────────┘
└────────────────────────────────────────────────────────────────┘
```

So a passing `VERIFY.sh` establishes exactly one thing: **the bundle is internally self-consistent and has not been damaged in transit.** It does not establish that the bundle reflects what the gateway recorded.

Co-tampering the file and the script is outside its detection boundary. Detecting that requires the MMR proofs checked against an independently obtained root, which is a separate step the script does not perform.

## 5. What a fully checked bundle establishes

Assume `VERIFY.sh` passes **and** every proof verifies against an independently trusted root. You then have:

| Established | Not established |
| --- | --- |
| These records were included under that root | That the root is authoritative, unless you obtained it independently |
| The bundle is internally consistent | That the bundle is complete |
| The records are unaltered relative to their digests | That an operator did not alter the WAL before export |
| The extract came from a gateway holding those records | Who caused the records to exist |
| — | When the events occurred, absent external anchoring |
| — | Chain of custody after export |
| — | Legal admissibility |

**Completeness is the limit most often overstated.** A bundle contains records inside the requested bounds that the process still retained. Absence of a record is not evidence it never existed.

## 6. Handling an exported bundle

A bundle contains governed request and response content, subject to whatever redaction was configured when the records were written. Redaction is best-effort pattern matching; see [PII Redaction Boundaries](../privacy/PII_REDACTION_BOUNDARIES.md).

Treat a bundle as sensitive evidence:

- Store it under the access controls that apply to the data it contains.
- Record who produced it, when, from which gateway, and with what bounds. That record is the start of a custody chain; the bundle does not carry one. See [ISO/IEC 27037 Technical Inputs](../compliance/ISO_27037_TECHNICAL_INPUTS.md).
- Digest it on receipt and record the digest separately from the bundle.
- Do not email it, and do not attach it to a public issue.

## 7. Practical guidance

**For an incident:** export early, before the retained window rolls over. Record the request bounds you used, because a later export with different bounds is a different extract.

**For an audit:** the auditor should obtain the trusted root through a channel that does not pass through the gateway under audit. Anything else is the system attesting to itself.

**For a legal process:** the bundle is technical integrity evidence. Admissibility, weight, and sufficiency are determinations made by a court applying its own rules. This repository makes no such determination and nothing in a bundle constitutes one.

---

**Related:** [Audit Endpoints](AUDIT_ENDPOINTS.md) · [MMR Proof v1](MMR_PROOF_V1.md) · [Incident Response](../security/INCIDENT_RESPONSE.md) · [PII Redaction Boundaries](../privacy/PII_REDACTION_BOUNDARIES.md) · [ISO/IEC 27037 Technical Inputs](../compliance/ISO_27037_TECHNICAL_INPUTS.md) · [Boundaries](../BOUNDARIES.md)
