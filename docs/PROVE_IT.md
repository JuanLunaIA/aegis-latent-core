<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Prove It Yourself

**Audience:** the sceptical evaluator. Someone who has read a claim about tamper-evident AI evidence and wants to falsify it.
**Scope:** verifying that one disclosed evidence record is included under a Merkle root you obtained independently — without trusting the gateway, the vendor, or the organisation that handed you the record.
**Boundary:** a successful verification establishes **inclusion under the root you supplied**, and nothing else. §5 states exactly what it does not establish. Every command below was executed on 2026-09-16 against this source tree; the outputs are transcribed, not predicted.

---

## 1. Why this page exists instead of an adjective

Every vendor in this category will tell you their logs are secure. The question that separates them is: **can someone who distrusts you check a record without your cooperation?**

If the answer requires a vendor API, a vendor dashboard, or a vendor attestation, then the vendor is still in the trust path and the record is only as good as the vendor's word. That is the same defect as the mutable database row it replaced, wearing better clothes.

So: here is the mechanism, the code, and three cases — one that must pass and two that must fail.

## 2. Setup

```bash
pip install aegis-latent-sdk
```

That is the only install the verifier needs. The proof logic is `aegis_sdk/proof.py` — 313 lines of pure Python with no network calls — and a TypeScript implementation exists with the same semantics (`npm install aegis-latent-sdk`). Read it before you run it; it is short enough to read in one sitting, which is the point.

## 3. The verifier

Save as `prove_it.py`:

```python
"""Verify an Aegis evidence record without trusting the gateway that made it."""
import json, sys
from aegis_sdk.proof import InclusionProof, verify_inclusion_hash

record = json.load(open(sys.argv[1]))          # the disclosed record
trusted_root = sys.argv[2]                     # obtained INDEPENDENTLY

proof = InclusionProof.from_mapping(record["mmr_proof"])
ok = verify_inclusion_hash(record["mmr_leaf_hash"], proof, trusted_root)

print(f"leaf {proof.leaf_index} of {proof.leaf_count}  scheme={proof.version}")
print("INCLUDED" if ok else "NOT INCLUDED")
sys.exit(0 if ok else 1)
```

Twelve lines. No vendor endpoint appears in it, because none is needed.

## 4. The three cases

### 4.1 A genuine record against the root it belongs to — must pass

```console
$ python prove_it.py record.json faf613f93d2dd4226740359ff3b24863c2f882f49789e377a4d9756991e92cf5
leaf 2 of 3  scheme=aegis-mmr-inclusion-v2
INCLUDED
$ echo $?
0
```

### 4.2 One altered byte in the record — must fail

The record's `mmr_leaf_hash` is changed and nothing else; the proof and the root are untouched.

```console
$ python prove_it.py record_tampered.json faf613f93d2dd4226740359ff3b24863c2f882f49789e377a4d9756991e92cf5
leaf 2 of 3  scheme=aegis-mmr-inclusion-v2
NOT INCLUDED
$ echo $?
1
```

This is the case that matters. Whoever holds the record cannot alter it and still produce a proof that verifies, because the proof commits to the leaf digest and the root commits to the proof.

### 4.3 A genuine record against a root you did not obtain — must fail

```console
$ python prove_it.py record.json 0000000000000000000000000000000000000000000000000000000000000000
leaf 2 of 3  scheme=aegis-mmr-inclusion-v2
NOT INCLUDED
$ echo $?
1
```

**This third case is the one to understand before relying on any of it.** The root is the trust anchor. If you accept a root from the same party that handed you the proof, you have verified that they are internally consistent with themselves — which any competent forger also is (`CLM-044`).

A root has to reach you by a path the discloser does not control: published on a schedule, countersigned by a counterparty, anchored to a timestamp authority, or held by you since before the dispute arose. **Getting that right is the buyer's design problem, and no software can solve it for you.** Any vendor who tells you otherwise has not understood the primitive they are selling.

### 4.4 Reading `leaf 2 of 3`

The proof was generated at commit time, so it commits to the chain as it stood at that moment — three leaves — even though the chain later grew. Proofs are contemporaneous with their record. That is a property, not a staleness bug: it is what lets you verify a two-year-old record against a two-year-old published root.

## 5. What a passing verification does **not** establish

Read this before quoting the result anywhere.

| It does not establish | Because |
|---|---|
| That the AI response was correct, safe, or appropriate | The record commits to what was sent and returned, not to its quality |
| That the request passed a security boundary | The WAF is bounded pattern detection, not an injection boundary (`UC-042`) |
| **Who** produced the record | With the default HMAC-SHA256 chain, any key holder can forge. It authenticates the key, not a party (`UC-041`, `CLM-090`). Attribution needs the HSM or PQC path |
| That the timestamp is accurate | It is the issuer's unattested clock unless an RFC 3161 token is attached |
| That the record is complete or that none were omitted | An inclusion proof proves inclusion. It says nothing about what is absent — there is no non-membership proof |
| That the record is admissible | Admissibility is a judicial determination involving custody and procedure this software does not create (`UC-022`, `UC-034`) |
| That the operator could not have deleted records | Tampering is **detected, not prevented**. An operator with filesystem access can destroy the chain; you would detect the break, not prevent it |

The last row deserves its bluntness. This mechanism converts *silent alteration* into *detected alteration*. That is a large and useful change, and it is not immutability.

## 6. Verify the rest of the claim surface too

The same invitation extends past the proof:

| Check | Command |
|---|---|
| The test suite is what we say | `pytest -n auto -q` |
| Every public claim has a locator | Read [Claims Matrix](CLAIMS_MATRIX.md); pick three rows at random and follow them to the code |
| What we refuse to claim | Read [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md) — 42 rows |
| The prose gate rejects overclaiming | `python tools/docs/verify_documentation.py --root . --strict` |
| The claims register is internally consistent | `python scripts/verify_claims.py --root .` |
| What was published, and what was not | [Release Status](RELEASE_STATUS.md) — each surface read back separately, with the gaps named |

Spot-checking three Claims Matrix rows takes about ten minutes and tells you more about a vendor than any questionnaire response.

---

**Related:** [MMR Proof v1](api/MMR_PROOF_V1.md) · [Claims Matrix](CLAIMS_MATRIX.md) · [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md) · [Positioning](commercial/POSITIONING.md) · [Developer SDK Guide](DEVELOPER_SDK_GUIDE.md)
