# Portable MMR Inclusion Proof v1

**Release baseline:** four-layer truth model
**Format identifier:** `aegis-mmr-inclusion-v1`
**Status:** implemented in the checked-out `v4.0.2` source baseline and covered by cross-language golden vectors
**Last reviewed:** 2026-08-27 UTC
**Source baseline:** checked-out source metadata is synchronized at `v4.0.2`
**External lifecycle boundary:** source metadata does not prove a tag, GitHub Release, registry package, OCI image, deployment, or acceptance; verify each surface by external readback
**Historical distribution boundary:** this format was not included in the `v3.1.0` distribution

## Purpose and claim boundary

A portable inclusion proof allows an independent verifier to determine whether a disclosed SHA-256 leaf digest belongs to the Merkle Mountain Range root named by the proof. The verifier does not need the gateway's in-memory MMR state. A successful verification establishes only this bounded cryptographic relationship. It does not establish the truth of the source event, wall-clock timestamp accuracy, external publication, retention, signer authorization, regulatory conformity, or legal admissibility.

## Hash construction

All digest strings are lowercase, 64-character hexadecimal SHA-256 values. Let `H(x)` be SHA-256 and let `hex(d)` be the lowercase hexadecimal representation of digest bytes.

A raw leaf is hashed as `hex(H(leaf_bytes))`. Internal nodes are computed as `hex(H(ASCII(left_hex || right_hex)))`. Current peaks are ordered by descending mountain height. The displayed root is `hex(H(ASCII(peak_0_hex || ... || peak_n_hex)))`.

The HTTP interface discloses the leaf digest, not the canonical leaf bytes. This avoids disclosing request or response preview material. SDK verifiers therefore begin from the trusted/disclosed leaf digest. Applications that possess canonical leaf bytes may hash those bytes first and use the equivalent raw-leaf verifier.

## JSON schema

| Field | Type | Constraint |
|---|---|---|
| `version` | string | Exactly `aegis-mmr-inclusion-v1` |
| `algorithm` | string | Exactly `sha256-asciihex` |
| `leaf_index` | integer | `0 <= leaf_index < leaf_count` |
| `leaf_count` | integer | At least 1 |
| `path` | array | Ordered from leaf level to containing peak; each item has `sibling_hash` and direction `L` or `R` |
| `peak_index` | integer | Index of the containing peak in the ordered `peaks` array |
| `peaks` | array | Every item has lowercase SHA-256 `hash` and integer `height`; heights equal the set bits of `leaf_count` in descending order |
| `root` | string | Lowercase SHA-256 root and equal to the independently supplied trusted root |

The verifier rejects unknown fields in the Python and TypeScript SDK parsers. It validates mountain boundaries, exact path length, sibling direction at every level, peak heights/order, containing peak, and the final bagged root. It does not accept partial proofs or silently substitute server state.

## HTTP transport

A durable non-streaming response exposes:

| Header | Value |
|---|---|
| `X-Aegis-MMR-Format` | `aegis-mmr-inclusion-v1` |
| `X-Aegis-MMR-Leaf` | Lowercase SHA-256 leaf digest |
| `X-Aegis-MMR-Leaf-Index` | Logical zero-based leaf ordinal |
| `X-Aegis-MMR-Leaf-Count` | Leaf count at commit |
| `X-Aegis-MMR-Proof` | Unpadded base64url of compact, sorted-key proof JSON |
| `X-Aegis-MMR-Root` | MMR root at commit |
| `Link` | Authenticated proof lookup with relation `aegis-inclusion-proof` |

An SSE response cannot change its HTTP headers after streaming begins. Its initial state is `X-Aegis-Evidence-Status: pending-terminal` and `X-Aegis-Proof-Status: pending-terminal`. After the stream terminal summary has been durably committed, an authorized caller retrieves the proof at `GET /v1/audit/proofs/{request_id}`. A client must not represent an initial streaming response as durably proven before that lookup succeeds.

## Persistence and replay

New WAL nodes persist the leaf digest, logical index/count, root, and portable proof. On startup, the ledger reconstructs the current portable MMR suffix from persisted leaf digests and rejects a replayed root mismatch. Legacy nodes that predate the portable fields remain readable, but the proof endpoint returns a conflict for them rather than fabricating a proof.

The integrity sweep parses and independently verifies every persisted portable proof. A malformed or altered leaf, index, count, sibling, peak, order, or root makes the sweep fail at that node. This is in addition to chain-link and configured signature checks.

## Golden vectors and falsification

The deterministic generator `scripts/generate_mmr_vectors.py` produces `sdk/shared/mmr-v1-vectors.json`. It covers MMR sizes that cross merge and multi-peak boundaries. Python core, Python SDK, and TypeScript SDK tests consume the same vectors and reject altered leaves, paths, directions, peaks, roots, indexes, and counts.

The hypothesis under test is:

> **H1:** For every valid generated leaf ordinal, all three verifiers accept the same proof/root pair; for any tested single-field integrity mutation, they reject it.

The falsifier is any valid vector rejected by one implementation, any mutated vector accepted by one implementation, or any post-WAL-replay root/count that differs from uninterrupted execution. Passing the bounded suite does not prove SHA-256 collision resistance or universal implementation correctness.

## Related documents

- [`../../sdk/python/README.md`](../../sdk/python/README.md)
- [`../../sdk/typescript/README.md`](../../sdk/typescript/README.md)
- [`../formal/FORMAL_VERIFICATION.md`](../formal/FORMAL_VERIFICATION.md)
- [`../CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
