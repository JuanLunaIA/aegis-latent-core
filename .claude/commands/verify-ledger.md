---
description: Scan the audit ledger — MMR chain continuity + signature integrity verification.
---
# /verify-ledger

Verify the integrity of the Aegis audit ledger end-to-end. Report mechanism on any failure;
never report "OK" without having actually checked each property.

## Verification Sequence

### 1. Chain Continuity (prev_hash linkage)
Walk the chain from genesis. For each node N: assert `N.prev_hash == hash(N-1)`.
- A break (prev_hash pointing to a non-existent or wrong node) = tamper or bug.
- Report the exact node_id and ts of the first break. X→Y because Z: a broken link means the
  chain is no longer append-only-verifiable from that point because the hash linkage is the
  tamper-evidence mechanism.

### 2. Merkle Root Recomputation
For each MMR peak/root: recompute the root from the leaves in range and compare to the stored root.
- Mismatch = leaves altered after root computation, or serialization bug (check domain separation).
- Use the executor to recompute hashes — never assert a hash matches by inspection.

### 3. Signature Verification (per signed root)
For each {root, signature, sig_algo, key_epoch}:
- ML-DSA-65: verify with the pubkey for that key_epoch (FIPS 204 verify).
- HMAC-SHA256: recompute and constant-time compare.
- Failure = signature invalid for the data → quarantine that segment, do NOT silently pass.
- Honor key rotation: a segment signed under epoch K verifies against epoch-K's pubkey.

### 4. Inclusion Proofs (if batch-signing mode)
For a sample of individual nodes: generate the Merkle inclusion proof against the nearest signed
root and verify it. Confirms per-node tamper-evidence under the batch-signing guarantee.

### 5. Coverage Report
- Total nodes, signed roots, key epochs spanned.
- Nodes NOT covered by any signed root (the trailing un-signed window — expected; report size).
- Any PENDING nodes (e.g. SSE streams that never finalized) — these are integrity gaps to flag.

## Output
```
LEDGER VERIFICATION REPORT
  nodes_total:            <n>
  chain_continuity:       PASS | BREAK at node <id> ts <ts>
  merkle_roots_checked:   <n>  | mismatches: <list>
  signatures_verified:    <n>  | failures: <list with node/root + reason>
  inclusion_proofs:       <sampled n> | failures: <list>
  uncovered_trailing:     <n nodes since last signed root>
  pending_nodes:          <n>  (integrity gap if > 0)
  key_epochs:             <list>
  VERDICT:                INTACT | COMPROMISED (<which property failed>)
```
All hash/signature checks run via the executor. No property reported as passing without execution.
