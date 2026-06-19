---
name: pqc-audit-chain
tier: HIGH
domains: [ML-DSA, FIPS-204, Dilithium, post-quantum, MMR, batch-signing, audit-ledger]
---
## Activation
Load on: post-quantum signing, ML-DSA/Dilithium, FIPS 204, audit ledger signature design,
batch-signing architecture, MMR signature integrity, quantum-resistant audit chain.

## Honest Guarantee Statement (read first)
```
[ESTABLISHED] Batch-signing over MMR peaks and per-node individual signatures are
MUTUALLY EXCLUSIVE guarantees. Choose explicitly:

  Per-node signing:     every node has its own signature. Tamper-evident per node.
                        Cost: 1 sign op per request. ML-DSA-65 sign ~ 100-300µs on AVX2 CPU.
                        At 16M RPS this is infeasible on commodity CPU (sign throughput bound).

  Batch peak signing:   sign the MMR root/peaks periodically (e.g. every N nodes or T ms).
                        Individual nodes get an INCLUSION PROOF against a signed peak, NOT
                        their own signature. Tamper-evidence = "node X was included under
                        signed root R at time T", verified via Merkle proof + one signature check.
                        Cost: amortized. 1 sign per batch. Latency: node commit is O(log n) hash
                        + enqueue; signature lands asynchronously.

DO NOT claim both. The README/docs must state which guarantee Aegis provides.
Recommended for scale: batch peak signing + inclusion proofs. State it honestly.
```

## ML-DSA (FIPS 204) Parameter Selection
```
[ESTABLISHED] FIPS 204 (Aug 2024) standardizes ML-DSA (derived from CRYSTALS-Dilithium).
ML-DSA-44:  NIST level 2  | pubkey 1312B  sig 2420B  | fastest
ML-DSA-65:  NIST level 3  | pubkey 1952B  sig 3309B  | recommended default
ML-DSA-87:  NIST level 5  | pubkey 2592B  sig 4627B  | highest assurance

X→Y because Z: choose ML-DSA-65 → balances assurance vs artifact size because
level-3 maps to "192-bit classical / quantum-resistant" which exceeds typical compliance
requirements while keeping signature at 3.3KB (storage cost matters at billions of nodes).

Stateful vs stateless: ML-DSA is STATELESS (unlike LMS/XMSS). No key-state management,
no one-time-signature exhaustion risk. X→Y because Z: stateless → safe for concurrent
multi-threaded signing because there is no shared mutable key counter to corrupt.
```

## Batch-Signing Architecture (lock-free claim corrected)
```
[ANALYSIS] "LMAX Disruptor lock-free ring buffer" is a real pattern, but "lock-free" is
not magic — it's a single-producer or multi-producer ring with CAS on sequence counters.
The honest design:

  1. Request path (hot): compute leaf = H(req_hash || resp_hash || ts). O(1). Enqueue to ring.
     This is the ONLY synchronous crypto cost on the user path. SHA-256 of ~64B ≈ sub-µs.
  2. Append path (off-path worker): drain ring, MMR.add_leaf in sequence (single consumer
     preserves order → no chain fork by construction). Periodically snapshot peaks.
  3. Sign path (off-path, batched): every N leaves OR every T ms, sign the current MMR root
     with ML-DSA-65. Persist {root, signature, leaf_range, ts}.
  4. Proof path (on-demand): for any node, generate inclusion proof against the nearest
     signed root. Verification = Merkle path check + 1 ML-DSA verify.

X→Y because Z: single-consumer append → no concurrent chain fork because order is
serialized by the ring's consumer, eliminating the get_latest/write race entirely (this
is structurally stronger than a lock around read-modify-write).
```

## Rust Implementation Blueprint (PyO3, real)
```rust
// Cargo.toml deps:
//   pqcrypto-mldsa = "0.1"   (or fips204 = "0.4" for pure-Rust FIPS 204)
//   pyo3 = { version = "0.22", features = ["extension-module"] }
use fips204::ml_dsa_65;
use fips204::traits::{Signer, Verifier, SerDes};
use pyo3::prelude::*;

#[pyclass]
pub struct BatchSigner {
    sk: ml_dsa_65::PrivateKey,
    pk_bytes: Vec<u8>,
}

#[pymethods]
impl BatchSigner {
    #[new]
    fn new() -> PyResult<Self> {
        // {P}: CSPRNG available. {Q}: returns signer with fresh keypair.
        let (pk, sk) = ml_dsa_65::try_keygen()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("keygen: {e}")))?;
        Ok(Self { sk, pk_bytes: pk.into_bytes().to_vec() })
    }

    /// Sign an MMR root (32 bytes). Called off the request hot path, batched.
    /// {P}: root.len() == 32. {Q}: returns 3309-byte ML-DSA-65 signature.
    fn sign_root(&self, py: Python<'_>, root: &[u8]) -> PyResult<Py<pyo3::types::PyBytes>> {
        if root.len() != 32 {
            return Err(pyo3::exceptions::PyValueError::new_err("root must be 32 bytes"));
        }
        // empty context string; deterministic=false for hedged signing
        let sig = self.sk.try_sign(root, &[], false)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("sign: {e}")))?;
        Ok(pyo3::types::PyBytes::new_bound(py, &sig).into())
    }

    fn public_key(&self, py: Python<'_>) -> Py<pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new_bound(py, &self.pk_bytes).into()
    }
}

#[pyfunction]
fn verify_root(pk_bytes: &[u8], root: &[u8], sig: &[u8]) -> PyResult<bool> {
    // {P}: pk_bytes is valid ML-DSA-65 pubkey. {Q}: true iff sig valid over root.
    let pk = ml_dsa_65::PublicKey::try_from_bytes(
        pk_bytes.try_into().map_err(|_| pyo3::exceptions::PyValueError::new_err("bad pk len"))?
    ).map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("pk parse: {e}")))?;
    let sig_arr: [u8; 3309] = sig.try_into()
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("bad sig len"))?;
    Ok(pk.verify(root, &sig_arr, &[]))
}
```

## SIMD Reality Check
```
[INFERENCE] AVX-512 / ARM SVE2 vectorized ML-DSA paths are real optimizations BUT:
  - AVX-512 absent on: all Haswell, many consumer Ice Lake/Alder Lake (fused off), pre-Zen4 AMD
  - SVE2 requires ARMv9 (Neoverse V2/N2, Graviton4) — not ubiquitous
RULE: ship a portable scalar/AVX2 baseline that runs everywhere; gate SIMD behind runtime
CPU feature detection (is_x86_feature_detected!("avx512f")). Never assume AVX-512 at compile time.
The fips204 crate's performance is adequate without hand-vectorization for batch (off-path) signing.
```

## Edge-Case Matrix & Recovery
| Scenario | Detection Signature | Recovery Protocol |
|---|---|---|
| MMR root hash collision | Two distinct leaf sets produce same root | [ESTABLISHED] SHA-256 collision is infeasible; if observed → assume code bug in serialization (domain separation missing), not crypto break. Add length-prefix domain separation to leaf encoding; rebuild from leaves. |
| ML-DSA verify failure on persisted node | `verify_root` returns false for stored {root,sig} | Quarantine the batch; check key rotation (was a different key used?); verify pubkey provenance; flag chain segment as unverified, do NOT silently drop. |
| Sign worker falls behind (ring saturation) | Ring buffer occupancy > high-watermark; commit lag metric rising | Apply backpressure: signal append path to slow OR shed to overflow disk queue. Never drop leaves silently (audit completeness). Alert. Increase batch frequency or add signer thread. |
| Key compromise / rotation | Operational decision or HSM signal | Sign a "rotation marker" node with old key, begin new chain segment with new key, publish both pubkeys; verification spans segments by key epoch. Document key epoch in each node. |
| Power loss mid-batch (signed root not persisted) | On restart: leaves exist past last signed root | Re-sign from last signed root over the un-signed leaf range; leaves are recoverable (they're in the LSM log), only the signature was pending. Idempotent re-sign. |
