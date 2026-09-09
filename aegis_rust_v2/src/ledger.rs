// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Cryptographic primitives: SHA-256, HMAC-SHA256, BLAKE3.
//!
//! `hash_sha256` and `hmac_sign` are retained for backward compatibility with
//! existing Python `CryptographicAuditLedger.node_hash` computation.
//! `blake3_hash` is the accelerated replacement for content-binding hashes
//! (request_hash, response_hash) — ~10× faster than SHA-256 on modern CPUs.

// `KeyInit` carries `new_from_slice` in the 0.11 digest line; in 0.12 `Mac`
// re-exported it. Importing both keeps the call below reading the same way.
use hmac::{Hmac, KeyInit, Mac};
use pyo3::prelude::*;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 of `data`, returned as lowercase hex.
#[pyfunction]
pub fn hash_sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// HMAC-SHA256 of `message` keyed by `key`. Returns raw bytes.
#[pyfunction]
pub fn hmac_sign(key: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// BLAKE3 of `data`, returned as lowercase hex.
/// ~4 GB/s SIMD throughput vs ~350 MB/s for SHA-256.
#[pyfunction]
pub fn blake3_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// BLAKE3 keyed hash for HMAC-equivalent signing (32-byte key required).
#[pyfunction]
pub fn blake3_keyed_hash(key: &[u8], data: &[u8]) -> PyResult<String> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "blake3_keyed_hash requires exactly 32 bytes for key",
        )
    })?;
    Ok(blake3::keyed_hash(&key_arr, data).to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 against the FIPS 180-4 published vectors, in full.
    ///
    /// These are the regression gate for a digest-stack upgrade. Every node
    /// hash, chain link and MMR root on the evidence path is built from this
    /// function, so a change in its output silently invalidates every
    /// signature and proof ever issued — including archived ones, which
    /// cannot be re-signed. Comparing full digests rather than a prefix is
    /// the point: a truncated compare passes on a stack that is subtly wrong.
    #[test]
    fn sha256_matches_the_fips_180_4_vectors() {
        assert_eq!(
            hash_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hash_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // The 56-byte case straddles a block boundary, which is where a
        // buffering defect shows up and a one-block input does not.
        assert_eq!(
            hash_sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// HMAC-SHA-256 against the RFC 4231 published vectors.
    ///
    /// The previous version of this test compared `hmac_sign` with itself,
    /// which holds for any deterministic function including a wrong one.
    /// These are external vectors, so they pin the actual construction.
    #[test]
    fn hmac_matches_the_rfc_4231_vectors() {
        // Case 1: 20-byte key, short data.
        assert_eq!(
            hex::encode(hmac_sign(&[0x0b; 20], b"Hi There").unwrap()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Case 2: key shorter than the block size.
        assert_eq!(
            hex::encode(hmac_sign(b"Jefe", b"what do ya want for nothing?").unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Case 3: data longer than one block, exercising the buffer refill.
        assert_eq!(
            hex::encode(hmac_sign(&[0xaa; 20], &[0xdd; 50]).unwrap()),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    /// A caught panic must not leave a digest buffer able to produce a wrong
    /// answer. `hash_sha256` owns its hasher for the length of one call, so
    /// there is no cursor to corrupt across calls; this asserts that
    /// invariant holds rather than assuming it, by unwinding through the FFI
    /// boundary and then re-checking a known vector.
    #[test]
    fn a_caught_panic_leaves_hashing_correct() {
        let unwound = std::panic::catch_unwind(|| {
            let _ = hash_sha256(b"abc");
            panic!("deliberate unwind between digest calls");
        });
        assert!(unwound.is_err(), "the panic must actually have been caught");
        assert_eq!(
            hash_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(hmac_sign(b"Jefe", b"what do ya want for nothing?").unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn blake3_faster_path_deterministic() {
        let h1 = blake3_hash(b"aegis");
        let h2 = blake3_hash(b"aegis");
        assert_eq!(h1, h2);
        assert_ne!(h1, blake3_hash(b"AEGIS"));
    }
}
