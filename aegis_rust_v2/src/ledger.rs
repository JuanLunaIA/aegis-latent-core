// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Cryptographic primitives: SHA-256, HMAC-SHA256, BLAKE3.
//!
//! `hash_sha256` and `hmac_sign` are retained for backward compatibility with
//! existing Python `CryptographicAuditLedger.node_hash` computation.
//! `blake3_hash` is the accelerated replacement for content-binding hashes
//! (request_hash, response_hash) — ~10× faster than SHA-256 on modern CPUs.

use hmac::{Hmac, Mac};
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

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c14...
        let h = hash_sha256(b"");
        assert!(h.starts_with("e3b0c4"));
    }

    #[test]
    fn hmac_deterministic() {
        let sig = hmac_sign(b"key", b"msg").unwrap();
        assert_eq!(sig.len(), 32);
        assert_eq!(sig, hmac_sign(b"key", b"msg").unwrap());
    }

    #[test]
    fn blake3_faster_path_deterministic() {
        let h1 = blake3_hash(b"aegis");
        let h2 = blake3_hash(b"aegis");
        assert_eq!(h1, h2);
        assert_ne!(h1, blake3_hash(b"AEGIS"));
    }
}
