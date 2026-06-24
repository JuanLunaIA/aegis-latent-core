// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! BLAKE3 hashing — ~4 GB/s SIMD vs ~350 MB/s for Python hashlib.sha256.
//!
//! BLAKE3 is used for:
//!   - `request_hash` / `response_hash` in audit nodes (content binding)
//!   - `keyed_hash_blake3` as a high-speed HMAC alternative (256-bit key)
//!   - `hash_audit_payload` — canonical leaf hashing for the audit chain
//!
//! SHA-256 is retained for `node_hash` to preserve backward compatibility with
//! existing WAL records and the Python `verify_integrity` path.

use pyo3::{prelude::*, types::PyBytes};
use sha2::{Digest, Sha256};

/// BLAKE3 hash of arbitrary bytes. Returns lowercase hex string.
#[pyfunction]
pub fn hash_blake3(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// BLAKE3 keyed hash (32-byte key required).
/// Semantically equivalent to HMAC but faster and simpler to use.
#[pyfunction]
pub fn keyed_hash_blake3(key: &[u8], data: &[u8]) -> PyResult<String> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "keyed_hash_blake3 requires exactly 32 bytes for key",
        )
    })?;
    Ok(blake3::keyed_hash(&key_arr, data).to_hex().to_string())
}

/// BLAKE3 keyed hash returning raw bytes (avoids hex encode overhead).
#[pyfunction]
pub fn keyed_hash_blake3_bytes<'py>(
    py: Python<'py>,
    key: &[u8],
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key_arr: [u8; 32] = key.try_into().map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "keyed_hash_blake3 requires exactly 32 bytes for key",
        )
    })?;
    let hash = blake3::keyed_hash(&key_arr, data);
    Ok(PyBytes::new(py, hash.as_bytes()))
}

/// Canonical audit-payload hash: BLAKE3 over null-separated chain fields.
///
/// Field order: prev_hash || state_id || timestamp || merkle_root ||
///              request_hash || response_hash
///
/// The null separator prevents length-extension attacks on the concatenation.
#[pyfunction]
pub fn hash_audit_payload(
    prev_hash: &str,
    state_id: &str,
    timestamp: &str,
    merkle_root: &str,
    request_hash: &str,
    response_hash: &str,
) -> String {
    let mut h = blake3::Hasher::new();
    for field in &[prev_hash, state_id, timestamp, merkle_root, request_hash, response_hash] {
        h.update(field.as_bytes());
        h.update(b"\x00");
    }
    h.finalize().to_hex().to_string()
}

/// SHA-256 hash — kept for backward-compatible `node_hash` computation.
#[pyfunction]
pub fn hash_sha256_fast(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_deterministic() {
        let h1 = hash_blake3(b"hello");
        let h2 = hash_blake3(b"hello");
        assert_eq!(h1, h2);
        assert_ne!(h1, hash_blake3(b"world"));
    }

    #[test]
    fn blake3_keyed_wrong_key_len() {
        assert!(keyed_hash_blake3(b"short", b"data").is_err());
        assert!(keyed_hash_blake3(&[0u8; 32], b"data").is_ok());
    }

    #[test]
    fn audit_payload_field_order_matters() {
        let h1 = hash_audit_payload("prev", "sid", "ts", "mr", "rq", "rs");
        let h2 = hash_audit_payload("sid", "prev", "ts", "mr", "rq", "rs");
        assert_ne!(h1, h2);
    }
}
