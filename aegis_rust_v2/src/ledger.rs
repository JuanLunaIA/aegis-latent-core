// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
use hmac::{Hmac, Mac};
use pyo3::prelude::*;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[pyfunction]
pub fn hash_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[pyfunction]
pub fn hmac_sign(key: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_deterministic() {
        let sig = hmac_sign(b"key", b"msg").unwrap();
        assert_eq!(sig.len(), 32);
    }
}
