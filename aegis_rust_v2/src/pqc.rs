// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroize;

/// Keypair exposed to Python with sign() and raw key bytes.
#[pyclass]
pub struct PqcKeypair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[pymethods]
impl PqcKeypair {
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.public_key)
    }

    #[getter]
    fn private_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.private_key)
    }

    fn sign<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let sk = mldsa65::SecretKey::from_bytes(&self.private_key)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid secret key: {e}")))?;
        let sig = mldsa65::detached_sign(data, &sk);
        Ok(PyBytes::new(py, sig.as_bytes()))
    }
}

impl Drop for PqcKeypair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[pyfunction]
#[pyo3(signature = ())]
pub fn generate_pqc_keypair() -> PyResult<PqcKeypair> {
    let (pk, sk) = mldsa65::keypair();
    Ok(PqcKeypair {
        public_key: pk.as_bytes().to_vec(),
        private_key: sk.as_bytes().to_vec(),
    })
}

/// Reconstruct a keypair from previously-persisted ML-DSA-65 key bytes.
///
/// ML-DSA-65 secret keys do not embed the full public key (`t1`), so a durable
/// signing identity must persist both halves. Both inputs are validated by
/// decoding them under `mldsa65`; malformed or wrong-size bytes are rejected
/// with `ValueError` rather than silently accepted.
#[pyfunction]
pub fn keypair_from_bytes(public_key: &[u8], private_key: &[u8]) -> PyResult<PqcKeypair> {
    mldsa65::PublicKey::from_bytes(public_key)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid public key: {e}")))?;
    mldsa65::SecretKey::from_bytes(private_key)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid secret key: {e}")))?;
    Ok(PqcKeypair {
        public_key: public_key.to_vec(),
        private_key: private_key.to_vec(),
    })
}

#[pyfunction]
pub fn verify_pqc_signature(data: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> {
    let pk = mldsa65::PublicKey::from_bytes(public_key)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid public key: {e}")))?;
    let sig = mldsa65::DetachedSignature::from_bytes(signature)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid signature: {e}")))?;
    Ok(mldsa65::verify_detached_signature(&sig, data, &pk).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_verify() {
        let (pk, sk) = mldsa65::keypair();
        let msg = b"merkle-root-test";
        let sig = mldsa65::detached_sign(msg, &sk);
        assert!(mldsa65::verify_detached_signature(&sig, msg, &pk).is_ok());
        assert!(mldsa65::verify_detached_signature(&sig, b"tampered", &pk).is_err());
    }

    #[test]
    fn keypair_from_bytes_accepts_valid_keys() {
        let (pk, sk) = mldsa65::keypair();
        let kp = keypair_from_bytes(pk.as_bytes(), sk.as_bytes())
            .expect("valid ML-DSA-65 keys must reconstruct");
        assert_eq!(kp.public_key, pk.as_bytes().to_vec());
        assert_eq!(kp.private_key, sk.as_bytes().to_vec());
    }

    #[test]
    fn keypair_from_bytes_rejects_malformed_keys() {
        let (pk, sk) = mldsa65::keypair();
        assert!(keypair_from_bytes(b"short-pk", sk.as_bytes()).is_err());
        assert!(keypair_from_bytes(pk.as_bytes(), b"short-sk").is_err());
    }

    #[test]
    fn reconstructed_keypair_signs_verifiably() {
        // A persisted-then-reloaded identity must produce signatures that verify
        // against the original public key.
        let (pk, sk) = mldsa65::keypair();
        let kp = keypair_from_bytes(pk.as_bytes(), sk.as_bytes()).unwrap();
        let reloaded_sk = mldsa65::SecretKey::from_bytes(&kp.private_key).unwrap();
        let msg = b"persistent-identity";
        let sig = mldsa65::detached_sign(msg, &reloaded_sk);
        assert!(mldsa65::verify_detached_signature(&sig, msg, &pk).is_ok());
    }
}
