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
        PyBytes::new_bound(py, &self.public_key)
    }

    #[getter]
    fn private_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.private_key)
    }

    fn sign<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let sk = mldsa65::SecretKey::from_bytes(&self.private_key)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid secret key: {e}")))?;
        let sig = mldsa65::detached_sign(data, &sk);
        Ok(PyBytes::new_bound(py, sig.as_bytes()))
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
}
