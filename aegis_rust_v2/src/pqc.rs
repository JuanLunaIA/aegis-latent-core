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
        let sk = mldsa65::SecretKey::from_bytes(&self.private_key).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid secret key: {e}"))
        })?;
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
    mldsa65::PublicKey::from_bytes(public_key).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid public key: {e}"))
    })?;
    mldsa65::SecretKey::from_bytes(private_key).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid secret key: {e}"))
    })?;
    Ok(PqcKeypair {
        public_key: public_key.to_vec(),
        private_key: private_key.to_vec(),
    })
}

/// Verify a detached ML-DSA-65 signature.
///
/// # Constant-time status: NOT ESTABLISHED — claim blocked
///
/// The retained timing experiment for `verify` reports `p = 0.0` with a mean
/// class difference of about 540 ns over 1,000,000 interleaved samples
/// (`docs/benchmarks/BENCHMARK_RESULTS.md`). No constant-time claim may be made
/// for this function, and `docs/security/PQC_CONSTANT_TIME.md` records the block.
///
/// ## Why this is not fixed by hoisting the decode step
///
/// A natural remedy is to split parsing out of verification and expose a
/// `verify_preparsed` taking already-decoded key and signature objects, on the
/// theory that `from_bytes` contributes the variable-time component. Measurement
/// on 2026-09-03 (CPython 3.11.15, 4 shared logical CPUs, medians over 800
/// samples after warm-up) does not support that theory:
///
/// | Quantity | Median |
/// |---|---|
/// | `keypair_from_bytes` — an upper bound on the public-key decode, since it also parses the secret key and copies both | 4.10 us |
/// | `verify_pqc_signature`, valid signature | 73.06 us |
/// | `verify_pqc_signature`, tampered signature | 75.08 us |
///
/// Decoding is about 5.6% of the call, and the valid-versus-tampered difference
/// — 2.02 us — is *larger* than the whole decode step. Hoisting the decode could
/// therefore remove at most a small constant and would leave the class-dependent
/// component untouched: it lives in the algebraic verification, which returns as
/// soon as a bound check fails rather than running to completion on every input.
///
/// Adding `verify_preparsed` here would move measurable cost without addressing
/// the measured effect, while introducing an API whose name implies a property
/// this code does not have. That is worse than leaving the shape as it is, so it
/// is deliberately not added. Closing the gap requires a verifier that does not
/// exit early — an upstream change in `pqcrypto-mldsa` or a different
/// implementation — not a refactor at this boundary.
///
/// ## Operational requirement
///
/// Callers MUST cache decoded public keys in memory rather than deserializing
/// one per request. That is a throughput requirement (it removes ~5.6% of the
/// call), not a mitigation: it does not narrow the timing difference above, and
/// it must not be described as one.
#[pyfunction]
pub fn verify_pqc_signature(data: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> {
    let pk = mldsa65::PublicKey::from_bytes(public_key).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid public key: {e}"))
    })?;
    let sig = mldsa65::DetachedSignature::from_bytes(signature).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid signature: {e}"))
    })?;
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
