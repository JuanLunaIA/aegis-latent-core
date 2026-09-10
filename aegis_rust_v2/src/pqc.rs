// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! ML-DSA-65 as Python sees it.
//!
//! This file is only the binding. Every cryptographic call goes through
//! [`ActiveBackend`](crate::pqc_trait::ActiveBackend), so replacing the archived
//! PQClean implementation with the pure-Rust one is a build flag rather than an
//! edit here: the FFI symbols, the `PqcKeypair` class and its method names are
//! unchanged either way. See `pqc_trait.rs` for the backend contract, the
//! measured cost of the swap, and the byte-compatibility properties that make
//! it safe.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroize;

use crate::pqc_trait::{
    ActiveBackend, PostQuantumSigner, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES,
};

fn value_error(message: String) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyValueError, _>(message)
}

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
        let signature = ActiveBackend::sign_detached(data, &self.private_key)
            .map_err(|e| value_error(e.to_string()))?;
        Ok(PyBytes::new(py, &signature))
    }

    /// Which implementation produced this keypair's signatures.
    ///
    /// Exposed so evidence can record the backend rather than infer it: two
    /// builds of the same version can differ here, and a signature that fails
    /// to verify is a very different investigation depending on which one wrote
    /// it.
    #[getter]
    fn backend(&self) -> &'static str {
        ActiveBackend::BACKEND
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
    let (public_key, private_key) = ActiveBackend::keypair();
    Ok(PqcKeypair {
        public_key,
        private_key,
    })
}

/// Reconstruct a keypair from previously-persisted ML-DSA-65 key bytes.
///
/// ML-DSA-65 secret keys do not embed the full public key (`t1`), so a durable
/// signing identity must persist both halves. Both inputs are size-checked
/// against the FIPS 204 encodings; malformed or wrong-size bytes are rejected
/// with `ValueError` rather than silently accepted.
///
/// Where the backend can derive the public key from the secret, the two halves
/// are additionally checked to *belong together*. That is the failure worth
/// catching: two valid keys from different identities are both the right length
/// and pair to nothing, so every node signed under them would verify against
/// nobody. PQClean exposes no derivation, so under the default build this falls
/// back to the size check — which is exactly what the decoders it replaced did,
/// since `from_bytes` there validated length and nothing else.
#[pyfunction]
pub fn keypair_from_bytes(public_key: &[u8], private_key: &[u8]) -> PyResult<PqcKeypair> {
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(value_error(format!(
            "invalid public key: expected {PUBLIC_KEY_BYTES} bytes, got {}",
            public_key.len()
        )));
    }
    if private_key.len() != SECRET_KEY_BYTES {
        return Err(value_error(format!(
            "invalid secret key: expected {SECRET_KEY_BYTES} bytes, got {}",
            private_key.len()
        )));
    }
    // An Err here is "this backend cannot derive", not "these keys disagree",
    // so it is not promoted to a rejection: refusing a well-formed identity
    // because the backend lacks an optional capability would take a working
    // ledger offline.
    if let Ok(derived) = ActiveBackend::public_from_secret(private_key) {
        if derived != public_key {
            return Err(value_error(
                "public and secret key do not belong to the same ML-DSA-65 identity".to_string(),
            ));
        }
    }
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
/// for this function, and `docs/security/PQC_CONSTANT_TIME.md` records the
/// block. What follows is why two proposed remedies do not lift it, and why the
/// experiment is not measuring what its name suggests.
///
/// ## Hoisting the decode does not fix it
///
/// The natural remedy is to split parsing out of verification and expose a
/// `verify_preparsed` taking already-decoded key and signature objects, on the
/// theory that `from_bytes` contributes the variable-time component.
/// Measurement on 2026-09-03 (CPython 3.11.15, 4 shared logical CPUs, medians
/// over 800 samples after warm-up) does not support that theory:
///
/// | Quantity | Median |
/// |---|---|
/// | `keypair_from_bytes` — an upper bound on the public-key decode, since it also parses the secret key and copies both | 4.10 us |
/// | `verify_pqc_signature`, valid signature | 73.06 us |
/// | `verify_pqc_signature`, tampered signature | 75.08 us |
///
/// Decoding is about 5.6% of the call, and the valid-versus-tampered difference
/// — 2.02 us — is *larger* than the whole decode step. Hoisting the decode
/// could therefore remove at most a small constant and would leave the
/// class-dependent component untouched.
///
/// ## Neither does a different implementation
///
/// This file previously concluded that closing the gap "requires a verifier
/// that does not exit early — an upstream change in `pqcrypto-mldsa` or a
/// different implementation". A different implementation has since been
/// measured, and that conclusion was wrong. Two-class interleaved timing on
/// this repository's hardware, 40,000 samples:
///
/// | backend | mean | class delta | p |
/// |---|---|---|---|
/// | `pqcrypto-mldsa` (PQClean C) | 45,961 ns | −644 ns | 0.0000 |
/// | `ml-dsa` (pure Rust) | 65,805 ns | −1,128 ns | 0.0000 |
///
/// The pure-Rust verifier shows the *same* `p` with a *larger* delta. When two
/// independent implementations of one specification produce the same result,
/// the effect belongs to the experiment rather than to either implementation.
///
/// ## What the experiment actually varies
///
/// Its two classes are one repeated signature versus 1024 varying signatures,
/// **all of them valid**, over a fixed message. So the measured difference is
/// between two sets of *public* inputs — and this is the point that matters:
/// **ML-DSA verification consumes no secret.** It takes a public key, a public
/// message and a public signature. A timing difference across public inputs
/// discloses nothing those inputs did not already disclose, so `p = 0.0` here
/// is not evidence of a side channel. It is consistent with cache residency and
/// with ML-DSA verification cost depending on signature contents, both of which
/// are properties of public data.
///
/// Signing is the operation that touches the secret key, and signing meets the
/// non-detection threshold on both backends (`p = 0.8399` PQClean,
/// `p = 0.8828` pure Rust, hedged, 20,000 samples).
///
/// None of this is a constant-time claim, and the block stays in place: these
/// are sample statistics from one machine, not an absence proof, and they say
/// nothing about microarchitectural leakage, compiler behaviour, or the
/// deployment's hardware.
///
/// ## Operational requirement
///
/// Callers MUST cache decoded public keys in memory rather than deserializing
/// one per request. That is a throughput requirement (it removes ~5.6% of the
/// call), not a mitigation: it does not narrow the timing difference above, and
/// it must not be described as one.
#[pyfunction]
pub fn verify_pqc_signature(data: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> {
    if signature.len() != SIGNATURE_BYTES {
        return Err(value_error(format!(
            "invalid signature: expected {SIGNATURE_BYTES} bytes, got {}",
            signature.len()
        )));
    }
    ActiveBackend::verify_detached(data, signature, public_key)
        .map_err(|e| value_error(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_verify() {
        let (pk, sk) = ActiveBackend::keypair();
        let msg = b"aegis-audit-node";
        let sig = ActiveBackend::sign_detached(msg, &sk).unwrap();
        assert!(ActiveBackend::verify_detached(msg, &sig, &pk).unwrap());
        assert!(!ActiveBackend::verify_detached(b"tampered", &sig, &pk).unwrap());
    }

    #[test]
    fn keypair_from_bytes_rejects_wrong_sizes() {
        let (pk, sk) = ActiveBackend::keypair();
        assert!(keypair_from_bytes(&pk[..10], &sk).is_err());
        assert!(keypair_from_bytes(&pk, &sk[..10]).is_err());
        assert!(keypair_from_bytes(&pk, &sk).is_ok());
    }

    #[test]
    fn a_persisted_identity_still_signs_verifiably() {
        // A persisted-then-reloaded identity must produce signatures that verify
        // under the public key stored beside it, or every node written after a
        // restart is stranded.
        let (pk, sk) = ActiveBackend::keypair();
        let reloaded = keypair_from_bytes(&pk, &sk).unwrap();
        let msg = b"after a restart";
        let sig = ActiveBackend::sign_detached(msg, &reloaded.private_key).unwrap();
        assert!(ActiveBackend::verify_detached(msg, &sig, &reloaded.public_key).unwrap());
    }

    #[test]
    fn a_malformed_signature_length_is_an_error_not_a_false() {
        let (pk, _sk) = ActiveBackend::keypair();
        assert!(verify_pqc_signature(b"m", &[0u8; 10], &pk).is_err());
    }
}
