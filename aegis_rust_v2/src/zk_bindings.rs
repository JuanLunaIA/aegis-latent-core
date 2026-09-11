// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Python surface for the zero-knowledge inclusion proof.
//!
//! Registered unconditionally, implemented conditionally. When the crate is
//! built **without** `zk-spartan` — which is every default build, and therefore
//! every wheel this repository currently publishes — each function raises with
//! the build flag named. That is the same posture `NitroBackend` and
//! `SevSnpBackend` take (`CLM-086`): a capability that is absent should refuse
//! in a way that says why, rather than be missing and read as a packaging bug.
//!
//! `has_zk_native()` is the discovery call. Nothing here simulates a proof, and
//! there is no code path on which an absent prover returns success.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[cfg(feature = "zk-spartan")]
use crate::zk_mmr;

/// Message used by every refusal, so the remedy is stated exactly once.
#[cfg(not(feature = "zk-spartan"))]
const NOT_BUILT: &str = "zero-knowledge proving is not compiled into this build of aegis_rust. \
     Rebuild the extension with `--features zk-spartan` (see `aegis_rust_v2/Cargo.toml` \
     for what enabling it adds to the dependency graph). No proof is produced and none \
     is simulated.";

/// Whether this build can produce and check zero-knowledge proofs.
///
/// `False` in every default build. Callers must branch on this rather than
/// assuming the capability from the presence of the functions below.
#[pyfunction]
pub fn has_zk_native() -> bool {
    cfg!(feature = "zk-spartan")
}

// Only reachable on the feature path: without it every entry point refuses
// before it looks at an argument.
#[cfg(feature = "zk-spartan")]
fn to_digest(bytes: &[u8], what: &str) -> PyResult<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "{what} must be exactly 32 bytes, got {}",
            bytes.len()
        ))
    })
}

#[cfg(feature = "zk-spartan")]
fn zk_error(error: zk_mmr::ZkError) -> PyErr {
    match error {
        zk_mmr::ZkError::ShapeMismatch(_) | zk_mmr::ZkError::Decoding(_) => {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(error.to_string())
        }
        // A refusal, not a bug: the caller asked for a proof of something that
        // is not true, or offered a proof of something else.
        zk_mmr::ZkError::Proving(_) | zk_mmr::ZkError::RootMismatch => {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(error.to_string())
        }
    }
}

/// Derive the verifier key for a proof shape.
///
/// A verifier calls this themselves. Accepting a key from whoever supplied the
/// proof establishes nothing — it is the prover's own claim about what is being
/// proved, exactly as a root supplied by the prover is.
#[pyfunction]
#[allow(unused_variables)]
pub fn zk_verifier_key(
    py: Python<'_>,
    prefix_len: usize,
    path_depth: usize,
    peak_count: usize,
) -> PyResult<Py<PyBytes>> {
    #[cfg(not(feature = "zk-spartan"))]
    {
        Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(NOT_BUILT))
    }
    #[cfg(feature = "zk-spartan")]
    {
        let shape = zk_mmr::ProofShape {
            prefix_len,
            path_depth,
            peak_count,
        };
        let (_, verifier_key) = zk_mmr::setup(shape).map_err(zk_error)?;
        let encoded = zk_mmr::encode_verifier_key(&verifier_key).map_err(zk_error)?;
        Ok(PyBytes::new(py, &encoded).unbind())
    }
}

/// Prove that a leaf recording `waf_verdict = passed` is included under a root.
///
/// Returns `(proof, verifier_key, committed_root)`. The root is **derived from
/// the witness**, not supplied: compare it against the root you trust before
/// relying on the proof, because a proof of inclusion in a tree the prover built
/// is perfectly valid and worth nothing.
///
/// `leaf_prefix` is the canonical leaf bytes **minus** the trailing
/// `,"waf_verdict":"passed"}`. That suffix is a constant of the circuit, which
/// is what makes a `blocked` or verdict-free leaf unprovable here rather than
/// merely rejected.
#[pyfunction]
#[allow(unused_variables)]
pub fn generate_zk_proof(
    py: Python<'_>,
    leaf_prefix: Vec<u8>,
    siblings: Vec<Vec<u8>>,
    sibling_is_left: Vec<bool>,
    peaks: Vec<Vec<u8>>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>, Py<PyBytes>)> {
    #[cfg(not(feature = "zk-spartan"))]
    {
        Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(NOT_BUILT))
    }
    #[cfg(feature = "zk-spartan")]
    {
        let siblings = siblings
            .iter()
            .map(|s| to_digest(s, "each sibling"))
            .collect::<PyResult<Vec<_>>>()?;
        let peaks = peaks
            .iter()
            .map(|p| to_digest(p, "each peak"))
            .collect::<PyResult<Vec<_>>>()?;

        let shape = zk_mmr::ProofShape {
            prefix_len: leaf_prefix.len(),
            path_depth: siblings.len(),
            peak_count: peaks.len(),
        };
        let witness = zk_mmr::Witness {
            prefix: leaf_prefix,
            siblings,
            sibling_is_left,
            peaks,
        };
        let circuit = zk_mmr::WafPassInclusionCircuit::new(shape, witness).map_err(zk_error)?;
        let root = circuit
            .committed_root()
            .expect("a circuit built from a witness always has a root");

        let (prover_key, verifier_key) = zk_mmr::setup(shape).map_err(zk_error)?;
        let proof = zk_mmr::prove(&prover_key, &verifier_key, circuit).map_err(zk_error)?;

        let proof_bytes = zk_mmr::encode_proof(&proof).map_err(zk_error)?;
        let key_bytes = zk_mmr::encode_verifier_key(&verifier_key).map_err(zk_error)?;
        Ok((
            PyBytes::new(py, &proof_bytes).unbind(),
            PyBytes::new(py, &key_bytes).unbind(),
            PyBytes::new(py, &root).unbind(),
        ))
    }
}

/// Check a proof against a root obtained independently of whoever sent it.
///
/// Returns `True` only when the proof verifies **and** the root it commits to is
/// `trusted_root`. A malformed proof or key raises; a well-formed proof about a
/// different tree returns `False`.
#[pyfunction]
#[allow(unused_variables)]
pub fn verify_zk_proof(
    proof: Vec<u8>,
    verifier_key: Vec<u8>,
    trusted_root: Vec<u8>,
) -> PyResult<bool> {
    #[cfg(not(feature = "zk-spartan"))]
    {
        Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(NOT_BUILT))
    }
    #[cfg(feature = "zk-spartan")]
    {
        let root = to_digest(&trusted_root, "trusted_root")?;
        let proof = zk_mmr::decode_proof(&proof).map_err(zk_error)?;
        let key = zk_mmr::decode_verifier_key(&verifier_key).map_err(zk_error)?;
        match zk_mmr::verify(&proof, &key, &root) {
            Ok(()) => Ok(true),
            // A proof that is valid but about another tree, or that does not
            // verify at all, is a `False` answer rather than an error: the
            // caller asked a question and this is the answer.
            Err(zk_mmr::ZkError::RootMismatch) | Err(zk_mmr::ZkError::Proving(_)) => Ok(false),
            Err(other) => Err(zk_error(other)),
        }
    }
}
