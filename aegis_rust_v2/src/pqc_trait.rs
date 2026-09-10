// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! The ML-DSA-65 boundary, behind one trait, so the backend can be replaced.
//!
//! `pqcrypto-mldsa`, `pqcrypto-traits` and `pqcrypto-internals` are marked
//! unmaintained (`RUSTSEC-2026-0166`, `-0162`, `-0163`) because upstream PQClean
//! was archived. An advisory against an unmaintained crate is not a
//! vulnerability, but it is a supply-chain position with no owner, and the
//! remedy — swapping in the pure-Rust RustCrypto `ml-dsa` crate — must not
//! require touching the FFI symbols or the PyO3 bindings above it. This module
//! is that seam: [`PostQuantumSigner`] states the contract in terms of bytes,
//! and [`ActiveBackend`] selects which implementation satisfies it.
//!
//! # Bytes, deliberately, not types
//!
//! Every method takes and returns plain slices and `Vec<u8>`. The two crates
//! model keys with incompatible type systems — `pqcrypto`'s newtypes versus
//! `ml-dsa`'s const-generic `Array` — and a trait built on either one would
//! only be implementable by that one. The wire format is what both agree on,
//! and the wire format is what Aegis persists.
//!
//! # The swap is safe, and that is a measurement rather than an expectation
//!
//! FIPS 204 fixes the encodings, but "both implement the standard" is a claim
//! about documents, not about the bytes on this machine. It was checked
//! directly, and the tests at the bottom of this file are that check, kept
//! runnable so it stays true:
//!
//! - `ml-dsa` verifies a signature PQClean produced, so evidence already in a
//!   WAL stays verifiable after a swap;
//! - PQClean verifies a signature `ml-dsa` produced, so a rollback stays open;
//! - `ml-dsa` loads the persisted 4032-byte expanded secret key and derives the
//!   *same* 1952-byte public key from it, so the durable signing identity
//!   survives — no re-keying, and no chain of nodes stranded under a public key
//!   that no longer resolves.
//!
//! # Why PQClean is still the default
//!
//! Measured on this repository's own hardware, interleaved two-class timing at
//! 40,000 (verify) and 20,000 (sign) samples, both arms hedged:
//!
//! | operation | `pqcrypto-mldsa` (C) | `ml-dsa` (pure Rust) |
//! |---|---|---|
//! | verify, mean | 45,961 ns | 65,805 ns (1.43x) |
//! | verify, class delta / p | −644 ns, p = 0.0000 | −1,128 ns, p = 0.0000 |
//! | sign, mean | 135,443 ns | 650,361 ns (4.80x) |
//! | sign, class delta / p | +256 ns, p = 0.8399 | +1,152 ns, p = 0.8828 |
//!
//! Two conclusions follow, and the second corrects something this repository
//! previously wrote down.
//!
//! **The pure-Rust backend costs 4.8x on signing**, which is per-commit work on
//! the evidence path. That is why the default here is unchanged: the swap is
//! *available*, not automatic, and flipping it is a decision with a price.
//!
//! **It does not fix the verify p-value, and nothing at this layer will.**
//! `pqc.rs` recorded that closing that gap "requires a verifier that does not
//! exit early — an upstream change in `pqcrypto-mldsa` or a different
//! implementation". A different implementation was measured, and it shows the
//! *same* `p = 0.0000` with a *larger* class delta. When two independent
//! implementations of one specification produce the same result, the effect
//! belongs to the experiment rather than to either implementation — and the
//! experiment's two classes are a repeated signature versus 1024 varying ones,
//! all of them valid. Which is the point worth stating plainly: **ML-DSA
//! verification consumes no secret.** It takes a public key, a message and a
//! signature, all public. A timing difference between two *public* inputs
//! discloses nothing that the inputs did not already disclose, so the verify
//! experiment is not measuring a side channel. Signing is the operation that
//! touches the secret key, and signing meets the non-detection threshold on
//! both backends.
//!
//! None of that is a constant-time claim. See `docs/security/PQC_CONSTANT_TIME.md`
//! for what remains blocked and why.

use std::fmt;

/// Sizes fixed by FIPS 204 for ML-DSA-65. Named so a mismatch is one edit.
pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SECRET_KEY_BYTES: usize = 4032;
pub const SIGNATURE_BYTES: usize = 3309;

/// A rejected input, kept as a plain error so no backend type escapes the seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcError(pub String);

impl fmt::Display for PqcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PqcError {}

/// One ML-DSA-65 implementation, addressed entirely through FIPS 204 encodings.
///
/// Implementations must reject wrong-size or malformed inputs rather than
/// truncating, padding or panicking: these bytes arrive from a file an operator
/// provisioned and from a WAL that may have been written by a different
/// version, so "malformed" is a case to be reported, not an impossibility.
pub trait PostQuantumSigner {
    /// Backend identifier, recorded so evidence says which code produced it.
    const BACKEND: &'static str;

    /// A fresh keypair as `(public_key, secret_key)` in FIPS 204 encodings.
    fn keypair() -> (Vec<u8>, Vec<u8>);

    /// Derive the public key from a persisted secret key.
    ///
    /// This is what makes a stored identity portable across backends: the
    /// caller can check that the derived key matches the one it stored beside
    /// the secret, instead of trusting that the pairing survived.
    fn public_from_secret(secret_key: &[u8]) -> Result<Vec<u8>, PqcError>;

    /// Sign `message`, returning a detached signature.
    ///
    /// Hedged (randomized), matching what the deployed backend does. The
    /// deterministic variant is deliberately not exposed: it makes the
    /// rejection-sampling loop's iteration count a function of the message
    /// alone, which is both a timing difference and a reuse hazard.
    fn sign_detached(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, PqcError>;

    /// Verify a detached signature.
    ///
    /// `Ok(false)` is a signature that did not verify; `Err` is an input that
    /// could not be parsed. Collapsing the two would let a malformed key be
    /// read as a failed signature, which is a different fact about the world.
    fn verify_detached(
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, PqcError>;
}

fn expect_len(label: &str, actual: usize, expected: usize) -> Result<(), PqcError> {
    if actual != expected {
        return Err(PqcError(format!(
            "{label} must be {expected} bytes for ML-DSA-65, got {actual}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PQClean backend (default)
// ---------------------------------------------------------------------------

/// ML-DSA-65 through `pqcrypto-mldsa`, the PQClean C implementation.
///
/// A zero-sized marker: every trait method is an associated function, so this
/// is only ever named as a type and never constructed. The lint cannot tell
/// that apart from genuinely unreachable code.
#[cfg(feature = "pqclean-pqc")]
#[allow(dead_code)]
pub struct PqCleanBackend;

#[cfg(feature = "pqclean-pqc")]
impl PostQuantumSigner for PqCleanBackend {
    const BACKEND: &'static str = "pqcrypto-mldsa";

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
        let (pk, sk) = pqcrypto_mldsa::mldsa65::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }

    fn public_from_secret(secret_key: &[u8]) -> Result<Vec<u8>, PqcError> {
        expect_len("secret key", secret_key.len(), SECRET_KEY_BYTES)?;
        // PQClean exposes no "derive public from secret" entry point: its API
        // treats the pair as produced together. The encoding does carry what is
        // needed — rho and t1 — but reaching them means reimplementing skDecode
        // plus the NTT expansion of A, which is the whole signer. The pure-Rust
        // backend can do it, so the capability is reported rather than faked.
        Err(PqcError(
            "pqcrypto-mldsa cannot derive a public key from a secret key; \
             persist both halves, or build with the `pure-rust-pqc` feature"
                .to_string(),
        ))
    }

    fn sign_detached(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, PqcError> {
        use pqcrypto_traits::sign::{DetachedSignature as _, SecretKey as _};
        expect_len("secret key", secret_key.len(), SECRET_KEY_BYTES)?;
        let sk = pqcrypto_mldsa::mldsa65::SecretKey::from_bytes(secret_key)
            .map_err(|e| PqcError(format!("invalid secret key: {e}")))?;
        Ok(pqcrypto_mldsa::mldsa65::detached_sign(message, &sk)
            .as_bytes()
            .to_vec())
    }

    fn verify_detached(
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, PqcError> {
        use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
        expect_len("public key", public_key.len(), PUBLIC_KEY_BYTES)?;
        expect_len("signature", signature.len(), SIGNATURE_BYTES)?;
        let pk = pqcrypto_mldsa::mldsa65::PublicKey::from_bytes(public_key)
            .map_err(|e| PqcError(format!("invalid public key: {e}")))?;
        let sig = pqcrypto_mldsa::mldsa65::DetachedSignature::from_bytes(signature)
            .map_err(|e| PqcError(format!("invalid signature: {e}")))?;
        Ok(pqcrypto_mldsa::mldsa65::verify_detached_signature(&sig, message, &pk).is_ok())
    }
}

// ---------------------------------------------------------------------------
// Pure-Rust backend (opt-in)
// ---------------------------------------------------------------------------

#[cfg(feature = "pure-rust-pqc")]
mod pure_rust {
    use super::{
        expect_len, PostQuantumSigner, PqcError, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES,
        SIGNATURE_BYTES,
    };

    // `from_expanded`/`to_expanded` are deprecated upstream in favour of seed
    // handling. They are still the only way to load the 4032-byte expanded
    // secret key that PQClean produced and Aegis persisted, and abandoning
    // those identities is not an option, so the deprecation is acknowledged
    // here rather than crate-wide. Upstream warns it can panic on a malformed
    // key; the length check above it is what keeps a truncated file from
    // reaching it, and the file is operator-provisioned, so a hostile value
    // there implies the signing key is already lost.
    #[allow(deprecated)]
    use ml_dsa::{
        EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes,
        MlDsa65, Signature, VerifyingKey,
    };

    /// ML-DSA-65 through RustCrypto's `ml-dsa`. No C, and no archived upstream.
    pub struct MlDsaBackend;

    #[allow(deprecated)]
    fn load_secret(secret_key: &[u8]) -> Result<ExpandedSigningKey<MlDsa65>, PqcError> {
        expect_len("secret key", secret_key.len(), SECRET_KEY_BYTES)?;
        let encoded = ExpandedSigningKeyBytes::<MlDsa65>::try_from(secret_key)
            .map_err(|_| PqcError("secret key is not a valid ML-DSA-65 encoding".to_string()))?;
        Ok(ExpandedSigningKey::<MlDsa65>::from_expanded(&encoded))
    }

    impl PostQuantumSigner for MlDsaBackend {
        const BACKEND: &'static str = "ml-dsa";

        fn keypair() -> (Vec<u8>, Vec<u8>) {
            #[allow(deprecated)]
            {
                let mut seed = ml_dsa::B32::default();
                getrandom::fill(&mut seed)
                    .expect("system RNG must be available for key generation");
                let sk = ExpandedSigningKey::<MlDsa65>::from_seed(&seed);
                let public = sk.verifying_key().encode().to_vec();
                let secret = sk.to_expanded().to_vec();
                (public, secret)
            }
        }

        fn public_from_secret(secret_key: &[u8]) -> Result<Vec<u8>, PqcError> {
            Ok(load_secret(secret_key)?.verifying_key().encode().to_vec())
        }

        fn sign_detached(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, PqcError> {
            let sk = load_secret(secret_key)?;
            let mut rng = OsRng;
            let signature = sk
                .sign_randomized(message, b"", &mut rng)
                .map_err(|_| PqcError("ML-DSA signing failed".to_string()))?;
            Ok(signature.encode().to_vec())
        }

        fn verify_detached(
            message: &[u8],
            signature: &[u8],
            public_key: &[u8],
        ) -> Result<bool, PqcError> {
            use ml_dsa::signature::Verifier;
            expect_len("public key", public_key.len(), PUBLIC_KEY_BYTES)?;
            expect_len("signature", signature.len(), SIGNATURE_BYTES)?;
            let encoded_pk = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
                .map_err(|_| PqcError("public key is not a valid encoding".to_string()))?;
            let vk = VerifyingKey::<MlDsa65>::decode(&encoded_pk);
            let encoded_sig = EncodedSignature::<MlDsa65>::try_from(signature)
                .map_err(|_| PqcError("signature is not a valid encoding".to_string()))?;
            let Some(parsed) = Signature::<MlDsa65>::decode(&encoded_sig) else {
                // A signature that does not decode is a malformed input, not a
                // failed verification: reporting it as `Ok(false)` would say
                // "this signature is wrong" about bytes that are not a
                // signature at all.
                return Err(PqcError("signature is not a valid encoding".to_string()));
            };
            Ok(vk.verify(message, &parsed).is_ok())
        }
    }

    /// Bridges the system RNG to the `rand_core` version `ml-dsa` expects.
    ///
    /// `getrandom` rather than a userspace PRNG: hedged signing needs 32 fresh
    /// bytes per signature and the kernel is the one source whose seeding is
    /// not this crate's problem.
    struct OsRng;

    impl rand_core::TryRng for OsRng {
        type Error = getrandom::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut buf = [0u8; 4];
            getrandom::fill(&mut buf)?;
            Ok(u32::from_le_bytes(buf))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut buf = [0u8; 8];
            getrandom::fill(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            getrandom::fill(dst)
        }
    }

    impl rand_core::TryCryptoRng for OsRng {}
}

#[cfg(feature = "pure-rust-pqc")]
pub use pure_rust::MlDsaBackend;

/// The backend the build selected. Everything above this seam names only this.
///
/// `pure-rust-pqc` wins when both are compiled in, which happens only under
/// `pqc-compat-tests`: enabling the replacement and then silently running the
/// implementation being replaced would make that test configuration prove
/// nothing about the replacement.
#[cfg(feature = "pure-rust-pqc")]
pub type ActiveBackend = MlDsaBackend;

/// The backend the build selected. Everything above this seam names only this.
#[cfg(all(feature = "pqclean-pqc", not(feature = "pure-rust-pqc")))]
pub type ActiveBackend = PqCleanBackend;

// A build with no backend would compile and then fail at the first signature,
// which is the worst time to discover it. Fail at the build instead.
#[cfg(not(any(feature = "pqclean-pqc", feature = "pure-rust-pqc")))]
compile_error!("no ML-DSA-65 backend selected: enable `pqclean-pqc` (default) or `pure-rust-pqc`");

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"aegis audit node: prev_hash || merkle_root || request || response";

    #[test]
    fn active_backend_round_trips() {
        let (pk, sk) = <ActiveBackend as PostQuantumSigner>::keypair();
        assert_eq!(pk.len(), PUBLIC_KEY_BYTES);
        assert_eq!(sk.len(), SECRET_KEY_BYTES);
        let sig = <ActiveBackend as PostQuantumSigner>::sign_detached(MSG, &sk).unwrap();
        assert_eq!(sig.len(), SIGNATURE_BYTES);
        assert!(<ActiveBackend as PostQuantumSigner>::verify_detached(MSG, &sig, &pk).unwrap());
        assert!(
            !<ActiveBackend as PostQuantumSigner>::verify_detached(b"tampered", &sig, &pk).unwrap()
        );
    }

    #[test]
    fn wrong_sizes_are_errors_not_verification_failures() {
        // A truncated key is a different fact from a signature that did not
        // verify, and collapsing them would hide a provisioning bug behind
        // what looks like a tampering alert.
        let (pk, sk) = <ActiveBackend as PostQuantumSigner>::keypair();
        let sig = <ActiveBackend as PostQuantumSigner>::sign_detached(MSG, &sk).unwrap();

        assert!(
            <ActiveBackend as PostQuantumSigner>::verify_detached(MSG, &sig, &pk[..100]).is_err()
        );
        assert!(
            <ActiveBackend as PostQuantumSigner>::verify_detached(MSG, &sig[..100], &pk).is_err()
        );
        assert!(<ActiveBackend as PostQuantumSigner>::sign_detached(MSG, &sk[..100]).is_err());
    }

    #[test]
    fn a_signature_does_not_verify_under_another_key() {
        let (_pk_a, sk_a) = <ActiveBackend as PostQuantumSigner>::keypair();
        let (pk_b, _sk_b) = <ActiveBackend as PostQuantumSigner>::keypair();
        let sig = <ActiveBackend as PostQuantumSigner>::sign_detached(MSG, &sk_a).unwrap();
        assert!(!<ActiveBackend as PostQuantumSigner>::verify_detached(MSG, &sig, &pk_b).unwrap());
    }

    // The migration-safety properties. These only mean something when both
    // backends are compiled in:
    //   cargo test --features pqc-compat-tests
    #[cfg(all(feature = "pqclean-pqc", feature = "pure-rust-pqc"))]
    mod cross_backend {
        use super::*;

        #[test]
        fn ml_dsa_verifies_a_pqclean_signature() {
            // Evidence already in a WAL must stay verifiable after a swap.
            let (pk, sk) = PqCleanBackend::keypair();
            let sig = PqCleanBackend::sign_detached(MSG, &sk).unwrap();
            assert!(MlDsaBackend::verify_detached(MSG, &sig, &pk).unwrap());
            assert!(!MlDsaBackend::verify_detached(b"tampered", &sig, &pk).unwrap());
        }

        #[test]
        fn pqclean_verifies_an_ml_dsa_signature() {
            // A rollback must stay open: nodes signed after a swap have to
            // remain verifiable by the backend being rolled back to.
            let (pk, sk) = PqCleanBackend::keypair();
            let sig = MlDsaBackend::sign_detached(MSG, &sk).unwrap();
            assert!(PqCleanBackend::verify_detached(MSG, &sig, &pk).unwrap());
            assert!(!PqCleanBackend::verify_detached(b"tampered", &sig, &pk).unwrap());
        }

        #[test]
        fn a_persisted_identity_survives_the_swap() {
            // The durable identity is a 4032-byte expanded secret key stored
            // beside its public key. If the pure-Rust backend derived a
            // different public key from it, every node ever signed under the
            // stored one would be stranded.
            let (pk, sk) = PqCleanBackend::keypair();
            assert_eq!(MlDsaBackend::public_from_secret(&sk).unwrap(), pk);
        }

        #[test]
        fn a_fresh_pure_rust_identity_is_verifiable_by_pqclean() {
            let (pk, sk) = MlDsaBackend::keypair();
            let sig = MlDsaBackend::sign_detached(MSG, &sk).unwrap();
            assert!(PqCleanBackend::verify_detached(MSG, &sig, &pk).unwrap());
        }
    }
}
