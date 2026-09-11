// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Zero-knowledge inclusion proof for a leaf whose recorded WAF verdict is
//! `passed`.
//!
//! # What this proves
//!
//! One statement, and the exact wording is load-bearing:
//!
//! > There exists a leaf `L` and an inclusion path for `L` such that `L` is
//! > included in the Merkle Mountain Range under public root `R`, and `L`'s
//! > canonical bytes end with `,"waf_verdict":"passed"}`.
//!
//! **It attests that the ledger contains a record asserting a WAF pass. It does
//! not re-execute the WAF, does not attest that the WAF is correct, and does not
//! attest semantic correctness, model safety, or upstream provider behavior.**
//! `docs/institutional/DOC-08_ZERO_KNOWLEDGE_INCLUSION.md` is the normative
//! statement of that boundary; this module must not be described in terms that
//! exceed it.
//!
//! # Why the verdict is a circuit *constant*, not a witness
//!
//! The verdict suffix is built into the hashed preimage as constant bits rather
//! than allocated and then constrained. The two are equivalent in soundness and
//! the constant form is free, but the reason it is *sound* is worth stating: a
//! prover chooses the prefix, so what they prove is "some preimage ending in
//! this suffix hashes to a digest that is in the tree". Because the only digests
//! in the tree are of genuine leaves, a matching preimage *is* a genuine leaf —
//! and it ends with a recorded `passed`. A leaf recording `blocked`, or no
//! verdict at all, has different bytes and therefore a different digest, so no
//! path to the root exists for it.
//!
//! # Why SHA-256 and not a SNARK-friendly hash
//!
//! A Poseidon circuit would be perhaps two orders of magnitude cheaper, and it
//! would prove a statement about a tree the gateway does not build. The MMR that
//! exists is SHA-256 with RFC 6962 domain separation (`aegis/core/mmr.py`,
//! `src/mmr.rs`), so the circuit pays SHA-256's cost to be about the real tree.
//!
//! # Why the direction bits are free
//!
//! The Python verifier checks each step's direction against the leaf index. This
//! circuit does not: directions are witness values the prover chooses. That is
//! deliberate, and it is safe **only because of v2's domain separation** — the
//! `0x00` leaf tag and `0x01` node tag make it impossible to present an interior
//! node's digest as a leaf, which is the attack free directions would otherwise
//! open. Leaving them free means the proof does not bind the leaf's position,
//! which discloses less.

use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::boolean::{AllocatedBit, Boolean};
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError};
use ff::{Field, PrimeField};
use spartan2::provider::PallasHyraxEngine;
use spartan2::spartan_zk::SpartanZkSNARK;
use spartan2::traits::circuit::SpartanCircuit;
use spartan2::traits::snark::R1CSSNARKTrait;
use spartan2::traits::Engine;

/// Curve used for the proving system. Pallas with a Hyrax polynomial commitment
/// — discrete-log based, so the setup is a transparent generator derivation with
/// no ceremony and no toxic waste.
pub type Curve = PallasHyraxEngine;
type Fr = <Curve as Engine>::Scalar;
/// The zero-knowledge SNARK. `spartan_zk`, never `spartan`: the latter is
/// documented in its own source as "Spartan **without** zero-knowledge", and
/// would produce a succinct proof that discloses the witness.
pub type Snark = SpartanZkSNARK<Curve>;
/// Verifier key. See [`verify`] for why this must not come from the prover.
pub type VerifierKey = <Snark as R1CSSNARKTrait<Curve>>::VerifierKey;
/// Prover key.
pub type ProverKey = <Snark as R1CSSNARKTrait<Curve>>::ProverKey;

/// RFC 6962 §2.1 domain tags, matching `HashScheme::V2BinaryDomainSeparated`.
const DOMAIN_LEAF: u8 = 0x00;
const DOMAIN_NODE: u8 = 0x01;
const DOMAIN_ROOT: u8 = 0x02;

/// The exact bytes a canonical forensic leaf ends with when the verdict is
/// recorded as `passed`.
///
/// `waf_verdict` is the alphabetically last key the envelope can carry, and
/// `aegis.core.forensic.build_merkle_leaf` serialises with `sort_keys=True`, so
/// a recorded verdict always lands here and always in this form. `parity` in
/// `tests/zk_mmr_parity.rs` pins that against the Python builder rather than
/// trusting this comment.
pub const PASSED_SUFFIX: &[u8] = br#","waf_verdict":"passed"}"#;

/// Errors this module raises. Every variant is a refusal; none is recoverable by
/// retrying with the same inputs.
#[derive(Debug)]
pub enum ZkError {
    /// A witness field does not match the shape the circuit was built for.
    ShapeMismatch(String),
    /// Proving or verification failed inside the proving system.
    Proving(String),
    /// Proof or key bytes could not be decoded.
    Decoding(String),
    /// The proof verified, but against a root other than the one supplied.
    RootMismatch,
}

impl std::fmt::Display for ZkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShapeMismatch(m) => write!(f, "witness does not match circuit shape: {m}"),
            Self::Proving(m) => write!(f, "proving system error: {m}"),
            Self::Decoding(m) => write!(f, "could not decode: {m}"),
            Self::RootMismatch => write!(
                f,
                "proof is internally valid but commits to a different root than the one supplied"
            ),
        }
    }
}

impl std::error::Error for ZkError {}

/// The public structure of a proof.
///
/// **These three numbers are disclosed**, because the R1CS shape depends on them
/// and the verifier must build the same shape to obtain a verifier key. They
/// reveal the leaf's byte length, the height of the mountain containing it, and
/// how many peaks the tree had — which together bound the ledger's size and the
/// request's size. They do **not** reveal the leaf's contents, its position, or
/// any other leaf. See `DOC-08 §6`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofShape {
    /// Leaf bytes *before* [`PASSED_SUFFIX`].
    pub prefix_len: usize,
    /// Number of sibling steps from leaf to peak.
    pub path_depth: usize,
    /// Number of peaks in the tree, i.e. `leaf_count.count_ones()`.
    pub peak_count: usize,
}

/// Everything the prover knows and the verifier does not.
#[derive(Clone, Debug)]
pub struct Witness {
    /// Leaf bytes before the verdict suffix.
    pub prefix: Vec<u8>,
    /// Sibling digest at each level, leaf-ward first.
    pub siblings: Vec<[u8; 32]>,
    /// `true` when the sibling at that level is the **left** child.
    pub sibling_is_left: Vec<bool>,
    /// The tree's peaks, in the order the root bags them.
    pub peaks: Vec<[u8; 32]>,
}

/// The circuit.
///
/// Cloneable and `Send + Sync` because `SpartanCircuit` requires it: the proving
/// system synthesises the same circuit more than once, and across threads.
#[derive(Clone, Debug)]
pub struct WafPassInclusionCircuit {
    shape: ProofShape,
    /// The root this witness leads to, computed natively at construction.
    ///
    /// Deliberately **not** a caller-supplied value. `SpartanCircuit` asks a
    /// circuit for its public values (`public_values`) and separately takes the
    /// instance's public values from the synthesized input assignment
    /// (`spartan_zk.rs`), absorbing the first into the prover's transcript and
    /// the second into the verifier's. A circuit that let a caller *declare* a
    /// root could therefore hold two roots that disagree, and the failure would
    /// surface as an opaque Fiat–Shamir mismatch rather than as the wrong-root
    /// error it is. Deriving it here means there is only ever one.
    committed_root: Option<[u8; 32]>,
    witness: Option<Witness>,
}

impl WafPassInclusionCircuit {
    /// A circuit carrying shape only — enough to derive keys, not to prove.
    ///
    /// Key derivation must not need a witness. That is what lets a verifier
    /// build their own verifier key from public shape alone, which is the whole
    /// reason [`verify`] can refuse a prover-supplied key.
    pub fn shape_only(shape: ProofShape) -> Self {
        Self {
            shape,
            committed_root: None,
            witness: None,
        }
    }

    /// A circuit that can produce a proof.
    ///
    /// Rejects a witness whose dimensions disagree with the shape rather than
    /// synthesising a circuit that silently proves something else. The root is
    /// derived from the witness, not accepted from the caller — read it back
    /// with [`Self::committed_root`] and compare it against the root you trust
    /// *before* paying for a proof.
    pub fn new(shape: ProofShape, witness: Witness) -> Result<Self, ZkError> {
        if witness.prefix.len() != shape.prefix_len {
            return Err(ZkError::ShapeMismatch(format!(
                "prefix is {} bytes, shape declares {}",
                witness.prefix.len(),
                shape.prefix_len
            )));
        }
        if witness.siblings.len() != shape.path_depth {
            return Err(ZkError::ShapeMismatch(format!(
                "path has {} siblings, shape declares depth {}",
                witness.siblings.len(),
                shape.path_depth
            )));
        }
        if witness.sibling_is_left.len() != shape.path_depth {
            return Err(ZkError::ShapeMismatch(format!(
                "path has {} directions, shape declares depth {}",
                witness.sibling_is_left.len(),
                shape.path_depth
            )));
        }
        if witness.peaks.len() != shape.peak_count {
            return Err(ZkError::ShapeMismatch(format!(
                "witness has {} peaks, shape declares {}",
                witness.peaks.len(),
                shape.peak_count
            )));
        }
        let committed_root = Some(native_root(&witness));
        Ok(Self {
            shape,
            committed_root,
            witness: Some(witness),
        })
    }

    /// The shape this circuit was built for.
    pub fn shape(&self) -> ProofShape {
        self.shape
    }

    /// The root this witness leads to, or `None` for a shape-only circuit.
    ///
    /// A caller holding a trusted root should compare it against this and stop
    /// if they differ: proving first and discovering the mismatch at
    /// verification costs seconds and tells you no more.
    pub fn committed_root(&self) -> Option<[u8; 32]> {
        self.committed_root
    }

    /// The canonical leaf bytes this witness commits to, outside the circuit.
    ///
    /// Exposed so a caller can check the circuit is about the leaf they meant
    /// before paying for a proof.
    pub fn leaf_bytes(&self) -> Option<Vec<u8>> {
        self.witness.as_ref().map(|w| {
            let mut bytes = w.prefix.clone();
            bytes.extend_from_slice(PASSED_SUFFIX);
            bytes
        })
    }
}

// ── the same walk, outside the circuit ────────────────────────────────────────

/// Compute the root a witness leads to, using ordinary SHA-256.
///
/// This mirrors `synthesize` step for step. The duplication is deliberate and it
/// is checked rather than assumed: `an_honest_witness_satisfies_the_circuit`
/// only passes when the circuit's computed root matches this one, because the
/// circuit's public input is bound to the bits it derived. A drift between the
/// two therefore fails a test rather than producing proofs nobody can verify.
fn native_root(witness: &Witness) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut leaf = witness.prefix.clone();
    leaf.extend_from_slice(PASSED_SUFFIX);

    let mut hasher = Sha256::new();
    hasher.update([DOMAIN_LEAF]);
    hasher.update(&leaf);
    let mut current: [u8; 32] = hasher.finalize().into();

    for (sibling, sibling_is_left) in witness.siblings.iter().zip(&witness.sibling_is_left) {
        let (left, right) = if *sibling_is_left {
            (sibling, &current)
        } else {
            (&current, sibling)
        };
        let mut hasher = Sha256::new();
        hasher.update([DOMAIN_NODE]);
        hasher.update(left);
        hasher.update(right);
        current = hasher.finalize().into();
    }

    let mut hasher = Sha256::new();
    hasher.update([DOMAIN_ROOT]);
    for peak in &witness.peaks {
        hasher.update(peak);
    }
    hasher.finalize().into()
}

// ── bit plumbing ──────────────────────────────────────────────────────────────

/// Big-endian bits of a byte, as circuit constants. Free: no constraint, no
/// witness variable.
fn constant_byte_bits(byte: u8) -> Vec<Boolean> {
    (0..8)
        .map(|i| Boolean::constant((byte >> (7 - i)) & 1 == 1))
        .collect()
}

fn constant_bits(bytes: &[u8]) -> Vec<Boolean> {
    bytes.iter().copied().flat_map(constant_byte_bits).collect()
}

/// Allocate the big-endian bits of `byte` as witness variables. `None` allocates
/// unconstrained bits, which is what shape synthesis needs.
fn alloc_byte_bits<CS: ConstraintSystem<Fr>>(
    mut cs: CS,
    byte: Option<u8>,
) -> Result<Vec<Boolean>, SynthesisError> {
    (0..8)
        .map(|i| {
            let value = byte.map(|b| (b >> (7 - i)) & 1 == 1);
            Ok(Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| format!("bit {i}")),
                value,
            )?))
        })
        .collect()
}

fn alloc_digest_bits<CS: ConstraintSystem<Fr>>(
    mut cs: CS,
    digest: Option<&[u8; 32]>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut bits = Vec::with_capacity(256);
    for index in 0..32 {
        bits.extend(alloc_byte_bits(
            cs.namespace(|| format!("byte {index}")),
            digest.map(|d| d[index]),
        )?);
    }
    Ok(bits)
}

/// `true` iff two bit vectors are equal, as a circuit value.
///
/// 256 XORs and 256 ANDs per comparison — negligible beside one SHA-256 block,
/// which is why comparing against *every* peak is affordable and the peak index
/// need never be disclosed.
fn bits_equal<CS: ConstraintSystem<Fr>>(
    mut cs: CS,
    a: &[Boolean],
    b: &[Boolean],
) -> Result<Boolean, SynthesisError> {
    debug_assert_eq!(a.len(), b.len());
    let mut same = Boolean::constant(true);
    for (index, (left, right)) in a.iter().zip(b.iter()).enumerate() {
        let differs = Boolean::xor(cs.namespace(|| format!("xor {index}")), left, right)?;
        same = Boolean::and(
            cs.namespace(|| format!("and {index}")),
            &same,
            &differs.not(),
        )?;
    }
    Ok(same)
}

/// Pack up to `Fr::CAPACITY` big-endian bits into one field element.
fn pack_bits<CS: ConstraintSystem<Fr>>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    assert!(bits.len() as u32 <= Fr::CAPACITY, "chunk exceeds field capacity");

    // `None` once any bit has no assignment: that is shape synthesis, where the
    // variable must still be allocated but carries no value.
    let value = bits.iter().try_fold(Fr::ZERO, |acc, bit| {
        bit.get_value()
            .map(|b| acc.double() + if b { Fr::ONE } else { Fr::ZERO })
    });

    let packed = AllocatedNum::alloc(cs.namespace(|| "packed"), || {
        value.ok_or(SynthesisError::AssignmentMissing)
    })?;

    // Bind the allocated number to the bits it claims to pack. Without this the
    // public input would be an unconstrained witness — i.e. the prover could
    // announce any root at all.
    let mut combination = LinearCombination::zero();
    let mut coefficient = Fr::ONE;
    for bit in bits.iter().rev() {
        combination = combination + &bit.lc(CS::one(), coefficient);
        coefficient = coefficient.double();
    }
    cs.enforce(
        || "packed equals its bits",
        |lc| lc + packed.get_variable(),
        |lc| lc + CS::one(),
        |_| combination,
    );

    Ok(packed)
}

/// Split a 32-byte digest into the two field elements the circuit publishes.
///
/// Two 128-bit halves rather than one 256-bit value: the Pallas scalar field is
/// ~255 bits, so a 256-bit digest does not fit in one element and packing it
/// whole would silently reduce modulo the field order — different digests would
/// then share a public input.
pub fn root_to_public_values(root: &[u8; 32]) -> Vec<Fr> {
    [&root[..16], &root[16..]]
        .iter()
        .map(|half| {
            half.iter().fold(Fr::ZERO, |acc, byte| {
                (0..8).fold(acc, |acc, i| {
                    acc.double() + if (byte >> (7 - i)) & 1 == 1 { Fr::ONE } else { Fr::ZERO }
                })
            })
        })
        .collect()
}

// ── the circuit ───────────────────────────────────────────────────────────────

impl SpartanCircuit<Curve> for WafPassInclusionCircuit {
    fn public_values(&self) -> Result<Vec<Fr>, SynthesisError> {
        // A shape-only circuit has no witness and therefore no root. It is never
        // proved — `setup` needs the shape alone — so zeros here are a
        // placeholder of the right arity, not a root anyone can prove against.
        Ok(root_to_public_values(
            &self.committed_root.unwrap_or([0u8; 32]),
        ))
    }

    fn shared<CS: ConstraintSystem<Fr>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<Fr>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Fr>],
        _: &[AllocatedNum<Fr>],
        _: Option<&[Fr]>,
    ) -> Result<(), SynthesisError> {
        let witness = self.witness.as_ref();

        // 1. leaf = SHA-256(0x00 || prefix || PASSED_SUFFIX).
        //
        // The suffix is constant, so the verdict is not something the prover
        // asserts and the circuit checks — it is a property of every preimage
        // this circuit can hash at all.
        let mut leaf_preimage = constant_byte_bits(DOMAIN_LEAF);
        for index in 0..self.shape.prefix_len {
            leaf_preimage.extend(alloc_byte_bits(
                cs.namespace(|| format!("leaf prefix byte {index}")),
                witness.map(|w| w.prefix[index]),
            )?);
        }
        leaf_preimage.extend(constant_bits(PASSED_SUFFIX));
        let mut current = sha256(cs.namespace(|| "leaf hash"), &leaf_preimage)?;

        // 2. Walk to a peak: node = SHA-256(0x01 || left || right).
        for level in 0..self.shape.path_depth {
            let mut cs = cs.namespace(|| format!("level {level}"));

            let sibling = alloc_digest_bits(
                cs.namespace(|| "sibling"),
                witness.map(|w| &w.siblings[level]),
            )?;
            let sibling_is_left = Boolean::from(AllocatedBit::alloc(
                cs.namespace(|| "sibling is left"),
                witness.map(|w| w.sibling_is_left[level]),
            )?);

            // sha256_ch(a, b, c) is (a AND b) XOR (NOT a AND c) — a multiplexer,
            // one constraint per bit.
            let mut node_preimage = constant_byte_bits(DOMAIN_NODE);
            for (index, (sibling_bit, current_bit)) in
                sibling.iter().zip(current.iter()).enumerate()
            {
                node_preimage.push(Boolean::sha256_ch(
                    cs.namespace(|| format!("left {index}")),
                    &sibling_is_left,
                    sibling_bit,
                    current_bit,
                )?);
            }
            for (index, (sibling_bit, current_bit)) in
                sibling.iter().zip(current.iter()).enumerate()
            {
                node_preimage.push(Boolean::sha256_ch(
                    cs.namespace(|| format!("right {index}")),
                    &sibling_is_left,
                    current_bit,
                    sibling_bit,
                )?);
            }

            current = sha256(cs.namespace(|| "node hash"), &node_preimage)?;
        }

        // 3. The walk must land on *some* peak.
        //
        // Comparing against every peak rather than an indexed one keeps the
        // peak index out of the public shape, so the proof does not narrow which
        // mountain — and therefore which range of ledger positions — the leaf
        // sits in.
        let mut peak_bits = Vec::with_capacity(self.shape.peak_count);
        let mut matched_a_peak = Boolean::constant(false);
        for index in 0..self.shape.peak_count {
            let peak = alloc_digest_bits(
                cs.namespace(|| format!("peak {index}")),
                witness.map(|w| &w.peaks[index]),
            )?;
            let matches = bits_equal(
                cs.namespace(|| format!("peak {index} matches")),
                &current,
                &peak,
            )?;
            matched_a_peak = Boolean::or(
                cs.namespace(|| format!("peak {index} accumulate")),
                &matched_a_peak,
                &matches,
            )?;
            peak_bits.push(peak);
        }
        Boolean::enforce_equal(
            cs.namespace(|| "path reaches a peak"),
            &matched_a_peak,
            &Boolean::constant(true),
        )?;

        // 4. root = SHA-256(0x02 || peak_1 || ... || peak_k).
        //
        // Peak order is not constrained because it does not need to be: a
        // reordering produces a different root, which then fails step 5.
        let mut root_preimage = constant_byte_bits(DOMAIN_ROOT);
        for peak in &peak_bits {
            root_preimage.extend(peak.iter().cloned());
        }
        let root = sha256(cs.namespace(|| "bagged root"), &root_preimage)?;

        // 5. Publish the root. `inputize` is what makes this the statement's
        //    public half; everything above stays witness.
        for (index, chunk) in root.chunks(128).enumerate() {
            let packed = pack_bits(cs.namespace(|| format!("root chunk {index}")), chunk)?;
            packed.inputize(cs.namespace(|| format!("root input {index}")))?;
        }

        Ok(())
    }
}

// ── proving and verification ──────────────────────────────────────────────────

/// Derive the prover and verifier keys for a shape.
///
/// Deterministic and transparent: the keys are a function of the shape alone.
/// There is no ceremony, no secret randomness, and therefore no toxic waste
/// whose retention would let someone forge a proof — which is why this proving
/// system was chosen over a Groth16-style one.
///
/// Expensive, and expense that grows with the shape. Callers that prove
/// repeatedly for one shape should derive once and reuse.
pub fn setup(shape: ProofShape) -> Result<(ProverKey, VerifierKey), ZkError> {
    Snark::setup(WafPassInclusionCircuit::shape_only(shape))
        .map_err(|e| ZkError::Proving(format!("{e:?}")))
}

/// Produce a proof that a leaf recording `waf_verdict = passed` sits under the
/// circuit's committed root.
///
/// **The proof is verified before it is returned, and that is not belt-and-
/// braces.** Spartan's prover is not a satisfiability oracle: given a witness
/// that does not satisfy the constraints it returns `Ok` with a proof object
/// rather than an error. That proof then verifies against nothing — measured,
/// not assumed: a tampered-sibling witness yields `Ok` from `Snark::prove`, and
/// the resulting proof fails verification against both the honest root and an
/// arbitrary one. Without the self-check a caller would have to treat a
/// successful `prove` as meaningless, and the first sign of trouble would be a
/// third party unable to verify. The check moves that failure to the only place
/// it can be handled.
///
/// The verifier key is required for exactly that reason. It costs one
/// verification on top of proving, which the measurements make a small fraction
/// of the total.
pub fn prove(
    prover_key: &ProverKey,
    verifier_key: &VerifierKey,
    circuit: WafPassInclusionCircuit,
) -> Result<Snark, ZkError> {
    let committed_root = circuit
        .committed_root()
        .ok_or_else(|| ZkError::ShapeMismatch("a shape-only circuit has no witness".into()))?;

    let prepared = Snark::prep_prove(prover_key, circuit.clone(), false)
        .map_err(|e| ZkError::Proving(format!("{e:?}")))?;
    let (proof, _) = Snark::prove(prover_key, circuit, prepared, false)
        .map_err(|e| ZkError::Proving(format!("{e:?}")))?;

    verify(&proof, verifier_key, &committed_root).map_err(|e| {
        ZkError::Proving(format!(
            "the proving system returned a proof that does not verify, \
             which means the witness does not satisfy the circuit: {e}"
        ))
    })?;
    Ok(proof)
}

/// Verify a proof against a root the caller already trusts.
///
/// Two things make this refuse, and the second is the one that is easy to get
/// wrong:
///
/// 1. The proof itself must verify under `verifier_key`.
/// 2. The public values it carries must equal `trusted_root`.
///
/// A proof carries its own public inputs, so `Snark::verify` succeeding means
/// only "this is a valid proof of *something*". Without step 2 a prover could
/// hand over a perfectly valid proof about a tree they invented. And
/// `verifier_key` must be one the caller derived themselves with [`setup`]: a
/// key accepted from the prover establishes nothing, for the same reason a root
/// accepted from the prover establishes nothing — both are the prover's own
/// claim about what is being proved.
pub fn verify(
    proof: &Snark,
    verifier_key: &VerifierKey,
    trusted_root: &[u8; 32],
) -> Result<(), ZkError> {
    let public_values = proof
        .verify(verifier_key)
        .map_err(|e| ZkError::Proving(format!("{e:?}")))?;
    if public_values != root_to_public_values(trusted_root) {
        return Err(ZkError::RootMismatch);
    }
    Ok(())
}

/// Serialise a proof for transport.
pub fn encode_proof(proof: &Snark) -> Result<Vec<u8>, ZkError> {
    bincode::serialize(proof).map_err(|e| ZkError::Decoding(e.to_string()))
}

/// Decode a proof. Malformed bytes are refused rather than partially accepted.
pub fn decode_proof(bytes: &[u8]) -> Result<Snark, ZkError> {
    bincode::deserialize(bytes).map_err(|e| ZkError::Decoding(e.to_string()))
}

/// Serialise a verifier key.
pub fn encode_verifier_key(key: &VerifierKey) -> Result<Vec<u8>, ZkError> {
    bincode::serialize(key).map_err(|e| ZkError::Decoding(e.to_string()))
}

/// Decode a verifier key.
///
/// Decoding a key says nothing about whether it should be trusted; see
/// [`verify`].
pub fn decode_verifier_key(bytes: &[u8]) -> Result<VerifierKey, ZkError> {
    bincode::deserialize(bytes).map_err(|e| ZkError::Decoding(e.to_string()))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use sha2::{Digest, Sha256};

    // A small MMR built here rather than driven through `MmrAccumulator`: the
    // accumulator is a `#[pyclass]` whose proof path is exercised elsewhere, and
    // a circuit test that shared its helper would pass whenever the two agreed
    // on a mistake. These three functions restate the v2 scheme from
    // `HashScheme::V2BinaryDomainSeparated`'s own documentation.

    fn leaf_hash(payload: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([DOMAIN_LEAF]);
        hasher.update(payload);
        hasher.finalize().into()
    }

    fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([DOMAIN_NODE]);
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    fn bagged_root(peaks: &[[u8; 32]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([DOMAIN_ROOT]);
        for peak in peaks {
            hasher.update(peak);
        }
        hasher.finalize().into()
    }

    /// Fold a perfect binary tree over `leaves`, returning its peak and the
    /// inclusion path for `index` as `(sibling, sibling_is_left)`.
    fn perfect_tree(leaves: &[[u8; 32]], index: usize) -> ([u8; 32], Vec<([u8; 32], bool)>) {
        let mut level = leaves.to_vec();
        let mut position = index;
        let mut path = Vec::new();
        while level.len() > 1 {
            let sibling = position ^ 1;
            path.push((level[sibling], sibling < position));
            level = level
                .chunks(2)
                .map(|pair| node_hash(&pair[0], &pair[1]))
                .collect();
            position /= 2;
        }
        (level[0], path)
    }

    /// A leaf whose canonical bytes record `waf_verdict = passed`.
    fn passed_leaf(prefix: &[u8]) -> ([u8; 32], Vec<u8>) {
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(PASSED_SUFFIX);
        (leaf_hash(&bytes), bytes)
    }

    const PREFIX: &[u8] = br#"{"endpoint":"/v1/chat","state_id":"s-1""#;

    struct Fixture {
        shape: ProofShape,
        /// The root the tree actually has, held so a test can assert the
        /// circuit derived the same one.
        root: [u8; 32],
        witness: Witness,
    }

    /// A four-leaf tree with one peak, proving leaf 0.
    fn fixture() -> Fixture {
        let (target, _) = passed_leaf(PREFIX);
        let leaves = [
            target,
            leaf_hash(b"other-1"),
            leaf_hash(b"other-2"),
            leaf_hash(b"other-3"),
        ];
        let (peak, path) = perfect_tree(&leaves, 0);
        let root = bagged_root(&[peak]);
        Fixture {
            shape: ProofShape {
                prefix_len: PREFIX.len(),
                path_depth: path.len(),
                peak_count: 1,
            },
            root,
            witness: Witness {
                prefix: PREFIX.to_vec(),
                siblings: path.iter().map(|(s, _)| *s).collect(),
                sibling_is_left: path.iter().map(|(_, l)| *l).collect(),
                peaks: vec![peak],
            },
        }
    }

    /// Synthesise against a witness and report whether every constraint holds.
    ///
    /// This is the circuit's logic under test without the cryptography on top.
    /// An unsatisfied system is exactly what makes `prove` fail, so a refusal
    /// here is the same refusal — reached in milliseconds instead of seconds.
    fn is_satisfied(circuit: &WafPassInclusionCircuit) -> bool {
        let mut cs = TestConstraintSystem::<Fr>::new();
        circuit
            .synthesize(&mut cs, &[], &[], None)
            .expect("synthesis must not error");
        cs.is_satisfied()
    }

    #[test]
    fn the_suffix_is_the_canonical_recorded_verdict() {
        // Mirrors `tests/test_waf_verdict_schema.py`'s
        // `test_a_recorded_verdict_only_appends`. If the Python builder ever
        // emits different bytes, the circuit would be proving a statement about
        // a leaf shape that no longer exists.
        assert_eq!(PASSED_SUFFIX, br#","waf_verdict":"passed"}"#);
        assert_eq!(PASSED_SUFFIX.len(), 24);
    }

    #[test]
    fn an_honest_witness_satisfies_the_circuit() {
        let f = fixture();
        let circuit = WafPassInclusionCircuit::new(f.shape, f.witness).unwrap();
        assert!(is_satisfied(&circuit));
    }

    #[test]
    fn the_leaf_the_circuit_commits_to_carries_the_verdict() {
        let f = fixture();
        let circuit = WafPassInclusionCircuit::new(f.shape, f.witness).unwrap();
        let leaf = circuit.leaf_bytes().unwrap();
        assert!(leaf.ends_with(PASSED_SUFFIX));
        assert_eq!(leaf_hash(&leaf), leaf_hash(&passed_leaf(PREFIX).1));
    }

    #[test]
    fn a_tampered_sibling_is_refused() {
        let f = fixture();
        let mut witness = f.witness;
        witness.siblings[0][0] ^= 0x01;
        let circuit = WafPassInclusionCircuit::new(f.shape, witness).unwrap();
        assert!(!is_satisfied(&circuit));
    }

    #[test]
    fn a_flipped_direction_is_refused() {
        // Directions are free, but not free of consequence: swapping one
        // reorders a node's children, which changes every digest above it.
        let f = fixture();
        let mut witness = f.witness;
        witness.sibling_is_left[0] = !witness.sibling_is_left[0];
        let circuit = WafPassInclusionCircuit::new(f.shape, witness).unwrap();
        assert!(!is_satisfied(&circuit));
    }

    #[test]
    fn a_leaf_outside_the_tree_is_refused() {
        let f = fixture();
        let mut witness = f.witness;
        witness.prefix[1] ^= 0x20;
        let circuit = WafPassInclusionCircuit::new(f.shape, witness).unwrap();
        assert!(!is_satisfied(&circuit));
    }

    #[test]
    fn a_blocked_leaf_cannot_be_proved_passed() {
        // The direction an attacker wants: a request the WAF refused, presented
        // as one it allowed. The leaf is genuinely in the tree; only its verdict
        // differs. Because the suffix is a circuit constant, no prefix makes the
        // hashed preimage equal the blocked leaf's bytes.
        let mut blocked = PREFIX.to_vec();
        blocked.extend_from_slice(br#","waf_verdict":"blocked"}"#);
        let leaves = [
            leaf_hash(&blocked),
            leaf_hash(b"other-1"),
            leaf_hash(b"other-2"),
            leaf_hash(b"other-3"),
        ];
        let (peak, path) = perfect_tree(&leaves, 0);

        let circuit = WafPassInclusionCircuit::new(
            ProofShape {
                prefix_len: PREFIX.len(),
                path_depth: path.len(),
                peak_count: 1,
            },
            Witness {
                prefix: PREFIX.to_vec(),
                siblings: path.iter().map(|(s, _)| *s).collect(),
                sibling_is_left: path.iter().map(|(_, l)| *l).collect(),
                peaks: vec![peak],
            },
        )
        .unwrap();
        assert!(!is_satisfied(&circuit));
    }

    #[test]
    fn a_leaf_with_no_recorded_verdict_cannot_be_proved_passed() {
        // The pre-change record. Its bytes stop at `"state_id":"s-1"}`, so the
        // same argument applies: the circuit can only hash preimages that end
        // with a recorded pass.
        let mut unrecorded = PREFIX.to_vec();
        unrecorded.push(b'}');
        let leaves = [
            leaf_hash(&unrecorded),
            leaf_hash(b"other-1"),
            leaf_hash(b"other-2"),
            leaf_hash(b"other-3"),
        ];
        let (peak, path) = perfect_tree(&leaves, 0);
        let circuit = WafPassInclusionCircuit::new(
            ProofShape {
                prefix_len: PREFIX.len(),
                path_depth: path.len(),
                peak_count: 1,
            },
            Witness {
                prefix: PREFIX.to_vec(),
                siblings: path.iter().map(|(s, _)| *s).collect(),
                sibling_is_left: path.iter().map(|(_, l)| *l).collect(),
                peaks: vec![peak],
            },
        )
        .unwrap();
        assert!(!is_satisfied(&circuit));
    }

    #[test]
    fn the_circuit_commits_to_the_root_the_tree_actually_has() {
        // There is no way to *declare* a root, so there is no test for declaring
        // a wrong one. What is testable is the property that replaces it: the
        // root is derived from the witness, so a caller can compare it against
        // the root they trust before proving anything.
        let f = fixture();
        let circuit = WafPassInclusionCircuit::new(f.shape, f.witness).unwrap();
        assert_eq!(circuit.committed_root(), Some(f.root));
    }

    #[test]
    fn a_tree_the_prover_built_themselves_commits_to_a_different_root() {
        // The two refusal paths are different and this is the second one.
        //
        // A *tampered* witness fails inside the circuit: the walk no longer
        // lands on a peak, so the constraints are unsatisfiable and no proof
        // exists (`a_tampered_sibling_is_refused`). It does not move the root,
        // because the root is bagged from the peaks rather than from the path.
        //
        // The attack that survives the circuit is a prover who builds an
        // entirely valid tree of their own, containing a leaf that genuinely
        // records a pass. Nothing about that proof is malformed. The only thing
        // that refuses it is the verifier holding a root from somewhere else —
        // which is why `verify` takes a trusted root and `CLM-044`'s
        // independent-root requirement carries over unchanged.
        let f = fixture();
        let (target, _) = passed_leaf(PREFIX);
        let (peak, path) = perfect_tree(
            &[
                target,
                leaf_hash(b"a leaf the prover invented"),
                leaf_hash(b"and another"),
                leaf_hash(b"and a third"),
            ],
            0,
        );
        let forged = WafPassInclusionCircuit::new(
            f.shape,
            Witness {
                prefix: PREFIX.to_vec(),
                siblings: path.iter().map(|(s, _)| *s).collect(),
                sibling_is_left: path.iter().map(|(_, l)| *l).collect(),
                peaks: vec![peak],
            },
        )
        .unwrap();

        // Internally consistent — the circuit cannot tell it is not the ledger.
        assert!(is_satisfied(&forged));
        // And useless against a root obtained independently.
        assert_ne!(forged.committed_root(), Some(f.root));
    }

    #[test]
    fn a_substituted_peak_set_is_refused() {
        let f = fixture();
        let mut witness = f.witness;
        witness.peaks[0] = leaf_hash(b"a peak the prover preferred");
        let circuit = WafPassInclusionCircuit::new(f.shape, witness).unwrap();
        assert!(!is_satisfied(&circuit));
    }

    #[test]
    fn a_multi_peak_tree_verifies_without_disclosing_which_peak() {
        // Six leaves: peaks of height 2 and 1. The circuit compares the walk
        // against every peak, so `peak_index` is not part of the shape.
        let (target, _) = passed_leaf(PREFIX);
        let first = [
            target,
            leaf_hash(b"o1"),
            leaf_hash(b"o2"),
            leaf_hash(b"o3"),
        ];
        let (peak_a, path) = perfect_tree(&first, 0);
        let (peak_b, _) = perfect_tree(&[leaf_hash(b"o4"), leaf_hash(b"o5")], 0);

        let circuit = WafPassInclusionCircuit::new(
            ProofShape {
                prefix_len: PREFIX.len(),
                path_depth: path.len(),
                peak_count: 2,
            },
            Witness {
                prefix: PREFIX.to_vec(),
                siblings: path.iter().map(|(s, _)| *s).collect(),
                sibling_is_left: path.iter().map(|(_, l)| *l).collect(),
                peaks: vec![peak_a, peak_b],
            },
        )
        .unwrap();
        assert!(is_satisfied(&circuit));
    }

    #[test]
    fn reordering_the_peaks_moves_the_root() {
        // Peak order is not constrained inside the circuit, and does not need to
        // be: bagging them in a different order produces a different root, which
        // is then not the root the verifier trusts. This is why step 4 of
        // `synthesize` carries no ordering check.
        let (target, _) = passed_leaf(PREFIX);
        let (peak_a, path) = perfect_tree(
            &[target, leaf_hash(b"o1"), leaf_hash(b"o2"), leaf_hash(b"o3")],
            0,
        );
        let (peak_b, _) = perfect_tree(&[leaf_hash(b"o4"), leaf_hash(b"o5")], 0);
        let shape = ProofShape {
            prefix_len: PREFIX.len(),
            path_depth: path.len(),
            peak_count: 2,
        };
        let witness = |peaks: Vec<[u8; 32]>| Witness {
            prefix: PREFIX.to_vec(),
            siblings: path.iter().map(|(s, _)| *s).collect(),
            sibling_is_left: path.iter().map(|(_, l)| *l).collect(),
            peaks,
        };

        let honest = WafPassInclusionCircuit::new(shape, witness(vec![peak_a, peak_b])).unwrap();
        let reordered = WafPassInclusionCircuit::new(shape, witness(vec![peak_b, peak_a])).unwrap();

        assert_eq!(honest.committed_root(), Some(bagged_root(&[peak_a, peak_b])));
        assert_ne!(reordered.committed_root(), honest.committed_root());
    }

    #[test]
    fn a_witness_that_disagrees_with_the_shape_is_refused_before_synthesis() {
        let f = fixture();
        let mut witness = f.witness.clone();
        witness.siblings.pop();
        let error = WafPassInclusionCircuit::new(f.shape, witness).unwrap_err();
        assert!(matches!(error, ZkError::ShapeMismatch(_)));

        let mut witness = f.witness.clone();
        witness.prefix.push(b'!');
        let error = WafPassInclusionCircuit::new(f.shape, witness).unwrap_err();
        assert!(matches!(error, ZkError::ShapeMismatch(_)));

        let mut witness = f.witness;
        witness.peaks.push([0u8; 32]);
        let error = WafPassInclusionCircuit::new(f.shape, witness).unwrap_err();
        assert!(matches!(error, ZkError::ShapeMismatch(_)));
    }

    #[test]
    fn root_packing_separates_digests_that_differ_anywhere() {
        // Two halves rather than one 256-bit value, because a 256-bit packing
        // would reduce modulo the ~255-bit field order and collide.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 0x80;
        assert_ne!(root_to_public_values(&a), root_to_public_values(&b));
        a[31] = 0x01;
        assert_ne!(root_to_public_values(&a), root_to_public_values(&[0u8; 32]));
        assert_eq!(root_to_public_values(&a).len(), 2);
    }

    #[test]
    fn the_shape_is_carried_on_the_circuit() {
        let f = fixture();
        let circuit = WafPassInclusionCircuit::new(f.shape, f.witness).unwrap();
        assert_eq!(circuit.shape(), f.shape);
        assert!(WafPassInclusionCircuit::shape_only(f.shape)
            .leaf_bytes()
            .is_none());
    }
}
