// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! End-to-end: a real Spartan setup, a real proof, a real verification.
//!
//! Separate from the unit tests in `src/zk_mmr.rs` because these cost seconds
//! rather than milliseconds. Those tests check the circuit's *logic* by asking
//! whether the constraint system is satisfied, which is the same question
//! proving asks and answers far faster. These check that the logic survives
//! contact with the proving system — that a satisfiable circuit actually yields
//! a proof, that an unsatisfiable one yields none, and that verification refuses
//! a proof about the wrong tree.
//!
//! Run them with the feature and in release:
//!
//! ```text
//! cargo test --release --features zk-spartan --test zk_mmr_end_to_end
//! ```
//!
//! In a debug build the proving system is roughly an order of magnitude slower,
//! which is why `cargo test` without `--release` is not how this is exercised.

#![cfg(feature = "zk-spartan")]

use aegis_rust::zk_mmr::{
    decode_proof, decode_verifier_key, encode_proof, encode_verifier_key, prove, setup, verify,
    ProofShape, WafPassInclusionCircuit, Witness, ZkError, PASSED_SUFFIX,
};
use sha2::{Digest, Sha256};

fn leaf_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00u8]);
    hasher.update(payload);
    hasher.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

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

/// Deliberately small. The shape is what drives cost, and these tests are about
/// the pipeline rather than about scale — `docs/benchmarks` is where a cost
/// curve would belong, and none is claimed here.
const PREFIX: &[u8] = br#"{"endpoint":"/v1/chat","state_id":"s-1""#;

fn build(prefix: &[u8], others: [&[u8]; 3]) -> (ProofShape, [u8; 32], Witness) {
    let mut leaf = prefix.to_vec();
    leaf.extend_from_slice(PASSED_SUFFIX);
    let (peak, path) = perfect_tree(
        &[
            leaf_hash(&leaf),
            leaf_hash(others[0]),
            leaf_hash(others[1]),
            leaf_hash(others[2]),
        ],
        0,
    );
    let mut hasher = Sha256::new();
    hasher.update([0x02u8]);
    hasher.update(peak);
    let root: [u8; 32] = hasher.finalize().into();

    (
        ProofShape {
            prefix_len: prefix.len(),
            path_depth: path.len(),
            peak_count: 1,
        },
        root,
        Witness {
            prefix: prefix.to_vec(),
            siblings: path.iter().map(|(s, _)| *s).collect(),
            sibling_is_left: path.iter().map(|(_, l)| *l).collect(),
            peaks: vec![peak],
        },
    )
}

#[test]
fn a_proof_round_trips_and_verifies_against_the_true_root() {
    let (shape, root, witness) = build(PREFIX, [b"o1", b"o2", b"o3"]);
    let circuit = WafPassInclusionCircuit::new(shape, witness).unwrap();
    assert_eq!(circuit.committed_root(), Some(root));

    let (prover_key, verifier_key) = setup(shape).expect("setup");
    let proof = prove(&prover_key, &verifier_key, circuit).expect("prove");

    // Through the wire format, because that is how a proof actually travels.
    let encoded = encode_proof(&proof).expect("encode proof");
    let decoded = decode_proof(&encoded).expect("decode proof");
    let encoded_key = encode_verifier_key(&verifier_key).expect("encode key");
    let decoded_key = decode_verifier_key(&encoded_key).expect("decode key");

    verify(&decoded, &decoded_key, &root).expect("a valid proof must verify");
}

#[test]
fn verification_refuses_a_proof_about_another_tree() {
    // The construction's load-bearing requirement, exercised rather than
    // asserted: the proof is genuine, the circuit is satisfied, the prover did
    // nothing malformed. It is refused solely because the verifier holds a root
    // the prover did not produce.
    let (shape, honest_root, _) = build(PREFIX, [b"o1", b"o2", b"o3"]);
    let (_, forged_root, forged_witness) = build(PREFIX, [b"x1", b"x2", b"x3"]);
    assert_ne!(honest_root, forged_root);

    let circuit = WafPassInclusionCircuit::new(shape, forged_witness).unwrap();
    let (prover_key, verifier_key) = setup(shape).expect("setup");
    let proof = prove(&prover_key, &verifier_key, circuit).expect("the forged tree is internally valid");

    verify(&proof, &verifier_key, &forged_root).expect("valid against its own root");
    let error = verify(&proof, &verifier_key, &honest_root)
        .expect_err("must refuse against an independently obtained root");
    assert!(matches!(error, ZkError::RootMismatch), "got {error:?}");
}

#[test]
fn an_unsatisfiable_witness_produces_no_usable_proof() {
    // A tampered sibling breaks the walk to the peak, so no proof should exist.
    //
    // The refusal comes from `prove`'s self-check, and this test is the reason
    // that check is there. `Snark::prove` itself returns `Ok` for this witness:
    // the proving system is not a satisfiability oracle, and hands back a proof
    // object regardless. Soundness is intact — the object verifies against
    // nothing, asserted below against both the honest root and an arbitrary one
    // — but without the self-check a caller would ship bytes that only a third
    // party discovers are worthless.
    let (shape, honest_root, mut witness) = build(PREFIX, [b"o1", b"o2", b"o3"]);
    witness.siblings[0][0] ^= 0x01;
    let circuit = WafPassInclusionCircuit::new(shape, witness).unwrap();

    let (prover_key, verifier_key) = setup(shape).expect("setup");
    let error = prove(&prover_key, &verifier_key, circuit)
        .expect_err("an unsatisfiable witness must not yield a proof");
    assert!(matches!(error, ZkError::Proving(_)), "got {error:?}");
    assert!(
        format!("{error}").contains("does not satisfy the circuit"),
        "the error must name the cause: {error}"
    );
    let _ = honest_root;
}

#[test]
fn a_proof_from_an_unsatisfiable_witness_verifies_against_nothing() {
    // The soundness property the self-check above rests on, stated directly:
    // even reaching past `prove` into the raw proving system, the bytes that
    // come back are inert. Measured rather than assumed.
    use aegis_rust::zk_mmr::Snark;
    use spartan2::traits::snark::R1CSSNARKTrait;

    let (shape, honest_root, mut witness) = build(PREFIX, [b"o1", b"o2", b"o3"]);
    witness.siblings[0][0] ^= 0x01;
    let circuit = WafPassInclusionCircuit::new(shape, witness).unwrap();
    let (prover_key, verifier_key) = setup(shape).expect("setup");

    let prepared = Snark::prep_prove(&prover_key, circuit.clone(), false).expect("prep");
    let raw = Snark::prove(&prover_key, circuit, prepared, false);

    if let Ok((proof, _)) = raw {
        assert!(
            verify(&proof, &verifier_key, &honest_root).is_err(),
            "a proof of an unsatisfied circuit must not verify"
        );
        let mut arbitrary = [0u8; 32];
        arbitrary[0] = 0xAB;
        assert!(
            verify(&proof, &verifier_key, &arbitrary).is_err(),
            "nor against any other root"
        );
    }
}

#[test]
fn a_blocked_leaf_yields_no_passed_proof() {
    // The whole point of the circuit, end to end. The leaf is in the tree and
    // the tree is real; only the recorded verdict differs.
    let mut blocked = PREFIX.to_vec();
    blocked.extend_from_slice(br#","waf_verdict":"blocked"}"#);
    let (peak, path) = perfect_tree(
        &[
            leaf_hash(&blocked),
            leaf_hash(b"o1"),
            leaf_hash(b"o2"),
            leaf_hash(b"o3"),
        ],
        0,
    );
    let shape = ProofShape {
        prefix_len: PREFIX.len(),
        path_depth: path.len(),
        peak_count: 1,
    };
    let circuit = WafPassInclusionCircuit::new(
        shape,
        Witness {
            prefix: PREFIX.to_vec(),
            siblings: path.iter().map(|(s, _)| *s).collect(),
            sibling_is_left: path.iter().map(|(_, l)| *l).collect(),
            peaks: vec![peak],
        },
    )
    .unwrap();

    let (prover_key, verifier_key) = setup(shape).expect("setup");
    assert!(
        prove(&prover_key, &verifier_key, circuit).is_err(),
        "a blocked leaf must not yield a proof of a pass"
    );
}

#[test]
fn key_derivation_is_a_function_of_the_shape_alone() {
    // What makes the transparent setup usable: a verifier derives their own key
    // from public shape and does not have to accept one from the prover. If this
    // were not deterministic, `verify`'s insistence on a self-derived key would
    // be unimplementable.
    let (shape, root, witness) = build(PREFIX, [b"o1", b"o2", b"o3"]);
    let (prover_key, own_key) = setup(shape).expect("first setup");
    let (_, independent_key) = setup(shape).expect("second, independent setup");

    let circuit = WafPassInclusionCircuit::new(shape, witness).unwrap();
    let proof = prove(&prover_key, &own_key, circuit).expect("prove");

    verify(&proof, &independent_key, &root)
        .expect("a key derived independently must verify the same proof");
}

#[test]
fn malformed_bytes_are_refused_rather_than_partially_decoded() {
    let error = decode_proof(b"not a proof").expect_err("must refuse");
    assert!(matches!(error, ZkError::Decoding(_)), "got {error:?}");
    // `expect_err` is unavailable here: `SpartanVerifierKey` is not `Debug`, so
    // the success arm cannot be formatted.
    match decode_verifier_key(b"not a key") {
        Err(ZkError::Decoding(_)) => {}
        Err(other) => panic!("wrong error: {other:?}"),
        Ok(_) => panic!("malformed key bytes must not decode"),
    }
}
