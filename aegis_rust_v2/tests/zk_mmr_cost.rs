// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Cost of the circuit, measured rather than asserted.
//!
//! `#[ignore]` by default: this is a measurement harness, not a gate, and it
//! takes minutes. Run it deliberately:
//!
//! ```text
//! cargo test --release --features zk-spartan --test zk_mmr_cost -- --ignored --nocapture
//! ```
//!
//! **Numbers printed here are attributable to the host that printed them and to
//! nothing else.** They are not a performance claim, and `docs/CLAIMS_MATRIX.md`
//! carries no row asserting one. What they *are* for is establishing the shape
//! of the cost curve, because that curve is what decides whether a given
//! deployment can use this at all — the leaf length term dominates, and a
//! gateway running the default `max_forensic_bytes` produces leaves far past
//! anything provable.

#![cfg(feature = "zk-spartan")]

use aegis_rust::zk_mmr::{encode_proof, prove, setup, verify, ProofShape, Witness};
use aegis_rust::zk_mmr::{WafPassInclusionCircuit, PASSED_SUFFIX};
use sha2::{Digest, Sha256};
use std::time::Instant;

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

/// A witness of the requested shape over a synthetic but structurally real tree.
fn witness_of(shape: ProofShape) -> ([u8; 32], Witness) {
    let mut leaf = vec![b'x'; shape.prefix_len];
    leaf.extend_from_slice(PASSED_SUFFIX);

    let mut current = leaf_hash(&leaf);
    let mut siblings = Vec::new();
    let mut directions = Vec::new();
    for level in 0..shape.path_depth {
        let sibling = leaf_hash(format!("sibling-{level}").as_bytes());
        siblings.push(sibling);
        directions.push(level % 2 == 1);
        current = if level % 2 == 1 {
            node_hash(&sibling, &current)
        } else {
            node_hash(&current, &sibling)
        };
    }

    let mut peaks = vec![current];
    for index in 1..shape.peak_count {
        peaks.push(leaf_hash(format!("peak-{index}").as_bytes()));
    }

    let mut hasher = Sha256::new();
    hasher.update([0x02u8]);
    for peak in &peaks {
        hasher.update(peak);
    }
    let root: [u8; 32] = hasher.finalize().into();

    (
        root,
        Witness {
            prefix: vec![b'x'; shape.prefix_len],
            siblings,
            sibling_is_left: directions,
            peaks,
        },
    )
}

fn measure(label: &str, shape: ProofShape) {
    let (root, witness) = witness_of(shape);
    let circuit = WafPassInclusionCircuit::new(shape, witness).expect("witness matches shape");
    assert_eq!(circuit.committed_root(), Some(root));

    let started = Instant::now();
    let (prover_key, verifier_key) = match setup(shape) {
        Ok(keys) => keys,
        Err(error) => {
            println!("{label:<34} SETUP FAILED: {error}");
            return;
        }
    };
    let setup_ms = started.elapsed().as_millis();

    let started = Instant::now();
    let proof = match prove(&prover_key, &verifier_key, circuit) {
        Ok(proof) => proof,
        Err(error) => {
            println!("{label:<34} PROVE FAILED: {error}");
            return;
        }
    };
    // Includes `prove`'s own verification self-check.
    let prove_ms = started.elapsed().as_millis();

    let bytes = encode_proof(&proof).map(|b| b.len()).unwrap_or(0);

    let started = Instant::now();
    let verified = verify(&proof, &verifier_key, &root).is_ok();
    let verify_ms = started.elapsed().as_millis();

    println!(
        "{label:<34} setup={setup_ms:>7}ms  prove={prove_ms:>7}ms  \
         verify={verify_ms:>5}ms  proof={bytes:>8}B  ok={verified}"
    );
}

#[test]
#[ignore = "measurement harness; run deliberately with --ignored"]
fn cost_curve() {
    println!();
    println!("Leaf length dominates. Prefix lengths below are the canonical leaf");
    println!("minus the 24-byte verdict suffix, for a gateway configured with");
    println!("max_forensic_bytes = 0 (351), 64 (607) and 256 (1375).");
    println!();

    for prefix_len in [351usize, 607, 1375] {
        measure(
            &format!("prefix={prefix_len} depth=10 peaks=4"),
            ProofShape {
                prefix_len,
                path_depth: 10,
                peak_count: 4,
            },
        );
    }

    println!();
    println!("Path depth and peak count, at the smallest realistic leaf.");
    println!();

    for (depth, peaks) in [(4usize, 2usize), (10, 4), (20, 10)] {
        measure(
            &format!("prefix=351 depth={depth} peaks={peaks}"),
            ProofShape {
                prefix_len: 351,
                path_depth: depth,
                peak_count: peaks,
            },
        );
    }
}
