// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
use pyo3::prelude::*;
use sha2::{Digest, Sha256};

#[derive(Clone)]
#[allow(dead_code)]
struct MmrNode {
    hash: String,
    height: u32,
    index: usize,
    left: Option<usize>,
    right: Option<usize>,
    parent: Option<usize>,
}

/// Hash scheme identifiers, matching `aegis/core/mmr.py` byte for byte. The
/// Python side is the reference: a mismatch in either name or construction
/// makes an accelerated deployment disagree with a pure-Python one on every
/// root, which `tests/test_mmr_parity.py` exists to catch.
pub const HASH_SCHEME_V1: &str = "v1-asciihex";
pub const HASH_SCHEME_V2: &str = "v2-binary-domain-separated";

/// Domain tags for v2, per RFC 6962 §2.1.
const DOMAIN_LEAF: u8 = 0x00;
const DOMAIN_NODE: u8 = 0x01;
const DOMAIN_ROOT: u8 = 0x02;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashScheme {
    /// `leaf = SHA-256(payload)`, `node = SHA-256(ascii(left_hex) || ascii(right_hex))`.
    ///
    /// Neither input carries a tag distinguishing the two cases, so a leaf
    /// whose payload is the 128-character concatenation of two child digests
    /// hashes to the same value as the interior node over those children. That
    /// is the type confusion v2 exists to prevent. v1 remains the default
    /// because the scheme decides every root a chain has recorded.
    V1AsciiHex,
    /// `leaf = SHA-256(0x00 || payload)`,
    /// `node = SHA-256(0x01 || left32 || right32)`,
    /// `root = SHA-256(0x02 || peak_1_32 || … || peak_k_32)`.
    V2BinaryDomainSeparated,
}

impl HashScheme {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            HASH_SCHEME_V1 => Some(Self::V1AsciiHex),
            HASH_SCHEME_V2 => Some(Self::V2BinaryDomainSeparated),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::V1AsciiHex => HASH_SCHEME_V1,
            Self::V2BinaryDomainSeparated => HASH_SCHEME_V2,
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn leaf_hash(scheme: HashScheme, data: &[u8]) -> String {
    match scheme {
        HashScheme::V1AsciiHex => sha256_hex(data),
        HashScheme::V2BinaryDomainSeparated => {
            let mut hasher = Sha256::new();
            hasher.update([DOMAIN_LEAF]);
            hasher.update(data);
            hex::encode(hasher.finalize())
        }
    }
}

/// Decode a 64-character hex digest back to its 32 raw bytes.
///
/// Every digest in this accumulator is produced by `hex::encode` over a
/// SHA-256 output, so a decode failure means memory corruption or a caller
/// that reached past the public API, not bad input. Panicking is the honest
/// response: continuing would silently fold a wrong digest into the root.
fn digest_bytes(hex_digest: &str) -> [u8; 32] {
    let raw = hex::decode(hex_digest).expect("accumulator digest is not valid hex");
    <[u8; 32]>::try_from(raw.as_slice()).expect("accumulator digest is not 32 bytes")
}

fn combine_hashes(scheme: HashScheme, left: &str, right: &str) -> String {
    match scheme {
        HashScheme::V1AsciiHex => sha256_hex(format!("{left}{right}").as_bytes()),
        HashScheme::V2BinaryDomainSeparated => {
            let mut hasher = Sha256::new();
            hasher.update([DOMAIN_NODE]);
            hasher.update(digest_bytes(left));
            hasher.update(digest_bytes(right));
            hex::encode(hasher.finalize())
        }
    }
}

#[pyclass]
pub struct MmrAccumulator {
    nodes: Vec<MmrNode>,
    peaks: Vec<usize>,
    leaf_count: usize,
    scheme: HashScheme,
}

#[pymethods]
impl MmrAccumulator {
    /// Defaults to v1, matching `MerkleMountainRange()` on the Python side.
    /// An unknown scheme name is refused rather than silently defaulted: a
    /// typo that fell back to v1 would produce a chain whose roots disagree
    /// with what the caller asked for, discoverable only by verification
    /// failure much later.
    #[new]
    #[pyo3(signature = (hash_scheme=None))]
    fn new(hash_scheme: Option<&str>) -> PyResult<Self> {
        let name = hash_scheme.unwrap_or(HASH_SCHEME_V1);
        let scheme = HashScheme::from_name(name).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "hash_scheme must be one of [\"{HASH_SCHEME_V1}\", \"{HASH_SCHEME_V2}\"], \
                 got {name:?}"
            ))
        })?;
        Ok(Self::with_scheme(scheme))
    }

    fn add_leaf(&mut self, data: &[u8]) -> PyResult<String> {
        Ok(self.append_leaf(data))
    }

    fn get_root_hash(&self) -> String {
        self.root_hash()
    }

    fn get_leaf_count(&self) -> usize {
        self.leaf_count
    }

    #[getter]
    fn hash_scheme(&self) -> &'static str {
        self.scheme.name()
    }
}

impl MmrAccumulator {
    pub fn with_scheme(scheme: HashScheme) -> Self {
        Self {
            nodes: Vec::new(),
            peaks: Vec::new(),
            leaf_count: 0,
            scheme,
        }
    }

    pub fn scheme(&self) -> HashScheme {
        self.scheme
    }

    pub fn append_leaf(&mut self, data: &[u8]) -> String {
        let leaf_hash = leaf_hash(self.scheme, data);
        let new_idx = self.nodes.len();
        self.nodes.push(MmrNode {
            hash: leaf_hash,
            height: 0,
            index: new_idx,
            left: None,
            right: None,
            parent: None,
        });
        self.leaf_count += 1;

        let mut current_idx = new_idx;

        while let Some(&peak_idx) = self.peaks.last() {
            let peak = &self.nodes[peak_idx];
            let current = &self.nodes[current_idx];
            if peak.height != current.height {
                break;
            }
            self.peaks.pop();
            let old_peak_idx = peak_idx;

            let old_peak = self.nodes[old_peak_idx].clone();
            let current_node = self.nodes[current_idx].clone();
            let combined_hash = combine_hashes(self.scheme, &old_peak.hash, &current_node.hash);
            let new_height = old_peak.height + 1;
            let parent_idx = self.nodes.len();

            self.nodes.push(MmrNode {
                hash: combined_hash,
                height: new_height,
                index: parent_idx,
                left: Some(old_peak_idx),
                right: Some(current_idx),
                parent: None,
            });
            self.nodes[old_peak_idx].parent = Some(parent_idx);
            self.nodes[current_idx].parent = Some(parent_idx);
            current_idx = parent_idx;
        }

        self.peaks.push(current_idx);
        self.root_hash()
    }

    pub fn root_hash(&self) -> String {
        if self.peaks.is_empty() {
            return "0".repeat(64);
        }
        let mut peak_refs: Vec<&MmrNode> = self.peaks.iter().map(|&i| &self.nodes[i]).collect();
        peak_refs.sort_by_key(|p| std::cmp::Reverse(p.height));
        match self.scheme {
            HashScheme::V1AsciiHex => {
                let combined: String = peak_refs.iter().map(|p| p.hash.as_str()).collect();
                sha256_hex(combined.as_bytes())
            }
            HashScheme::V2BinaryDomainSeparated => {
                let mut hasher = Sha256::new();
                hasher.update([DOMAIN_ROOT]);
                for peak in &peak_refs {
                    hasher.update(digest_bytes(&peak.hash));
                }
                hex::encode(hasher.finalize())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_changes_root() {
        let mut mmr = MmrAccumulator::with_scheme(HashScheme::V1AsciiHex);
        let r0 = mmr.append_leaf(b"a");
        let r1 = mmr.append_leaf(b"b");
        assert_ne!(r0, r1);
        assert_eq!(r1, mmr.root_hash());
    }

    #[test]
    fn v2_append_changes_root() {
        let mut mmr = MmrAccumulator::with_scheme(HashScheme::V2BinaryDomainSeparated);
        let r0 = mmr.append_leaf(b"a");
        let r1 = mmr.append_leaf(b"b");
        assert_ne!(r0, r1);
        assert_eq!(r1, mmr.root_hash());
    }

    #[test]
    fn the_two_schemes_produce_different_roots() {
        // Not cosmetic: it is why an existing v1 chain cannot be reopened
        // under v2 without its own integrity check declaring it corrupt.
        let mut v1 = MmrAccumulator::with_scheme(HashScheme::V1AsciiHex);
        let mut v2 = MmrAccumulator::with_scheme(HashScheme::V2BinaryDomainSeparated);
        for leaf in [b"alpha".as_slice(), b"beta", b"gamma"] {
            v1.append_leaf(leaf);
            v2.append_leaf(leaf);
        }
        assert_ne!(v1.root_hash(), v2.root_hash());
    }

    /// The RFC 6962 §2.1 type confusion, on the accumulator that produces the
    /// roots a deployment records.
    ///
    /// Under v1 a leaf whose payload is the ASCII concatenation of two child
    /// digests hashes identically to the interior node over those children,
    /// so a verifier handed such a payload cannot tell a leaf from a node.
    /// Under v2 the leaf carries `0x00` and the node carries `0x01`, and the
    /// node consumes raw digests rather than their hex text, so the two
    /// inputs cannot collide by construction.
    #[test]
    fn v1_confuses_a_leaf_with_an_interior_node_and_v2_does_not() {
        let left = sha256_hex(b"left child");
        let right = sha256_hex(b"right child");

        let v1_node = combine_hashes(HashScheme::V1AsciiHex, &left, &right);
        let confusing_payload = format!("{left}{right}");
        let v1_leaf = leaf_hash(HashScheme::V1AsciiHex, confusing_payload.as_bytes());
        assert_eq!(
            v1_node, v1_leaf,
            "v1 must exhibit the confusion this test documents"
        );

        let v2_node = combine_hashes(HashScheme::V2BinaryDomainSeparated, &left, &right);
        let v2_leaf = leaf_hash(
            HashScheme::V2BinaryDomainSeparated,
            confusing_payload.as_bytes(),
        );
        assert_ne!(v2_node, v2_leaf);

        // Also for the raw-digest form of the same payload, which is what a v2
        // node actually hashes: tagging, not encoding, is what separates them.
        let mut raw = Vec::with_capacity(64);
        raw.extend_from_slice(&digest_bytes(&left));
        raw.extend_from_slice(&digest_bytes(&right));
        let v2_leaf_over_raw = leaf_hash(HashScheme::V2BinaryDomainSeparated, &raw);
        assert_ne!(v2_node, v2_leaf_over_raw);
    }

    #[test]
    fn scheme_names_round_trip_and_reject_unknown() {
        assert_eq!(
            HashScheme::from_name(HASH_SCHEME_V1),
            Some(HashScheme::V1AsciiHex)
        );
        assert_eq!(
            HashScheme::from_name(HASH_SCHEME_V2),
            Some(HashScheme::V2BinaryDomainSeparated)
        );
        assert_eq!(HashScheme::from_name("v3-imaginary"), None);
        assert_eq!(HashScheme::V1AsciiHex.name(), HASH_SCHEME_V1);
        assert_eq!(HashScheme::V2BinaryDomainSeparated.name(), HASH_SCHEME_V2);
    }

    #[test]
    fn an_empty_accumulator_has_the_zero_root_under_both_schemes() {
        for scheme in [HashScheme::V1AsciiHex, HashScheme::V2BinaryDomainSeparated] {
            let mmr = MmrAccumulator::with_scheme(scheme);
            assert_eq!(mmr.root_hash(), "0".repeat(64));
        }
    }
}
