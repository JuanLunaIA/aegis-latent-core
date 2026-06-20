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

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn combine_hashes(left: &str, right: &str) -> String {
    sha256_hex(format!("{left}{right}").as_bytes())
}

#[pyclass]
pub struct MmrAccumulator {
    nodes: Vec<MmrNode>,
    peaks: Vec<usize>,
    leaf_count: usize,
}

#[pymethods]
impl MmrAccumulator {
    #[new]
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            peaks: Vec::new(),
            leaf_count: 0,
        }
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
}

impl MmrAccumulator {
    pub fn append_leaf(&mut self, data: &[u8]) -> String {
        let leaf_hash = sha256_hex(data);
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
            let combined_hash = combine_hashes(&old_peak.hash, &current_node.hash);
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
        let combined: String = peak_refs.iter().map(|p| p.hash.as_str()).collect();
        sha256_hex(combined.as_bytes())
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_changes_root() {
        let mut mmr = MmrAccumulator::new();
        let r0 = mmr.append_leaf(b"a");
        let r1 = mmr.append_leaf(b"b");
        assert_ne!(r0, r1);
        assert_eq!(r1, mmr.root_hash());
    }
}
