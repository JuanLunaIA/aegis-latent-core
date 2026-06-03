"""
aegis.core.mmr — Merkle Mountain Ranges (MMR).
Implements a mathematically rigorous, append-only Merkle structure
for efficient inclusion and consistency proofs.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MMRNode:
    hash: str
    height: int
    index: int
    left: int | None = None
    right: int | None = None
    parent: int | None = None


class MerkleMountainRange:
    """
    A production-hardened Merkle Mountain Range (MMR) implementation.
    Provides O(log N) inclusion proofs and O(log N) consistency proofs.
    """

    def __init__(self):
        self.nodes: list[MMRNode] = []
        self.peaks: list[MMRNode] = []
        self._leaf_count = 0

    def add_leaf(self, data: bytes) -> str:
        """
        Appends a new leaf and performs peak merging to maintain the MMR property.
        """
        leaf_hash = hashlib.sha256(data).hexdigest()
        new_node = MMRNode(hash=leaf_hash, height=0, index=len(self.nodes))
        self.nodes.append(new_node)
        self._leaf_count += 1

        current_node = new_node

        # Merge peaks of the same height
        while self.peaks and self.peaks[-1].height == current_node.height:
            old_peak = self.peaks.pop()

            # Create internal node (parent of the two peaks)
            combined_hash = hashlib.sha256((old_peak.hash + current_node.hash).encode()).hexdigest()
            new_height = old_peak.height + 1
            new_idx = len(self.nodes)

            parent_node = MMRNode(
                hash=combined_hash,
                height=new_height,
                index=new_idx,
                left=old_peak.index,
                right=current_node.index,
                parent=None,  # Will be set by children
            )

            # Update parent pointers
            old_peak.parent = new_idx
            current_node.parent = new_idx

            self.nodes.append(parent_node)
            current_node = parent_node

        self.peaks.append(current_node)
        return self.get_root_hash()

    def get_root_hash(self) -> str:
        """
        The root hash is the hash of the concatenated hashes of all current peaks,
        sorted by height descending to ensure a canonical representation.
        """
        if not self.peaks:
            return "0" * 64

        # Sort peaks by height descending for canonical root
        sorted_peaks = sorted(self.peaks, key=lambda p: p.height, reverse=True)
        combined = "".join([p.hash for p in sorted_peaks]).encode()
        return hashlib.sha256(combined).hexdigest()

    def get_inclusion_proof(self, leaf_index: int) -> list[tuple[str, str]]:
        """
        Generates a Merkle inclusion proof for a leaf at the given index.
        Returns a list of (sibling_hash, direction) tuples, where direction is 'L' or 'R'.
        """
        if leaf_index < 0 or leaf_index >= self._leaf_count:
            raise IndexError("Leaf index out of range")

        proof: list[tuple[str, str]] = []
        current_idx = leaf_index

        # Traverse up from the leaf to the highest peak it belongs to
        while True:
            node = self.nodes[current_idx]
            if node.parent is None:
                break

            parent = self.nodes[node.parent]
            if node.index == parent.left:
                # Current node is left child, sibling is right
                sibling = self.nodes[parent.right]
                proof.append((sibling.hash, "R"))
            else:
                # Current node is right child, sibling is left
                sibling = self.nodes[parent.left]
                proof.append((sibling.hash, "L"))

            current_idx = parent.index

        return proof

    def verify_inclusion(
        self, leaf_data: bytes, leaf_index: int, proof: list[tuple[str, str]], root: str
    ) -> bool:
        """
        Verifies that leaf_data is part of the MMR root.
        """
        current_hash = hashlib.sha256(leaf_data).hexdigest()

        for sibling_hash, direction in proof:
            if direction == "R":
                combined = (current_hash + sibling_hash).encode()
            else:
                combined = (sibling_hash + current_hash).encode()
            current_hash = hashlib.sha256(combined).hexdigest()

        # In an MMR, the leaf's proof leads to one of the peaks.
        # We check if the resulting hash is one of the current peaks.
        peak_hashes = {p.hash for p in self.peaks}
        if current_hash not in peak_hashes:
            return False

        # Finally, verify that the set of peaks produces the provided root.
        sorted_peaks = sorted(self.peaks, key=lambda p: p.height, reverse=True)
        combined = "".join([p.hash for p in sorted_peaks]).encode()
        actual_root = hashlib.sha256(combined).hexdigest()

        return actual_root == root

    def get_consistency_proof(self, old_root: str, old_count: int) -> tuple[str, list[str]]:
        """
        Compute a simple consistency proof for an earlier MMR root given the
        previous leaf count. This returns the current root plus the list of
        peak hashes that reconstruct the canonical root for `old_count` leaves.

        The caller can recompute the old root by hashing the concatenated peaks
        (sorted by height descending) and compare against the supplied `old_root`.
        """
        if old_count < 0 or old_count > self._leaf_count:
            raise ValueError("old_count out of range")

        if old_count == 0:
            old_peaks: list[MMRNode] = []
        else:
            # Collect the first `old_count` leaf hashes (in insertion order).
            leaf_hashes: list[str] = []
            for n in self.nodes:
                if n.height == 0:
                    leaf_hashes.append(n.hash)
                    if len(leaf_hashes) >= old_count:
                        break

            # Rebuild temporary peaks from those leaf hashes
            temp_peaks: list[MMRNode] = []
            for lh in leaf_hashes:
                node_hash = lh
                node_height = 0
                # Merge with the last peak while heights match
                while temp_peaks and temp_peaks[-1].height == node_height:
                    left = temp_peaks.pop()
                    combined = hashlib.sha256((left.hash + node_hash).encode()).hexdigest()
                    node_hash = combined
                    node_height += 1
                temp_peaks.append(MMRNode(hash=node_hash, height=node_height, index=-1))

            # Canonicalize peaks by height descending
            sorted_peaks = sorted(temp_peaks, key=lambda p: p.height, reverse=True)
            old_peaks = sorted_peaks

        proof_hashes = [p.hash for p in old_peaks]
        return self.get_root_hash(), proof_hashes


mmr_manager = MerkleMountainRange()
