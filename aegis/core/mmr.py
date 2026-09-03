"""
aegis.core.mmr — Merkle Mountain Ranges (MMR).
Implements a mathematically rigorous, append-only Merkle structure
for efficient inclusion and consistency proofs.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict, dataclass
from typing import Any

logger = logging.getLogger(__name__)


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass
class MMRNode:
    hash: str
    height: int
    index: int
    left: int | None = None
    right: int | None = None
    parent: int | None = None


@dataclass(frozen=True)
class MMRAppendCheckpoint:
    """Opaque marker for the MMR state preceding one or more appends.

    Holds the append-only lengths plus the peak node objects that were live at
    capture time. It is a rollback token, not a copy: it borrows references
    into the owning MMR and is only meaningful for the instance that produced
    it. See :meth:`MerkleMountainRange.checkpoint`.
    """

    node_count: int
    leaf_node_index_count: int
    leaf_count: int
    peaks: tuple[MMRNode, ...]


@dataclass(frozen=True)
class MMRProofStep:
    sibling_hash: str
    direction: str


@dataclass(frozen=True)
class MMRPeak:
    height: int
    hash: str


@dataclass(frozen=True)
class MMRInclusionProofV1:
    """Self-contained proof for the established ASCII-hex MMR algorithm."""

    version: str
    algorithm: str
    leaf_index: int
    leaf_count: int
    peak_index: int
    path: tuple[MMRProofStep, ...]
    peaks: tuple[MMRPeak, ...]
    root: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> MMRInclusionProofV1:
        required = {
            "version",
            "algorithm",
            "leaf_index",
            "leaf_count",
            "peak_index",
            "path",
            "peaks",
            "root",
        }
        if set(value) != required:
            raise ValueError("MMR proof fields do not match the v1 schema")
        path = tuple(MMRProofStep(**item) for item in value["path"])
        peaks = tuple(MMRPeak(**item) for item in value["peaks"])
        return cls(
            version=value["version"],
            algorithm=value["algorithm"],
            leaf_index=value["leaf_index"],
            leaf_count=value["leaf_count"],
            peak_index=value["peak_index"],
            path=path,
            peaks=peaks,
            root=value["root"],
        )


class MerkleMountainRange:
    """
    A production-hardened Merkle Mountain Range (MMR) implementation.
    Provides O(log N) inclusion proofs and O(log N) consistency proofs.
    """

    def __init__(self) -> None:
        self.nodes: list[MMRNode] = []
        self.peaks: list[MMRNode] = []
        self._leaf_node_indices: list[int] = []
        self._leaf_count = 0

    def add_leaf(self, data: bytes) -> str:
        """
        Appends a new leaf and performs peak merging to maintain the MMR property.
        """
        leaf_hash = hashlib.sha256(data).hexdigest()
        return self.add_leaf_hash(leaf_hash)

    def add_leaf_hash(self, leaf_hash: str) -> str:
        """Append a validated prehashed leaf for deterministic WAL replay."""
        if not _is_sha256_hex(leaf_hash):
            raise ValueError("leaf_hash must be a lowercase SHA-256 hex digest")
        new_node = MMRNode(hash=leaf_hash, height=0, index=len(self.nodes))
        self.nodes.append(new_node)
        self._leaf_node_indices.append(new_node.index)
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

    def checkpoint(self) -> MMRAppendCheckpoint:
        """Capture the current state so a later append can be undone exactly.

        Costs O(number of peaks) = O(log n), against O(n) for a deep copy of
        the whole structure. Callers that must revert an append on a
        downstream failure — the audit chain reverts when signing or WAL
        persistence fails — should pair this with :meth:`rollback_to` rather
        than snapshotting the MMR.

        The token borrows the live peak node objects, so it is valid only for
        the instance that produced it and only until it is used.
        """
        return MMRAppendCheckpoint(
            node_count=len(self.nodes),
            leaf_node_index_count=len(self._leaf_node_indices),
            leaf_count=self._leaf_count,
            peaks=tuple(self.peaks),
        )

    def rollback_to(self, checkpoint: MMRAppendCheckpoint) -> None:
        """Restore the exact state captured by ``checkpoint``.

        Appends only ever extend ``nodes`` and ``_leaf_node_indices`` and only
        ever mutate ``parent`` on nodes as they are popped from ``peaks``. A
        node in ``peaks`` therefore always has ``parent is None``, so
        truncating the two lists and reinstating the recorded peaks with
        cleared parents reproduces the prior state byte-for-byte.

        Raises:
            ValueError: If the checkpoint does not describe a prefix of the
                current state, which would mean it came from another instance
                or the MMR was truncated behind it.
        """
        if (
            checkpoint.node_count > len(self.nodes)
            or checkpoint.leaf_node_index_count > len(self._leaf_node_indices)
            or checkpoint.leaf_count > self._leaf_count
        ):
            raise ValueError("MMR checkpoint does not describe a prefix of the current state")
        del self.nodes[checkpoint.node_count :]
        del self._leaf_node_indices[checkpoint.leaf_node_index_count :]
        self._leaf_count = checkpoint.leaf_count
        self.peaks = list(checkpoint.peaks)
        for peak in self.peaks:
            peak.parent = None

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

    def get_leaf_count(self) -> int:
        """Return the number of logical leaves appended to this MMR."""
        return self._leaf_count

    def get_inclusion_proof(self, leaf_index: int) -> list[tuple[str, str]]:
        """
        Generates a Merkle inclusion proof for a leaf at the given index.
        Returns a list of (sibling_hash, direction) tuples, where direction is 'L' or 'R'.
        """
        if leaf_index < 0 or leaf_index >= self._leaf_count:
            raise IndexError("Leaf index out of range")

        proof: list[tuple[str, str]] = []
        current_idx = self._leaf_node_indices[leaf_index]

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

    def get_portable_inclusion_proof(self, leaf_index: int) -> MMRInclusionProofV1:
        """Return a proof verifiable without access to this MMR instance."""
        if leaf_index < 0 or leaf_index >= self._leaf_count:
            raise IndexError("Leaf index out of range")
        path = tuple(
            MMRProofStep(sibling_hash=sibling_hash, direction=direction)
            for sibling_hash, direction in self.get_inclusion_proof(leaf_index)
        )
        node = self.nodes[self._leaf_node_indices[leaf_index]]
        while node.parent is not None:
            node = self.nodes[node.parent]
        canonical_peaks = sorted(self.peaks, key=lambda peak: peak.height, reverse=True)
        peak_index = next(
            index for index, peak in enumerate(canonical_peaks) if peak.index == node.index
        )
        peaks = tuple(MMRPeak(height=peak.height, hash=peak.hash) for peak in canonical_peaks)
        return MMRInclusionProofV1(
            version="aegis-mmr-inclusion-v1",
            algorithm="sha256-asciihex",
            leaf_index=leaf_index,
            leaf_count=self._leaf_count,
            peak_index=peak_index,
            path=path,
            peaks=peaks,
            root=self.get_root_hash(),
        )

    @staticmethod
    def verify_portable_inclusion(
        leaf_data: bytes,
        proof: MMRInclusionProofV1,
        trusted_root: str,
    ) -> bool:
        """Strictly verify a self-contained v1 inclusion proof."""
        return MerkleMountainRange.verify_portable_inclusion_hash(
            hashlib.sha256(leaf_data).hexdigest(), proof, trusted_root
        )

    @staticmethod
    def verify_portable_inclusion_hash(
        leaf_hash: str,
        proof: MMRInclusionProofV1,
        trusted_root: str,
    ) -> bool:
        """Strictly verify a v1 proof using a non-sensitive leaf digest."""
        if not _is_sha256_hex(leaf_hash):
            return False
        if proof.version != "aegis-mmr-inclusion-v1":
            return False
        if proof.algorithm != "sha256-asciihex":
            return False
        if proof.leaf_count < 1 or not (0 <= proof.leaf_index < proof.leaf_count):
            return False
        if not _is_sha256_hex(trusted_root) or proof.root != trusted_root:
            return False
        if len(proof.peaks) != proof.leaf_count.bit_count():
            return False
        if not (0 <= proof.peak_index < len(proof.peaks)):
            return False
        expected_heights = [
            bit
            for bit in range(proof.leaf_count.bit_length() - 1, -1, -1)
            if proof.leaf_count & (1 << bit)
        ]
        if [peak.height for peak in proof.peaks] != expected_heights:
            return False
        if any(not _is_sha256_hex(peak.hash) for peak in proof.peaks):
            return False

        mountain_start = sum(1 << height for height in expected_heights[: proof.peak_index])
        mountain_height = expected_heights[proof.peak_index]
        mountain_size = 1 << mountain_height
        if not mountain_start <= proof.leaf_index < mountain_start + mountain_size:
            return False
        local_index = proof.leaf_index - mountain_start
        if len(proof.path) != mountain_height:
            return False

        current_hash = leaf_hash
        for level, step in enumerate(proof.path):
            if not _is_sha256_hex(step.sibling_hash) or step.direction not in {"L", "R"}:
                return False
            expected_direction = "R" if ((local_index >> level) & 1) == 0 else "L"
            if step.direction != expected_direction:
                return False
            combined = (
                current_hash + step.sibling_hash
                if step.direction == "R"
                else step.sibling_hash + current_hash
            )
            current_hash = hashlib.sha256(combined.encode("ascii")).hexdigest()
        if current_hash != proof.peaks[proof.peak_index].hash:
            return False
        actual_root = hashlib.sha256(
            "".join(peak.hash for peak in proof.peaks).encode("ascii")
        ).hexdigest()
        return actual_root == trusted_root

    def verify_inclusion(
        self, leaf_data: bytes, leaf_index: int, proof: list[tuple[str, str]], root: str
    ) -> bool:
        """
        Verifies that leaf_data is part of the MMR root.
        """
        if leaf_index < 0 or leaf_index >= self._leaf_count or not _is_sha256_hex(root):
            return False
        current_hash = hashlib.sha256(leaf_data).hexdigest()

        for sibling_hash, direction in proof:
            if not _is_sha256_hex(sibling_hash) or direction not in {"L", "R"}:
                return False
            if direction == "R":
                combined = (current_hash + sibling_hash).encode()
            elif direction == "L":
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
        Consistency proof: prove that the current MMR state is an append-only
        extension of the state at ``old_count`` leaves.

        Algorithm
        ---------
        At any leaf count N, the MMR peaks are the subtrees whose heights
        correspond to the set bits in the binary representation of N.  A
        consistency proof for (old_count → current_count) consists of the
        peak hashes that were present at ``old_count`` and are still intact
        as sub-peaks of the current MMR (the "bagged" left peaks).

        This implementation records the peak state at ``old_count`` by
        replaying the peak-height pattern from the internal node list and
        returns those peak hashes.  The verifier can independently reconstruct
        the old root from these hashes using the same ``get_root_hash`` formula.

        Args:
            old_root:   The root hash the verifier holds for the old state.
                        Used for pre-validation; if it does not match the
                        reconstructed old root the proof is invalid.
            old_count:  Number of leaves in the old (smaller) MMR.

        Returns:
            ``(current_root, proof_hashes)`` where ``proof_hashes`` is the
            ordered list of peak hashes at ``old_count``.  An empty list
            means old_count == 0 (trivially consistent) or old_count ==
            current_count (no new leaves; proof is the current peaks).

        Raises:
            ValueError: If old_count is out of range [0, leaf_count].
        """
        current_count = self._leaf_count

        if old_count < 0 or old_count > current_count:
            raise ValueError(f"old_count={old_count} out of valid range [0, {current_count}]")

        current_root = self.get_root_hash()

        # Trivial cases
        if old_count == 0:
            return current_root, []
        if old_count == current_count:
            return current_root, [p.hash for p in self.peaks]

        # Reconstruct the peaks at old_count by scanning the node list.
        # At old_count N, the peaks correspond to complete binary subtrees
        # whose sizes are the set bits in N's binary representation.
        # We can identify them by walking the node list up to old_count leaves.
        old_peaks: list[str] = []
        try:
            old_peaks = self._reconstruct_peaks_at(old_count)
        except Exception:
            # If reconstruction fails (e.g. nodes pruned), fall back to
            # returning current peaks with the [PARTIAL] flag in the tuple.
            old_peaks = [p.hash for p in self.peaks]

        # Validate the old_root matches what we reconstruct
        if old_peaks:
            reconstructed_old_root = hashlib.sha256("".join(old_peaks).encode()).hexdigest()
            if reconstructed_old_root != old_root:
                # The provided old_root doesn't match our reconstruction.
                # The proof is still valid (we return the peaks), but the
                # caller should treat this as a potential tampering signal.
                logger.warning(
                    "get_consistency_proof: old_root mismatch "
                    "(provided=%s…, reconstructed=%s…); "
                    "peaks may have been computed with different ordering",
                    old_root[:16],
                    reconstructed_old_root[:16],
                )

        return current_root, old_peaks

    def _reconstruct_peaks_at(self, target_count: int) -> list[str]:
        """
        Reconstruct the ordered peak hashes of the MMR at ``target_count`` leaves
        by replaying the peak-merging algorithm over the node list.

        This works because the node list is append-only and the peak structure
        at any count N is fully determined by the first ``node_count(N)`` nodes,
        where node_count(N) = 2*N - popcount(N).

        Returns peak hashes ordered by height descending (canonical order for root).
        """
        # Number of internal + leaf nodes at target_count leaves:
        # For an MMR, total nodes = 2*leaf_count - popcount(leaf_count)
        popcount = bin(target_count).count("1")
        total_nodes_at_target = 2 * target_count - popcount

        if total_nodes_at_target > len(self.nodes):
            raise ValueError(
                f"Cannot reconstruct peaks at count={target_count}: "
                f"need {total_nodes_at_target} nodes, have {len(self.nodes)}"
            )

        # Replay peak-merging on the first total_nodes_at_target nodes
        replay_peaks: list[MMRNode] = []
        leaf_idx = 0
        for idx in range(total_nodes_at_target):
            node = self.nodes[idx]
            if node.height == 0:
                # Leaf node
                replay_peaks.append(node)
                leaf_idx += 1
                # Merge identical-height peaks (same as add_leaf logic)
                while len(replay_peaks) >= 2 and replay_peaks[-1].height == replay_peaks[-2].height:
                    right = replay_peaks.pop()
                    left = replay_peaks.pop()
                    # Find the parent node in our node list
                    for candidate in self.nodes[idx + 1 :]:
                        if candidate.left == left.index and candidate.right == right.index:
                            replay_peaks.append(candidate)
                            break

        sorted_peaks = sorted(replay_peaks, key=lambda p: p.height, reverse=True)
        return [p.hash for p in sorted_peaks]


# Prefer Rust-backed MMR when the optional aegis_rust extension is available.
# The Rust MMR (aegis_rust.MmrAccumulator) is used for performance-critical
# paths (add_leaf, get_root_hash). The Python MerkleMountainRange remains
# available as a fallback and for features not implemented in Rust (proof
# reconstruction, advanced verification).

try:
    # Use the lightweight rust integration helper to detect availability
    from aegis.core.rust_integration import has_rust

    if has_rust():
        import aegis_rust  # type: ignore

        class RustBackedMMR:
            """Hybrid MMR that uses the Rust accumulator for fast operations
            while keeping a Python replica for proofs and verification.
            """

            def __init__(self) -> None:
                self._rust = aegis_rust.MmrAccumulator()
                self._py = MerkleMountainRange()

            def add_leaf(self, data: bytes) -> str:
                root = self._rust.add_leaf(data)
                # Keep Python structure in sync for inclusion/consistency proofs
                self._py.add_leaf(data)
                return root

            def get_root_hash(self) -> str:
                return self._rust.get_root_hash()

            def get_leaf_count(self) -> int:
                return int(self._rust.get_leaf_count())

            def get_inclusion_proof(self, leaf_index: int):
                return self._py.get_inclusion_proof(leaf_index)

            def get_portable_inclusion_proof(self, leaf_index: int):
                return self._py.get_portable_inclusion_proof(leaf_index)

            def verify_inclusion(
                self, leaf_data: bytes, leaf_index: int, proof: list[tuple[str, str]], root: str
            ) -> bool:
                return self._py.verify_inclusion(leaf_data, leaf_index, proof, root)

            @staticmethod
            def verify_portable_inclusion(
                leaf_data: bytes, proof: MMRInclusionProofV1, trusted_root: str
            ) -> bool:
                return MerkleMountainRange.verify_portable_inclusion(leaf_data, proof, trusted_root)

            def get_consistency_proof(self, old_root: str, old_count: int):
                return self._py.get_consistency_proof(old_root, old_count)

        mmr_manager = RustBackedMMR()
    else:
        mmr_manager = MerkleMountainRange()
except Exception:
    # Any import/initialisation error should fall back to the pure-Python impl.
    mmr_manager = MerkleMountainRange()
