"""
aegis.core.mmr — Merkle Mountain Ranges (MMR).
Implements a mathematically rigorous, append-only Merkle structure
for efficient inclusion and consistency proofs.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import base64
import binascii
import hashlib
import logging
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

logger = logging.getLogger(__name__)


class MMRHistoricalLeafUnavailableError(LookupError):
    """A leaf's in-memory proof path was discarded by a peak-set restore.

    Distinct from ``IndexError`` (a leaf that does not exist) because the leaf
    does exist and its proof is retrievable — from the ``mmr_proof`` stored on
    the committed audit node, which is self-contained. Raised rather than
    returning a partial path, which would not be a proof of anything.
    """


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


# ── Hash schemes ──────────────────────────────────────────────────────────────
#
# Two constructions exist, and which one a chain uses is recorded rather than
# assumed.
#
# ``v1-asciihex`` is the original: a leaf is ``SHA-256(payload)`` and a node is
# ``SHA-256(ascii(left_hex) || ascii(right_hex))``. Both are a bare SHA-256 over
# bytes with no tag distinguishing the two cases, so a *leaf whose payload
# happens to be the 128-character concatenation of two child digests hashes to
# the same value as the internal node over those children*. A verifier handed
# such a payload cannot tell a leaf from an interior node. That is the classic
# second-preimage / type-confusion weakness RFC 6962 §2.1 exists to prevent, and
# it is reachable here through ``verify_portable_inclusion``, which accepts
# caller-supplied leaf bytes.
#
# ``v2-binary-domain-separated`` fixes it the standard way: every hash input is
# prefixed with a one-byte domain tag, and interior hashing consumes the raw
# 32-byte digests rather than their hex text.
#
#     leaf   = SHA-256(0x00 || payload)
#     node   = SHA-256(0x01 || left_digest_32 || right_digest_32)
#     root   = SHA-256(0x02 || peak_1_32 || ... || peak_k_32)
#
# v1 is retained, and remains the default, because the scheme decides every root
# a chain has ever recorded. Switching an existing ledger would make its WAL
# replay to a different root and its own integrity check declare it corrupt —
# an unrecoverable outcome for the evidence this system exists to hold. Proofs
# carry their scheme so a verifier never has to guess.
#
# Two prerequisites remain before a *ledger* may select v2, and both are
# unmet today, which is why ``CryptographicAuditLedger`` does not expose the
# choice:
#
#   1. ``aegis_rust``'s accumulator implements v1 only (``aegis_rust_v2/src/
#      mmr.rs`` hashes ``format!("{left}{right}")``). An accelerated deployment
#      running Python v2 against the Rust root would disagree on every root,
#      and ``tests/test_mmr_parity.py`` exists precisely to catch that class of
#      divergence.
#   2. Existing chains need a migration story — a new chain, or a recorded
#      scheme transition — since a root cannot be recomputed under a different
#      construction without rewriting history.
#
# Until both land, v2 is available to callers constructing their own
# accumulator and to verifiers checking v2 proofs, which is what makes the
# construction reviewable before anything depends on it.
HASH_SCHEME_V1: str = "v1-asciihex"
HASH_SCHEME_V2: str = "v2-binary-domain-separated"
_HASH_SCHEMES: frozenset[str] = frozenset({HASH_SCHEME_V1, HASH_SCHEME_V2})

MMR_PROOF_VERSION_V1: str = "aegis-mmr-inclusion-v1"
MMR_PROOF_VERSION_V2: str = "aegis-mmr-inclusion-v2"
MMR_ALGORITHM_V1: str = "sha256-asciihex"
MMR_ALGORITHM_V2: str = "sha256-binary-domain-separated"

_DOMAIN_LEAF: bytes = b"\x00"
_DOMAIN_NODE: bytes = b"\x01"
_DOMAIN_ROOT: bytes = b"\x02"

# RFC 4648 §5 base64url alphabet, without padding. Checked explicitly because
# ``urlsafe_b64decode`` also accepts standard-base64 ``+`` and ``/``.
_B64U_ALPHABET: frozenset[str] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _hex_to_b64u(value: str) -> str:
    """Encode a 32-byte hex digest as unpadded base64url for the v2 wire form."""
    return base64.urlsafe_b64encode(bytes.fromhex(value)).decode("ascii").rstrip("=")


def _b64u_to_hex(value: object) -> str:
    """Decode an unpadded base64url v2 digest back to lowercase hex.

    Strict in three ways, each closing a distinct way a wire digest could be
    written more than one way:

    - The alphabet is base64url only. ``urlsafe_b64decode`` silently accepts
      standard-base64 ``+`` and ``/``, which the TypeScript parser refuses, so
      without this check the same document parses in Python and fails in
      TypeScript.
    - The encoding must be canonical. 43 characters carry 258 bits for a
      256-bit digest, so the two spare bits in the final character are free:
      ``…8`` and ``…9`` decode to identical bytes. Re-encoding and comparing
      rejects every non-canonical spelling, leaving exactly one wire form per
      digest.
    - It must decode to exactly 32 bytes.

    A digest that cannot be decoded is a malformed proof, not a proof that
    happens to fail, so this raises rather than returning a value that would
    quietly fail to verify later.
    """
    if not isinstance(value, str) or len(value) != 43:
        raise ValueError("v2 proof digests must be 43-character unpadded base64url")
    if not _B64U_ALPHABET.issuperset(value):
        raise ValueError("v2 proof digests must use the base64url alphabet")
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error) as exc:
        raise ValueError("v2 proof digest is not valid base64url") from exc
    if len(raw) != 32:
        raise ValueError("v2 proof digests must decode to 32 bytes")
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("v2 proof digest is not canonically encoded")
    return raw.hex()


def _identity_hex(value: object) -> str:
    """Pass a v1 hex digest through unchanged, rejecting a non-string."""
    if not isinstance(value, str):
        raise ValueError("v1 proof digests must be hex strings")
    return value


def v2_leaf_hash(payload: bytes) -> bytes:
    """``SHA-256(0x00 || payload)`` — the domain-separated leaf digest."""
    return hashlib.sha256(_DOMAIN_LEAF + payload).digest()


def v2_node_hash(left: bytes, right: bytes) -> bytes:
    """``SHA-256(0x01 || left || right)`` over raw 32-byte digests."""
    if len(left) != 32 or len(right) != 32:
        raise ValueError("v2 node hashing requires two 32-byte digests")
    return hashlib.sha256(_DOMAIN_NODE + left + right).digest()


def v2_bagged_root(peaks: Sequence[bytes]) -> bytes:
    """``SHA-256(0x02 || peak_1 || ... || peak_k)`` over raw 32-byte digests.

    Peaks are consumed in the order given; callers bag height-descending, which
    is the canonical order the accumulator maintains.
    """
    if any(len(peak) != 32 for peak in peaks):
        raise ValueError("v2 root bagging requires 32-byte digests")
    return hashlib.sha256(_DOMAIN_ROOT + b"".join(peaks)).digest()


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
        """Serialise to the wire form for this proof's version.

        Digests live in the dataclass as lowercase hex — the canonical internal
        form every other component already validates and stores. Only the wire
        encoding differs by version: v2 transmits the raw 32 bytes as unpadded
        base64url, which is the same digest in 43 characters instead of 64. The
        encoding carries no security property; the second-preimage fix is the
        domain separation, not the transport.
        """
        document = asdict(self)
        if self.version != MMR_PROOF_VERSION_V2:
            return document
        document["root"] = _hex_to_b64u(self.root)
        for step, source in zip(document["path"], self.path, strict=True):
            step["sibling_hash"] = _hex_to_b64u(source.sibling_hash)
        for peak, origin in zip(document["peaks"], self.peaks, strict=True):
            peak["hash"] = _hex_to_b64u(origin.hash)
        return document

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
            raise ValueError("MMR proof fields do not match the proof schema")
        # The field *set* matching is not the field *types* matching. A proof
        # arrives as attacker-controlled JSON, where `"leaf_count": ""` is as
        # easy to send as a number, and the comparisons in
        # `verify_portable_inclusion_hash` then raise TypeError instead of
        # returning False. A verifier that throws on malformed input is a
        # denial of service against the auditor, and an exception caught too
        # broadly one frame up becomes an accidental "valid".
        #
        # `bool` is excluded explicitly because it is an `int` subclass, so
        # `True` would otherwise pass as a leaf index of 1.
        for field in ("leaf_index", "leaf_count", "peak_index"):
            if not isinstance(value[field], int) or isinstance(value[field], bool):
                raise ValueError(f"MMR proof field {field!r} must be an integer")
        # v2 transmits digests as unpadded base64url; decode back to the hex the
        # dataclass and every downstream check use. An undecodable digest raises
        # here rather than surviving as a value that silently fails to verify.
        decode = _b64u_to_hex if value["version"] == MMR_PROOF_VERSION_V2 else _identity_hex
        path = tuple(
            MMRProofStep(sibling_hash=decode(item["sibling_hash"]), direction=item["direction"])
            for item in value["path"]
        )
        peaks = tuple(
            MMRPeak(height=item["height"], hash=decode(item["hash"])) for item in value["peaks"]
        )
        return cls(
            version=value["version"],
            algorithm=value["algorithm"],
            leaf_index=value["leaf_index"],
            leaf_count=value["leaf_count"],
            peak_index=value["peak_index"],
            path=path,
            peaks=peaks,
            root=decode(value["root"]),
        )


class MerkleMountainRange:
    """
    A production-hardened Merkle Mountain Range (MMR) implementation.
    Provides O(log N) inclusion proofs and O(log N) consistency proofs.
    """

    def __init__(self, *, hash_scheme: str = HASH_SCHEME_V1) -> None:
        if hash_scheme not in _HASH_SCHEMES:
            raise ValueError(
                f"hash_scheme must be one of {sorted(_HASH_SCHEMES)}, got {hash_scheme!r}"
            )
        # Defaults to v1 deliberately: the scheme determines every root the
        # chain records, so an existing ledger must keep the one it was built
        # with or its own replay check will reject it. See the scheme notes.
        self.hash_scheme = hash_scheme
        self.nodes: list[MMRNode] = []
        self.peaks: list[MMRNode] = []
        self._leaf_node_indices: list[int] = []
        self._leaf_count = 0
        # Logical index of the first leaf whose interior nodes are materialised
        # in ``nodes``. Zero for an accumulator built entirely by appending.
        # After :meth:`restore_from_peaks` it equals the restored leaf count:
        # the leaves below it are summarised by the restored peak hashes and
        # are not individually addressable in memory. See that method.
        self._leaf_index_base = 0

    @property
    def leaf_index_base(self) -> int:
        """First logical leaf index whose in-memory inclusion proof is derivable."""
        return self._leaf_index_base

    def add_leaf(self, data: bytes) -> str:
        """
        Appends a new leaf and performs peak merging to maintain the MMR property.
        """
        if self.hash_scheme == HASH_SCHEME_V2:
            leaf_hash = v2_leaf_hash(data).hex()
        else:
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
            if self.hash_scheme == HASH_SCHEME_V2:
                combined_hash = v2_node_hash(
                    bytes.fromhex(old_peak.hash), bytes.fromhex(current_node.hash)
                ).hex()
            else:
                combined_hash = hashlib.sha256(
                    (old_peak.hash + current_node.hash).encode()
                ).hexdigest()
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

    def restore_from_peaks(self, *, leaf_count: int, peaks: Sequence[MMRPeak]) -> str:
        """Reseat an empty accumulator on a persisted peak set in O(log N).

        Rebuilding an MMR by replaying N leaves costs O(N log N) time and holds
        O(N) interior nodes. A peak set is the complete summary of those leaves
        for every purpose this accumulator serves after a restart: appending,
        computing the root, and proving inclusion of the leaves appended next.
        Restoring it directly costs O(number of peaks) = O(log N).

        What is given up is precise and bounded: the leaves below ``leaf_count``
        are summarised by peak hashes and are no longer individually
        addressable, so :meth:`get_inclusion_proof` raises
        :class:`MMRHistoricalLeafUnavailableError` for them. Their proofs are
        not lost — every committed node carries its own ``mmr_proof``, which is
        self-contained and verifies against a trusted root without this
        instance. The ledger never asks the live accumulator for a historical
        proof; it only ever proves the leaf it just appended.

        Proofs issued after a restore are unaffected. The portable verifier is
        structural: it derives peak heights from ``leaf_count``'s set bits and
        locates the leaf's mountain from them, so a proof whose logical
        ``leaf_index``, ``leaf_count`` and peak hashes are correct verifies
        identically whether the accumulator was appended to or restored.

        Args:
            leaf_count: Number of logical leaves the peak set summarises.
            peaks: Peaks in canonical order — descending height. Their heights
                must equal the set bits of ``leaf_count``, descending, which is
                the same invariant ``verify_portable_inclusion_hash`` enforces.

        Returns:
            The bagged root of the restored peak set.

        Raises:
            ValueError: If this accumulator is not empty, or the peak set is not
                a structurally valid summary of exactly ``leaf_count`` leaves.
                Both are fail-closed: a caller that cannot restore must replay.
        """
        if self.nodes or self.peaks or self._leaf_count:
            raise ValueError("restore_from_peaks requires an empty accumulator")
        if leaf_count < 1:
            raise ValueError("restore_from_peaks requires leaf_count >= 1")

        expected_heights = [
            bit for bit in range(leaf_count.bit_length() - 1, -1, -1) if leaf_count & (1 << bit)
        ]
        if [peak.height for peak in peaks] != expected_heights:
            raise ValueError(
                "peak heights do not match the set bits of leaf_count "
                f"(expected {expected_heights}, got {[peak.height for peak in peaks]})"
            )
        if any(not _is_sha256_hex(peak.hash) for peak in peaks):
            raise ValueError("every restored peak hash must be a lowercase SHA-256 hex digest")

        for peak in peaks:
            node = MMRNode(hash=peak.hash, height=peak.height, index=len(self.nodes))
            self.nodes.append(node)
            self.peaks.append(node)
        self._leaf_count = leaf_count
        self._leaf_index_base = leaf_count
        return self.get_root_hash()

    def _physical_leaf_node_index(self, leaf_index: int) -> int:
        """Map a logical leaf index to its node index, or refuse to guess."""
        if leaf_index < 0 or leaf_index >= self._leaf_count:
            raise IndexError("Leaf index out of range")
        physical = leaf_index - self._leaf_index_base
        if physical < 0:
            raise MMRHistoricalLeafUnavailableError(
                f"leaf {leaf_index} predates this accumulator's restore point "
                f"({self._leaf_index_base}); it is summarised by a restored peak. "
                "Use the mmr_proof stored on the committed node."
            )
        return self._leaf_node_indices[physical]

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
        if self.hash_scheme == HASH_SCHEME_V2:
            return v2_bagged_root([bytes.fromhex(p.hash) for p in sorted_peaks]).hex()
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
        proof: list[tuple[str, str]] = []
        current_idx = self._physical_leaf_node_index(leaf_index)

        # Traverse up from the leaf to the highest peak it belongs to
        while True:
            node = self.nodes[current_idx]
            if node.parent is None:
                break

            parent = self.nodes[node.parent]
            # An internal node is only ever created with both children set
            # (`_add_parent`), so a half-linked parent means the accumulator is
            # corrupt. Raise rather than index with None: the proof this would
            # return is not a proof of anything.
            if parent.left is None or parent.right is None:
                raise ValueError(
                    f"MMR node {parent.index} is an internal node with a missing child link"
                )
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
        node = self.nodes[self._physical_leaf_node_index(leaf_index)]
        path = tuple(
            MMRProofStep(sibling_hash=sibling_hash, direction=direction)
            for sibling_hash, direction in self.get_inclusion_proof(leaf_index)
        )
        while node.parent is not None:
            node = self.nodes[node.parent]
        canonical_peaks = sorted(self.peaks, key=lambda peak: peak.height, reverse=True)
        peak_index = next(
            index for index, peak in enumerate(canonical_peaks) if peak.index == node.index
        )
        peaks = tuple(MMRPeak(height=peak.height, hash=peak.hash) for peak in canonical_peaks)
        v2 = self.hash_scheme == HASH_SCHEME_V2
        return MMRInclusionProofV1(
            version=MMR_PROOF_VERSION_V2 if v2 else MMR_PROOF_VERSION_V1,
            algorithm=MMR_ALGORITHM_V2 if v2 else MMR_ALGORITHM_V1,
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
        """Strictly verify a self-contained inclusion proof, v1 or v2.

        The leaf digest is computed under the scheme the *proof* declares, so a
        v1 proof cannot be replayed against a v2 leaf digest or the reverse.
        """
        if proof.version == MMR_PROOF_VERSION_V2:
            leaf_hash = v2_leaf_hash(leaf_data).hex()
        else:
            leaf_hash = hashlib.sha256(leaf_data).hexdigest()
        return MerkleMountainRange.verify_portable_inclusion_hash(leaf_hash, proof, trusted_root)

    @staticmethod
    def verify_portable_inclusion_hash(
        leaf_hash: str,
        proof: MMRInclusionProofV1,
        trusted_root: str,
    ) -> bool:
        """Strictly verify a proof using a non-sensitive leaf digest.

        Dispatches on the version the proof carries: ``v1`` keeps the original
        ASCII-hex construction so historical proofs continue to verify
        unchanged, ``v2`` uses the domain-separated binary one. The version and
        algorithm must agree — a proof claiming v2 with the v1 algorithm, or the
        reverse, is rejected rather than resolved in the caller's favour.
        """
        if not _is_sha256_hex(leaf_hash):
            return False
        if proof.version == MMR_PROOF_VERSION_V2:
            if proof.algorithm != MMR_ALGORITHM_V2:
                return False
            v2 = True
        elif proof.version == MMR_PROOF_VERSION_V1:
            if proof.algorithm != MMR_ALGORITHM_V1:
                return False
            v2 = False
        else:
            return False
        # Defence in depth behind `from_dict`'s schema check: a proof can also
        # be built directly or through `dataclasses.replace`, and this function
        # is documented to return a bool for any input. Comparing an `int` with
        # a `str` raises TypeError, so the type check has to come before the
        # range check rather than being implied by it. `bool` is rejected for
        # the same reason it is in `from_dict`: it is an `int` subclass.
        for count in (proof.leaf_index, proof.leaf_count, proof.peak_index):
            if not isinstance(count, int) or isinstance(count, bool):
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
            left, right = (
                (current_hash, step.sibling_hash)
                if step.direction == "R"
                else (step.sibling_hash, current_hash)
            )
            if v2:
                current_hash = v2_node_hash(bytes.fromhex(left), bytes.fromhex(right)).hex()
            else:
                current_hash = hashlib.sha256((left + right).encode("ascii")).hexdigest()
        if current_hash != proof.peaks[proof.peak_index].hash:
            return False
        if v2:
            actual_root = v2_bagged_root([bytes.fromhex(peak.hash) for peak in proof.peaks]).hex()
        else:
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
                return str(root)

            def get_root_hash(self) -> str:
                return str(self._rust.get_root_hash())

            def get_leaf_count(self) -> int:
                return int(self._rust.get_leaf_count())

            def get_inclusion_proof(self, leaf_index: int) -> list[tuple[str, str]]:
                return self._py.get_inclusion_proof(leaf_index)

            def get_portable_inclusion_proof(self, leaf_index: int) -> MMRInclusionProofV1:
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

            def get_consistency_proof(self, old_root: str, old_count: int) -> tuple[str, list[str]]:
                return self._py.get_consistency_proof(old_root, old_count)

        mmr_manager: RustBackedMMR | MerkleMountainRange = RustBackedMMR()
    else:
        mmr_manager = MerkleMountainRange()
except Exception:
    # Any import/initialisation error should fall back to the pure-Python impl.
    mmr_manager = MerkleMountainRange()
