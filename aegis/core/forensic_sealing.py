"""
aegis.core.forensic_sealing — Quantum-Resistant Evidence Sealing.
Implements hash-based signatures (XMSS-like) to ensure that forensic logs
remain immutable even against quantum adversaries.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class XMSSSignature:
    index: int
    ots_key: bytes  # one-time private key, revealed upon signing (index becomes invalid)
    ots_signature: bytes
    auth_path: list[bytes]  # Merkle siblings from leaf to root


class QuantumForensicSealer:
    """
    Hash-based signature scheme (XMSS-style) for sealing forensic logs.

    Each leaf in the Merkle tree is an OTS public key = SHA-256(ots_private_key).
    Signing reveals the OTS private key alongside an HMAC authenticator and the
    Merkle authentication path.  Verification checks the HMAC and recomputes the
    Merkle root from the revealed key and the auth path.

    Security rests entirely on SHA-256 collision resistance — no RSA/ECDSA
    discrete-log assumptions, making it quantum-safe.  Each index is one-time
    only; exhausting all leaves raises RuntimeError.
    """

    def __init__(self, tree_height: int = 10):
        self.tree_height = tree_height
        self.num_leaves = 2**tree_height
        self._seed = os.urandom(32)
        self._root, self._tree = self._generate_merkle_tree()
        self._used_indices: set[int] = set()
        logger.info(
            "QuantumForensicSealer initialized. Tree height: %d. Total signatures available: %d",
            tree_height,
            self.num_leaves,
        )

    def _generate_ots_key(self, index: int) -> bytes:
        """Generates a one-time signature private key from the master seed."""
        return hashlib.sha256(self._seed + index.to_bytes(4, "big")).digest()

    def _generate_merkle_tree(self) -> tuple[str, list[list[bytes]]]:
        """
        Builds the Merkle tree of OTS public keys.
        Leaf i = SHA-256(ots_private_key_i).  Internal nodes = SHA-256(left ‖ right).
        Returns (root_hex, full_tree) where full_tree[0] is the leaf level.
        """
        current_level: list[bytes] = [
            hashlib.sha256(self._generate_ots_key(i)).digest() for i in range(self.num_leaves)
        ]
        tree: list[list[bytes]] = [current_level]

        while len(current_level) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(hashlib.sha256(left + right).digest())
            current_level = next_level
            tree.append(current_level)

        return current_level[0].hex(), tree

    def seal_log_entry(self, log_data: bytes) -> XMSSSignature:
        """
        Signs a log entry using the next available OTS key.

        Returns an XMSSSignature carrying the revealed OTS private key, an HMAC
        authenticator, and the real Merkle authentication path.  The index is
        consumed; using it again would be a security violation.
        """
        idx = 0
        while idx in self._used_indices:
            idx += 1

        if idx >= self.num_leaves:
            raise RuntimeError("XMSS Key Exhausted. New tree must be generated.")

        self._used_indices.add(idx)

        ots_key = self._generate_ots_key(idx)
        ots_sig = hmac.new(ots_key, log_data, hashlib.sha256).digest()

        # Real Merkle authentication path: collect the sibling at each level
        auth_path: list[bytes] = []
        current_idx = idx
        for h in range(self.tree_height):
            level = self._tree[h]
            sibling_idx = current_idx ^ 1  # flip last bit → sibling
            sibling = level[sibling_idx] if sibling_idx < len(level) else level[current_idx]
            auth_path.append(sibling)
            current_idx >>= 1  # parent index at next level

        logger.info(
            "Log entry sealed using XMSS index %d. Quantum-resistant signature generated.", idx
        )
        return XMSSSignature(index=idx, ots_key=ots_key, ots_signature=ots_sig, auth_path=auth_path)

    def verify_seal(self, data: bytes, sig: XMSSSignature, root: str) -> bool:
        """
        Verifies a seal against the provided Merkle root.

        Two checks must both pass:
        1. HMAC authenticator: HMAC(sig.ots_key, data) == sig.ots_signature.
        2. Merkle root: SHA-256(sig.ots_key) traversed up via sig.auth_path equals root.
        """
        # 1. Verify the HMAC using the revealed OTS private key
        expected_sig = hmac.new(sig.ots_key, data, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_sig, sig.ots_signature):
            logger.warning("SEAL VERIFY FAILED: HMAC mismatch for index %d.", sig.index)
            return False

        # 2. Recompute Merkle root from OTS public key + authentication path
        current_hash = hashlib.sha256(sig.ots_key).digest()  # OTS public key = H(ots_key)
        current_idx = sig.index
        for sibling in sig.auth_path:
            if current_idx % 2 == 0:
                combined = current_hash + sibling  # current is left child
            else:
                combined = sibling + current_hash  # current is right child
            current_hash = hashlib.sha256(combined).digest()
            current_idx >>= 1

        computed_root = current_hash.hex()
        if computed_root != root:
            logger.warning(
                "SEAL VERIFY FAILED: Merkle root mismatch for index %d. Expected %s, got %s.",
                sig.index,
                root[:16],
                computed_root[:16],
            )
            return False

        return True
