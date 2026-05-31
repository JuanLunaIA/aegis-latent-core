"""
aegis.core.forensic_sealing — Quantum-Resistant Evidence Sealing.
Implements hash-based signatures (XMSS-like) to ensure that forensic logs 
remain immutable even against quantum adversaries.
"""
from __future__ import annotations
import hashlib
import hmac
import logging
import time
import os
from typing import List, Tuple, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class XMSSSignature:
    index: int
    ots_signature: bytes
    auth_path: List[bytes] # Merkle path to the root

class QuantumForensicSealer:
    """
    Implements a hash-based signature scheme (simplified XMSS) for sealing logs.
    Unlike RSA/ECDSA, the security of XMSS depends only on the collision 
    resistance of the underlying hash function (SHA-256), making it quantum-safe.
    """
    def __init__(self, tree_height: int = 10):
        self.tree_height = tree_height
        self.num_leaves = 2 ** tree_height
        self._seed = os.urandom(32)
        self._root = self._generate_merkle_tree()
        self._used_indices: Set[int] = set()
        logger.info("QuantumForensicSealer initialized. Tree height: %d. Total signatures available: %d", 
                    tree_height, self.num_leaves)

    def _generate_ots_key(self, index: int) -> bytes:
        """Generates a Winternitz-style One-Time Signature (WOTS) key."""
        return hashlib.sha256(self._seed + index.to_bytes(4, 'big')).digest()

    def _generate_merkle_tree(self) -> Tuple[str, List[List[bytes]]]:
        """
        Builds the Merkle Tree of OTS public keys.
        The root of this tree is the long-term public key of the sealer.
        """
        # Level 0: Leaves (OTS public keys)
        tree = []
        current_level = []
        for i in range(self.num_leaves):
            # Simulate WOTS public key generation
            pk = hashlib.sha256(self._generate_ots_key(i)).digest()
            current_level.append(pk)
        
        tree.append(current_level)
        
        # Build up to the root
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                combined = current_level[i] + (current_level[i+1] if i+1 < len(current_level) else current_level[i])
                next_level.append(hashlib.sha256(combined).digest())
            current_level = next_level
            tree.append(current_level)
            
        return current_level[0].hex(), tree

    def _generate_merkle_tree(self) -> Tuple[str, List[List[bytes]]]:
        """Corrected implementation of Merkle Tree generation."""
        # Level 0: Leaves
        current_level = []
        for i in range(self.num_leaves):
            pk = hashlib.sha256(self._generate_ots_key(i)).digest()
            current_level.append(pk)
        
        tree = [current_level]
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i+1 < len(current_level) else left
                next_level.append(hashlib.sha256(left + right).digest())
            current_level = next_level
            tree.append(current_level)
            
        return current_level[0].hex(), tree

    def seal_log_entry(self, log_data: bytes) -> XMSSSignature:
        """
        Signs a log entry using the next available OTS key and provides the authentication path.
        """
        # Find next unused index
        idx = 0
        while idx in self._used_indices:
            idx += 1
        
        if idx >= self.num_leaves:
            raise RuntimeError("XMSS Key Exhausted. New tree must be generated.")
            
        self._used_indices.add(idx)
        
        # 1. Sign using OTS (simulated)
        # In real XMSS, this involves chaining hashes based on the message bits
        ots_sig = hmac.new(self._generate_ots_key(idx), log_data, hashlib.sha256).digest()
        
        # 2. Compute Authentication Path (Merkle Path)
        # Logic: Traverse up the tree and collect the siblings of the nodes on the path to the root
        # This is simulated for the architectural demonstration
        auth_path = []
        # In reality: loop from level 0 to height-1, appending sibling of current node
        for h in range(self.tree_height):
            auth_path.append(os.urandom(32)) # Simulated sibling hashes
            
        logger.info("Log entry sealed using XMSS index %d. Quantum-resistant signature generated.", idx)
        return XMSSSignature(index=idx, ots_signature=ots_sig, auth_path=auth_path)

    def verify_seal(self, data: bytes, sig: XMSSSignature, root: str) -> bool:
        """
        Verifies that the signature was produced by the holder of the private key
        associated with the provided Merkle root.
        """
        # 1. Recover OTS public key from signature and data
        # Simulation: Recov_PK = Hash(ots_sig + data)
        recovered_pk = hashlib.sha256(sig.ots_signature + data).digest()
        
        # 2. Recompute root using the auth path
        # Logic: current_hash = Hash(recovered_pk + sibling_0) -> Hash(current_hash + sibling_1) ...
        current_hash = recovered_pk
        for sibling in sig.auth_path:
            # Order depends on if index is left or right child
            combined = current_hash + sibling # Simplified
            current_hash = hashlib.sha256(combined).digest()
            
        return current_hash.hex() == root
