"""
aegis.core.anchoring — External Root Anchoring.
Provides mechanisms to anchor Merkle roots into immutable storage (WORM / Blockchain).
"""
from __future__ import annotations
import logging
import time
import hashlib
from dataclasses import dataclass
from typing import Optional, Dict

from aegis.core.blockchain_anchor import blockchain_provider, BlockchainProof
from aegis.core.worm_storage import worm_provider

logger = logging.getLogger(__name__)

@dataclass
class AnchorProof:
    root_hash: str
    anchor_id: str
    timestamp: float
    provider: str
    verification_url: str

class AnchorManager:
    """
    Orchestrates anchoring of Merkle roots across multiple immutable providers.
    """
    def __init__(self):
        self._anchors: Dict[str, AnchorProof] = {}

    async def anchor_root(self, root_hash: str) -> AnchorProof:
        """
        Anchors the provided root hash into BOTH Blockchain and WORM storage
        for maximum redundancy and legal admissibility.
        """
        logger.info("Executing Redundant Anchoring for root [%s]...", root_hash)
        
        # 1. Anchor to Public Blockchain (Temporal proof)
        bc_proof = await blockchain_provider.publish_root(root_hash)
        
        # 2. Anchor to WORM Storage (Physical proof)
        # We store the root_hash as bytes in the WORM device.
        worm_idx = await worm_provider.write_entry(root_hash.encode())
        
        # Create a consolidated proof
        anchor_id = bc_proof.tx_hash
        proof = AnchorProof(
            root_hash=root_hash,
            anchor_id=anchor_id,
            timestamp=bc_proof.timestamp,
            provider=f"Hybrid(BC:{bc_proof.network}|WORM:{worm_provider.storage_type})",
            verification_url=bc_proof.verification_url
        )
        
        self._anchors[anchor_id] = proof
        logger.info("Root anchored redundantly. BC_TX: %s | WORM_IDX: %d", anchor_id, worm_idx)
        return proof

    async def verify_anchor(self, anchor_id: str, expected_root: str) -> bool:
        """
        Verifies the root against both providers.
        """
        # 1. Verify via Blockchain
        bc_ok = await blockchain_provider.verify_proof(anchor_id, expected_root)
        
        # 2. Verify via WORM (Search for the root in storage)
        # Simplified for simulation: check if the root exists in any WORM entry.
        worm_ok = any(entry.data.decode() == expected_root 
                      for entry in worm_provider._storage.values())
        
        return bc_ok and worm_ok

anchor_manager = AnchorManager()
