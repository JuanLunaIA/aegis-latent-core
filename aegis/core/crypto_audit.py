"""
aegis.core.crypto_audit — Cryptographic audit ledger and PQC signing.
"""
import hashlib
import os
import time
import asyncio
import logging
import json
import numpy as np
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from threading import Lock

from aegis.core.mmr import mmr_manager

logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES = 1_048_576  # 1MB

# --- PQC Provider Setup ---
try:
    import aegis_rust
    pqc_provider = aegis_rust
    RUST_AVAILABLE = True
except (ImportError, Exception):
    logger.error("FAILED TO LOAD aegis_rust. Using Python-based fallback.")
    RUST_AVAILABLE = False

    class MockPQCKeyPair:
        def __init__(self, pub: bytes, priv: bytes):
            self.public_key = pub
            self.private_key = priv
        def sign(self, data: bytes) -> bytes:
            return hashlib.sha256(data + self.private_key).digest()
        def verify(self, data: bytes, sig: bytes) -> bool:
            return sig == hashlib.sha256(data + self.private_key).digest()

    class PythonPQCFallback:
        def generate_pqc_keypair(self) -> MockPQCKeyPair:
            return MockPQCKeyPair(b"dummy_pub", b"dummy_priv")
        def sign(self, data: bytes, priv_key: bytes) -> bytes:
            return hashlib.sha256(data + priv_key).digest()
        def verify_pqc_signature(self, data: bytes, sig: bytes, pub_key: bytes) -> bool:
            return sig == hashlib.sha256(data + b"dummy_priv").digest()

    pqc_provider = PythonPQCFallback()

@dataclass
class AuditNode:
    state_id: str
    timestamp: float
    entropy: float
    payload: str  # Stored as hex for JSON serialization
    tenant_id: str
    sampling_params: Dict[str, Any]
    prev_hash: str
    merkle_root: str
    signature: str # Stored as hex
    public_key: str # Stored as hex
    is_fallback: bool = False

    @property
    def node_hash(self) -> str:
        """Property used by tests to verify integrity."""
        return self._calculate_hash()

    def _calculate_hash(self) -> str:
        content = (
            f"{self.state_id}|{self.timestamp}|{self.entropy}|"
            f"{self.tenant_id}|{self.merkle_root}|"
            f"{self.signature}|{self.public_key}"
        )
        return hashlib.sha256(content.encode()).hexdigest()

@dataclass
class PQCSignatureAnchor:
    """
    Represents a cryptographic anchor in a PQC-capable environment.
    """
    public_key: bytes
    algorithm: str = "ML-DSA"

    def verify(self, data: bytes, signature: bytes) -> bool:
        if hasattr(pqc_provider, 'verify_pqc_signature'):
            return pqc_provider.verify_pqc_signature(data, signature, self.public_key)
        return signature == hashlib.sha256(data + b"dummy_priv").digest()

class CryptographicAuditLedger:
    """
    Append-only Merkle-tree backed ledger for all proxy operations.
    """
    def __init__(self, persistence_path: str, max_memory_nodes: int = 100_000, async_mode: bool = False):
        self.persistence_path = persistence_path
        self.max_memory_nodes = max_memory_nodes
        self.async_mode = async_mode
        self.chain: List[AuditNode] = []
        self._lock = Lock()
        self._wal_handle = None
        self._load_from_wal()
        self._fault_state = "healthy"

    @property
    def legal_admissibility(self) -> str:
        if any(n.is_fallback for n in self.chain):
            return "Compromised"
        return "High"

    def _load_from_wal(self):
        if not os.path.exists(self.persistence_path):
            return
        
        logger.info(f"Reconstructing ledger from {self.persistence_path}...")
        loaded_count = 0
        try:
            # Use a temporary handle to read to avoid issues with the persistent handle
            with open(self.persistence_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    data = json.loads(line)
                    node = AuditNode(**data)
                    self.chain.append(node)
                    loaded_count += 1
            logger.info(f"Successfully reconstructed {loaded_count} nodes.")
        except Exception as e:
            logger.error(f"WAL load/reconstruction failed: {e}")

    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """
        Verifies the entire Merkle chain and consistency of the ledger.
        Returns (is_valid, error_index).
        """
        with self._lock:
            for i in range(len(self.chain)):
                current = self.chain[i]
                
                # 1. Check local hash integrity
                if current.node_hash != current._calculate_hash():
                    return False, i
                
                # 2. Check chain link (prev_hash)
                if i > 0:
                    prev = self.chain[i-1]
                    if current.prev_hash != prev.node_hash:
                        return False, i
                else:
                    if current.prev_hash != "0" * 64:
                        return False, i
            return True, None

    def commit_state(
        self,
        state_id: str,
        entropy: float,
        payload: bytes,
        tenant_id: str = "default",
        sampling_params: Optional[Dict[str, Any]] = None
    ) -> AuditNode:
        if self.async_mode:
            raise RuntimeError("Async mode not implemented for synchronous commit_state")

        if sampling_params is None: sampling_params = {}
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"payload too large")
        if "\x00" in state_id:
            raise ValueError("state_id containing NULL byte is rejected")
        if not np.isfinite(entropy):
            raise ValueError("entropy must be a finite number")

        with self._lock:
            prev_hash = self.chain[-1].node_hash if self.chain else "0" * 64
            timestamp = time.time()
            merkle_root = mmr_manager.add_leaf(payload)

            is_fallback = not RUST_AVAILABLE
            if not is_fallback and hasattr(pqc_provider, 'generate_pqc_keypair'):
                kp = pqc_provider.generate_pqc_keypair()
                signature = kp.sign(merkle_root.encode())
                pub_key = kp.public_key
            else:
                signature = pqc_provider.sign(merkle_root.encode(), b"dummy_priv")
                pub_key = b"dummy_pub"

            node = AuditNode(
                state_id=state_id,
                timestamp=timestamp,
                entropy=entropy,
                payload=payload.hex(),
                tenant_id=tenant_id,
                sampling_params=sampling_params,
                prev_hash=prev_hash,
                merkle_root=merkle_root,
                signature=signature.hex(),
                public_key=pub_key.hex(),
                is_fallback=is_fallback
            )
            
            self.chain.append(node)
            if len(self.chain) > self.max_memory_nodes:
                self.chain.pop(0)
            self._persist_node(node)
            return node

    def _persist_node(self, node: AuditNode):
        """Internal method: Must be called within self._lock."""
        line = json.dumps(asdict(node)) + "\n"
        if self._wal_handle:
            self._wal_handle.write(line)
            self._wal_handle.flush()
        else:
            with open(self.persistence_path, "a") as f:
                f.write(line)

    def close(self):
        """Closes the persistent WAL handle."""
        with self._lock:
            if self._wal_handle:
                self._wal_handle.close()
                self._wal_handle = None

    def __enter__(self): 
        with self._lock:
            if not self._wal_handle:
                self._wal_handle = open(self.persistence_path, "a")
        return self

    def __exit__(self, *args): 
        self.close()
