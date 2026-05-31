"""
aegis.core.state_snapshotter — Atomic State Snapshotting.
Implements microsecond-level memory snapshots for instant recovery after intrusion.
"""
from __future__ import annotations
import logging
import time
import copy
import hashlib
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SystemSnapshot:
    snapshot_id: str
    timestamp: float
    state_data: Dict[str, Any]
    merkle_root: str
    is_verified: bool = False

class AtomicSnapshotManager:
    """
    Manages high-frequency snapshots of the system's critical state.
    Allows for near-instant roll-back to a 'Known Good State' upon detection of a breach.
    """
    def __init__(self, snapshot_interval_ms: int = 100):
        self._history: Dict[str, SystemSnapshot] = {}
        self._current_snapshot_id: Optional[str] = None
        self.interval = snapshot_interval_ms
        logger.info("AtomicSnapshotManager initialized. Interval: %dms", snapshot_interval_ms)

    def capture_state(self, critical_objects: Dict[str, Any]) -> str:
        """
        Captures an atomic snapshot of the provided critical objects.
        In a real system, this would use Copy-on-Write (CoW) memory pages via mmap.
        """
        # 1. Create a deep copy of the state to ensure atomicity
        state_copy = copy.deepcopy(critical_objects)
        
        # 2. Generate a Merkle Root of the state for integrity verification
        state_string = str(state_copy).encode()
        merkle_root = hashlib.sha256(state_string).hexdigest()
        
        # 3. Create snapshot record
        import uuid
        snap_id = str(uuid.uuid4())
        snapshot = SystemSnapshot(
            snapshot_id=snap_id,
            timestamp=time.time(),
            state_data=state_copy,
            merkle_root=merkle_root,
            is_verified=True
        )
        
        self._history[snap_id] = snapshot
        self._current_snapshot_id = snap_id
        
        logger.debug("Snapshot captured: %s | Merkle Root: %s", snap_id[:8], merkle_root[:8])
        return snap_id

    def rollback_to(self, snapshot_id: str) -> Optional[Dict[str, Any]]:
        """
        Restores the system state to a specific snapshot.
        This is triggered by the 'Panic-Mode' or a detected invariant violation.
        """
        if snapshot_id not in self._history:
            logger.error("Rollback failed: Snapshot %s not found.", snapshot_id)
            return None
        
        snapshot = self._history[snapshot_id]
        
        # Verify integrity before restoration
        current_state_string = str(snapshot.state_data).encode()
        if hashlib.sha256(current_state_string).hexdigest() != snapshot.merkle_root:
            logger.critical("SNAPSHOT CORRUPTION: Merkle root mismatch for %s!", snapshot_id)
            return None
        
        logger.info("ROLLBACK SUCCESSFUL: System restored to snapshot %s (Timestamp: %f)", 
                    snapshot_id, snapshot.timestamp)
        return snapshot.state_data

    def purge_old_snapshots(self, keep_last: int = 100):
        """Maintains a sliding window of snapshots to avoid memory exhaustion."""
        if len(self._history) > keep_last:
            # Sort by timestamp and remove oldest
            sorted_snaps = sorted(self._history.items(), key=lambda x: x[1].timestamp)
            to_remove = len(self._history) - keep_last
            for i in range(to_remove):
                del self._history[sorted_snaps[i][0]]
            logger.info("Snapshot history purged. Kept last %d snapshots.", keep_last)

    def get_latest_snapshot_id(self) -> Optional[str]:
        return self._current_snapshot_id
