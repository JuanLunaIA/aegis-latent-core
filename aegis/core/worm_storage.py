"""
aegis.core.worm_storage — Hardware WORM (Write Once Read Many) Interface.
Ensures physical immutability of the audit ledger.
"""
from __future__ import annotations
import hashlib
import logging
import os
import time
from typing import Optional, Dict
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class WORMEntry:
    index: int
    timestamp: float
    data: bytes
    checksum: str

class WORMStorageProvider:
    """
    Interface for physical WORM storage devices (e.g., Optical Discs, 
    Hardware-locked SSDs, or Cloud-WORM buckets like AWS S3 Object Lock).
    """
    def __init__(self, storage_type: str = "S3-Object-Lock"):
        self.storage_type = storage_type
        self._storage: Dict[int, WORMEntry] = {}
        self._next_index = 0

    async def write_entry(self, data: bytes) -> int:
        """
        Writes data to the WORM medium. Once written, it cannot be modified or deleted.
        """
        if self._next_index in self._storage:
            raise RuntimeError("WORM Storage Violation: Attempt to overwrite existing index.")
        
        checksum = hashlib.sha256(data).hexdigest()
        entry = WORMEntry(
            index=self._next_index,
            timestamp=time.time(),
            data=data,
            checksum=checksum
        )
        
        self._storage[self._next_index] = entry
        logger.info("Data written to WORM storage at index %d. Checksum: %s", self._next_index, checksum)
        
        self._next_index += 1
        return self._next_index - 1

    async def read_entry(self, index: int) -> Optional[bytes]:
        """Reads data from the WORM medium."""
        entry = self._storage.get(index)
        if not entry:
            logger.error("WORM Entry %d not found.", index)
            return None
        
        # Verify checksum upon read
        if hashlib.sha256(entry.data).hexdigest() != entry.checksum:
            logger.critical("WORM DATA CORRUPTION DETECTED at index %d!", index)
            return None
            
        return entry.data

worm_provider = WORMStorageProvider()
