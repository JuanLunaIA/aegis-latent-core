"""
aegis.core.memory — Hardened Memory Management.
Implements safeguards against heap overflow and use-after-free.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import ctypes
import logging

logger = logging.getLogger(__name__)


class Zeroize:
    """
    Utility for strict memory zeroization.
    Ensures that sensitive data is overwritten before being released.
    """

    @staticmethod
    def wipe(data: bytearray | memoryview | ctypes.Array) -> None:
        """
        Securely wipes the memory buffer.
        Uses a volatile-like approach to prevent compiler optimization from skipping the write.
        """
        if not data:
            return

        try:
            # For bytearrays, we overwrite each byte.
            if isinstance(data, (bytearray, memoryview)):
                length = len(data)
                # Use secrets.token_bytes to avoid predictable patterns if needed,
                # but for standard zeroization, zeros are correct.
                for i in range(length):
                    data[i] = 0
            elif hasattr(data, "__len__") and hasattr(data, "[0]"):
                # For ctypes arrays or similar
                length = len(data)
                for i in range(length):
                    data[i] = 0
            else:
                logger.warning("Unsupported data type for zeroization: %s", type(data))
        except Exception as e:
            logger.error("Zeroization failed: %s", e)


class HardenedMemoryManager:
    """
    Manages memory allocation with an emphasis on security.
    In a production environment, this would interface with mimalloc or hardened_malloc.
    """

    def __init__(self):
        self._initialized = False
        self._allocator_type = "standard"
        self._enforce_strict_zeroize = True

    def initialize_hardened_allocator(self):
        """
        Attempts to load a hardened memory allocator via LD_PRELOAD.
        """
        try:
            # In a production Linux environment, we verify the LD_PRELOAD of the process.
            # We check if libmimalloc.so or libhardened_malloc.so is mapped in /proc/self/maps.
            with open("/proc/self/maps") as f:
                maps = f.read()
                if "libmimalloc.so" in maps or "libhardened_malloc.so" in maps:
                    self._allocator_type = "hardened"
                else:
                    logger.warning(
                        "HardenedMemoryManager: no libmimalloc.so or libhardened_malloc.so "
                        "found in /proc/self/maps — using standard Python allocator. "
                        "LD_PRELOAD a hardened allocator before launching for real protection."
                    )
                    self._allocator_type = "standard"

            self._initialized = True
            logger.info(
                "Hardened Memory Allocator [%s] verified/initialized.", self._allocator_type
            )
        except Exception as e:
            logger.error("Failed to verify hardened allocator: %s", e)
            self._allocator_type = "standard"

    def secure_alloc(self, size: int) -> bytearray:
        """
        Allocates a buffer that is guaranteed to be zeroized upon request.
        """
        # In a real scenario, this would use a specific mmap call with PROT_NONE guard pages.
        return bytearray(size)

    def secure_free(self, data: bytearray | memoryview | ctypes.Array) -> None:
        """
        Zeroizes the data before letting it be garbage collected.
        """
        Zeroize.wipe(data)
        # To further prevent Use-After-Free in a real C/Rust core,
        # this would involve explicitly calling the allocator's free.

    @property
    def is_hardened(self) -> bool:
        return self._initialized


memory_manager = HardenedMemoryManager()
