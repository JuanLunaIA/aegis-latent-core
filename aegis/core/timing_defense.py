"""
aegis.core.timing_defense — Side-Channel Timing Mitigation.
Implements constant-time operations and deterministic padding to prevent timing leaks.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hmac
import logging
import secrets

logger = logging.getLogger(__name__)


class TimingDefense:
    """
    Protects the system against side-channel timing attacks.
    """

    @staticmethod
    def constant_time_compare(val1: str | bytes, val2: str | bytes) -> bool:
        """
        Compares two values in constant time to prevent timing attacks.
        Uses hmac.compare_digest, which is designed to resist timing analysis.
        """
        if isinstance(val1, str):
            val1 = val1.encode()
        if isinstance(val2, str):
            val2 = val2.encode()

        return hmac.compare_digest(val1, val2)

    @staticmethod
    def deterministic_padding(data: bytes, block_size: int = 1024) -> bytes:
        """
        Pads the data to a fixed block size to prevent information leakage
        via packet length (Traffic Analysis).
        """
        if len(data) > block_size:
            # If data exceeds block size, we pad to the next multiple of block_size.
            padding_len = block_size - (len(data) % block_size)
            if padding_len == block_size:
                padding_len = 0
        else:
            padding_len = block_size - len(data)

        # Use cryptographically secure random bytes for padding to prevent
        # padding-oracle style attacks.
        padding = secrets.token_bytes(padding_len)

        # Format: [OriginalData][Padding][PaddingLen(4 bytes, big-endian)]
        # Appending the length LAST allows strip_padding to read padded_data[-4:]
        # to recover the exact length, then slice off -(padding_len + 4) bytes.
        return data + padding + len(padding).to_bytes(4, "big")

    @staticmethod
    def strip_padding(padded_data: bytes) -> bytes:
        """
        Removes the deterministic padding.
        """
        if len(padded_data) < 4:
            raise ValueError("Padded data too short to contain padding length.")

        # Format: [Data][Padding][PaddingLen(4 bytes, big-endian)]
        # The length is always the last 4 bytes — O(1) to read.
        padding_len = int.from_bytes(padded_data[-4:], "big")
        if padding_len > len(padded_data):
            raise ValueError("Invalid padding length.")

        return padded_data[: -(padding_len + 4)]


# Singleton instance
timing_defense = TimingDefense()
