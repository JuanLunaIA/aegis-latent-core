"""
aegis.core.leak_detector — Data Exfiltration Detection via Entropy.
Detects potential leaks of API keys, private keys, or encrypted blobs in LLM outputs.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import math
import re

logger = logging.getLogger(__name__)


class DataLeakDetector:
    """
    Analyzes generated text for high-entropy sequences that indicate sensitive data leaks.
    """

    def __init__(self, entropy_threshold: float = 4.5, min_length: int = 16):
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length

        # Patterns for common secrets (Hex, Base64) to trigger deeper entropy analysis
        self.secret_patterns = [
            re.compile(r"[a-fA-F0-9]{32,}"),  # Long Hex strings (API keys, hashes)
            re.compile(r"[a-zA-Z0-9+/]{32,}=*"),  # Long Base64 strings
            re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),  # Private key headers
        ]

    def _calculate_entropy(self, text: str) -> float:
        """Computes Shannon entropy of a string in bits per character."""
        if not text:
            return 0.0

        counts: dict[str, int] = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1

        probs = [count / len(text) for count in counts.values()]
        return -sum(p * math.log2(p) for p in probs)

    def scan_text(self, text: str) -> list[tuple[int, int, float, str]]:
        """
        Scans text for high-entropy regions.
        Returns a list of (start, end, entropy, reason).
        """
        leaks = []

        # 1. Fast pattern scan to find candidates
        for pattern in self.secret_patterns:
            for match in pattern.finditer(text):
                start, end = match.span()
                candidate = text[start:end]
                entropy = self._calculate_entropy(candidate)

                if entropy > self.entropy_threshold:
                    leaks.append(
                        (start, end, entropy, f"High-entropy pattern match: {pattern.pattern}")
                    )

        # 2. Sliding window scan for unknown high-entropy blobs
        window_size = 32
        step = 8
        for i in range(0, len(text) - window_size, step):
            window = text[i : i + window_size]
            entropy = self._calculate_entropy(window)
            if entropy > self.entropy_threshold:
                leaks.append((i, i + window_size, entropy, "High-entropy blob detected"))

        return leaks

    def is_leaking(self, text: str) -> tuple[bool, str | None]:
        """Determines if the text contains a likely data leak."""
        leaks = self.scan_text(text)
        if leaks:
            # Return the most severe leak
            best_leak = max(leaks, key=lambda x: x[2])
            return (
                True,
                f"Leak detected at {best_leak[0]}:{best_leak[1]} with entropy {best_leak[2]:.4f} ({best_leak[3]})",
            )

        return False, None
