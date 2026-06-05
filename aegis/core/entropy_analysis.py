"""
aegis.core.entropy_analysis — Shannon entropy and drift monitoring for LLM payloads.

Used by the request-entropy guard path in app.py when
``AEGIS_REQUEST_ENTROPY_GUARD=true``.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import math
from collections import deque

import numpy as np

logger = logging.getLogger(__name__)

# Sliding window for drift detection — O(1) append/eviction
_HISTORY_MAXLEN: int = 100


class PayloadEntropyAnalyzer:
    """
    Computes Shannon entropy of raw request text and blocks payloads whose
    entropy falls below a configurable baseline fraction (default 40 %).

    A very low-entropy payload (e.g. a repeated token flood) is a reliable
    signal of an adversarial prompt-injection attempt.
    """

    def __init__(self, baseline_entropy: float = 2.5) -> None:
        self.baseline_entropy = baseline_entropy
        # deque(maxlen=N) gives O(1) append and automatic eviction — no pop(0).
        self._history: deque[float] = deque(maxlen=_HISTORY_MAXLEN)

    def analyze_payload(self, text: str) -> tuple[bool, float]:
        """
        Compute Shannon entropy of *text*.

        Returns:
            (is_allowed, calculated_entropy)
        """
        if not text:
            return True, 0.0

        entropy = self._calculate_shannon_entropy(text)
        is_allowed = bool(entropy > self.baseline_entropy * 0.4)
        self._history.append(entropy)
        return is_allowed, entropy

    def detect_entropy_shift(self, text: str) -> bool:
        """
        Returns True when the current text's entropy is an outlier (> 2 σ)
        relative to recent history.  Requires at least 10 prior samples.
        """
        if len(self._history) < 10:
            return False

        current_entropy = self._calculate_shannon_entropy(text)
        history_list = list(self._history)
        avg = sum(history_list) / len(history_list)
        std = float(np.std(history_list)) if len(history_list) > 1 else 0.1
        return bool(abs(current_entropy - avg) > 2.0 * std)

    @staticmethod
    def _calculate_shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        n = len(text)
        probs = [text.count(c) / n for c in set(text)]
        return -sum(p * math.log2(p) for p in probs if p > 0)
