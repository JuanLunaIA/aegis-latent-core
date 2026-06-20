"""
math_utils.py — Numerically Stable & Cryptographically Deterministic Layer

Provides compensated mathematical operations and deterministic float serialization
to ensure cross-platform cryptographic reproducibility.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

import math
import struct

import numpy as np


class KahanSummation:
    """
    Kahan Compensated Summation.
    Reduces absorption errors to O(eps_mach) by maintaining a running compensation term.
    """

    def __init__(self) -> None:
        self.sum: float = 0.0
        self.compensation: float = 0.0

    def add(self, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError(f"KahanSummation.add() received non-finite value: {value}")
        y = value - self.compensation
        t = self.sum + y
        self.compensation = (t - self.sum) - y
        self.sum = t
        return self.sum

    def reset(self) -> None:
        self.sum = 0.0
        self.compensation = 0.0


def pack_float64(value: float) -> bytes:
    """
    Packs a float64 into an exact 8-byte big-endian IEEE-754 binary representation.
    Completely eliminates string/repr platform discrepancies in cryptographic hashing.
    """
    if not math.isfinite(value):
        raise ValueError(f"Cannot pack non-finite float: {value}")
    return struct.pack(">d", value)


def logsumexp(logits: np.ndarray) -> float:
    """
    Numerically stable computation of log(sum(exp(x))).
    """
    if logits.size == 0:
        raise ValueError("Empty array passed to logsumexp")
    max_val = np.max(logits)
    return float(max_val + np.log(np.sum(np.exp(logits - max_val))))


def log_softmax(logits: np.ndarray) -> np.ndarray:
    """
    Numerically stable log-softmax: log(P(x)).
    Computes shifted logits directly in log-space to prevent underflow/overflow.
    """
    if logits.ndim != 1 or logits.size == 0:
        raise ValueError("log_softmax requires a non-empty 1-D array.")
    if not np.all(np.isfinite(logits)):
        raise ValueError("Non-finite values detected in logits.")
    return logits - logsumexp(logits)


def normalize_logits(logits: np.ndarray) -> np.ndarray:
    """
    Numerically stable softmax. Converts logits to a valid probability distribution.
    """
    if logits.ndim != 1 or logits.size == 0:
        raise ValueError("normalize_logits requires a non-empty 1-D array.")
    if not np.all(np.isfinite(logits)):
        raise ValueError("Non-finite values detected in logits.")
    shifted = logits - np.max(logits)
    exps = np.exp(shifted)
    return exps / np.sum(exps)


def verify_distribution(probs: np.ndarray, tolerance: float = 1e-9) -> bool:
    return abs(math.fsum(probs.tolist()) - 1.0) < tolerance
