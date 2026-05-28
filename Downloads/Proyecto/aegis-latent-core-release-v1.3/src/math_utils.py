"""
math_utils.py — Numerical Stability Layer

Provides Kahan Compensated Summation and numerically stable Softmax.
All public functions validate inputs strictly; non-finite values raise
ValueError rather than propagating silently (NEXUS INV-04, INV-06).

Fixes applied (NEXUS audit 2026-05-27):
  - KahanSummation.add(): raises ValueError on NaN / ±inf (F-04)
  - normalize_logits(): validates 1-D non-empty input (F-02 prerequisite)
  - verify_distribution(): uses math.fsum for consistency with Kahan principle (F-07)
"""

import math
import numpy as np
from typing import Union


class KahanSummation:
    """
    Kahan Compensated Summation.

    Reduces floating-point absorption error from O(n·ε_mach) (naive) to
    O(ε_mach) by maintaining a running compensation term that recovers
    precision lost when a small addend is absorbed into a large accumulator.

    Reference: Kahan, W. (1965). "Pracniques: Further Remarks on Reducing
    Truncation Errors." Communications of the ACM, 8(1), 40.

    Boundary conditions:
      - Non-finite inputs (NaN, ±inf) raise ValueError immediately.
        Rationale: silent NaN propagation corrupts the entropy signal and
        produces a valid-looking node_hash computed over the string "nan".
      - Empty accumulation (no add() calls) returns sum=0.0 correctly.

    Thread safety: NOT thread-safe. Wrap in threading.Lock if shared.
    """

    def __init__(self) -> None:
        self.sum: float = 0.0
        self.compensation: float = 0.0

    def add(self, value: float) -> float:
        """
        Adds value to the running total.

        Raises:
            ValueError: if value is NaN or ±inf. Callers must sanitize
                        inputs before accumulation.
        """
        if not math.isfinite(value):
            raise ValueError(
                f"KahanSummation.add() received non-finite value: {value!r}. "
                "Sanitize inputs before accumulation."
            )
        y: float = value - self.compensation
        t: float = self.sum + y
        self.compensation = (t - self.sum) - y
        self.sum = t
        return self.sum

    def reset(self) -> None:
        """Resets accumulator and compensation term to 0.0."""
        self.sum = 0.0
        self.compensation = 0.0


def normalize_logits(logits: np.ndarray) -> np.ndarray:
    """
    Numerically stable Softmax: converts raw logits to a probability distribution.

    Mechanism:
        shifted = logits - max(logits)   # prevents exp() overflow
        probs   = exp(shifted) / sum(exp(shifted))

    The shift is mathematically equivalent (cancels in the ratio) but
    guarantees that exp(shifted[argmax]) = exp(0) = 1.0, preventing
    float64 overflow for logits with large positive values.

    Underflow note: tokens with logit - max(logits) < -709.78 produce
    exp() = 0.0 in float64. This is expected and handled downstream by
    epsilon clamping in entropy/KL computations.

    Args:
        logits: 1-D float64 ndarray, non-empty.

    Returns:
        1-D ndarray with same shape; values in (0, 1]; sums to 1.0 ± 1e-9.

    Raises:
        ValueError: if logits is empty or not 1-D.
        ValueError: if logits contains non-finite values.
    """
    if logits.ndim != 1:
        raise ValueError(
            f"normalize_logits() expects a 1-D array; got shape {logits.shape}."
        )
    if logits.size == 0:
        raise ValueError("normalize_logits() received an empty array.")
    if not np.all(np.isfinite(logits)):
        raise ValueError(
            "normalize_logits() received non-finite logits. "
            "Replace NaN/±inf before calling."
        )
    shifted = logits - np.max(logits)
    exps = np.exp(shifted)
    return exps / np.sum(exps)


def verify_distribution(probs: np.ndarray, tolerance: float = 1e-9) -> bool:
    """
    Verifies that a probability array sums to 1.0 within tolerance.

    Uses math.fsum (exact floating-point summation via compensated algorithm
    in C stdlib) for consistency with the Kahan principle applied elsewhere
    in this module.

    Args:
        probs:     1-D ndarray of probabilities.
        tolerance: Acceptable absolute deviation from 1.0. Default: 1e-9.

    Returns:
        True if |sum(probs) - 1.0| < tolerance.
    """
    return abs(math.fsum(probs.tolist()) - 1.0) < tolerance
