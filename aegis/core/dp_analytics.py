"""Internal, non-published Laplace mechanism for one bounded count release.

One invocation of :class:`LaplaceCountMechanism` is calibrated for record-level
add/remove adjacency with sensitivity one. This module does not provide a privacy
accountant, memoization, contribution bounds for arbitrary aggregates, protection
from raw-ledger access, or a telemetry publishing surface.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import math
import secrets
from typing import Protocol


class UniformSource(Protocol):
    """Minimal random-source contract used by the inverse-CDF sampler."""

    def random(self) -> float:
        """Return a sample in ``[0, 1)``."""


def _open_unit_sample(rng: UniformSource) -> float:
    """Return a finite sample strictly inside ``(0, 1)`` with bounded retries."""
    for _ in range(8):
        value = rng.random()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("random source must return a real number")
        sample = float(value)
        if math.isfinite(sample) and 0.0 < sample < 1.0:
            return sample
    raise RuntimeError("random source did not produce an open-unit sample")


def _laplace_sample(scale: float, rng: UniformSource) -> float:
    """Sample ``Laplace(0, scale)`` by inverse CDF using an injected source."""
    if not math.isfinite(scale) or scale <= 0:
        raise ValueError("scale must be finite and positive")
    centered = _open_unit_sample(rng) - 0.5
    value = -scale * math.copysign(1.0, centered) * math.log1p(-2.0 * abs(centered))
    if not math.isfinite(value):
        raise RuntimeError("Laplace sampler produced a non-finite value")
    return value


class LaplaceCountMechanism:
    """Release one noised non-negative count with sensitivity one.

    The narrow claim applies to one invocation under add/remove-one-record
    adjacency. Repeated publication requires a separate durable privacy accountant
    and stable dataset/query identity; those controls are not implemented here.
    """

    def __init__(self, epsilon: float, *, rng: UniformSource | None = None) -> None:
        if isinstance(epsilon, bool) or not isinstance(epsilon, (int, float)):
            raise TypeError("epsilon must be a real number")
        self.epsilon = float(epsilon)
        if not math.isfinite(self.epsilon) or self.epsilon <= 0:
            raise ValueError("epsilon must be finite and positive")
        self._rng: UniformSource = rng if rng is not None else secrets.SystemRandom()

    @property
    def sensitivity(self) -> float:
        """Return the fixed add/remove adjacency sensitivity."""
        return 1.0

    @property
    def scale(self) -> float:
        """Return the calibrated Laplace scale ``1 / epsilon``."""
        return self.sensitivity / self.epsilon

    def release(self, count: int) -> float:
        """Return one finite noisy release for a non-negative integer count."""
        if isinstance(count, bool) or not isinstance(count, int):
            raise TypeError("count must be an integer")
        if count < 0:
            raise ValueError("count must be non-negative")
        result = float(count) + _laplace_sample(self.scale, self._rng)
        if not math.isfinite(result):
            raise RuntimeError("noisy count is non-finite")
        return result

    def noisy_count(self, count: int) -> float:
        """Compatibility alias for :meth:`release`."""
        return self.release(count)


LaplaceDP = LaplaceCountMechanism

__all__ = ["LaplaceCountMechanism", "LaplaceDP", "UniformSource"]
