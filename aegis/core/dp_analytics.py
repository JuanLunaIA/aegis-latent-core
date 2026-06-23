# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.dp_analytics — Differential privacy for aggregate audit analytics.

Implements the Laplace mechanism (ε-DP) for adding calibrated noise to numeric
aggregates computed over the audit chain, so individual session entropy or token
fingerprints cannot be reverse-engineered from published statistics.

Reference: Dwork & Roth, "The Algorithmic Foundations of Differential Privacy",
           FnTCS 9(3-4), 2014, §3.3 (Laplace Mechanism).

Usage::

    dp = LaplaceDP(epsilon=1.0)

    # Noisy count of audit nodes
    noisy_n = dp.noisy_count(len(ledger.chain))

    # Noisy mean entropy (entropy in [0, max_bits], sensitivity = range/n)
    entropies = [node.entropy for node in ledger.chain]
    noisy_mu = dp.noisy_mean(entropies, value_range=20.0)

    # Full analytics report
    agg = DPAggregator(epsilon=1.0, delta=0.0)
    report = agg.compute(ledger.chain)
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field


def _laplace_sample(scale: float, rng: random.Random) -> float:
    """Sample from Laplace(0, scale) using the inverse CDF method."""
    u = rng.uniform(-0.5, 0.5)
    return -scale * math.copysign(1.0, u) * math.log(1.0 - 2.0 * abs(u))


class LaplaceDP:
    """Pure ε-differential privacy via the Laplace mechanism.

    Parameters
    ----------
    epsilon:
        Privacy budget.  Smaller values give stronger privacy guarantees but
        more noise.  Must be > 0.
    seed:
        Optional RNG seed for reproducible noise in tests.  In production
        leave as None (uses ``random.Random()`` with OS-level entropy).
    """

    def __init__(self, epsilon: float, seed: int | None = None) -> None:
        if epsilon <= 0:
            raise ValueError(f"epsilon must be > 0, got {epsilon!r}")
        self.epsilon = epsilon
        self._rng = random.Random(seed)

    def _noise(self, sensitivity: float) -> float:
        """Return one Laplace noise sample calibrated to (sensitivity, epsilon)."""
        scale = sensitivity / self.epsilon
        return _laplace_sample(scale, self._rng)

    def noisy_count(self, count: int) -> float:
        """Return ε-DP-noised count.  Sensitivity = 1 (one record in/out)."""
        return float(count) + self._noise(1.0)

    def noisy_sum(self, values: list[float], value_range: float) -> float:
        """Return ε-DP-noised sum.  Sensitivity = value_range (one record contribution)."""
        if not values:
            return self._noise(value_range)
        return sum(values) + self._noise(value_range)

    def noisy_mean(self, values: list[float], value_range: float) -> float:
        """Return ε-DP-noised mean.

        Sensitivity of the mean with n fixed records is value_range / n.
        When ``values`` is empty returns the noise floor (0 + noise).

        Parameters
        ----------
        values:
            Numeric values to average.
        value_range:
            Max − min of the value domain (e.g. 20.0 for Shannon entropy in bits).
        """
        if not values:
            return self._noise(value_range)
        n = len(values)
        true_mean = sum(values) / n
        sensitivity = value_range / n
        return true_mean + self._noise(sensitivity)

    def noisy_variance(self, values: list[float], value_range: float) -> float:
        """Return ε-DP-noised population variance.

        Sensitivity of variance is value_range² / n.
        """
        if len(values) < 2:
            return max(0.0, self._noise(value_range**2))
        n = len(values)
        mean = sum(values) / n
        true_var = sum((x - mean) ** 2 for x in values) / n
        sensitivity = (value_range**2) / n
        return max(0.0, true_var + self._noise(sensitivity))


@dataclass
class DPAnalyticsReport:
    """Differentially-private aggregate statistics over the audit chain."""

    epsilon: float
    delta: float = 0.0  # always 0.0 for pure Laplace DP
    mechanism: str = "laplace"

    # Noised aggregates
    node_count: float = 0.0
    mean_entropy: float = 0.0
    entropy_variance: float = 0.0
    phi_scrubbed_count: float = 0.0

    # Per-tenant noised counts (tenant_id → noised count)
    tenant_counts: dict[str, float] = field(default_factory=dict)


class DPAggregator:
    """Compute differentially-private aggregate statistics over audit chain nodes.

    Parameters
    ----------
    epsilon:
        Privacy budget.  Applied independently to each statistic reported
        (parallel composition).  Use a smaller epsilon for tighter guarantees.
    delta:
        Accepted for documentation/interface parity with Gaussian DP.  Always
        0.0 for the Laplace mechanism (pure DP).
    entropy_range:
        Maximum plausible Shannon entropy in bits.  Used as value_range for
        mean/variance computations.  Default 20.0 (well above practical LLM
        log-prob entropy values).
    seed:
        RNG seed forwarded to :class:`LaplaceDP`.
    """

    def __init__(
        self,
        epsilon: float = 1.0,
        delta: float = 0.0,
        entropy_range: float = 20.0,
        seed: int | None = None,
    ) -> None:
        if delta != 0.0:
            raise ValueError(
                "delta must be 0.0 for the Laplace mechanism (pure ε-DP). "
                "For (ε, δ)-DP use the Gaussian mechanism (not yet implemented)."
            )
        self.epsilon = epsilon
        self.delta = delta
        self.entropy_range = entropy_range
        self._dp = LaplaceDP(epsilon=epsilon, seed=seed)

    def compute(self, chain: list) -> DPAnalyticsReport:  # type: ignore[type-arg]
        """Return a :class:`DPAnalyticsReport` from a list of :class:`~aegis.core.crypto_audit.AuditNode` objects.

        Each numeric aggregate gets independent Laplace noise.  Tenant ID is
        treated as a categorical label — per-tenant counts are also noised
        (sensitivity = 1 per partition).

        Parameters
        ----------
        chain:
            Iterable of ``AuditNode``-like objects with attributes: ``entropy``,
            ``phi_scrubbed`` (bool), ``tenant_id`` (str).
        """
        nodes = list(chain)

        entropies = [n.entropy for n in nodes]
        phi_count = sum(1 for n in nodes if getattr(n, "phi_scrubbed", False))

        tenant_raw: dict[str, int] = {}
        for n in nodes:
            tid = getattr(n, "tenant_id", "default")
            tenant_raw[tid] = tenant_raw.get(tid, 0) + 1

        # Each query gets a fresh noise draw (parallel composition: each
        # statistic uses the full epsilon budget, privacy composes in parallel
        # since each query operates on disjoint aspects of the data).
        report = DPAnalyticsReport(
            epsilon=self.epsilon,
            delta=self.delta,
            mechanism="laplace",
            node_count=self._dp.noisy_count(len(nodes)),
            mean_entropy=self._dp.noisy_mean(entropies, self.entropy_range),
            entropy_variance=self._dp.noisy_variance(entropies, self.entropy_range),
            phi_scrubbed_count=self._dp.noisy_count(phi_count),
            tenant_counts={tid: self._dp.noisy_count(cnt) for tid, cnt in tenant_raw.items()},
        )
        return report
