# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.dp_analytics — differential privacy noise injection."""

from __future__ import annotations

import statistics
from dataclasses import dataclass

import pytest

from aegis.core.dp_analytics import DPAggregator, DPAnalyticsReport, LaplaceDP

# ── Minimal AuditNode stub ────────────────────────────────────────────────────


@dataclass
class _FakeNode:
    entropy: float
    phi_scrubbed: bool = False
    tenant_id: str = "default"


# ── LaplaceDP tests ───────────────────────────────────────────────────────────


class TestLaplaceDP:
    def test_invalid_epsilon_raises(self):
        with pytest.raises(ValueError, match="epsilon"):
            LaplaceDP(epsilon=0.0)

    def test_negative_epsilon_raises(self):
        with pytest.raises(ValueError, match="epsilon"):
            LaplaceDP(epsilon=-1.0)

    def test_noisy_count_not_exact(self):
        dp = LaplaceDP(epsilon=1.0, seed=0)
        result = dp.noisy_count(100)
        assert result != 100.0  # noise added (astronomically unlikely to be exact)

    def test_noisy_count_mean_near_true(self):
        """Mean of many noisy counts should converge to the true count."""
        dp = LaplaceDP(epsilon=1.0, seed=42)
        samples = [dp.noisy_count(50) for _ in range(2000)]
        assert abs(statistics.mean(samples) - 50.0) < 0.5

    def test_noisy_mean_converges(self):
        """Mean of many noisy means should be near the true mean."""
        true_values = [2.0, 3.0, 4.0]  # true mean = 3.0
        dp = LaplaceDP(epsilon=5.0, seed=7)
        samples = [dp.noisy_mean(true_values, value_range=10.0) for _ in range(2000)]
        assert abs(statistics.mean(samples) - 3.0) < 0.3

    def test_noisy_mean_empty_returns_float(self):
        dp = LaplaceDP(epsilon=1.0, seed=0)
        result = dp.noisy_mean([], value_range=10.0)
        assert isinstance(result, float)

    def test_noisy_sum_converges(self):
        dp = LaplaceDP(epsilon=5.0, seed=3)
        values = [1.0, 2.0, 3.0]  # true sum = 6.0
        samples = [dp.noisy_sum(values, value_range=10.0) for _ in range(2000)]
        assert abs(statistics.mean(samples) - 6.0) < 0.5

    def test_noisy_variance_non_negative(self):
        """Variance is always clamped to >= 0."""
        dp = LaplaceDP(epsilon=0.01, seed=1)  # very noisy
        values = [1.0, 2.0, 3.0]
        for _ in range(50):
            result = dp.noisy_variance(values, value_range=10.0)
            assert result >= 0.0

    def test_noisy_variance_single_value(self):
        """Variance of one value is 0 (or near-zero with noise)."""
        dp = LaplaceDP(epsilon=1.0, seed=5)
        result = dp.noisy_variance([3.0], value_range=10.0)
        assert isinstance(result, float)

    def test_larger_epsilon_less_noise(self):
        """Higher epsilon → smaller scale → less variance in noise."""

        def variance_of_noise(eps, n=5000):
            dp = LaplaceDP(epsilon=eps, seed=0)
            samples = [dp.noisy_count(0) for _ in range(n)]
            return statistics.variance(samples)

        low_eps_var = variance_of_noise(0.1)
        high_eps_var = variance_of_noise(10.0)
        assert high_eps_var < low_eps_var

    def test_seed_reproducible(self):
        dp1 = LaplaceDP(epsilon=1.0, seed=99)
        dp2 = LaplaceDP(epsilon=1.0, seed=99)
        results1 = [dp1.noisy_count(10) for _ in range(10)]
        results2 = [dp2.noisy_count(10) for _ in range(10)]
        assert results1 == results2

    def test_different_seeds_different_results(self):
        dp1 = LaplaceDP(epsilon=1.0, seed=1)
        dp2 = LaplaceDP(epsilon=1.0, seed=2)
        r1 = [dp1.noisy_count(0) for _ in range(10)]
        r2 = [dp2.noisy_count(0) for _ in range(10)]
        assert r1 != r2


# ── DPAggregator tests ────────────────────────────────────────────────────────


class TestDPAggregator:
    def test_delta_nonzero_raises(self):
        with pytest.raises(ValueError, match="delta"):
            DPAggregator(epsilon=1.0, delta=1e-5)

    def test_delta_zero_accepted(self):
        agg = DPAggregator(epsilon=1.0, delta=0.0)
        assert agg.delta == 0.0

    def test_empty_chain_returns_report(self):
        agg = DPAggregator(epsilon=1.0, seed=0)
        report = agg.compute([])
        assert isinstance(report, DPAnalyticsReport)
        assert report.epsilon == 1.0
        assert report.mechanism == "laplace"
        assert isinstance(report.node_count, float)
        assert report.tenant_counts == {}

    def test_report_epsilon_matches(self):
        agg = DPAggregator(epsilon=2.5, seed=0)
        nodes = [_FakeNode(entropy=1.5)]
        report = agg.compute(nodes)
        assert report.epsilon == 2.5

    def test_node_count_near_true(self):
        """Noisy count should be in a plausible range of the true count."""
        agg = DPAggregator(epsilon=10.0, seed=0)
        nodes = [_FakeNode(entropy=2.0) for _ in range(20)]
        report = agg.compute(nodes)
        # With ε=10, scale=0.1; noise very small. Should be within ±5 of 20.
        assert abs(report.node_count - 20) < 5

    def test_mean_entropy_near_true(self):
        agg = DPAggregator(epsilon=10.0, seed=0)
        nodes = [_FakeNode(entropy=3.0) for _ in range(10)]
        report = agg.compute(nodes)
        # sensitivity = 20/10 = 2, scale = 2/10 = 0.2 → small noise
        assert abs(report.mean_entropy - 3.0) < 1.0

    def test_phi_scrubbed_count_noised(self):
        agg = DPAggregator(epsilon=10.0, seed=0)
        nodes = [
            _FakeNode(entropy=1.0, phi_scrubbed=True),
            _FakeNode(entropy=1.0, phi_scrubbed=True),
            _FakeNode(entropy=1.0, phi_scrubbed=False),
        ]
        report = agg.compute(nodes)
        # True = 2, noise is small at ε=10
        assert abs(report.phi_scrubbed_count - 2) < 3

    def test_tenant_counts_present(self):
        agg = DPAggregator(epsilon=5.0, seed=0)
        nodes = [
            _FakeNode(entropy=1.0, tenant_id="t1"),
            _FakeNode(entropy=1.0, tenant_id="t1"),
            _FakeNode(entropy=1.0, tenant_id="t2"),
        ]
        report = agg.compute(nodes)
        assert "t1" in report.tenant_counts
        assert "t2" in report.tenant_counts

    def test_tenant_counts_noised(self):
        """Tenant counts are floats (noisy), not exact integers."""
        agg = DPAggregator(epsilon=1.0, seed=42)
        nodes = [_FakeNode(entropy=1.0, tenant_id="t1") for _ in range(5)]
        report = agg.compute(nodes)
        assert isinstance(report.tenant_counts["t1"], float)

    def test_multiple_tenants_independent(self):
        agg = DPAggregator(epsilon=5.0, seed=10)
        nodes = [
            *[_FakeNode(entropy=2.0, tenant_id="alpha") for _ in range(10)],
            *[_FakeNode(entropy=2.0, tenant_id="beta") for _ in range(5)],
        ]
        report = agg.compute(nodes)
        # Both tenants noised independently
        assert abs(report.tenant_counts["alpha"] - 10) < 5
        assert abs(report.tenant_counts["beta"] - 5) < 5

    def test_report_is_dp_analytics_report(self):
        agg = DPAggregator(epsilon=1.0, seed=0)
        report = agg.compute([_FakeNode(entropy=1.0)])
        assert isinstance(report, DPAnalyticsReport)

    def test_entropy_variance_non_negative(self):
        agg = DPAggregator(epsilon=1.0, seed=0)
        nodes = [_FakeNode(entropy=float(i)) for i in range(5)]
        report = agg.compute(nodes)
        assert report.entropy_variance >= 0.0
