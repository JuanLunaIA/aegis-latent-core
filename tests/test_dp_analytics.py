# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Deterministic tests for the internal one-release Laplace count primitive."""

from __future__ import annotations

import math
import secrets

import pytest

from aegis.core.dp_analytics import LaplaceCountMechanism, LaplaceDP


class FixedRandom:
    def __init__(self, *values: object) -> None:
        self._values = iter(values)

    def random(self) -> object:
        return next(self._values)


@pytest.mark.parametrize("epsilon", [0.0, -1.0, float("nan"), float("inf")])
def test_rejects_non_positive_or_non_finite_epsilon(epsilon: float) -> None:
    with pytest.raises(ValueError, match="epsilon"):
        LaplaceCountMechanism(epsilon)


@pytest.mark.parametrize("epsilon", [True, "1.0", None])
def test_rejects_non_numeric_epsilon(epsilon: object) -> None:
    with pytest.raises(TypeError, match="epsilon"):
        LaplaceCountMechanism(epsilon)  # type: ignore[arg-type]


def test_default_uses_system_random() -> None:
    mechanism = LaplaceCountMechanism(1.0)
    assert isinstance(mechanism._rng, secrets.SystemRandom)


def test_compatibility_alias_names_same_mechanism() -> None:
    assert LaplaceDP is LaplaceCountMechanism


def test_scale_is_unit_sensitivity_over_epsilon() -> None:
    mechanism = LaplaceCountMechanism(4.0, rng=FixedRandom(0.5))  # type: ignore[arg-type]
    assert mechanism.sensitivity == 1.0
    assert mechanism.scale == 0.25


def test_midpoint_draw_adds_exact_zero_noise() -> None:
    mechanism = LaplaceCountMechanism(1.0, rng=FixedRandom(0.5))  # type: ignore[arg-type]
    assert mechanism.release(17) == 17.0


@pytest.mark.parametrize("draw", [0.25, 0.75])
def test_inverse_cdf_matches_formula(draw: float) -> None:
    mechanism = LaplaceCountMechanism(2.0, rng=FixedRandom(draw))  # type: ignore[arg-type]
    centered = draw - 0.5
    expected_noise = -0.5 * math.copysign(1.0, centered) * math.log1p(-2.0 * abs(centered))
    assert mechanism.release(10) == pytest.approx(10.0 + expected_noise)


def test_fixed_draw_preserves_unit_adjacency_difference() -> None:
    left = LaplaceCountMechanism(0.7, rng=FixedRandom(0.25))  # type: ignore[arg-type]
    right = LaplaceCountMechanism(0.7, rng=FixedRandom(0.25))  # type: ignore[arg-type]
    assert right.release(101) - left.release(100) == pytest.approx(1.0)


@pytest.mark.parametrize("count", [-1, -10])
def test_rejects_negative_counts(count: int) -> None:
    with pytest.raises(ValueError, match="count"):
        LaplaceCountMechanism(1.0, rng=FixedRandom(0.5)).release(count)  # type: ignore[arg-type]


@pytest.mark.parametrize("count", [True, 1.5, "1"])
def test_rejects_non_integer_counts(count: object) -> None:
    with pytest.raises(TypeError, match="count"):
        LaplaceCountMechanism(1.0, rng=FixedRandom(0.5)).release(count)  # type: ignore[arg-type]


@pytest.mark.parametrize("draw", [0.0, 1.0, float("nan"), float("inf")])
def test_rejects_random_source_that_never_returns_open_unit_sample(draw: float) -> None:
    mechanism = LaplaceCountMechanism(1.0, rng=FixedRandom(*([draw] * 8)))  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="open-unit"):
        mechanism.release(1)


def test_rejects_non_numeric_random_sample() -> None:
    mechanism = LaplaceCountMechanism(1.0, rng=FixedRandom("bad"))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="random source"):
        mechanism.release(1)


def test_noisy_count_alias_delegates_to_release() -> None:
    mechanism = LaplaceCountMechanism(1.0, rng=FixedRandom(0.5))  # type: ignore[arg-type]
    assert mechanism.noisy_count(3) == 3.0
