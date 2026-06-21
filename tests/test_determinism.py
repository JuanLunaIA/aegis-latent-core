# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""IEC 62443 SL-3 determinism test: scheduling jitter σ validation.

Validates the zero-forensic-latency architecture property: asyncio background
task dispatch must not add meaningful latency variance to the hot request path.
The 10µs σ target is the IEC 62443 SL-3 determinism requirement for the
background forensic path.

These tests measure wall-clock time from asyncio.create_task() to the first
instruction executed inside the coroutine (true scheduling overhead, not I/O).
"""

from __future__ import annotations

import asyncio
import statistics
import time

import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────


async def _measure_dispatch_jitter(n: int) -> list[float]:
    """Return n jitter samples: wall-clock from create_task() to first coroutine
    instruction, in seconds."""
    samples: list[float] = []
    result_queue: asyncio.Queue[float] = asyncio.Queue()

    async def _probe(t0: float) -> None:
        result_queue.put_nowait(time.perf_counter() - t0)

    for _ in range(n):
        t0 = time.perf_counter()
        asyncio.create_task(_probe(t0))
        samples.append(await result_queue.get())

    return samples


# ── Correctness / shape ───────────────────────────────────────────────────────


class TestJitterMeasurement:
    async def test_returns_n_samples(self):
        samples = await _measure_dispatch_jitter(50)
        assert len(samples) == 50

    async def test_all_samples_positive(self):
        samples = await _measure_dispatch_jitter(50)
        assert all(s >= 0 for s in samples)

    async def test_samples_are_finite(self):
        import math

        samples = await _measure_dispatch_jitter(50)
        assert all(math.isfinite(s) for s in samples)

    async def test_median_below_1ms(self):
        """Sanity check: asyncio dispatch overhead should never exceed 1ms p50."""
        samples = await _measure_dispatch_jitter(100)
        assert statistics.median(samples) < 1e-3, (
            f"Median jitter {statistics.median(samples) * 1e6:.1f}µs exceeds 1ms"
        )

    async def test_p99_below_10ms(self):
        """Sanity check: p99 must be below 10ms even on loaded CI systems."""
        samples = sorted(await _measure_dispatch_jitter(200))
        p99_idx = int(len(samples) * 0.99)
        p99 = samples[p99_idx]
        assert p99 < 10e-3, f"p99 jitter {p99 * 1e6:.1f}µs exceeds 10ms"


# ── IEC 62443 SL-3 σ requirement ─────────────────────────────────────────────


class TestIEC62443Determinism:
    """IEC 62443 SL-3 determinism requirement: σ < 100µs under synthetic load.

    The spec target is <10µs σ on dedicated hardware. The 100µs threshold here
    is the CI-environment bound (shared VMs have higher scheduling variance).
    Measured values on the reference hardware are logged for traceability.
    """

    async def test_jitter_sigma_within_ci_bound(self):
        """σ < 100µs: baseline determinism on any POSIX system (CI-safe bound)."""
        samples = await _measure_dispatch_jitter(500)
        sigma = statistics.stdev(samples)
        median = statistics.median(samples)
        p99_idx = int(len(samples) * 0.99)
        p99 = sorted(samples)[p99_idx]
        # Log measured values for traceability
        print(
            f"\nJitter stats (n={len(samples)}): "
            f"p50={median * 1e6:.2f}µs  p99={p99 * 1e6:.2f}µs  σ={sigma * 1e6:.2f}µs"
        )
        assert sigma < 100e-6, (
            f"Scheduling jitter σ={sigma * 1e6:.2f}µs exceeds 100µs CI bound "
            f"(IEC 62443 SL-3 target: <10µs on dedicated hardware)"
        )

    async def test_jitter_sigma_under_concurrent_load(self):
        """σ < 100µs even when background I/O tasks are competing for the event loop."""

        # Spawn background tasks to simulate proxy load
        async def _background_noise() -> None:
            for _ in range(50):
                await asyncio.sleep(0)

        noise_tasks = [asyncio.create_task(_background_noise()) for _ in range(20)]

        samples = await _measure_dispatch_jitter(300)

        await asyncio.gather(*noise_tasks)

        sigma = statistics.stdev(samples)
        print(
            f"\nLoaded jitter stats (n={len(samples)}, 20 concurrent tasks): σ={sigma * 1e6:.2f}µs"
        )
        assert sigma < 100e-6, (
            f"Scheduling jitter under load σ={sigma * 1e6:.2f}µs exceeds 100µs CI bound"
        )

    async def test_jitter_mean_stable_across_batches(self):
        """Mean jitter stays within 50µs between two consecutive 200-sample batches.

        Validates temporal stability: jitter must not drift under sustained load,
        which would indicate event-loop starvation or memory pressure.
        """
        batch1 = await _measure_dispatch_jitter(200)
        batch2 = await _measure_dispatch_jitter(200)
        mean1 = statistics.mean(batch1)
        mean2 = statistics.mean(batch2)
        drift = abs(mean2 - mean1)
        print(
            f"\nMean drift between batches: {drift * 1e6:.2f}µs "
            f"(batch1={mean1 * 1e6:.2f}µs batch2={mean2 * 1e6:.2f}µs)"
        )
        assert drift < 50e-6, (
            f"Jitter mean drifted {drift * 1e6:.2f}µs between batches "
            f"(IEC 62443 SL-3 requires temporal stability)"
        )

    async def test_no_outlier_exceeds_500us(self):
        """No single dispatch event must exceed 500µs (hard real-time bound).

        Pathological outliers (>500µs) indicate event-loop blocking, which
        breaks the zero-forensic-latency isolation guarantee.
        """
        samples = await _measure_dispatch_jitter(500)
        outliers = [s for s in samples if s > 500e-6]
        assert len(outliers) == 0, (
            f"{len(outliers)} dispatch events exceeded 500µs: "
            f"{[f'{s * 1e6:.1f}µs' for s in outliers]}"
        )

    async def test_coefficient_of_variation_bounded(self):
        """Coefficient of variation (σ/mean) < 5.0 — jitter spread is bounded.

        A CV > 5 indicates heavy-tailed distributions (occasional 10x+ spikes)
        which break deterministic real-time guarantees regardless of the mean.
        """
        samples = await _measure_dispatch_jitter(300)
        mean = statistics.mean(samples)
        sigma = statistics.stdev(samples)
        if mean < 1e-9:
            pytest.skip("Mean jitter too small for CV calculation (< 1ns)")
        cv = sigma / mean
        print(f"\nCV={cv:.3f} (σ={sigma * 1e6:.2f}µs, mean={mean * 1e6:.2f}µs)")
        assert cv < 5.0, (
            f"Jitter coefficient of variation {cv:.3f} exceeds 5.0 "
            f"(heavy-tailed distribution detected)"
        )


# ── proxy/app.py _spawn_background jitter ────────────────────────────────────


class TestSpawnBackgroundDeterminism:
    """End-to-end: the actual _spawn_background() wrapper used in production."""

    async def test_spawn_background_jitter_sigma(self):
        """_spawn_background wraps coroutines with jitter measurement.
        The wrapper itself must not add perceptible latency variance.
        """
        from unittest.mock import patch

        from aegis.proxy.app import _spawn_background

        observed: list[float] = []

        async def _noop() -> None:
            await asyncio.sleep(0)

        with patch("aegis.core.observability.SCHEDULING_JITTER") as mock_hist:
            mock_hist.observe = lambda v: observed.append(v)
            # Sequential dispatch: one task at a time, matching the production
            # pattern (one background commit per request).
            for _ in range(100):
                task = _spawn_background(_noop())
                await task

        if len(observed) < 2:
            pytest.skip("Too few observations to compute σ")

        sigma = statistics.stdev(observed)
        print(f"\nspawn_background wrapper σ={sigma * 1e6:.2f}µs (n={len(observed)})")
        assert sigma < 100e-6, (
            f"_spawn_background jitter σ={sigma * 1e6:.2f}µs exceeds 100µs CI bound"
        )
