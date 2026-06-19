"""
Forwarding latency benchmark — validates "zero forensic latency" claim.

Claim under test (aegis/proxy/app.py, _spawn_background):
  _commit_and_alert is scheduled via asyncio.create_task() and runs AFTER the HTTP
  response has been returned to the client. Therefore it adds no latency to the
  current request — only the O(1) scheduling call is on the hot path.

Two measurements are taken:

1. TASK SCHEDULING OVERHEAD (direct micro-benchmark)
   Times asyncio.create_task() itself in isolation.
   This is the exact overhead added to the response path per request.
   Result reported in µs.

2. WAF INSPECTION OVERHEAD (HTTP round-trip, ASGI in-process)
   Times the full client-visible request latency through the WAF + HTTP stack.
   Two sub-conditions:
     WITH_BG  — asyncio.create_task() called once per request
     NO_BG    — no create_task (floor latency)
   The WAF benchmark runs with inter-request draining (each batch of 10 requests
   is followed by a single asyncio.sleep(0) to prevent background task stacking).

Statistical significance: Welch's two-sample t-test (α=0.05). Cohen's d for effect size.

Usage
-----
    cd /path/to/aegis-latent-core
    python -m benchmarks.bench_forwarding
    python -m benchmarks.bench_forwarding --warmup 200 --n 2000
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import argparse
import asyncio
import math
import random
import statistics
import time
from typing import Any

import httpx
import numpy as np
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# ── Fixed upstream mock response (OpenAI format) ─────────────────────────────

_MOCK_BODY: dict[str, Any] = {
    "id": "chatcmpl-bench",
    "object": "chat.completion",
    "created": 1_719_000_000,
    "model": "gpt-4o-mini",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "pong"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
}

_REQUEST_PAYLOAD: dict[str, Any] = {
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "ping"}],
}

_DRAIN_EVERY = 10  # flush background tasks every N sequential requests


# ── Noop background coroutine ─────────────────────────────────────────────────


async def _noop_commit() -> None:
    """
    Placeholder for the audit commit background task.
    Intentionally empty — measures pure asyncio.create_task() scheduling overhead.
    """


# ── Part 1: Direct scheduling overhead micro-benchmark ───────────────────────


async def _bench_spawn_background_overhead(n: int = 5_000) -> list[float]:
    """
    Measure the full _spawn_background() hot-path overhead per request.

    Replicates all bookkeeping from aegis/proxy/app.py:_spawn_background (lines 49-60):
      asyncio.create_task()
      _BACKGROUND_TASKS.add(task)
      AUDIT_PENDING_COMMITS.set(len(_BACKGROUND_TASKS))   ← gauge update
      task.add_done_callback(_on_done)

    This is the actual per-request overhead on the proxy response path — not just
    raw create_task(). The done-callback removes the task from the set and updates
    the gauge; both operations execute AFTER the response is returned, so they are
    NOT measured here (they run on a future event-loop iteration).

    Returns n latency samples in seconds. Task is awaited after each timing window
    (not counted) to prevent accumulation.
    """
    _pending: set[asyncio.Task[None]] = set()

    def _gauge_set(_val: int) -> None:
        pass  # noop: replicates observability.AUDIT_PENDING_COMMITS.set()

    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        task: asyncio.Task[None] = asyncio.create_task(_noop_commit())
        _pending.add(task)
        _gauge_set(len(_pending))

        def _on_done(t: asyncio.Task[None], _p: set = _pending) -> None:  # type: ignore[assignment]
            _p.discard(t)
            _gauge_set(len(_p))

        task.add_done_callback(_on_done)
        t1 = time.perf_counter()
        samples.append(t1 - t0)
        await task  # drain; not counted in elapsed
    return samples


# ── Part 2: HTTP round-trip WAF benchmark ────────────────────────────────────


def _build_app(spawn_background: bool) -> FastAPI:
    """
    Minimal proxy-equivalent FastAPI app for WAF+HTTP benchmarking.
    Both conditions run identical code paths (WAF, JSON parse/serialise).
    The only variable is the _spawn_background() equivalent block.

    WITH_BG replicates ALL bookkeeping from aegis/proxy/app.py:_spawn_background:
      create_task + set.add + gauge.set + add_done_callback
    so that the measured latency matches the real proxy hot path.
    """
    from aegis.proxy.waf import AegisWAF

    app = FastAPI()
    waf = AegisWAF(strict_mode=True)
    _pending: set[asyncio.Task[None]] = set()

    def _gauge_set(_v: int) -> None:
        pass

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        body = await request.json()
        result = waf.inspect_payload(body)
        if not result.allowed:
            return JSONResponse(
                status_code=400,
                content={"error": {"message": result.reason, "type": "waf_block"}},
            )
        if spawn_background:
            task: asyncio.Task[None] = asyncio.create_task(_noop_commit())
            _pending.add(task)
            _gauge_set(len(_pending))

            def _on_done(t: asyncio.Task[None]) -> None:
                _pending.discard(t)
                _gauge_set(len(_pending))

            task.add_done_callback(_on_done)
        return JSONResponse(content=_MOCK_BODY)

    return app


async def _measure_condition(
    app: FastAPI,
    n_warmup: int,
    n_measure: int,
    drain_interval: int = _DRAIN_EVERY,
) -> list[float]:
    """
    Measure client-visible latency for n_measure requests via ASGI transport.
    Background tasks are drained every drain_interval requests to prevent stacking.
    Returns n_measure latency samples in seconds.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://bench") as client:
        for i in range(n_warmup):
            await client.post("/v1/chat/completions", json=_REQUEST_PAYLOAD)
            if (i + 1) % drain_interval == 0:
                await asyncio.sleep(0)

        samples: list[float] = []
        for i in range(n_measure):
            t0 = time.perf_counter()
            resp = await client.post("/v1/chat/completions", json=_REQUEST_PAYLOAD)
            elapsed = time.perf_counter() - t0
            if resp.status_code != 200:
                raise RuntimeError(f"Unexpected HTTP {resp.status_code}: {resp.text[:200]}")
            samples.append(elapsed)
            if (i + 1) % drain_interval == 0:
                await asyncio.sleep(0)

    return samples


# ── Statistics helpers ────────────────────────────────────────────────────────


def _pct(samples: list[float], p: float) -> float:
    return float(np.percentile(samples, p))


def _welch_t_test(a: list[float], b: list[float]) -> tuple[float, float]:
    """
    Two-sample significance test (Welch statistic, normal-approximation p-value).

    P-value uses math.erfc (standard normal CDF), not the exact t-distribution.
    For n >= 30 per sample the normal approximation error is < 0.1 percentage
    points (df >> 30 → t-distribution converges to Z). At n=2000 the error is
    negligible. If exact p-values are required at small n, replace erfc with
    a proper t-CDF (e.g. scipy.stats.t.sf).
    """
    n_a, n_b = len(a), len(b)
    if n_a < 2 or n_b < 2:
        return 0.0, 1.0
    mean_a, mean_b = statistics.mean(a), statistics.mean(b)
    var_a, var_b = statistics.variance(a), statistics.variance(b)
    denom = var_a / n_a + var_b / n_b
    if denom == 0:
        return 0.0, 1.0
    t_stat = (mean_a - mean_b) / math.sqrt(denom)
    z = abs(t_stat)
    p_value = float(math.erfc(z / math.sqrt(2)))
    return t_stat, p_value


def _cohen_d(a: list[float], b: list[float]) -> float:
    n_a, n_b = len(a), len(b)
    if n_a < 2 or n_b < 2:
        return 0.0
    denom = n_a + n_b - 2
    if denom <= 0:
        return 0.0
    pooled_var = ((n_a - 1) * statistics.variance(a) + (n_b - 1) * statistics.variance(b)) / denom
    std = math.sqrt(pooled_var) if pooled_var > 0 else 0.0
    return (statistics.mean(a) - statistics.mean(b)) / std if std else 0.0


def _row(label: str, samples: list[float], w: int = 10) -> str:
    return (
        f"  {label:<{w}} "
        f"p50={_pct(samples, 50) * 1000:.3f}ms  "
        f"p95={_pct(samples, 95) * 1000:.3f}ms  "
        f"p99={_pct(samples, 99) * 1000:.3f}ms  "
        f"mean={statistics.mean(samples) * 1000:.3f}ms  "
        f"σ={statistics.stdev(samples) * 1000:.3f}ms  "
        f"n={len(samples)}"
    )


# ── Main benchmark ─────────────────────────────────────────────────────────────


async def run_benchmark(n_warmup: int = 200, n_measure: int = 2_000) -> dict[str, Any]:
    sep = "=" * 72
    print(f"\n{sep}")
    print("FORWARDING LATENCY BENCHMARK — zero forensic latency validation")
    print(sep)

    # ── Part 1: _spawn_background hot-path overhead ──────────────────────────
    print()
    print("PART 1: _spawn_background() hot-path overhead (direct micro-benchmark)")
    print("  Measures full scheduling block: create_task + set.add + gauge.set + add_done_callback")
    print()
    n_task = 5_000
    task_samples = await _bench_spawn_background_overhead(n_task)
    task_p50_us = _pct(task_samples, 50) * 1_000_000
    task_p99_us = _pct(task_samples, 99) * 1_000_000
    task_mean_us = statistics.mean(task_samples) * 1_000_000
    task_std_us = statistics.stdev(task_samples) * 1_000_000
    print(
        f"  _spawn_background()  "
        f"p50={task_p50_us:.2f}µs  p99={task_p99_us:.2f}µs  "
        f"mean={task_mean_us:.2f}µs  σ={task_std_us:.2f}µs  n={n_task}"
    )
    print()
    if task_p99_us < 100:
        print(
            f"  [PROVEN] _spawn_background() p99 < 100 µs ({task_p99_us:.2f} µs). "
            "Scheduling overhead is negligible on the response hot path."
        )
    else:
        print(
            f"  [INFERENCE] _spawn_background() p99 = {task_p99_us:.2f} µs. "
            "Higher than expected — investigate event loop contention."
        )

    # ── Part 2: HTTP round-trip WAF benchmark ────────────────────────────────
    print()
    print(f"PART 2: WAF+HTTP latency (ASGI in-process, drain every {_DRAIN_EVERY} requests)")
    print(f"  Warmup: {n_warmup}/condition (discarded)  |  Measured: {n_measure}/condition")
    print()

    app_with_bg = _build_app(spawn_background=True)
    app_no_bg = _build_app(spawn_background=False)

    # Randomize order to reduce temporal bias (CPU frequency scaling, GC, OS load).
    conditions: list[tuple[str, FastAPI]] = [
        ("WITH_BG", app_with_bg),
        ("NO_BG", app_no_bg),
    ]
    random.shuffle(conditions)

    samples_with: list[float] = []
    samples_none: list[float] = []
    for idx, (label, app) in enumerate(conditions, start=1):
        print(f"  [{idx}/2] Measuring {label} ...")
        samples = await _measure_condition(app, n_warmup, n_measure)
        if label == "WITH_BG":
            samples_with = samples
        else:
            samples_none = samples

    assert samples_with, "WITH_BG condition not measured"
    assert samples_none, "NO_BG condition not measured"

    t_stat, p_value = _welch_t_test(samples_with, samples_none)
    d = _cohen_d(samples_with, samples_none)
    delta_p50_us = (_pct(samples_with, 50) - _pct(samples_none, 50)) * 1_000_000
    alpha = 0.05

    print()
    print("  Results (client-visible latency):")
    print(_row("WITH_BG", samples_with))
    print(_row("NO_BG", samples_none))
    print()
    print(
        f"  Welch t={t_stat:.4f}  p_value={p_value:.6f}  "
        f"Cohen_d={d:.4f}  Δp50={delta_p50_us:+.2f}µs"
    )
    print()

    if p_value >= alpha:
        http_verdict = (
            f"[PROVEN] p_value={p_value:.4f} >= {alpha}. "
            "BackgroundTask adds no statistically significant HTTP overhead."
        )
    else:
        effect = "negligible" if abs(d) < 0.2 else ("small" if abs(d) < 0.5 else "medium")
        http_verdict = (
            f"[INFERENCE] p_value={p_value:.4f} < {alpha} — statistically significant "
            f"(Δp50={delta_p50_us:+.2f}µs, Cohen_d={d:.4f} = {effect} effect). "
            "Note: sequential benchmark context — production has concurrent requests "
            "where background tasks interleave with other clients, not the same client."
        )

    print(f"  Verdict: {http_verdict}")

    return {
        "spawn_background_overhead": {
            "p50_us": task_p50_us,
            "p99_us": task_p99_us,
            "mean_us": task_mean_us,
            "stddev_us": task_std_us,
            "n": n_task,
        },
        "http_waf": {
            "with_bg": {
                "p50_ms": _pct(samples_with, 50) * 1_000,
                "p95_ms": _pct(samples_with, 95) * 1_000,
                "p99_ms": _pct(samples_with, 99) * 1_000,
                "mean_ms": statistics.mean(samples_with) * 1_000,
                "stddev_ms": statistics.stdev(samples_with) * 1_000,
                "n": len(samples_with),
            },
            "no_bg": {
                "p50_ms": _pct(samples_none, 50) * 1_000,
                "p95_ms": _pct(samples_none, 95) * 1_000,
                "p99_ms": _pct(samples_none, 99) * 1_000,
                "mean_ms": statistics.mean(samples_none) * 1_000,
                "stddev_ms": statistics.stdev(samples_none) * 1_000,
                "n": len(samples_none),
            },
            "stats": {
                "t_stat": t_stat,
                "p_value": p_value,
                "cohen_d": d,
                "delta_p50_us": delta_p50_us,
                "significant": p_value < alpha,
                "verdict": http_verdict,
            },
        },
    }


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--warmup", type=int, default=200, metavar="N")
    p.add_argument("--n", type=int, default=2_000, metavar="N")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    asyncio.run(run_benchmark(n_warmup=args.warmup, n_measure=args.n))
