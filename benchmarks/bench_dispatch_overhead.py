"""
Background-dispatch overhead and steady-state memory benchmark.

Two properties of the proxy's evidence path that no other harness in this
repository measures:

1. **Dispatch overhead.** ``aegis.proxy.app._spawn_background`` is on the
   request path: it wraps a coroutine, creates a task, records it in a live
   set, and updates a gauge. Its cost is charged to the caller before the
   response is returned, so the distribution — not just the mean — is what
   matters. The tail is reported explicitly because a p99 is what a governed
   request actually experiences under load.

2. **Steady-state memory.** The same path retains a task set, an MMR that
   grows with every leaf, and an open WAL handle. A leak in any of them shows
   up as monotonically rising RSS across repeated commit batches, which is what
   the second phase samples.

Boundary
--------
In-process measurement of one function and one commit loop. It **excludes**
the network, the upstream provider, request parsing, admission control, WAF
evaluation, rate limiting, and response handling. Dispatch overhead is not
end-to-end request latency and must never be presented as such. RSS stability
over a bounded run is evidence against a leak in the sampled path; it is not
proof of absence, and it says nothing about fragmentation over days or about
any other process. **No number here is a capacity claim, a service level, or a
statement about any target deployment.** See ``docs/benchmarks/BENCHMARK_METHOD.md``.

Usage
-----
    python -m benchmarks.bench_dispatch_overhead
    python benchmarks/bench_dispatch_overhead.py --dispatch-samples 5000 --json
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_DEFAULT_DISPATCH_SAMPLES = 5_000
_DEFAULT_MEMORY_ROUNDS = 30
_DEFAULT_COMMITS_PER_ROUND = 200

_REQUEST = b'{"model":"gpt-4o","messages":[{"role":"user","content":"benchmark payload"}]}'
_RESPONSE = b'{"choices":[{"message":{"role":"assistant","content":"ok"}}]}'


def _percentile(ordered: list[float], fraction: float) -> float:
    """Nearest-rank percentile over an already-sorted sample."""
    if not ordered:
        raise ValueError("percentile of an empty sample")
    rank = max(1, min(len(ordered), int(round(fraction * len(ordered)))))
    return ordered[rank - 1]


def _rss_kib() -> int | None:
    """Resident set size in KiB, or None where /proc is unavailable."""
    try:
        with open("/proc/self/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


async def _measure_dispatch(samples: int) -> dict[str, float]:
    """Time ``_spawn_background`` itself, not the coroutine it schedules.

    The awaited coroutine is a bare ``sleep(0)`` so the measured interval
    covers task creation, set insertion, gauge update and callback
    registration — the work the caller pays for — and nothing else.
    """
    from aegis.proxy.app import _spawn_background

    async def _noop() -> None:
        await asyncio.sleep(0)

    # Warm the event loop, the gauge and the import path before sampling.
    for _ in range(200):
        await _spawn_background(_noop())

    durations: list[float] = []
    tasks = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        task = _spawn_background(_noop())
        durations.append(float(time.perf_counter_ns() - start))
        tasks.append(task)
    await asyncio.gather(*tasks)

    durations.sort()
    return {
        "samples": float(samples),
        "min_ns": durations[0],
        "p25_ns": _percentile(durations, 0.25),
        "p50_ns": _percentile(durations, 0.50),
        "mean_ns": statistics.fmean(durations),
        "p75_ns": _percentile(durations, 0.75),
        "p90_ns": _percentile(durations, 0.90),
        "p95_ns": _percentile(durations, 0.95),
        "p99_ns": _percentile(durations, 0.99),
        "max_ns": durations[-1],
        "stdev_ns": statistics.stdev(durations) if len(durations) > 1 else 0.0,
    }


def _measure_memory(rounds: int, commits_per_round: int) -> dict[str, Any]:
    """Sample RSS across repeated commit batches on one long-lived ledger.

    A single ledger is reused for every round precisely so that a leak in the
    task set, the MMR or the WAL writer would accumulate rather than being
    reclaimed between rounds.
    """
    from aegis.core.crypto_audit import CryptographicAuditLedger

    samples: list[int] = []
    with (
        tempfile.TemporaryDirectory() as tmp,
        CryptographicAuditLedger(
            persistence_path=str(Path(tmp) / "memory.wal.jsonl"),
            signing_key="k" * 32,
            max_memory_nodes=512,
            fsync_fn=lambda fd: None,
        ) as ledger,
    ):
        index = 0
        for _ in range(rounds):
            for _ in range(commits_per_round):
                ledger.commit_forensic(
                    state_id=f"mem-{index}",
                    request_bytes=_REQUEST,
                    response_bytes=_RESPONSE,
                )
                index += 1
            rss = _rss_kib()
            if rss is None:
                return {"available": False, "reason": "/proc/self/status unavailable"}
            samples.append(rss)

    # The first round pays one-time costs — interpreter arenas, allocator
    # growth, lazily imported modules — that are not per-commit behaviour.
    # Reporting only first-to-last would attribute those to the commit path and
    # read as a leak. Steady state is measured from the second sample onward,
    # and both figures are reported so the split is visible rather than assumed.
    steady = samples[1:] if len(samples) > 1 else samples
    return {
        "available": True,
        "rounds": rounds,
        "commits_per_round": commits_per_round,
        "total_commits": rounds * commits_per_round,
        "first_kib": samples[0],
        "last_kib": samples[-1],
        "min_kib": min(samples),
        "max_kib": max(samples),
        "delta_kib": samples[-1] - samples[0],
        "spread_kib": max(samples) - min(samples),
        "steady_first_kib": steady[0],
        "steady_delta_kib": steady[-1] - steady[0],
        "steady_spread_kib": max(steady) - min(steady),
        "steady_commits": (rounds - 1) * commits_per_round if rounds > 1 else 0,
    }


def run_benchmark(
    dispatch_samples: int = _DEFAULT_DISPATCH_SAMPLES,
    memory_rounds: int = _DEFAULT_MEMORY_ROUNDS,
    commits_per_round: int = _DEFAULT_COMMITS_PER_ROUND,
) -> dict[str, Any]:
    dispatch = asyncio.run(_measure_dispatch(dispatch_samples))
    memory = _measure_memory(memory_rounds, commits_per_round)
    return {
        "benchmark": "dispatch_overhead_and_memory_stability",
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "logical_cpus": os.cpu_count(),
        },
        "boundary": (
            "In-process measurement of _spawn_background and a commit loop. "
            "Excludes network, provider, request parsing, admission control, WAF "
            "and response handling. Not end-to-end latency, not a capacity claim, "
            "not a service level, and not a statement about any deployment."
        ),
        "dispatch": dispatch,
        "memory": memory,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dispatch-samples", type=int, default=_DEFAULT_DISPATCH_SAMPLES)
    parser.add_argument("--memory-rounds", type=int, default=_DEFAULT_MEMORY_ROUNDS)
    parser.add_argument("--commits-per-round", type=int, default=_DEFAULT_COMMITS_PER_ROUND)
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON on stdout.")
    args = parser.parse_args()

    report = run_benchmark(args.dispatch_samples, args.memory_rounds, args.commits_per_round)

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    dispatch = report["dispatch"]
    memory = report["memory"]
    separator = "=" * 72
    print(f"\n{separator}")
    print("BACKGROUND DISPATCH OVERHEAD AND STEADY-STATE MEMORY")
    print(separator)
    print(f"  Python {report['environment']['python']} on {report['environment']['platform']}")
    print(f"  Logical CPUs: {report['environment']['logical_cpus']}")
    print()
    print(f"  _spawn_background, n = {int(dispatch['samples']):,}")
    for label in ("min", "p25", "p50", "mean", "p75", "p90", "p95", "p99", "max", "stdev"):
        print(f"    {label:>6}  {dispatch[f'{label}_ns'] / 1000:8.3f} us")
    print()
    if memory["available"]:
        print(
            f"  RSS across {memory['rounds']} samples x "
            f"{memory['commits_per_round']} commits "
            f"({memory['total_commits']:,} commits)"
        )
        print(f"    first   {memory['first_kib'] / 1024:8.2f} MiB")
        print(f"    last    {memory['last_kib'] / 1024:8.2f} MiB")
        print(f"    delta   {memory['delta_kib'] / 1024:8.2f} MiB  (includes round-1 warm-up)")
        print(f"    spread  {memory['spread_kib'] / 1024:8.2f} MiB")
        print(
            f"    steady  {memory['steady_delta_kib'] / 1024:8.2f} MiB "
            f"delta over {memory['steady_commits']:,} commits after warm-up"
        )
    else:
        print(f"  RSS sampling unavailable: {memory['reason']}")
    print()
    print("  Boundary: in-process only. Not end-to-end latency, not capacity.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
