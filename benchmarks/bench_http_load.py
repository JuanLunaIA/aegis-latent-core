# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""benchmarks.bench_http_load — real concurrent HTTP load test against a live server.

Drives a running Aegis proxy (launched separately via uvicorn) with a high volume
of concurrent requests and reports measured latency percentiles, throughput (RPS),
and process CPU/RAM sampled from ``/proc``.

All numbers printed are from actual execution. Nothing is synthesised.

Usage::

    # In one shell: launch the server
    uvicorn aegis.proxy.app:create_proxy_app --factory \
        --host 127.0.0.1 --port 8080 --workers 4

    # In another: drive load
    python -m benchmarks.bench_http_load \
        --url http://127.0.0.1:8080/health \
        --total 100000 --concurrency 256
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path

import httpx


def _read_proc_rss_kb(pid: int) -> int:
    """Resident set size (KiB) for *pid* from /proc/<pid>/status, or 0."""
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _read_proc_cpu_jiffies(pid: int) -> int:
    """utime+stime jiffies for *pid* (and its children) from /proc/<pid>/stat."""
    try:
        parts = Path(f"/proc/{pid}/stat").read_text().split()
        # fields 14,15 = utime,stime; 16,17 = cutime,cstime (1-indexed)
        return int(parts[13]) + int(parts[14]) + int(parts[15]) + int(parts[16])
    except (OSError, ValueError, IndexError):
        return 0


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = k - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


async def _worker(
    client: httpx.AsyncClient,
    url: str,
    queue: asyncio.Queue[int],
    latencies: list[float],
    errors: list[int],
) -> None:
    while True:
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            return
        t0 = time.perf_counter()
        try:
            resp = await client.get(url)
            dt = (time.perf_counter() - t0) * 1000.0  # ms
            if resp.status_code == 200:
                latencies.append(dt)
            else:
                errors.append(resp.status_code)
        except (httpx.HTTPError, OSError):
            errors.append(-1)


async def run_load(
    url: str,
    total: int,
    concurrency: int,
    server_pid: int | None,
) -> dict[str, object]:
    queue: asyncio.Queue[int] = asyncio.Queue()
    for i in range(total):
        queue.put_nowait(i)

    latencies: list[float] = []
    errors: list[int] = []

    limits = httpx.Limits(
        max_connections=concurrency,
        max_keepalive_connections=concurrency,
    )
    cpu0 = _read_proc_cpu_jiffies(server_pid) if server_pid else 0
    rss_samples: list[int] = []

    async with httpx.AsyncClient(limits=limits, timeout=30.0) as client:
        t_start = time.perf_counter()

        async def _sampler() -> None:
            while True:
                if server_pid:
                    rss = _read_proc_rss_kb(server_pid)
                    if rss:
                        rss_samples.append(rss)
                await asyncio.sleep(0.1)

        sampler_task = asyncio.create_task(_sampler())
        workers = [
            asyncio.create_task(_worker(client, url, queue, latencies, errors))
            for _ in range(concurrency)
        ]
        await asyncio.gather(*workers)
        wall = time.perf_counter() - t_start
        sampler_task.cancel()

    cpu1 = _read_proc_cpu_jiffies(server_pid) if server_pid else 0
    clk_tck = 100  # standard Linux USER_HZ
    cpu_seconds = (cpu1 - cpu0) / clk_tck if server_pid else 0.0

    latencies.sort()
    ok = len(latencies)
    result: dict[str, object] = {
        "url": url,
        "total_requested": total,
        "successful": ok,
        "errors": len(errors),
        "concurrency": concurrency,
        "wall_seconds": round(wall, 4),
        "throughput_rps": round(ok / wall, 1) if wall > 0 else 0.0,
        "latency_ms": {
            "p50": round(_percentile(latencies, 0.50), 4),
            "p90": round(_percentile(latencies, 0.90), 4),
            "p95": round(_percentile(latencies, 0.95), 4),
            "p99": round(_percentile(latencies, 0.99), 4),
            "max": round(latencies[-1], 4) if latencies else 0.0,
            "mean": round(statistics.fmean(latencies), 4) if latencies else 0.0,
        },
    }
    if server_pid:
        result["server_cpu_seconds"] = round(cpu_seconds, 3)
        result["server_cpu_utilization_pct"] = (
            round(100.0 * cpu_seconds / wall, 1) if wall > 0 else 0.0
        )
        result["server_peak_rss_mib"] = (
            round(max(rss_samples) / 1024.0, 1) if rss_samples else 0.0
        )
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default="http://127.0.0.1:8080/health")
    ap.add_argument("--total", type=int, default=100_000)
    ap.add_argument("--concurrency", type=int, default=256)
    ap.add_argument("--server-pid", type=int, default=None)
    ap.add_argument("--warmup", type=int, default=2_000)
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    if args.warmup > 0:
        asyncio.run(run_load(args.url, args.warmup, args.concurrency, None))

    result = asyncio.run(
        run_load(args.url, args.total, args.concurrency, args.server_pid)
    )
    print(json.dumps(result, indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
