#!/usr/bin/env python3
"""Reproducible local benchmark for the bounded SSE transformation path.

No network or synthetic performance claim is hidden: the harness measures the
in-process BoundedStreamProxy with a deterministic generated upstream. Results
are workload- and host-specific and are emitted as machine-readable JSON.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import sys
import time
import tracemalloc
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from aegis.proxy.streaming import BoundedStreamProxy, StreamEvidenceSummary


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * probability)))
    return ordered[index]


async def run_once(events: int) -> dict[str, float | int | str]:
    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        for index in range(events):
            payload = {
                "id": "benchmark",
                "choices": [{"index": 0, "delta": {"content": f"token-{index} "}}],
            }
            yield b"data: " + json.dumps(payload, separators=(",", ":")).encode() + b"\n\n", payload
        yield b"data: [DONE]", None

    terminal: list[StreamEvidenceSummary] = []

    async def commit(summary: StreamEvidenceSummary) -> None:
        terminal.append(summary)

    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=max(1_048_576, events * 256),
        max_duration_seconds=120.0,
        max_event_bytes=16_384,
        queue_max_items=8,
        queue_max_bytes=131_072,
        preview_bytes=65_536,
        deidentifier_window_chars=128,
    )
    tracemalloc.start()
    started = time.perf_counter()
    first_byte: float | None = None
    output_bytes = 0
    chunks = 0
    async for chunk in proxy:
        if first_byte is None:
            first_byte = time.perf_counter() - started
        output_bytes += len(chunk)
        chunks += 1
    duration = time.perf_counter() - started
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if len(terminal) != 1 or first_byte is None:
        raise RuntimeError("benchmark did not observe exactly one terminal commit and first byte")
    return {
        "events": events,
        "chunks": chunks,
        "output_bytes": output_bytes,
        "first_byte_ms": first_byte * 1000.0,
        "duration_ms": duration * 1000.0,
        "events_per_second": events / duration,
        "tracemalloc_peak_bytes": peak_memory,
        "proxy_peak_queue_bytes": proxy.peak_queue_bytes,
        "proxy_peak_queue_items": proxy.peak_queue_items,
        "terminal_outcome": terminal[0].terminal_outcome,
    }


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=1_000)
    parser.add_argument("--rounds", type=int, default=7)
    args = parser.parse_args()
    if args.events < 1_000 or args.rounds < 3:
        parser.error("events must be >= 1000 and rounds must be >= 3")
    runs = [await run_once(args.events) for _ in range(args.rounds)]
    first = [float(run["first_byte_ms"]) for run in runs]
    duration = [float(run["duration_ms"]) for run in runs]
    throughput = [float(run["events_per_second"]) for run in runs]
    result = {
        "benchmark": "bounded-stream-proxy-in-process-v1",
        "events_per_round": args.events,
        "rounds": args.rounds,
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or "not-reported",
        },
        "warmup_rounds": 0,
        "source_state": "working-tree measurement; bind to the merge commit before release use",
        "first_byte_ms": {"p50": statistics.median(first), "p95": percentile(first, 0.95)},
        "duration_ms": {"p50": statistics.median(duration), "p95": percentile(duration, 0.95)},
        "events_per_second": {"p50": statistics.median(throughput)},
        "max_tracemalloc_peak_bytes": max(int(run["tracemalloc_peak_bytes"]) for run in runs),
        "max_proxy_queue_bytes": max(int(run["proxy_peak_queue_bytes"]) for run in runs),
        "max_proxy_queue_items": max(int(run["proxy_peak_queue_items"]) for run in runs),
        "claim_scope": "local in-process transformation only; excludes network and durable WAL latency",
        "runs": runs,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
