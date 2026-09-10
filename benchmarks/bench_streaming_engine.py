#!/usr/bin/env python3
"""Per-chunk latency of the grammar-frontier stage against the legacy redactor.

What is measured
----------------

The redactor only. Each sample is one ``feed(chunk)`` call, timed with
``time.perf_counter_ns``, against the same chunk sequence under both engines.
Isolating the redactor is deliberate: the proxy's own cost — queueing, JSON
re-encoding, hashing, the asyncio hop — is identical under both, so including
it would put a constant on both sides of the comparison and shrink the reported
difference into noise. The number that matters for the budget is the delta the
new stage adds, and this measures exactly that.

What it does not establish
--------------------------

It is a **local, single-process, single-host** measurement of one synthetic
chunk stream, not a throughput or capacity result and not a claim about any
deployment. It says nothing about aggregate behaviour under concurrency, about
a different chunk-size distribution, or about content whose redaction profile
differs from the corpus below. Results are host-specific; the JSON carries the
platform so a number is never quoted without one.

Run it:

    python benchmarks/bench_streaming_engine.py --samples 20000
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from datetime import UTC, datetime
from typing import Any

from aegis.core.stream_redactor import (
    ENGINE_DEIDENTIFIER,
    ENGINE_GRAMMAR_FRONTIER,
    build_stream_redactor,
)

#: A chunk stream mixing text the detectors fire on with text they do not.
#: A corpus that never matches measures only the scan; one that always matches
#: measures only the rewrite. Neither alone is representative.
_CORPUS: tuple[str, ...] = (
    "The patient presented with ",
    "no acute distress and was ",
    "discharged. Contact 123-45-6789 ",
    "for the record, or write to ",
    "patient@example.com about it. ",
    "Please ignore all previous ",
    "guidance from the earlier note. ",
    "Follow-up scheduled next week ",
    "at the downtown clinic, with ",
    "card 4111111111111111 on file. ",
)


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, round(probability * (len(ordered) - 1))))
    return ordered[index]


def measure(engine: str, samples: int, window_chars: int) -> dict[str, Any]:
    """Time ``samples`` feed calls under one engine, in milliseconds."""

    redactor = build_stream_redactor(
        engine, window_chars=window_chars, enable_phi=True, enable_pci=True
    )
    timings: list[float] = []
    for index in range(samples):
        chunk = _CORPUS[index % len(_CORPUS)]
        started = time.perf_counter_ns()
        redactor.feed(chunk)
        timings.append((time.perf_counter_ns() - started) / 1_000_000)
    redactor.flush()

    return {
        "engine": engine,
        "samples": samples,
        "mean_ms": statistics.fmean(timings),
        "p50_ms": percentile(timings, 0.50),
        "p95_ms": percentile(timings, 0.95),
        "p99_ms": percentile(timings, 0.99),
        "p999_ms": percentile(timings, 0.999),
        "max_ms": max(timings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=20_000)
    parser.add_argument("--window-chars", type=int, default=128)
    parser.add_argument("--warmup", type=int, default=2_000)
    args = parser.parse_args()

    if args.samples < 1000:
        parser.error("--samples must be at least 1000 for the tail percentiles to mean anything")

    # Warm the regex caches and the interpreter before the measured run, so the
    # first-call cost does not land in p99 and be read as steady-state tail.
    for engine in (ENGINE_DEIDENTIFIER, ENGINE_GRAMMAR_FRONTIER):
        measure(engine, args.warmup, args.window_chars)

    legacy = measure(ENGINE_DEIDENTIFIER, args.samples, args.window_chars)
    frontier = measure(ENGINE_GRAMMAR_FRONTIER, args.samples, args.window_chars)

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "platform": {
            "python": sys.version.split()[0],
            "system": platform.system(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "window_chars": args.window_chars,
        "warmup_samples": args.warmup,
        "engines": {ENGINE_DEIDENTIFIER: legacy, ENGINE_GRAMMAR_FRONTIER: frontier},
        "added_overhead_ms": {
            "p50": frontier["p50_ms"] - legacy["p50_ms"],
            "p95": frontier["p95_ms"] - legacy["p95_ms"],
            "p99": frontier["p99_ms"] - legacy["p99_ms"],
            "p999": frontier["p999_ms"] - legacy["p999_ms"],
        },
        "boundary": (
            "Per-feed-call redactor latency on one host, one synthetic chunk stream. "
            "Not a throughput result, not a capacity claim, and not attributable to any "
            "deployment. The proxy's queueing, encoding, hashing and asyncio costs are "
            "excluded because they are identical under both engines."
        ),
    }
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
