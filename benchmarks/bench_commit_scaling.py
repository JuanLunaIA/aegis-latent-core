"""
Commit-cost scaling benchmark — per-commit latency as a function of chain length.

``benchmarks/bench_crypto_audit.py`` measures commit throughput at one fixed N,
which cannot distinguish a constant per-commit cost from one that grows with the
number of leaves already in the MMR. This benchmark varies the chain length and
reports the per-commit latency at each, so a change with the wrong asymptotic
shape shows up as a rising column rather than as a slightly worse single number.

That distinction is load-bearing here: the ledger reverts a failed commit by
restoring the MMR, and the revert used to be a ``copy.deepcopy`` of the whole
accumulator taken on *every* commit — including the overwhelming majority that
succeed. Cost per commit therefore grew with the chain, and the growth was
invisible to a fixed-N benchmark.

Boundary
--------
This is an in-process microbenchmark of the commit path only. It excludes the
network, the upstream provider, request parsing, admission control, WAF
evaluation, and response handling. By default it also installs a no-op
``fsync_fn``, which removes durable-write cost so the CPU-bound shape is visible;
pass ``--fsync`` to include real ``fsync``. **None of these numbers is a capacity
claim, a service level, or a statement about any target deployment.** See
``docs/benchmarks/BENCHMARK_METHOD.md``.

Usage
-----
    python -m benchmarks.bench_commit_scaling
    python benchmarks/bench_commit_scaling.py --lengths 0,1000,4000 --batch 500
    python benchmarks/bench_commit_scaling.py --json > report.json
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import argparse
import json
import platform
import secrets
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from aegis.core.crypto_audit import CryptographicAuditLedger

_DEFAULT_LENGTHS = (0, 500, 1_000, 2_000, 4_000, 8_000)
_DEFAULT_BATCH = 500
_DEFAULT_K = 3

_REQUEST = b'{"model":"gpt-4o","messages":[{"role":"user","content":"benchmark payload"}]}'
_RESPONSE = b'{"choices":[{"message":{"role":"assistant","content":"ok"}}]}'


def _noop_fsync(_fd: int) -> None:
    """Remove durable-write cost so the CPU-bound shape of the path is visible."""


def measure_at_length(prefill: int, batch: int, k: int, *, real_fsync: bool) -> dict[str, float]:
    """Time ``batch`` commits made against a chain that already holds ``prefill``.

    Best-of-k is reported, matching ``bench_crypto_audit.py`` and ``bench_mmr.py``
    (Google Benchmark min methodology), which strips scheduler noise without
    hiding a systematic cost.
    """
    key = secrets.token_hex(32)
    latencies: list[float] = []
    for trial in range(k):
        with (
            tempfile.TemporaryDirectory() as tmp,
            CryptographicAuditLedger(
                persistence_path=str(Path(tmp) / f"scaling_{trial}.wal.jsonl"),
                signing_key=key,
                fsync_fn=None if real_fsync else _noop_fsync,
            ) as ledger,
        ):
            for i in range(prefill):
                ledger.commit_forensic(
                    state_id=f"prefill-{trial}-{i}",
                    request_bytes=_REQUEST,
                    response_bytes=_RESPONSE,
                )
            start = time.perf_counter()
            for i in range(batch):
                ledger.commit_forensic(
                    state_id=f"measured-{trial}-{i}",
                    request_bytes=_REQUEST,
                    response_bytes=_RESPONSE,
                )
            # Taken before the ledger closes, so the timed region excludes the
            # final flush and fsync that `__exit__` performs.
            elapsed = time.perf_counter() - start
        latencies.append(elapsed / batch)
    best = min(latencies)
    return {
        "best_us_per_commit": best * 1_000_000,
        "mean_us_per_commit": statistics.mean(latencies) * 1_000_000,
        "best_commits_per_second": 1.0 / best,
    }


def run_benchmark(
    lengths: tuple[int, ...] = _DEFAULT_LENGTHS,
    batch: int = _DEFAULT_BATCH,
    k: int = _DEFAULT_K,
    *,
    real_fsync: bool = False,
    emit_json: bool = False,
) -> dict[str, Any]:
    results: dict[str, Any] = {
        "benchmark": "commit_scaling",
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
        },
        "parameters": {
            "prefill_lengths": list(lengths),
            "measured_batch": batch,
            "trials": k,
            "fsync": "real" if real_fsync else "no-op seam",
        },
        "boundary": (
            "In-process commit path only. Excludes network, provider, request "
            "parsing, admission control and response handling. Not a capacity "
            "claim, service level, or statement about any target deployment."
        ),
        "measurements": [],
    }

    if not emit_json:
        separator = "=" * 72
        print(f"\n{separator}", file=sys.stderr)
        print("COMMIT-COST SCALING — per-commit latency vs. existing chain length", file=sys.stderr)
        print(separator, file=sys.stderr)
        print(f"  Measured batch:  {batch:,} commits at each length", file=sys.stderr)
        print(f"  Trials:          k={k} (best-of-k reported)", file=sys.stderr)
        print(
            f"  fsync:           {'real' if real_fsync else 'no-op seam (durability excluded)'}",
            file=sys.stderr,
        )
        print(file=sys.stderr)
        print(
            f"  {'prior leaves':>14}{'µs/commit':>14}{'commits/s':>14}{'vs. first':>12}",
            file=sys.stderr,
        )
        print("  " + "-" * 52, file=sys.stderr)

    baseline: float | None = None
    for prefill in lengths:
        measured = measure_at_length(prefill, batch, k, real_fsync=real_fsync)
        if baseline is None:
            baseline = measured["best_us_per_commit"]
        ratio = measured["best_us_per_commit"] / baseline if baseline else float("nan")
        results["measurements"].append(
            {
                "prior_leaves": prefill,
                "best_us_per_commit": round(measured["best_us_per_commit"], 3),
                "mean_us_per_commit": round(measured["mean_us_per_commit"], 3),
                "best_commits_per_second": round(measured["best_commits_per_second"], 1),
                "ratio_to_shortest_chain": round(ratio, 3),
            }
        )
        if not emit_json:
            print(
                f"  {prefill:>14,}"
                f"{measured['best_us_per_commit']:>14.1f}"
                f"{measured['best_commits_per_second']:>14,.0f}"
                f"{ratio:>11.2f}x",
                file=sys.stderr,
                flush=True,
            )

    if not emit_json:
        print(file=sys.stderr)
        print(
            "  A flat 'vs. first' column means per-commit cost is independent of\n"
            "  chain length. A rising column means the commit path does work\n"
            "  proportional to the number of leaves already committed.",
            file=sys.stderr,
        )
        print(file=sys.stderr)

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lengths",
        default=",".join(str(value) for value in _DEFAULT_LENGTHS),
        help="Comma-separated chain lengths to prefill before measuring.",
    )
    parser.add_argument("--batch", type=int, default=_DEFAULT_BATCH)
    parser.add_argument("--k", type=int, default=_DEFAULT_K)
    parser.add_argument(
        "--fsync",
        action="store_true",
        help="Use real fsync instead of the no-op seam (much slower).",
    )
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON on stdout.")
    args = parser.parse_args()

    lengths = tuple(int(value) for value in args.lengths.split(",") if value.strip())
    report = run_benchmark(lengths, args.batch, args.k, real_fsync=args.fsync, emit_json=args.json)
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
