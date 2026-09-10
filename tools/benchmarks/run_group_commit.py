# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Measure what coalescing the WAL fsync does to commit latency and throughput.

Runs the same concurrent commit workload twice against the real ledger and the
real filesystem, and reports both arms:

``per_record_fsync``
    The behaviour before ``aegis.core.group_commit`` — one ``fsync`` per
    committed record. Reproduced by wrapping ``_persist_node`` so each record is
    synced inline, rather than by checking out the old code, so both arms run
    the same ledger, the same signing path and the same disk in one process.

``group_commit``
    The shipped behaviour: records are written under the ledger lock and one
    ``fsync`` retires every record written while it was in flight.

The comparison is only meaningful for *concurrent* commits. With one writer
there is nothing to coalesce and the two arms are the same code path, which is
deliberate — see ``aegis/core/group_commit.py`` on why a lone committer is never
made to wait.

What this does not establish: an ``fsync`` on this filesystem is not an
``fsync`` on the reader's. Container overlay filesystems, a battery-backed
controller and a cloud network disk differ by orders of magnitude, and the
slower the device the *larger* the coalescing win, because the fixed per-call
cost being shared is bigger. The numbers below are one machine's, recorded with
its own device characteristics; they are not a capacity claim for any
deployment.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.core.crypto_audit import AuditNode, CryptographicAuditLedger


def git_head(root: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def _percentile(sorted_values: list[float], fraction: float) -> float:
    """Nearest-rank percentile; the sample sizes here do not warrant interpolation."""
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, int(len(sorted_values) * fraction))
    return sorted_values[index]


def _force_inline_fsync(ledger: CryptographicAuditLedger) -> None:
    """Make every record pay its own ``fsync``, as the ledger used to.

    Wraps rather than replaces ``_persist_node`` so the write, the rotation
    check and the ticket accounting stay exactly as they are; only the sync
    moves back inside the ledger lock.
    """
    original: Callable[[AuditNode], int | None] = ledger._persist_node

    def persist_and_sync(node: AuditNode) -> int | None:
        ticket = original(node)
        if ticket is not None:
            ledger._sync_wal()
            ledger._commit_engine.note_external_sync()
        return ticket

    ledger._persist_node = persist_and_sync  # type: ignore[method-assign]


def measure(
    *, records: int, workers: int, payload_bytes: int, inline_fsync: bool
) -> dict[str, Any]:
    """Commit ``records`` nodes across ``workers`` threads and time each one."""
    with tempfile.TemporaryDirectory() as directory:
        ledger = CryptographicAuditLedger(
            os.path.join(directory, "benchmark.jsonl"),
            signing_key="benchmark-key",
        )
        if inline_fsync:
            _force_inline_fsync(ledger)
        payload = b"x" * payload_bytes

        def one(index: int) -> float:
            started = time.perf_counter()
            ledger.commit_forensic(
                state_id=f"bench-{index:06d}",
                request_bytes=payload,
                response_bytes=payload,
                tenant_id="benchmark",
            )
            return (time.perf_counter() - started) * 1000.0

        wall_start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            latencies = list(pool.map(one, range(records)))
        wall_seconds = time.perf_counter() - wall_start

        stats = ledger.group_commit_stats
        committed = len(ledger.chain)
        intact, broken_at = ledger.verify_integrity()
        ledger.close()

    latencies.sort()
    return {
        "offered_records": records,
        "durable_commits": committed,
        "chain_intact": intact,
        "chain_broken_at": broken_at,
        "wall_seconds": round(wall_seconds, 4),
        "commits_per_second": round(records / wall_seconds, 1),
        "latency_ms": {
            "mean": round(statistics.fmean(latencies), 3),
            "p50": round(_percentile(latencies, 0.50), 3),
            "p95": round(_percentile(latencies, 0.95), 3),
            "p99": round(_percentile(latencies, 0.99), 3),
            "max": round(latencies[-1], 3),
        },
        "fsync_calls": stats.batches,
        "records_per_fsync": round(stats.records_per_fsync, 2),
        "largest_batch": stats.largest_batch,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=400)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--payload-bytes", type=int, default=512)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.records < 1 or args.workers < 1 or args.payload_bytes < 1:
        raise ValueError("records, workers and payload-bytes must all be >= 1")

    root = Path(__file__).resolve().parents[2]
    results: dict[str, Any] = {}
    for arm, inline in (("per_record_fsync", True), ("group_commit", False)):
        results[arm] = measure(
            records=args.records,
            workers=args.workers,
            payload_bytes=args.payload_bytes,
            inline_fsync=inline,
        )

    before = results["per_record_fsync"]
    after = results["group_commit"]
    report = {
        "schema": "aegis-group-commit-report-v1",
        "generated_at_utc": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "repository": "JuanLunaIA/aegis-latent-core",
        "commit_sha": git_head(root),
        "experiment": {
            "method": "same-process A/B of the real ledger against the real filesystem",
            "records": args.records,
            "concurrent_workers": args.workers,
            "payload_bytes": args.payload_bytes,
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
        },
        "results": results,
        "delta": {
            "throughput_ratio": round(
                after["commits_per_second"] / before["commits_per_second"], 3
            ),
            "p99_ms_before": before["latency_ms"]["p99"],
            "p99_ms_after": after["latency_ms"]["p99"],
            "fsync_calls_before": before["fsync_calls"],
            "fsync_calls_after": after["fsync_calls"],
        },
        "limitations": [
            "fsync cost is a property of the device and filesystem under the run, "
            "not of this code; the same A/B on different storage will differ, and a "
            "slower device makes the coalescing win larger, not smaller.",
            "Concurrency here comes from a thread pool in one process. It stands in "
            "for the proxy's asyncio.to_thread commit path but is not that path.",
            "This is a throughput and latency measurement. It is not a durability "
            "proof; the durability properties are asserted in "
            "tests/test_coalesced_commit.py.",
            "No capacity, SLA or production-readiness claim is made or implied.",
        ],
    }
    # `per_record_fsync` reports 0 fsync_calls because its syncs are issued
    # inline and published through note_external_sync, which the engine does not
    # count as a batch. The real count for that arm is one per record, by
    # construction.
    report["results"]["per_record_fsync"]["fsync_calls"] = args.records
    report["delta"]["fsync_calls_before"] = args.records

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["delta"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
