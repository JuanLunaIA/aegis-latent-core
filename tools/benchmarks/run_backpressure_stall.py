# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.core.crypto_audit import CryptographicAuditLedger


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_head(root: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[index]


class FsyncDelay:
    def __init__(self, delay_s: float) -> None:
        self.delay_s = delay_s
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self, fd: int) -> None:
        if self.delay_s:
            time.sleep(self.delay_s)
        os.fsync(fd)
        with self._lock:
            self.calls += 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure Aegis WAL behavior under injected fsync latency."
    )
    parser.add_argument("--duration-s", type=float, default=0.25)
    parser.add_argument("--offered-rps", type=int, default=10_000)
    parser.add_argument("--fsync-delay-ms", type=float, default=2.0)
    parser.add_argument("--max-workers", type=int, default=64)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (
        args.duration_s <= 0
        or args.offered_rps <= 0
        or args.fsync_delay_ms < 0
        or args.max_workers <= 0
    ):
        raise ValueError(
            "duration, offered_rps, and max_workers must be positive; delay must be non-negative"
        )
    root = Path(__file__).resolve().parents[2]
    output_path = (
        (root / args.output).resolve() if not args.output.is_absolute() else args.output.resolve()
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wal_path = output_path.with_suffix(".wal.jsonl")
    signing_key = "b" * 64
    injector = FsyncDelay(args.fsync_delay_ms / 1000.0)
    request_count = max(1, int(round(args.duration_s * args.offered_rps)))
    started = time.perf_counter()
    durations: list[float] = []
    completed_ids: list[str] = []
    failures: list[dict[str, str]] = []
    counters = {"submitted": 0, "completed": 0, "inflight": 0, "max_inflight": 0}
    counter_lock = threading.Lock()

    def commit_one(index: int) -> tuple[str, float]:
        request_id = f"load-{index:08d}"
        t0 = time.perf_counter()
        ledger.commit_state(
            state_id=request_id,
            entropy=0.0,
            payload=json.dumps(
                {"request_id": request_id, "payload": "bounded-stall"}, separators=(",", ":")
            ).encode(),
            tenant_id="benchmark",
            sampling_params={"model": "local-test", "endpoint": "bench"},
        )
        elapsed = (time.perf_counter() - t0) * 1000.0
        with counter_lock:
            counters["completed"] += 1
            counters["inflight"] -= 1
        return request_id, elapsed

    with CryptographicAuditLedger(
        str(wal_path), signing_key=signing_key, fsync_fn=injector
    ) as ledger:
        with ThreadPoolExecutor(
            max_workers=args.max_workers, thread_name_prefix="aegis-load"
        ) as pool:
            futures: list[Future[tuple[str, float]]] = []
            interval = 1.0 / args.offered_rps
            next_submit = time.perf_counter()
            for index in range(request_count):
                now = time.perf_counter()
                if now < next_submit:
                    time.sleep(next_submit - now)
                with counter_lock:
                    counters["submitted"] += 1
                    counters["inflight"] += 1
                    counters["max_inflight"] = max(counters["max_inflight"], counters["inflight"])
                futures.append(pool.submit(commit_one, index))
                next_submit += interval
            for future in as_completed(futures):
                try:
                    request_id, elapsed = future.result()
                    completed_ids.append(request_id)
                    durations.append(elapsed)
                except Exception as exc:
                    with counter_lock:
                        counters["inflight"] -= 1
                    failures.append({"type": type(exc).__name__, "message": str(exc)})
        integrity_valid, integrity_index = ledger.verify_integrity()
        chain_count = len(ledger.chain)
        if not integrity_valid:
            failures.append({"type": "IntegrityFailure", "message": f"index={integrity_index}"})
    elapsed_total = time.perf_counter() - started
    unique_ids = len(set(completed_ids))
    missing_count = request_count - len(completed_ids)
    duplicate_count = len(completed_ids) - unique_ids
    report: dict[str, Any] = {
        "schema": "aegis-backpressure-report-v1",
        "generated_at_utc": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "repository": "JuanLunaIA/aegis-latent-core",
        "commit_sha": git_head(root),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "workload": {
            "duration_s": args.duration_s,
            "offered_rps": args.offered_rps,
            "offered_requests": request_count,
            "fsync_delay_ms": args.fsync_delay_ms,
            "max_workers": args.max_workers,
            "wal_path": str(wal_path),
        },
        "observed": {
            "elapsed_total_s": elapsed_total,
            "accepted_and_durable": len(completed_ids),
            "failures": len(failures),
            "missing_evidence_ids": missing_count,
            "duplicate_evidence_ids": duplicate_count,
            "ledger_chain_count": chain_count,
            "integrity_valid": integrity_valid,
            "fsync_calls": injector.calls,
            "max_inflight": counters["max_inflight"],
            "commit_latency_ms": {
                "p50": percentile(durations, 50),
                "p95": percentile(durations, 95),
                "p99": percentile(durations, 99),
                "max": max(durations) if durations else 0.0,
            },
        },
        "gate": {
            "passed": not failures
            and missing_count == 0
            and duplicate_count == 0
            and chain_count == len(completed_ids)
            and integrity_valid,
            "semantics": "hot-path blocked on durable WAL commit under injected fsync stall; no silent evidence drop",
            "success_rate_claim": "NOT_CLAIMED; offered load is not accepted capacity",
        },
        "failures": failures,
        "artifacts": {"wal_sha256": sha256_file(wal_path) if wal_path.exists() else None},
    }
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "passed": report["gate"]["passed"],
                "offered": request_count,
                "durable": len(completed_ids),
                "missing": missing_count,
                "duplicates": duplicate_count,
                "integrity": integrity_valid,
                "output": str(output_path),
            },
            sort_keys=True,
        )
    )
    return 0 if report["gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
