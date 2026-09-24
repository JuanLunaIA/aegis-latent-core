"""
scripts/run_benchmarks_5.0.1.py — real measurements for the v5.0.1 documentation pass.

Four things a reader asked for real numbers on: commit latency distribution,
concurrent commit throughput, streaming-ingestion memory, and asymmetric
signing latency. Each measurement follows the four-part discipline
``docs/benchmarks/BENCHMARK_METHOD.md`` §1 requires — artifact, environment,
date, boundary — and this file's own boundary section states what none of
these numbers is.

This is a thin orchestrator over the same primitives ``benchmarks/`` already
exercises (``CryptographicAuditLedger.commit_forensic``, ``BoundedStreamProxy``,
the real Ed25519/ML-DSA backends); it does not reimplement measurement logic,
and it prints the same provenance banner those harnesses do
(:func:`benchmarks.print_provenance`).

Boundary
--------
**None of these numbers is a capacity claim, a service level, a production
figure, or a statement about any target deployment.** Specifically:

* **Latency** is the commit path only (SHA-256 payload digest, MMR leaf
  insertion, HMAC-SHA256 node signature, one WAL ``write`` + ``fsync``) — no
  network, no upstream provider, no request parsing, no admission control,
  no WAF evaluation, no response handling.
* **Throughput** measures *this* ledger's single-writer WAL lock under
  Python thread contention on *this* host's core count — it is not a
  multi-process or multi-replica figure, and GIL and lock contention both
  bound it below what N independent cores would suggest.
* **Memory** is `resource.getrusage().ru_maxrss` delta around an in-process
  asyncio simulation of concurrent streams, not real sockets, and Linux
  `ru_maxrss` is a whole-process high-water mark that never falls, so the
  delta is an upper-bound approximation, not an isolated allocation figure.
* **Cryptographic** timings exclude constant-time behaviour entirely — a
  latency sample cannot establish it (see `docs/institutional/DOC-08...`
  analogue for signing: `timing_defense.py` and `REG-041`/`UC-012` for what
  *is* established about ML-DSA verify timing).

Usage
-----
    python scripts/run_benchmarks_5.0.1.py
    python scripts/run_benchmarks_5.0.1.py --json > evidence/benchmarks_5.0.1_$(date +%F).json
    python scripts/run_benchmarks_5.0.1.py --commit-n 2000 --threads 10,50,100 --streams 1000
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
import resource
import secrets
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.proxy.streaming import BoundedStreamProxy, StreamEvidenceSummary
from benchmarks import PROVENANCE_NOTE, print_provenance

ROOT = Path(__file__).resolve().parent.parent

_REQUEST = b'{"model":"gpt-4o","messages":[{"role":"user","content":"benchmark payload"}]}'
_RESPONSE = b'{"choices":[{"message":{"role":"assistant","content":"benchmark response"}}]}'


def _git_head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return "unknown"


def _percentiles(samples_seconds: list[float]) -> dict[str, float]:
    """P50/P95/P99 in milliseconds, nearest-rank on the sorted sample."""
    ordered = sorted(samples_seconds)

    def at(probability: float) -> float:
        index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * probability)))
        return ordered[index] * 1_000.0

    return {"p50_ms": at(0.50), "p95_ms": at(0.95), "p99_ms": at(0.99), "max_ms": at(1.0)}


# ── 1. Commit latency distribution ──────────────────────────────────────────


def bench_commit_latency(n: int) -> dict[str, Any]:
    """P50/P95/P99 of ``commit_forensic`` — one real WAL fsync per commit."""
    with tempfile.TemporaryDirectory() as tmp:
        ledger = CryptographicAuditLedger(
            persistence_path=str(Path(tmp) / "bench.wal.jsonl"),
            signing_key=secrets.token_hex(32),
        )
        try:
            samples: list[float] = []
            for index in range(n):
                start = time.perf_counter()
                ledger.commit_forensic(
                    state_id=f"bench-{index}",
                    request_bytes=_REQUEST,
                    response_bytes=_RESPONSE,
                    tenant_id="bench-tenant",
                    model="bench-model",
                    endpoint="chat.completions",
                )
                samples.append(time.perf_counter() - start)
        finally:
            ledger.close()
    result: dict[str, Any] = {"operation": "commit_forensic (MMR append + HMAC sign + WAL fsync)"}
    result.update(_percentiles(samples))
    result["n"] = n
    return result


# ── 2. Concurrent commit throughput ──────────────────────────────────────────


def bench_concurrent_throughput(
    thread_counts: list[int], ops_per_thread: int
) -> list[dict[str, Any]]:
    """Sustained commits/sec with N threads sharing one ledger's write lock."""
    results: list[dict[str, Any]] = []
    for threads in thread_counts:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = CryptographicAuditLedger(
                persistence_path=str(Path(tmp) / "bench.wal.jsonl"),
                signing_key=secrets.token_hex(32),
            )
            try:
                counter = 0

                def _worker(worker_id: int, *, ledger: CryptographicAuditLedger = ledger) -> int:
                    for index in range(ops_per_thread):
                        ledger.commit_forensic(
                            state_id=f"w{worker_id}-{index}",
                            request_bytes=_REQUEST,
                            response_bytes=_RESPONSE,
                            tenant_id="bench-tenant",
                            model="bench-model",
                            endpoint="chat.completions",
                        )
                    return ops_per_thread

                start = time.perf_counter()
                with ThreadPoolExecutor(max_workers=threads) as pool:
                    counts = list(pool.map(_worker, range(threads)))
                elapsed = time.perf_counter() - start
                counter = sum(counts)
            finally:
                ledger.close()
        results.append(
            {
                "threads": threads,
                "total_commits": counter,
                "elapsed_seconds": elapsed,
                "commits_per_second": counter / elapsed,
            }
        )
    return results


# ── 3. Peak RSS under concurrent streaming ingestion ─────────────────────────


async def _one_stream(events_per_stream: int) -> None:
    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        for index in range(events_per_stream):
            payload = {
                "id": "benchmark",
                "choices": [{"index": 0, "delta": {"content": f"token-{index} "}}],
            }
            yield b"data: " + json.dumps(payload, separators=(",", ":")).encode() + b"\n\n", payload
        yield b"data: [DONE]", None

    async def commit(_summary: StreamEvidenceSummary) -> None:
        return None

    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=1_048_576,
        max_duration_seconds=120.0,
        max_event_bytes=16_384,
        queue_max_items=8,
        queue_max_bytes=131_072,
        preview_bytes=65_536,
        deidentifier_window_chars=128,
    )
    async for _chunk in proxy:
        pass


async def _run_concurrent_streams(concurrency: int, events_per_stream: int) -> None:
    await asyncio.gather(*(_one_stream(events_per_stream) for _ in range(concurrency)))


def bench_streaming_memory(concurrency: int, events_per_stream: int) -> dict[str, Any]:
    """Peak-RSS delta around ``concurrency`` simultaneous in-process SSE streams.

    ``ru_maxrss`` is a whole-process high-water mark on Linux (kilobytes) that
    never decreases within a process lifetime, so the reported figure is
    ``after - before``, not an isolated allocation of the ingestion path; a
    warmup pass runs first so import and JIT-adjacent one-time costs are not
    attributed to the measured phase.
    """
    asyncio.run(_run_concurrent_streams(min(concurrency, 8), events_per_stream))
    before_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    asyncio.run(_run_concurrent_streams(concurrency, events_per_stream))
    after_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Note for any caller that reorders run_all(): the delta is meaningless
    # once a later, larger-footprint phase has already run in this process,
    # because ru_maxrss then reflects that phase's peak, not this one's.
    return {
        "operation": "concurrent in-process BoundedStreamProxy ingestion",
        "concurrency": concurrency,
        "events_per_stream": events_per_stream,
        "rss_before_kb": before_kb,
        "rss_after_kb": after_kb,
        "rss_delta_kb": after_kb - before_kb,
        "rss_delta_mb": (after_kb - before_kb) / 1024.0,
    }


# ── 4. Asymmetric signing latency ────────────────────────────────────────────


def _best_of_k_latency(operation: Callable[[], Any], n: int, k: int) -> dict[str, float]:
    best: float | None = None
    for _ in range(k):
        start = time.perf_counter()
        for _ in range(n):
            operation()
        elapsed = time.perf_counter() - start
        if best is None or elapsed < best:
            best = elapsed
    assert best is not None
    return {"best_us_per_op": (best / n) * 1_000_000.0, "best_ops_per_second": n / best}


def bench_ed25519(n: int, k: int) -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    key = Ed25519PrivateKey.from_private_bytes(secrets.token_bytes(32))
    public_key = key.public_key()
    message = secrets.token_bytes(256)
    signature = key.sign(message)

    sign = _best_of_k_latency(lambda: key.sign(message), n, k)
    verify = _best_of_k_latency(lambda: public_key.verify(signature, message), n, k)
    return {
        "algorithm": "Ed25519",
        "backend": "cryptography (RFC 8032)",
        "signature_bytes": len(signature),
        "sign": sign,
        "verify": verify,
    }


def bench_ml_dsa(n: int, k: int) -> dict[str, Any] | None:
    """``None`` when the native backend is not compiled in — never simulated."""
    from aegis.core.pqc_signer import PQCSigner, backend_available

    if not backend_available():
        return None
    signer = PQCSigner(require_real=True)
    public_key = signer.public_key
    message = secrets.token_bytes(256)
    signature = signer.sign(message)

    sign = _best_of_k_latency(lambda: signer.sign(message), n, k)
    verify = _best_of_k_latency(lambda: PQCSigner.verify(message, signature, public_key), n, k)
    return {
        "algorithm": signer.ALGORITHM,
        "backend": "aegis_rust (pqcrypto-mldsa, FIPS 204)",
        "public_key_bytes": signer.PUBLIC_KEY_BYTES,
        "private_key_bytes": signer.PRIVATE_KEY_BYTES,
        "signature_bytes": signer.SIGNATURE_BYTES,
        "sign": sign,
        "verify": verify,
        "timing_boundary": (
            "single-sample latency only; establishes nothing about constant-time "
            "behaviour — see REG-041/UC-012 and aegis/core/timing_defense.py"
        ),
    }


# ── Orchestration ────────────────────────────────────────────────────────────


def run_all(
    *,
    commit_n: int,
    thread_counts: list[int],
    ops_per_thread: int,
    stream_concurrency: int,
    events_per_stream: int,
    crypto_n: int,
    crypto_k: int,
) -> dict[str, Any]:
    # streaming_memory runs first: resource.getrusage().ru_maxrss is a
    # whole-process, never-decreasing high-water mark on Linux, so running it
    # after the thread-heavy commit phases would measure nothing — their own
    # allocations would already have set a higher mark than streaming adds.
    streaming_memory = bench_streaming_memory(stream_concurrency, events_per_stream)
    return {
        "harness": "scripts/run_benchmarks_5.0.1.py",
        "git_head": _git_head(),
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "host": platform.node() or "unknown",
        "machine": platform.machine(),
        "system": platform.system(),
        "cpus": os.cpu_count(),
        "python_version": platform.python_version(),
        "provenance_note": PROVENANCE_NOTE,
        "streaming_memory": streaming_memory,
        "commit_latency": bench_commit_latency(commit_n),
        "concurrent_throughput": bench_concurrent_throughput(thread_counts, ops_per_thread),
        "ed25519": bench_ed25519(crypto_n, crypto_k),
        "ml_dsa_65": bench_ml_dsa(crypto_n, crypto_k),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--commit-n", type=int, default=1_000, help="commits for the latency sample"
    )
    parser.add_argument(
        "--threads", type=str, default="10,50,100", help="comma-separated concurrent thread counts"
    )
    parser.add_argument("--ops-per-thread", type=int, default=200)
    parser.add_argument(
        "--streams", type=int, default=1_000, help="concurrent simulated SSE streams"
    )
    parser.add_argument("--events-per-stream", type=int, default=20)
    parser.add_argument("--crypto-n", type=int, default=500)
    parser.add_argument("--crypto-k", type=int, default=5)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON to stdout")
    args = parser.parse_args()

    if not args.json:
        print_provenance("run_benchmarks_5.0.1")

    result = run_all(
        commit_n=args.commit_n,
        thread_counts=[int(v) for v in args.threads.split(",")],
        ops_per_thread=args.ops_per_thread,
        stream_concurrency=args.streams,
        events_per_stream=args.events_per_stream,
        crypto_n=args.crypto_n,
        crypto_k=args.crypto_k,
    )

    if args.json:
        # No banner precedes this: --json output is redirected straight to an
        # evidence file (see Usage above) and must parse as JSON on its own.
        # Host/date/git-head travel inside the object instead (see run_all).
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return

    latency = result["commit_latency"]
    print(f"\ncommit_forensic latency (n={latency['n']}):")
    print(
        f"  P50={latency['p50_ms']:.3f}ms  P95={latency['p95_ms']:.3f}ms  "
        f"P99={latency['p99_ms']:.3f}ms  max={latency['max_ms']:.3f}ms"
    )

    print("\nconcurrent commit throughput (single shared WAL writer lock):")
    for row in result["concurrent_throughput"]:
        print(f"  {row['threads']:>4} threads: {row['commits_per_second']:.1f} commits/sec")

    mem = result["streaming_memory"]
    print(f"\nstreaming ingestion peak RSS delta ({mem['concurrency']} concurrent streams):")
    print(f"  {mem['rss_delta_mb']:.2f} MB ({mem['rss_before_kb']} KB -> {mem['rss_after_kb']} KB)")

    ed = result["ed25519"]
    print("\nEd25519 (RFC 8032):")
    print(
        f"  sign:   {ed['sign']['best_us_per_op']:.2f} us/op "
        f"({ed['sign']['best_ops_per_second']:.0f} ops/sec)"
    )
    print(
        f"  verify: {ed['verify']['best_us_per_op']:.2f} us/op "
        f"({ed['verify']['best_ops_per_second']:.0f} ops/sec)"
    )

    dsa = result["ml_dsa_65"]
    if dsa is None:
        print(
            "\nML-DSA-65: native backend not compiled in on this host; not measured (not simulated)."
        )
    else:
        print(f"\n{dsa['algorithm']} ({dsa['backend']}):")
        print(
            f"  sign:   {dsa['sign']['best_us_per_op']:.2f} us/op "
            f"({dsa['sign']['best_ops_per_second']:.0f} ops/sec)"
        )
        print(
            f"  verify: {dsa['verify']['best_us_per_op']:.2f} us/op "
            f"({dsa['verify']['best_ops_per_second']:.0f} ops/sec)"
        )

    print(f"\n{PROVENANCE_NOTE}")


if __name__ == "__main__":
    main()
