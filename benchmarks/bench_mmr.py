"""
MMR throughput benchmark — Python MerkleMountainRange vs Rust MmrAccumulator.

Measures add_leaf + get_root_hash throughput for N = 10², 10³, 10⁴, 10⁵ leaves.
Reports leaves/second and speedup ratio when the Rust extension is available.

Methodology
-----------
For each N, a fresh MMR instance is constructed and N leaves are appended with
time.perf_counter() bracketing the full loop (add_leaf calls only, get_root_hash
is called once after all insertions to separate per-leaf and per-root costs).
Each (implementation, N) pair is repeated K=5 times; min latency is reported
(eliminates OS scheduling noise, consistent with Google Benchmark methodology).

Rust extension availability
---------------------------
aegis_rust.MmrAccumulator requires `maturin develop --release` in aegis_rust_v2/.
If unavailable, the Rust column is marked UNKNOWN — resolves via:
    cd aegis_rust_v2 && maturin develop --release

Usage
-----
    cd /path/to/aegis-latent-core
    python -m benchmarks.bench_mmr
    python benchmarks/bench_mmr.py
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import statistics
import time
from typing import Any

# ── Rust extension probe ──────────────────────────────────────────────────────

try:
    import aegis_rust

    _HAS_RUST = True
    _RUST_VERSION: str = getattr(aegis_rust, "__version__", "unknown")
except ImportError:
    _HAS_RUST = False
    _RUST_VERSION = "unavailable"

from aegis.core.mmr import MerkleMountainRange

# ── Benchmark helpers ─────────────────────────────────────────────────────────

_LEAF_SIZES = [100, 1_000, 10_000, 100_000]
_K_REPEATS = 5  # independent trials per (impl, N)


def _leaf(i: int) -> bytes:
    """Deterministic synthetic leaf: SHA-256 of i in big-endian 8 bytes."""
    return hashlib.sha256(i.to_bytes(8, "big")).digest()


def _bench_python(n_leaves: int, k: int) -> dict[str, float]:
    """
    Benchmark Python MerkleMountainRange.add_leaf for n_leaves leaves, k trials.
    Returns min/mean/max throughput (leaves/second) and min latency per leaf (µs).
    """
    leaves = [_leaf(i) for i in range(n_leaves)]  # precompute — not MMR work
    throughputs: list[float] = []
    for _ in range(k):
        mmr = MerkleMountainRange()
        t0 = time.perf_counter()
        for leaf in leaves:
            mmr.add_leaf(leaf)
        _ = mmr.get_root_hash()
        elapsed = time.perf_counter() - t0
        throughputs.append(n_leaves / elapsed)

    return {
        "min_throughput": min(throughputs),
        "mean_throughput": statistics.mean(throughputs),
        "max_throughput": max(throughputs),
        "best_us_per_leaf": 1_000_000 / max(throughputs),
    }


def _bench_rust(n_leaves: int, k: int) -> dict[str, float] | None:
    """
    Benchmark Rust MmrAccumulator.add_leaf for n_leaves leaves, k trials.
    Returns None if aegis_rust is not available.
    """
    if not _HAS_RUST:
        return None

    leaves = [_leaf(i) for i in range(n_leaves)]  # precompute — not MMR work
    throughputs: list[float] = []
    for _ in range(k):
        acc = aegis_rust.MmrAccumulator()
        t0 = time.perf_counter()
        for leaf in leaves:
            acc.add_leaf(leaf)
        _ = acc.get_root_hash()
        elapsed = time.perf_counter() - t0
        throughputs.append(n_leaves / elapsed)

    return {
        "min_throughput": min(throughputs),
        "mean_throughput": statistics.mean(throughputs),
        "max_throughput": max(throughputs),
        "best_us_per_leaf": 1_000_000 / max(throughputs),
    }


# ── Output ────────────────────────────────────────────────────────────────────


def _fmt_throughput(v: float) -> str:
    if v >= 1_000_000:
        return f"{v / 1_000_000:.2f}M"
    if v >= 1_000:
        return f"{v / 1_000:.2f}k"
    return f"{v:.1f}"


def run_benchmark(leaf_sizes: list[int] = _LEAF_SIZES, k: int = _K_REPEATS) -> dict[str, Any]:
    sep = "=" * 72
    print(f"\n{sep}")
    print("MMR THROUGHPUT BENCHMARK — Python vs Rust MerkleMountainRange")
    print(sep)
    print("  Python MerkleMountainRange:  aegis.core.mmr (pure Python, SHA-256)")
    if _HAS_RUST:
        print(f"  Rust MmrAccumulator:         aegis_rust v{_RUST_VERSION}")
    else:
        print(
            "  Rust MmrAccumulator:         UNAVAILABLE "
            "(run: cd aegis_rust_v2 && maturin develop --release)"
        )
    print(f"  Trials per point:  k={k} (best-of-k reported, methodology: Google Benchmark min)")
    print("  Leaf payload:      32 bytes (SHA-256 of index)")
    print()

    header = f"  {'N':>8}  {'Python leaves/s':>16}  {'Python µs/leaf':>14}"
    if _HAS_RUST:
        header += f"  {'Rust leaves/s':>14}  {'Rust µs/leaf':>12}  {'Speedup':>8}"
    print(header)
    print("  " + "-" * (len(header) - 2))

    results: dict[str, Any] = {"python": {}, "rust": {}}

    for n in leaf_sizes:
        py = _bench_python(n, k)
        ru = _bench_rust(n, k)

        py_tp = _fmt_throughput(py["max_throughput"])
        py_us = f"{py['best_us_per_leaf']:.3f}"

        row = f"  {n:>8,}  {py_tp:>16}  {py_us:>14}"
        if _HAS_RUST and ru is not None:
            ru_tp = _fmt_throughput(ru["max_throughput"])
            ru_us = f"{ru['best_us_per_leaf']:.3f}"
            speedup = ru["max_throughput"] / py["max_throughput"]
            row += f"  {ru_tp:>14}  {ru_us:>12}  {speedup:>7.2f}x"
        elif _HAS_RUST is False:
            row += "  UNKNOWN — resolves via maturin develop --release"

        print(row)

        results["python"][str(n)] = py
        if ru is not None:
            results["rust"][str(n)] = ru

    print()

    if _HAS_RUST and results["rust"]:
        speedups = [
            results["rust"][str(n)]["max_throughput"] / results["python"][str(n)]["max_throughput"]
            for n in leaf_sizes
            if str(n) in results["rust"]
        ]
        avg_speedup = statistics.mean(speedups)
        max_speedup = max(speedups)
        print(f"  Rust/Python speedup: avg={avg_speedup:.2f}x  max={max_speedup:.2f}x")
        if avg_speedup >= 5.0:
            print(
                "  [PROVEN] Rust extension yields significant performance gains (>5x throughput)."
            )
        elif avg_speedup >= 2.0:
            print(
                f"  [PROVEN] Rust extension is faster than Python ({avg_speedup:.2f}x), "
                f"but README 'significant' claim requires quantification — use measured ratio."
            )
        else:
            print(
                f"  [INFERENCE] Rust speedup ({avg_speedup:.2f}x) is modest; "
                f"PyO3 marshalling overhead dominates for small N."
            )
    else:
        print(
            "  [SPECULATIVE] Rust speedup: UNKNOWN — resolves via "
            "`cd aegis_rust_v2 && maturin develop --release && python -m benchmarks.bench_mmr`"
        )
        print(
            "  README claim 'significant performance gains' cannot be verified in this environment."
        )

    results["rust_available"] = _HAS_RUST
    return results


if __name__ == "__main__":
    run_benchmark()
