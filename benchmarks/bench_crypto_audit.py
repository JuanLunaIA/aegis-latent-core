"""
Cryptographic audit chain benchmark — commit + verification throughput.

Measures the three costs that define the forensic core guarantee (G1/G3):

  1. HMAC-SHA256 node signing (crypto-only, no I/O)  — isolates the signature cost
  2. ``commit_forensic()`` end-to-end                — full node: SHA-256 of payload,
     MMR leaf insertion, HMAC sign, and WAL append (fsync) — the real sustainable
     background-commit rate behind the zero-forensic-latency design.
  3. ``verify_integrity()``                          — full hash-chain sweep over N
     committed nodes — the auditor-side replay cost.

Methodology
-----------
Each measurement brackets the operation with ``time.perf_counter()`` over a fixed
N and reports operations/second plus per-op latency. The commit and verify phases
use a real ``CryptographicAuditLedger`` backed by a temp-dir WAL (0o600, fsync) so
the numbers include genuine durable-write cost, not an in-memory mock. Each phase
is repeated K times; the best-of-K (min-latency) trial is reported, consistent with
``bench_mmr.py`` (Google Benchmark min methodology — strips OS scheduling noise).

Epistemic tags per CLAUDE.md I-03: [PROVEN] = executor output, [INFERENCE] =
deduction from proven facts.

Usage
-----
    cd /path/to/aegis-latent-core
    python -m benchmarks.bench_crypto_audit
    python benchmarks/bench_crypto_audit.py --n 2000 --k 5
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any

from aegis.core.crypto_audit import CryptographicAuditLedger

# ── Defaults ──────────────────────────────────────────────────────────────────

_DEFAULT_N = 2_000
_DEFAULT_K = 5


def _fmt_throughput(v: float) -> str:
    if v >= 1_000_000:
        return f"{v / 1_000_000:.2f}M"
    if v >= 1_000:
        return f"{v / 1_000:.2f}k"
    return f"{v:.1f}"


# ── Phase 1: HMAC-SHA256 signing (crypto-only) ────────────────────────────────


def bench_hmac_sign(n: int, k: int) -> dict[str, float]:
    """Raw HMAC-SHA256 over a representative 256-byte node payload, no I/O."""
    key = secrets.token_bytes(32)
    payloads = [secrets.token_bytes(256) for _ in range(n)]
    throughputs: list[float] = []
    for _ in range(k):
        t0 = time.perf_counter()
        for p in payloads:
            hmac.new(key, p, hashlib.sha256).hexdigest()
        elapsed = time.perf_counter() - t0
        throughputs.append(n / elapsed)
    best = max(throughputs)
    return {
        "best_throughput": best,
        "mean_throughput": statistics.mean(throughputs),
        "best_us_per_op": 1_000_000 / best,
    }


# ── Phase 2: commit_forensic end-to-end (HMAC + MMR + WAL fsync) ──────────────


def bench_commit(n: int, k: int) -> dict[str, float]:
    """Full commit_forensic() throughput against a real WAL (fsync per node)."""
    key = secrets.token_hex(32)
    req = b'{"model":"gpt-4o","messages":[{"role":"user","content":"benchmark payload"}]}'
    resp = b'{"choices":[{"message":{"role":"assistant","content":"ok"}}]}'

    throughputs: list[float] = []
    for trial in range(k):
        with tempfile.TemporaryDirectory() as tmp:
            wal = str(Path(tmp) / f"bench_{trial}.wal.jsonl")
            ledger = CryptographicAuditLedger(persistence_path=wal, signing_key=key)
            try:
                t0 = time.perf_counter()
                for i in range(n):
                    ledger.commit_forensic(
                        state_id=f"bench-{trial}-{i}",
                        request_bytes=req,
                        response_bytes=resp,
                        entropy=2.5,
                        model="gpt-4o",
                        endpoint="chat.completions",
                    )
                elapsed = time.perf_counter() - t0
                throughputs.append(n / elapsed)
            finally:
                ledger.close()
    best = max(throughputs)
    return {
        "best_throughput": best,
        "mean_throughput": statistics.mean(throughputs),
        "best_us_per_op": 1_000_000 / best,
    }


# ── Phase 3: verify_integrity sweep ───────────────────────────────────────────


def bench_verify(n: int, k: int) -> dict[str, float]:
    """verify_integrity() throughput: full hash-chain sweep over N committed nodes."""
    key = secrets.token_hex(32)
    req = b'{"model":"gpt-4o","messages":[{"role":"user","content":"verify payload"}]}'

    throughputs: list[float] = []
    with tempfile.TemporaryDirectory() as tmp:
        wal = str(Path(tmp) / "verify.wal.jsonl")
        ledger = CryptographicAuditLedger(persistence_path=wal, signing_key=key)
        try:
            for i in range(n):
                ledger.commit_forensic(
                    state_id=f"verify-{i}",
                    request_bytes=req,
                    response_bytes=None,
                    entropy=1.0,
                )
            for _ in range(k):
                t0 = time.perf_counter()
                ok, bad_idx = ledger.verify_integrity()
                elapsed = time.perf_counter() - t0
                if not ok:
                    raise AssertionError(f"chain failed verification at node {bad_idx}")
                throughputs.append(n / elapsed)
        finally:
            ledger.close()
    best = max(throughputs)
    return {
        "best_throughput": best,
        "mean_throughput": statistics.mean(throughputs),
        "best_us_per_op": 1_000_000 / best,
    }


# ── Driver ────────────────────────────────────────────────────────────────────


def run_benchmark(n: int = _DEFAULT_N, k: int = _DEFAULT_K) -> dict[str, Any]:
    sep = "=" * 72
    print(f"\n{sep}")
    print("CRYPTOGRAPHIC AUDIT CHAIN BENCHMARK — commit + verification throughput")
    print(sep)
    print("  Ledger:            aegis.core.crypto_audit.CryptographicAuditLedger")
    print("  Signing:           HMAC-SHA256 (constant-time verify)")
    print("  WAL:               JSONL, 0o600, fsync per node (real durable write)")
    print(f"  N per phase:       {n:,}")
    print(f"  Trials per phase:  k={k} (best-of-k reported, Google Benchmark min)")
    print()

    hmac_r = bench_hmac_sign(n, k)
    commit_r = bench_commit(n, k)
    verify_r = bench_verify(n, k)

    header = f"  {'Phase':<34}{'ops/s':>14}{'µs/op':>14}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    print(
        f"  {'HMAC-SHA256 sign (crypto-only)':<34}"
        f"{_fmt_throughput(hmac_r['best_throughput']):>14}"
        f"{hmac_r['best_us_per_op']:>14.3f}"
    )
    print(
        f"  {'commit_forensic (HMAC+MMR+WAL)':<34}"
        f"{_fmt_throughput(commit_r['best_throughput']):>14}"
        f"{commit_r['best_us_per_op']:>14.3f}"
    )
    print(
        f"  {'verify_integrity (chain sweep)':<34}"
        f"{_fmt_throughput(verify_r['best_throughput']):>14}"
        f"{verify_r['best_us_per_op']:>14.3f}"
    )
    print()
    print(
        f"  [PROVEN] HMAC-SHA256 node signing sustains "
        f"{_fmt_throughput(hmac_r['best_throughput'])} ops/s "
        f"({hmac_r['best_us_per_op']:.3f} µs/op) — signature cost is negligible vs WAL I/O."
    )
    print(
        f"  [PROVEN] Full durable commit (fsync per node) sustains "
        f"{_fmt_throughput(commit_r['best_throughput'])} commits/s "
        f"({commit_r['best_us_per_op']:.1f} µs/commit) on this host."
    )
    print(
        f"  [PROVEN] Offline chain verification sweeps "
        f"{_fmt_throughput(verify_r['best_throughput'])} nodes/s "
        f"({verify_r['best_us_per_op']:.3f} µs/node)."
    )
    ratio = commit_r["best_us_per_op"] / max(hmac_r["best_us_per_op"], 1e-9)
    print(
        f"  [INFERENCE] Durable commit is ~{ratio:.0f}× the bare HMAC cost — the "
        f"per-node budget is dominated by MMR insertion + WAL fsync, not signing."
    )

    return {"hmac": hmac_r, "commit": commit_r, "verify": verify_r, "n": n, "k": k}


def main() -> None:
    parser = argparse.ArgumentParser(description="Cryptographic audit chain benchmark")
    parser.add_argument("--n", type=int, default=_DEFAULT_N, help="operations per phase")
    parser.add_argument("--k", type=int, default=_DEFAULT_K, help="trials per phase (best-of-k)")
    args = parser.parse_args()
    run_benchmark(n=args.n, k=args.k)


if __name__ == "__main__":
    main()
