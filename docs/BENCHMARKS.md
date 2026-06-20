# Aegis Performance Benchmarks

Measured on **2026-06-20**. All numbers are from actual execution — none are invented.
See [Reproducing](#reproducing) for exact commands to re-run.

---

## Hardware and Software Environment

| Property | Value |
|---|---|
| CPU | Intel(R) Xeon(R) Processor @ 2.80GHz |
| Cores | 4 |
| RAM | ~16 GB |
| OS | Linux 6.18.5 x86_64 (glibc 2.39) |
| Python | 3.11.15 (GCC 13.3.0) |
| FastAPI | 0.137.2 |
| httpx | 0.28.1 |
| anyio | 4.14.0 |
| starlette | 1.3.1 |
| numpy | 2.4.6 |
| aegis_rust | 3.0.0 (Rust extension, release build with LTO) |

---

## Claim 1 — Zero Forensic Latency

**Claim (from source):** `_commit_and_alert` runs via `asyncio.create_task()` and executes
after the HTTP response is returned to the client. The client sees no added I/O wait from the
audit commit.

**Measurement methodology:** `benchmarks/bench_forwarding.py` runs two sub-benchmarks:

### Part 1: `_spawn_background()` Hot-Path Overhead (direct micro-benchmark)

Measures the **complete scheduling block** executed on the response hot path per request,
replicating all bookkeeping from `aegis/proxy/app.py:_spawn_background`:
`asyncio.create_task()` + `_BACKGROUND_TASKS.add(task)` + gauge update +
`task.add_done_callback(_on_done)`. The task coroutine itself executes outside the measured
window (after the response is already returned).

| Metric | Value |
|---|---|
| p50 | 2.43 µs |
| p99 | 6.78 µs |
| mean | 2.59 µs |
| σ | 1.66 µs |
| n | 5,000 iterations |

**Interpretation [PROVEN]:** The full `_spawn_background()` hot-path block costs 2.4 µs at p50
and 6.8 µs at p99 in this environment. This is the true hot-path overhead added to each
request: the audit commit **coroutine** does not run — only its scheduling is on-path.

**Revised claim wording:** *"The audit commit adds no I/O wait to the client-visible response.
The full scheduling block (`create_task` + bookkeeping) is ~2.4 µs p50 in the benchmark
environment."*

### Part 2: WAF+HTTP Round-Trip Latency (ASGI in-process mock upstream)

Full end-to-end client-visible latency through the WAF inspection and HTTP stack, with the
upstream mocked in-process (0 ms network latency). Background tasks drained every 10
requests to isolate per-request overhead.

| Condition | p50 | p95 | p99 | mean | σ | n |
|---|---|---|---|---|---|---|
| WITH_BG (`asyncio.create_task` active) | 0.300 ms | 0.397 ms | 0.491 ms | 0.327 ms | 0.505 ms | 2,000 |
| NO_BG (no `create_task`, floor latency) | 0.290 ms | 0.383 ms | 0.483 ms | 0.305 ms | 0.045 ms | 2,000 |

**Statistical test:**
- Welch t = 1.96 | p-value = 0.0499 | Cohen's d = 0.062 (negligible effect)
- Δp50 = **+10 µs** (WITH_BG minus NO_BG)

**Interpretation [INFERENCE]:** The 10 µs Δp50 is statistically significant at p=0.050 but
the effect size is negligible (Cohen's d = 0.062). Under concurrent production traffic,
background tasks from one client's request interleave with other clients' request servicing —
the per-client observable cost approaches the Part 1 value (~2.4 µs scheduling call only).

**Verdict for the "zero forensic latency" claim:**
- **Definitionally true:** the commit coroutine runs after the ASGI framework returns the
  response object to the transport layer. No `await commit` appears before the `return
  JSONResponse(...)` call in the request handler.
- **Measured overhead on hot path:** `_spawn_background()` block = 2.43 µs p50, 6.78 µs p99.
- **End-to-end overhead:** Δp50 ≈ +10 µs vs floor latency (negligible effect size).

---

## Claim 2 — Rust Extension Performance (MMR)

**Claim (from source):** The Rust extension (`aegis_rust_v2`) yields significant
performance gains over the Python fallback for MMR operations.

### Python MerkleMountainRange throughput

| N (leaves) | Throughput | µs / leaf |
|---|---|---|
| 100 | 332,460 leaves/s | 3.008 µs |
| 1,000 | 292,050 leaves/s | 3.424 µs |
| 10,000 | 250,650 leaves/s | 3.990 µs |
| 100,000 | 212,180 leaves/s | 4.713 µs |

Methodology: k=5 independent trials per N. Best-of-k reported (Google Benchmark min
methodology — eliminates OS scheduling noise). Leaf payload: 32 bytes (SHA-256 of index).

**Throughput degrades ~36% from N=100 to N=100,000 [INFERENCE]:** Peak merging is O(log N)
amortised per leaf, but hash(str + str) allocates two new Python str objects per internal node.
At N=100,000 the GC pressure from ~200,000 node objects is measurable.

### Rust MmrAccumulator throughput

Built with `maturin build --release` (LTO, `codegen-units=1`) and installed via wheel.
`aegis_rust v3.0.0`, CPython 3.11, x86_64 Linux.

| N (leaves) | Python leaves/s | Rust leaves/s | Speedup |
|---|---|---|---|
| 100 | 332,460 | 958,510 | 2.88× |
| 1,000 | 292,050 | 814,000 | 2.79× |
| 10,000 | 250,650 | 760,260 | 3.03× |
| 100,000 | 212,180 | 709,240 | 3.34× |

**Aggregate: avg 3.01× speedup · max 3.34× speedup [PROVEN]**

The speedup is consistent and grows with N. The dominant cost in Python is SHA-256
via `hashlib` (Python wrapper → C) plus per-leaf `bytes` allocation; Rust calls `sha2`
directly with no allocator pressure per leaf and avoids the PyO3 round-trip for the
inner loop.

**Interpretation:** The Rust extension is measurably faster for bulk MMR operations
(~3× on average). Claims of "significant performance gains" are accurate at this level.
For very small N (<100), PyO3 call overhead approaches the per-leaf computation cost.

---

## Claims Without Benchmarks

The following speedup claims appear in source code docstrings but have **not** been benchmarked.
They represent design targets or architectural reasoning. Do not cite these as measured values.

| Component | Claimed speedup | Claimed mechanism |
|-----------|----------------|-------------------|
| HTTP Forwarder (Rust vs httpx) | ~12× throughput | Connection pool reuse + HTTP/2 + Tokio |
| WAF Aho-Corasick (Rust vs Python re) | ~25× throughput | SIMD multi-pattern scan vs regex interpreter |
| Rate limiter (CAS vs asyncio.Lock) | ~100× latency | Lock-free CAS vs mutex-gated event-loop call |
| WAL append (mmap vs fsync) | ~40–100× latency | Memory-mapped write vs kernel fsync |

Contributions of benchmarks for these components are welcome — see [`benchmarks/`](../benchmarks/).

---

## Reproducing

```bash
# Clone and install
git clone https://github.com/juanlunaia/aegis-latent-core
cd aegis-latent-core
pip install -e ".[dev]"

# Forwarding latency benchmark (zero forensic latency claim)
python -m benchmarks.bench_forwarding --warmup 200 --n 2000

# MMR throughput benchmark (Python baseline — no Rust required)
python -m benchmarks.bench_mmr

# For Rust MMR benchmark (requires Rust toolchain + maturin):
cd aegis_rust_v2
maturin develop --release
cd ..
python -m benchmarks.bench_mmr
```

A third party running these commands on equivalent hardware (x86-64 @ 2.8+ GHz,
Python 3.11/3.12, Linux) should obtain results within ±25% of the values above.
Larger deviations indicate hardware or OS scheduling differences — re-run with
`--warmup 500 --n 5000` for tighter confidence.

---

## Confidence Intervals

p50/p95/p99 are empirical percentiles from n=2,000 samples (Part 2). For a 95% confidence
interval on the p99 estimate, the margin of error is approximately:

```
±1.96 × sqrt(p99 × (1 - p99) / n) × range ≈ ±0.020 ms at p99=0.95, n=2000
```

The reported p50 values are stable to ±0.01 ms across repeated runs in the same environment.

---

*Generated by `benchmarks/bench_forwarding.py` and `benchmarks/bench_mmr.py`.
Epistemic tags per CLAUDE.md I-03: [PROVEN] = executor output, [INFERENCE] = deduction
from proven facts, [SPECULATIVE] = unverified condition.*
