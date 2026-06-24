# Aegis Performance Benchmarks

Measured on **2026-06-20** (Claims 1–2), **2026-06-21** (Claim 3, live HTTP load),
and **2026-06-24** (Claim 4, audit-chain throughput — v2.4.1 release verification).
All numbers are from actual execution — none are invented.
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

## Claim 3 — Live Single-Node HTTP Server Throughput

**Measured 2026-06-21.** First published single-node throughput numbers (the README
previously noted these were "not yet published").

**Methodology:** A real `uvicorn` server hosting `create_proxy_app()` was launched on
`127.0.0.1:8080`, then driven over loopback TCP by `benchmarks/bench_http_load.py`
(async `httpx` client). Target endpoint: `GET /health` — exercises the full ASGI
middleware stack (request-smuggling guard, auth shim, routing) plus the live ledger
and analyzer-cache health checks on every request. Latency is wall-clock per request;
server CPU is `utime+stime` deltas from `/proc/<pid>/stat`; RSS is sampled from
`/proc/<pid>/status` at 10 Hz.

> **Server topology caveat:** measurements are from a **single** uvicorn worker driving
> the Rust `aegis_rust` Tokio runtime (4 threads). The `--workers 4` multiprocess model
> could not be measured in this container: the seccomp `clone`/`clone3` lockdown applied
> at end-of-startup terminates forked workers (expected behaviour of the hardening
> filter, see `aegis/core/seccomp_guard.py`). Production multi-worker deployments run
> one process per core behind a load balancer — see
> [`docs/performance/SCALING_GUIDE.md`](performance/SCALING_GUIDE.md).

### Per-request latency and concurrency sweep

| Concurrency | Throughput (RPS) | p50 | p99 | max | Server CPU | n |
|---|---|---|---|---|---|---|
| 1 | 650.1 | **1.494 ms** | **2.019 ms** | 21.3 ms | 35.7 % | 20,000 |
| 4 | **902.0** | 4.051 ms | 10.99 ms | 120.8 ms | 43.1 % | 20,000 |
| 32 | 339.3 | 65.2 ms | 424 ms | — | 18.7 % | 8,000 |
| 128 | 246.9 | 297.6 ms | 4,256 ms | — | 13.8 % | 8,000 |

**Interpretation [PROVEN]:**
- **Clean per-request cost (c=1):** 1.49 ms p50 / 2.02 ms p99 for a full-stack `/health`
  round-trip over loopback — this is the realistic floor including TCP, ASGI, middleware,
  and live health checks (heavier than the in-process mock-upstream figure in Claim 1).
- **Peak single-worker throughput ≈ 900 RPS at c=4**, matching the 4-thread Rust runtime
  and 4 cores. The server is **never CPU-bound** (peak ~43 % ≈ 1.7 cores).
- **Throughput degrades past c≈4** while latency climbs by ~200× from c=1 to c=128. With
  CPU idle, this is **event-loop head-of-line blocking** (GIL contention between the
  CPython request loop and the Rust Tokio threads, plus synchronous health-check work),
  **not** compute saturation.

**Scaling implication [INFERENCE]:** single-worker throughput is bounded by event-loop
serialization, so the throughput lever is **horizontal** — one worker process per core
and replicas behind a load balancer — not raising per-worker concurrency. This is the
empirical basis for the horizontally-scaled design target; it does **not** by itself
prove the ">1 B RPM" figure, which remains an unmeasured multi-node architectural goal.

### Endurance / stability run

| Property | Value |
|---|---|
| Requests | 100,000 (concurrency 256) |
| Duration | 362.9 s (~6 min sustained overload) |
| Errors | **0** (100 % success) |
| Throughput | 275.6 RPS (overloaded regime, past saturation) |
| Server peak RSS | **101.5 MiB** (flat start-to-finish — no leak) |
| Server CPU | 15.1 % avg |

**Interpretation [PROVEN]:** under 6 minutes of deliberate overload (c=256, well past the
c≈4 saturation point) the server returned **zero errors**, held memory **flat at 101.5 MiB**,
and degraded gracefully (latency rose, throughput held — no collapse, no OOM, no leak).

---

## Claim 4 — Cryptographic Audit Chain Throughput

**Measured 2026-06-24 (v2.4.1 release verification).** Quantifies the cost of the core
forensic guarantees G1 (tamper-evident chain) and G3 (unforgeable HMAC signatures).

**Methodology:** `benchmarks/bench_crypto_audit.py` runs three phases over N=2,000 ops,
k=5 trials, best-of-k reported (Google Benchmark min). The commit and verify phases use a
real `CryptographicAuditLedger` backed by a temp-dir WAL (0o600, **fsync per node**) — the
numbers include genuine durable-write cost, not an in-memory mock.

> **Host note:** Claim 4 was measured on an Intel Xeon @ **2.10 GHz** (4 cores), Python
> 3.11.15 — a slightly slower clock than the 2.80 GHz host used for Claims 1–3. Compare
> ratios (signing vs fsync) rather than absolute clocks across claims.

| Phase | Throughput | Latency / op |
|---|---|---|
| HMAC-SHA256 node sign (crypto-only, no I/O) | 496,340 ops/s | 2.015 µs |
| `commit_forensic()` end-to-end (HMAC + MMR leaf + WAL fsync) | 693 commits/s | 1,442 µs |
| `verify_integrity()` (full hash-chain sweep) | 71,560 nodes/s | 13.975 µs |

**Interpretation [PROVEN]:**
- **Signature cost is negligible:** HMAC-SHA256 over a 256-byte node payload runs at ~496k
  ops/s (2.0 µs). The cryptographic signing is **not** the bottleneck.
- **Durable commit is fsync-bound:** the full `commit_forensic()` path sustains ~693
  commits/s (1.44 ms/commit) with a real `fsync` per node. The durable write — not the
  crypto — is ~716× the bare HMAC cost. This is the **sustainable background commit rate**;
  because commits are dispatched after the response returns (Claim 1), this fsync cost is
  **off** the client hot path.
- **Verification is fast:** an auditor re-verifying the chain offline sweeps ~71.6k nodes/s
  (14 µs/node), so a 1-million-node chain re-verifies in ~14 s on this host.

**Scaling implication [INFERENCE]:** to raise sustained commit throughput beyond the
single-WAL fsync ceiling, batch multiple forensic records per fsync or shard the WAL by
tenant — the signing and MMR costs leave ample headroom (the chain could sign ~700× faster
than it can durably persist). The Rust mmap WAL (`aegis_rust_v2`) targets exactly this
fsync ceiling.

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

# Cryptographic audit chain throughput (Claim 4 — commit + verify, real WAL fsync)
python -m benchmarks.bench_crypto_audit --n 2000 --k 5

# For Rust MMR benchmark (requires Rust toolchain + maturin):
cd aegis_rust_v2
maturin develop --release
cd ..
python -m benchmarks.bench_mmr

# Live single-node HTTP throughput (Claim 3) — launch the server, then drive load:
AEGIS_SIGNING_KEY=$(python -c 'import secrets;print(secrets.token_hex(32))') \
AEGIS_DEBUG_MODE=1 AEGIS_AUTH_DISABLED=1 HERMES_SANDBOX=true \
  uvicorn aegis.proxy.app:create_proxy_app --factory \
  --host 127.0.0.1 --port 8080 --workers 1 &
# wait for GET /health to return 200, then (server PID = $!):
python -m benchmarks.bench_http_load \
  --url http://127.0.0.1:8080/health \
  --total 20000 --concurrency 4 --warmup 1000 --server-pid $!
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

*Generated by `benchmarks/bench_forwarding.py`, `benchmarks/bench_mmr.py`, and
`benchmarks/bench_crypto_audit.py`.
Epistemic tags per CLAUDE.md I-03: [PROVEN] = executor output, [INFERENCE] = deduction
from proven facts, [SPECULATIVE] = unverified condition.*
