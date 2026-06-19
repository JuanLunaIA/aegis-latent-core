---
name: zero-latency-profiler
tier: MEDIUM
domains: [profiling, py-spy, flamegraph, PyO3-marshalling, latency-budget, measure-first, memory-leak]
---
## Activation
Load on: latency profiling, PyO3 marshalling overhead, "is X the bottleneck", flamegraph
analysis, memory leak hunt, before ANY performance claim enters docs/README.

## Prime Directive
```
[ESTABLISHED] No performance number enters documentation without a reproducible measurement.
"<1.2ms latency", "<0.5ms signing", "sub-millisecond entropy" are CLAIMS until measured on
named hardware with a published method. Measure → then claim. This skill produces the evidence.
```

## Measure the PyO3 Boundary (the suspected bottleneck)
```python
# Isolate the Python↔Rust crossing cost. Compare: pure-Python op vs PyO3 op vs native baseline.
import time, statistics
def bench(fn, n=100_000, warmup=1000):
    for _ in range(warmup): fn()
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns(); fn(); samples.append(time.perf_counter_ns() - t0)
    samples.sort()
    return {
        "p50_us": samples[len(samples)//2] / 1000,
        "p99_us": samples[int(len(samples)*0.99)] / 1000,
        "mean_us": statistics.mean(samples) / 1000,
    }
# Run for: leaf_hash_python(), leaf_hash_pyo3(), and time the marshalling alone
# (call a PyO3 no-op that just returns to measure pure crossing cost).
# X→Y because Z: comparing no-op PyO3 vs real PyO3 op → isolates marshalling from compute
#   because the delta of (real - noop) is the actual work, and noop is the crossing tax.
```

## py-spy (sampling profiler, no code change, prod-safe)
```bash
# Attach to a running proxy, get a flamegraph — where is wall-clock actually spent?
py-spy record -o profile.svg --pid $(pgrep -f aegis) --duration 60 --rate 200
# --native: include native (Rust/C) stacks to see if time is in PyO3 calls or Python
py-spy record -o profile_native.svg --pid $(pgrep -f aegis) --native --duration 60
# Dump current stacks (instant snapshot of what's blocking)
py-spy dump --pid $(pgrep -f aegis)
# X→Y because Z: sampling at 200Hz → low-overhead profiling because it samples the stack
#   periodically rather than instrumenting every call (no per-call cost added).
```

## Rust Side: cargo flamegraph
```bash
# For the Rust extension/data-plane component:
cargo flamegraph --bin aegis_dataplane -- --bench
# Or perf directly for the native lib under load:
perf record -F 997 -g -p $(pgrep -f aegis) -- sleep 30
perf script | stackcollapse-perf.pl | flamegraph.pl > rust_flame.svg
```

## Memory Leak Detection (PyO3 refcount leaks)
```python
import tracemalloc, gc
tracemalloc.start(25)  # 25-frame traceback
snap1 = tracemalloc.take_snapshot()
# ... run N requests through the PyO3 path ...
gc.collect()
snap2 = tracemalloc.take_snapshot()
for stat in snap2.compare_to(snap1, 'lineno')[:15]:
    print(stat)  # growing allocations across snapshots = leak candidate
# PyO3 leak signature: Py<T> not dropped, or Python objects held in Rust statics.
# X→Y because Z: refcount not decremented on the crossing → memory grows because PyO3
#   objects need explicit drop or scope exit; a leaked Py<T> pins the Python object forever.
```

## Edge-Case Matrix & Recovery
| Scenario | Detection Signature | Recovery Protocol |
|---|---|---|
| Marshalling dominates compute | (real_pyo3 - noop_pyo3) << noop_pyo3 cost | Batch crossings (one call with many items, not many calls); use buffer protocol/memoryview for zero-copy; reduce boundary frequency |
| GIL contention under load | py-spy shows threads waiting on GIL; CPU < 100% but throughput flat | Move CPU work into Rust with py.allow_threads (releases GIL during native work); multiprocess workers |
| py-spy can't attach | "Permission denied" / ptrace_scope | sudo, or sysctl kernel.yama.ptrace_scope=0 (dev only); run profiler as same user; container ptrace cap |
| Flamegraph all in native, no Python frames | Time in Rust, not Python | Bottleneck is the native code — profile Rust with cargo flamegraph/perf, not py-spy |
| Memory grows but tracemalloc flat | Leak is in Rust/native, not Python heap | Use valgrind/heaptrack on the native lib; check Rust-side static collections and un-dropped Py<T> |
