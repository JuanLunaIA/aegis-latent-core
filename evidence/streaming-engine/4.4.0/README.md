# Grammar-frontier stage — measured per-chunk overhead

**Observed:** 2026-09-10 UTC
**Harness:** `benchmarks/bench_streaming_engine.py --samples 20000`
**Artifacts:** `run_1.json` … `run_5.json`, five independent runs of the same harness
**Host:** Linux `x86_64`, CPython 3.11.15, single process, no concurrency

## What was measured

One `feed(chunk)` call per sample, timed with `time.perf_counter_ns`, over the
same 10-chunk corpus under both engines: `deidentifier` (the Safe Harbor set
alone, which every release through `4.3.0` ran) and `grammar_frontier` (that set
followed by the grammar-frontier rules, which `4.4.0` runs by default).

The redactor is isolated from the rest of the proxy on purpose. Queueing, JSON
re-encoding, SHA-256 hashing and the asyncio hop are identical under both
engines, so including them would add a constant to both sides and shrink the
delta into the surrounding noise. The delta the new stage adds is the number
the latency budget is about, and that is what this measures.

Each run warms both engines with 2,000 unmeasured calls first, so first-call
regex compilation does not land in the tail and get read as steady state.

## Result

Delta = `grammar_frontier` minus `deidentifier`, in microseconds per chunk,
across the five runs:

| Percentile | Min | Median | Max |
|---|---:|---:|---:|
| p50 | +10.41 | +11.04 | +11.71 |
| p95 | +2.84 | +12.46 | +14.60 |
| p99 | +3.76 | +12.39 | +22.72 |
| p99.9 | +12.09 | +21.07 | +23.42 |

Absolute p99 per chunk, for scale: `deidentifier` 0.147–0.164 ms,
`grammar_frontier` 0.161–0.177 ms.

**Against the budget.** `MISSION ORDER III` sets a 5 ms p99 threshold above
which the stage must be gated off by default. The measured p99 delta is
**0.0038–0.0227 ms**, roughly two to three orders of magnitude under it, so the
stage ships on by default. The configuration flag `AEGIS_STREAMING_ENGINE`
exists regardless — not for latency, but because the stage changes which
patterns are redacted, and an operator must be able to return to the previous
output.

## What this does not establish

- **p50 is resolvable; the tail is close to the noise floor.** The p50 delta is
  stable across runs at roughly +10 to +12 µs. The p99 delta spans +3.8 to
  +22.7 µs, and an earlier pair of runs at the same sample size produced −4.2 µs
  and −0.6 µs — the frontier engine measuring *faster* than the legacy one,
  which it cannot actually be. Read the tail figures as "small enough that this
  harness cannot separate them from run-to-run variance", not as a measurement
  of the stage.
- **One host, one process, one corpus.** No throughput result, no capacity
  claim, and nothing attributable to any deployment. Aggregate behaviour under
  concurrency is not measured here and is not implied.
- **Corpus-dependent.** The corpus deliberately mixes matching and non-matching
  text; content that matches on every chunk, or never, would move both engines'
  numbers and their difference.
- **Not a redaction-quality result.** Timing says nothing about what either
  engine catches. Coverage is asserted in
  `tests/test_streaming_safety_engine_integration.py`, and the boundaries on
  what pattern matching establishes — `CLM-016`, `CLM-024`, `CLM-057` — are
  unchanged.
