# NEXUS Skills Index
Skills are activation prompts loaded before domain responses.
Reference path in CLAUDE.md activation matrix: `.skills/{domain}/{skill}.md`

## Domains
- `security/`      — Defensive security, compliance, forensics, audit
- `architecture/`  — Systems design, APIs, data, SRE, IaC, CI/CD
- `implementation/`— Code generation: Python, Rust, Go, ML, LLM
- `quality/`       — Review, debug, test, refactor, performance
- `documentation/` — Docs, runbooks, ADRs, technical writing
- `sre/`           — Reliability, cost, incident response
- `frontend/`      — Web frontend, accessibility
- `product/`       — PRDs, roadmaps, experimentation

---

## Tier-4 / Aegis PQC Extension (added)

Skills for re-engineering an LLM-governance proxy toward higher scale and post-quantum audit,
with honest physical limits (every performance claim must be measured, not asserted).

| Skill | Purpose |
|---|---|
| `security/pqc-audit-chain` | ML-DSA-65 (FIPS 204) batch-signing over MMR peaks + inclusion proofs. States the batch-vs-per-node guarantee explicitly. Runtime SIMD detection, not compile-time AVX-512 assumption. |
| `architecture/lsm-storage-ops` | RocksDB local audit tier. WAL recovery mode fixes startup-halt-on-corrupt-tail. Dual-tier with explicit fail-open/closed policy. |
| `architecture/clickhouse-ledger-ops` | Columnar analytical tier. ReplacingMergeTree for idempotent at-least-once ingestion. Compliance/entropy/chain-continuity queries. |
| `architecture/data-plane-scale` | The load-bearing truth: Python/GIL caps ~10-50k RPS regardless of native code beneath. WHEN Python must leave the hot path; eBPF/XDP scope (front-line filter, not L7 governance). |
| `quality/zero-latency-profiler` | py-spy + cargo flamegraph + PyO3 boundary isolation + leak detection. Prime directive: no perf number enters docs without reproducible measurement. |
| `implementation/onnx-latent-waf` | Tiered detection (L0 regex µs / L1 tiny-ONNX ms inline / L2 large-model async). Corrects "130M-param sub-ms on CPU" — tens of ms; budget guard + fallback. Prefer provider logprobs over local re-estimation. |

**Honesty invariant**: a 130M-param transformer is not sub-millisecond on CPU; >1B RPM is not
reachable with Python in the hot path; per-node signing and batch-peak signing are mutually
exclusive guarantees. These skills encode the corrected reality, not the original over-claim.
