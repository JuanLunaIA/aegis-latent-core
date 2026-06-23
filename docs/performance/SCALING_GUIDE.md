<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Scaling Guide

> Horizontal fan-out · WAL tuning · Redis TLS.
> One of the system "laws" referenced by [`README.md`](../../README.md). Tuning advice
> here is derived from **measured** behaviour ([BENCHMARKS Claim 3](../BENCHMARKS.md#claim-3--live-single-node-http-server-throughput)),
> not aspiration. The unmeasured ">1 B RPM" figure is treated as a design target only.

---

## 1. The Core Scaling Fact (measured)

A single worker process is **not CPU-bound**. Measured `/health` throughput over the
full ASGI stack (2026-06-21, 4-core Xeon @ 2.8 GHz):

| Concurrency | Throughput | p50 | p99 | Server CPU |
|---|---|---|---|---|
| 1 | 650 RPS | 1.49 ms | 2.02 ms | 36 % |
| **4** | **902 RPS** | 4.05 ms | 11.0 ms | 43 % |
| 32 | 339 RPS | 65 ms | 424 ms | 19 % |
| 128 | 247 RPS | 298 ms | 4,256 ms | 14 % |

**Reading the curve:** throughput peaks near concurrency = core count, then *falls* as
concurrency rises while CPU stays under half. That is event-loop / GIL serialization
between the CPython request loop and the Rust Tokio threads — **not** compute saturation.

### Consequence

> **Scale out, not up per worker.** The throughput lever is *more worker processes and
> more replicas*, each pinned near its own core count. Piling client concurrency onto a
> single worker only inflates tail latency.

---

## 2. Single-Node Tuning

### 2.1 Workers per node

Run **one uvicorn worker per physical core**, behind the node's event loop:

```bash
# Production: one process per core (N = nproc)
AEGIS_SIGNING_KEY=$(cat /run/secrets/aegis_signing_key) \
  uvicorn aegis.proxy.app:create_proxy_app --factory \
  --host 0.0.0.0 --port 8080 --workers "$(nproc)"
```

> **Container caveat (observed):** the end-of-startup **seccomp** lockdown denies
> `clone`/`clone3`. Some container runtimes terminate uvicorn's forked workers under
> that filter (this is the hardening filter doing its job). Two supported options:
> 1. Run **one worker per container** and scale containers (recommended for Kubernetes —
>    one process per pod, HPA on replicas); or
> 2. Use a process manager that forks **before** app startup (e.g. a pre-fork gunicorn
>    master with the uvicorn worker class), so all `clone` calls precede seccomp install.

### 2.2 CPU pinning & quotas

- `AEGIS_CGROUP_CPU_MAX`, `AEGIS_CGROUP_MEMORY_MAX` apply cgroups v2 quotas to the
  process's own cgroup (graceful no-op off-Linux / without permission).
- For OT/IEC-62443 latency determinism, pin hot-path workers to isolated cores at the
  orchestration layer (`cpuset`); `SCHED_FIFO`/NUMA pinning are **roadmap**, not implemented.

### 2.3 Memory budget

Measured RSS held **flat at 101.5 MiB** through a 6-minute 100k-request overload — no
leak. Plan capacity from the in-memory chain, not the request path:

| Resource | Default | Knob |
|---|---|---|
| In-memory audit chain | 100k nodes × ~2 KB ≈ 200 MB | `AEGIS_MAX_MEMORY_NODES` |
| Analyzer LRU cache | 4,096 sessions | `MAX_ANALYZER_SESSIONS` (code constant) |
| WAL mmap segment | 256 MiB | `WAL_SEGMENT_SIZE` (`wal.rs`) |
| Rust conn pool | 100 idle/host | `max_idle_per_host` (`forwarder.rs`) |

---

## 3. Write-Ahead Log Tuning

The WAL is the durability backbone; tune it to your write rate and disk.

### 3.1 Backpressure thresholds

`WALBackpressureMonitor` raises `aegis_wal_backpressure_active` (Prometheus) when the
active WAL + rotated segments exceed either bound:

| Env var | Default | Meaning |
|---|---|---|
| `AEGIS_WAL_BACKPRESSURE_THRESHOLD` | 1000 | entry-count ceiling (min 1) |
| `AEGIS_WAL_BACKPRESSURE_BYTES` | 104857600 (100 MiB) | byte ceiling (min 1) |

Alert on this gauge: a stuck-high value means commits are outpacing rotation/archival —
add disk throughput or shorten the segment size.

### 3.2 Rotation & archival

- Size-bounded active WAL rotates into immutable `0o600` segments `<wal>.NNNNNN`; the full
  chain replays across all segments at startup. Rotation never drops nodes.
- Keep `WAL_SEGMENT_SIZE` small enough that a single segment fsync stays under your tail-
  latency budget, large enough to avoid excessive rotation churn (256 MiB default is a
  reasonable midpoint for SSD).

### 3.3 Disk guidance

- Use a **dedicated, fsync-honoring** volume (local NVMe/SSD). Network filesystems that
  buffer fsync silently weaken the durability guarantee.
- WAL writes are append-only and CRC-framed; on `OSError` the node stays in the in-memory
  chain and a `CRITICAL` log line fires — monitor for it.

---

## 4. Multi-Replica Deployment

```
                       ┌───────────────┐
        clients ──────▶│ Load Balancer │  (tenant-affinity hashing optional)
                       └──────┬────────┘
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌──────────┐    ┌──────────┐    ┌──────────┐
        │ Aegis #1 │    │ Aegis #2 │    │ Aegis #N │   each: 1 worker / core
        │  WAL #1  │    │  WAL #2  │    │  WAL #N  │   each: own local WAL
        └────┬─────┘    └────┬─────┘    └────┬─────┘
             └──────── shared Redis (TLS) ───┘         rate-limit + session state
```

### 4.1 Shared state via Redis

Per-tenant rate limiting and session state can be backed by Redis (GCRA) so limits hold
**across** replicas rather than per-process. Without Redis each replica rate-limits
independently (acceptable if the LB does tenant-affinity hashing).

### 4.2 Audit chain across replicas

Each replica keeps its **own** local WAL and hash chain today. Cross-replica audit
ordering (Raft-replicated WAL, CRDT node ordering, gossip sync, multi-region replication)
is **roadmap, not implemented** — see [`../ROADMAP.md`](../ROADMAP.md) Domain 3.2 / 4.2.
For a single auditable timeline now, either:
- export and merge sealed bundles per replica (each is independently verifiable), or
- front a single writer for the audit path while fanning out the proxy path.

`aegis_wal_replication_lag_bytes` (Prometheus, `follower` label) is exposed for when
replication lands; it reads zero in standalone mode.

---

## 5. Redis over TLS

For shared rate-limit/session state, secure the Redis leg:

- Use `rediss://` (TLS) endpoints; verify the server certificate against your CA bundle.
- In air-gapped deployments, host Redis inside the enclave network and pin its CA.
- Never place Redis credentials in code or logs — source them from env/Vault, consistent
  with the secret-hygiene invariant in [THREAT_MODEL §4](../security/THREAT_MODEL.md#4-secret-leakage-mitigation-explicit).
- Redis is **availability-shared, not trust-shared**: it holds counters and session
  metadata, never signing keys or raw payloads.

---

## 6. Observability for Scaling Decisions

| Signal | Source | Scale action |
|---|---|---|
| `aegis_request_latency_p99` rising, CPU < 60 % | Prometheus | add replicas (event-loop bound, not CPU) |
| CPU pinned ~100 % across workers | node metrics | add nodes / cores |
| `aegis_wal_backpressure_active` = 1 | Prometheus | faster disk or smaller segments |
| `eviction_rate > 0.30` in `/health` | health endpoint | raise analyzer cache size |
| Circuit breaker open | `/health` provider status | upstream capacity, not Aegis |
| SLO burn-rate alert (1h/6h/24h/72h) | PrometheusRule CRD | capacity review |

---

## 7. Capacity Planning Honesty

- The **measured** per-worker baseline is ~900 RPS for `/health` on this hardware. Real
  proxy traffic (WAF + adapter + upstream forward) will differ; benchmark *your* endpoint
  and hardware with `benchmarks/bench_http_load.py` before sizing.
- The ">1 billion RPM" target assumes large horizontal fan-out of such workers and has
  **not** been validated end-to-end. Do not use it for capacity commitments.

---

## 8. Cross-References

- Architecture & persistence internals: [`../architecture/DEEP_DIVE.md`](../architecture/DEEP_DIVE.md)
- Threat model & TLS posture: [`../security/THREAT_MODEL.md`](../security/THREAT_MODEL.md)
- Measured numbers & reproduction: [`../BENCHMARKS.md`](../BENCHMARKS.md)
