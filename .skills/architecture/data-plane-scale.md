---
name: data-plane-scale
tier: HIGH
domains: [data-plane, throughput, eBPF, XDP, tokio, hot-path, Python-GIL, Tier-4, scaling-reality]
---
## Activation
Load on: high-RPS data plane design, "Tier-4 scale", >100k RPS proxy, removing Python from
hot path, eBPF/XDP forwarding, when latency budget conflicts with language choice.

## The Load-Bearing Truth (read first)
```
[ESTABLISHED] CPython has a GIL. asyncio runs Python bytecode on one core at a time.
A Python process tops out at O(10k-50k) RPS for non-trivial request handling, regardless
of what native code sits beneath it, because the Python↔native boundary crossing and the
GIL-serialized event loop are the ceiling.

Therefore:
  < ~10k RPS    : Python FastAPI in hot path is FINE. Optimize Python, not architecture.
  10k-100k RPS  : multiprocess Python (gunicorn workers) + native offload of crypto/hashing.
                  PyO3 helps HERE (move CPU work off the GIL'd path into Rust with py.allow_threads).
  > 100k RPS    : Python must LEAVE the hot path. This is an architecture decision, not tuning.
  > 1M RPS      : pure Rust/C++ data plane, or kernel-bypass (XDP/DPDK). No interpreter in path.

X→Y because Z: "zero-copy ring buffers feeding a Python event loop" does NOT reach 16M RPS
because the consumer (Python) is the bottleneck — you optimized the pipe to a constrained valve.
```

## When Python Must Leave the Hot Path (the honest Tier-4 path)
```
[INFERENCE] If a genuine >1M RPM data plane is required, the governance logic splits:

  CONTROL PLANE (Python, off hot path):  policy config, key management, compliance export,
                                          dashboards, audit query. Python excels here.
  DATA PLANE (Rust, hot path):           request forwarding, leaf hashing, ring enqueue.
                                          No Python. Tokio multi-threaded runtime or hyper.

  AUDIT (async, off hot path):           MMR append + batch signing (see pqc-audit-chain),
                                          LSM persist (see lsm-storage-ops). Never blocks forwarding.

The Python proxy and Rust data plane share the audit ledger format, not the request path.
```

## eBPF/XDP — When and Why (not cargo-culted)
```
[ANALYSIS] XDP (eXpress Data Path) runs eBPF at the NIC driver before sk_buff allocation.
Use XDP for: L3/L4 filtering, DDoS drop, load distribution — BEFORE the request reaches userspace.
X→Y because Z: XDP drop → near-line-rate filtering because packets are processed before the
  kernel network stack allocates per-packet structures, saving the most expensive per-packet cost.

XDP is NOT for: L7 governance (reading prompt content, entropy analysis, signing). That needs
  userspace. So XDP is a front-line filter, not where Aegis's governance logic lives.
Honest scope: XDP/eBPF reduce load reaching the proxy; they don't run the LLM-governance logic.
```

## Socket-Level Tuning (real knobs, with mechanism)
```bash
# SO_REUSEPORT: multiple processes bind the same port; kernel load-balances connections.
# X→Y because Z: SO_REUSEPORT → even connection distribution across workers because the
#   kernel hashes connections to listening sockets, avoiding a single accept() thundering herd.
sysctl -w net.core.somaxconn=65535               # accept queue depth
sysctl -w net.ipv4.tcp_tw_reuse=1                # reuse TIME_WAIT sockets for outbound
sysctl -w net.core.netdev_max_backlog=250000     # NIC → kernel queue (high pps)
sysctl -w net.ipv4.ip_local_port_range="1024 65535"  # ephemeral port exhaustion (proxy→upstream)
# These help a real high-RPS proxy. They do NOT make Python reach 16M RPS.
```

## Edge-Case Matrix & Recovery
| Scenario | Detection Signature | Recovery Protocol |
|---|---|---|
| Latency target conflicts with Python in path | p99 latency floor ~ms; CPU pinned at GIL | Measure first (zero-latency-profiler); if Python is the floor, move forwarding to Rust data plane; do not micro-optimize Python |
| Ephemeral port exhaustion (proxy→upstream) | "cannot assign requested address"; high TIME_WAIT | Expand ip_local_port_range; tcp_tw_reuse=1; connection pooling to upstreams; HTTP keep-alive |
| Single-core soft-IRQ starvation | one CPU at 100% si (softirq); others idle | RSS/RPS to spread IRQs across cores; SO_REUSEPORT for app-level distribution |
| XDP program drops legit traffic | Traffic loss after XDP load; drop counters high | XDP maps are hot-swappable; revert program; validate filter logic in xdpdump first; fail-open default |
| Claimed RPS unachievable on hardware | Load test plateaus far below target | Report measured ceiling honestly; identify binding resource (CPU/GIL/NIC/upstream); right-size target or change architecture — do not fabricate the number |
