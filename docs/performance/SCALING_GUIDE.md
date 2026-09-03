# Scaling Guide — Aegis Latent Core

This guide explains how to scale Aegis without confusing horizontal fan-out, storage capacity, queueing and provider behavior. It is for platform engineers and SREs. The guide provides sizing hypotheses and telemetry requirements; it does not publish a production capacity number or SLO.

**Last verified:** 2026-08-27 UTC
**Release baseline:** four-layer truth model
**Source baseline/release target:** `v4.1.1` with 14 synchronized anchors; source metadata does not establish external lifecycle state; verify the tag, GitHub Release, PyPI, npm, OCI digest, signature, and attestation through independent readback
**Immutable comparison source:** `fdace8844568eb788216740b2cb5daf187d99d3b` with `4.0.0` anchors
**Previous public GitHub Release:** `v4.0.1` lightweight tag targeting `6469904380218584ae0b5221334bc9a46500f5ba`
**Observed registries:** PyPI `aegis-latent-sdk` `4.1.1` and GHCR `4.1.1`, read back 2026-09-03; npm still `4.0.0`
**Historical evidence baseline:** `v3.1.0`; retained measurements are historical evidence for that release only
**Audience:** Platform engineering and SRE
**Primary runtime contract:** [`DEPLOYMENT_GUIDE.md`](../../DEPLOYMENT_GUIDE.md)

The checked-out `v4.1.1` source baseline/release target and immutable comparison source identify implementations under documentation review; they do not reclassify or reproduce the published `v3.1.0` evidence. Historical v3.1.0 measurements must not be used as v4 capacity, latency, availability, or SLO claims. A v4 claim requires a v4 rerun plus acceptance evidence from the actual target environment.

## Scaling invariant

Aegis has two coupled paths: the authoritative evidence path and optional enrichment. Scaling enrichment cannot compensate for a storage or signer bottleneck in the authoritative path. A governed response still waits for the durable evidence boundary.

A single local benchmark cannot predict production capacity because upstream latency, body size, WAF cost, provider behavior, filesystem semantics, CPU quota, Redis, ingress, topology and queue policy all change the result.

## Topology choices

| Topology | Evidence model | Scaling use | Limitation |
|---|---|---|---|
| One process and WAL | One local chain | Evaluation and small deployments | One process, volume and key custody failure domain |
| One worker per pod | Independent per-pod bundles | Kubernetes horizontal scaling | No global ordering or cross-pod atomicity |
| Multiple workers per node | Multiple local processes | Controlled host deployments | Seccomp/process-spawn and shared-volume interactions require acceptance |
| Centralized writer | One ordered evidence sequence | Global ordering requirement | Writer capacity and availability become critical |

The current repository does not implement cross-replica global ordering or multi-region consensus. A customer requiring a single timeline must deploy a centralized writer or merge independently verifiable bundles through a reviewed process.

## Storage and queueing

The WAL is the durability backbone. Monitor active bytes, rotated segments, write latency, `fsync` latency, free space, inode use, synchronization failures and restore-test status. Network filesystems and cloud volumes require an environment-specific acceptance test because their flush and replication semantics vary.

The retained `v3.1.0` backpressure run offered 10,000 requests at 10,000 RPS with a 2 ms injected `fsync` delay. It preserved 10,000 durable records with zero failures, missing IDs or duplicates, but observed p99 commit latency of 1,189.89 ms. The mechanism preserved evidence while queueing increased tail latency in that historical harness. This is not a capacity or SLO claim for v3.1.0 or v4.

For SSE, memory is not proportional to retaining the complete response. Each `BoundedStreamProxy` has an item-and-byte-bounded queue, finite de-identification holdback and bounded preview while SHA-256 is updated incrementally over emitted bytes. Size aggregate stream memory from concurrent streams and `stream_queue_max_bytes`, `stream_queue_max_items`, `max_stream_event_bytes` and `stream_deidentifier_window_chars`; also include Python object overhead and downstream socket buffering. A limit breach closes upstream and produces a terminal failure outcome rather than growing without bound.

## Resource dimensions

| Dimension | Primary bottleneck | Telemetry | Scaling response |
|---|---|---|---|
| Evidence commit | Storage, signer or `fsync` | Commit latency, errors, queue depth | Faster accepted storage, signer isolation or centralized writer |
| Request controls | CPU, parsing and normalization | WAF duration, body size, CPU | More workers or replicas after storage acceptance |
| Upstream | Provider latency and errors | Upstream latency, status, circuit state | Provider capacity or routing policy |
| Redis limiter | Connection/command latency and partitions | Redis latency, failures, pool use | HA Redis, pool tuning and fail-closed testing |
| Enrichment | Queue depth and worker time | Queue depth, rejection, analysis latency | Bound work, scale optional workers or disable optional path |
| Memory | In-memory chain, per-stream byte-bounded queues/holdback/previews, caches | RSS, heap, configured queue bytes, stream concurrency | Bound inputs and events, tune stream queue/holdback, rotate WAL, add replicas |

## Benchmark before sizing

A capacity acceptance test must include the real ingress, representative request/response sizes, provider behavior, signer path, storage, Redis, TLS, concurrency, error injection, warmup, sample count, percentiles, resource telemetry and recovery behavior. Record hardware, operating system, runtime versions, source commit, image digest and raw output.

```bash
pytest -q
python tools/benchmarks/run_backpressure_stall.py \
  --offered-rps 10000 --fsync-delay-ms 2 \
  --output evidence/backpressure_stall_report.json
```

The backpressure harness is a local fault-injection tool. It does not replace a customer end-to-end capacity test or `dm-delay` experiment.

## Redis over TLS

Use `rediss://` with certificate verification, protected credentials and an HA design appropriate to the deployment. Redis stores limiter/session state in the declared path; it must not receive signing keys or raw prompt/response content. Validate failover, partition, timeout, rate-limit consistency and recovery before calling a multi-replica topology accepted.

## Kernel and container effects

Strict Seccomp and LSM/AppArmor/SELinux profiles can affect process creation, filesystem access, networking and observability. Run one worker per pod when the target profile conflicts with post-start process spawning. Record the exact image, runtime, profile and negative test; do not relax strict mode to hide a deployment mismatch.

## Observability and scale decisions

| Signal | Interpretation | Required action |
|---|---|---|
| p99 commit latency rising while CPU is low | Storage or signer queueing | Inspect storage, `fsync`, signer and queue before adding replicas |
| Queue saturation | Optional analysis or authoritative pressure | Preserve the evidence gate; bound or reject optional work |
| Redis failures | Distributed limiter unavailable | Fail closed and repair dependency |
| Upstream circuit open | Provider path degraded | Follow provider incident path; do not claim Aegis capacity |
| `aegis_stream_duration_seconds{provider,outcome}` tail or limit outcomes rise | Slow provider/consumer or limits are being reached | Correlate provider, concurrency and configured bounds before scaling |
| `aegis_stream_tokens_total{provider}` or `aegis_stream_redactions_total{provider,entity}` shifts | Stream traffic mix or redaction behavior changed | Validate against request mix and privacy policy; never inspect through raw-content logs |
| WAL growth | Rotation/archive lag | Verify free space, archive and retention policy |
| Integrity failure | Evidence trust boundary violated | Stop affected scope, preserve bytes and escalate |

## Capacity language rules

Use “offered load,” “measured commit latency,” “local fault-injection result,” and “per-replica evidence bundle.” Do not use “accepts 10k RPS,” “unlimited throughput,” “zero overhead,” “low latency,” or “global HA” without a matching target artifact, owner-approved gate and defined SLO.

## Related documents

- [`docs/architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md)
- [`docs/benchmarks/BENCHMARK_RESULTS.md`](../benchmarks/BENCHMARK_RESULTS.md)
- [`docs/benchmarks/README.md`](../benchmarks/README.md)
- [`docs/operations/BACKPRESSURE_RUNBOOK.md`](../operations/BACKPRESSURE_RUNBOOK.md)
- [`docs/PLATFORM_OPERATOR_GUIDE.md`](../PLATFORM_OPERATOR_GUIDE.md)
- [`DEPLOYMENT_GUIDE.md`](../../DEPLOYMENT_GUIDE.md)
