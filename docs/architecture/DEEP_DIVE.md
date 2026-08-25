<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Architecture Deep Dive

> Cryptographic flow · Merkle Mountain Range · terminal evidence persistence.
> This document is one of the system "laws" referenced by the top-level
> [`README.md`](../../README.md). It describes **what the code does**, not what
> it aspires to do. Unmeasured or unimplemented items are marked explicitly.

---

## 1. Authoritative and Optional Execution Paths

Aegis separates **authoritative evidence persistence** from optional forensic
enrichment. For admitted non-streaming outcomes, the handler awaits the WAL evidence
commit before returning the governed response. Optional analysis may be queued only
after that authoritative operation and is not part of the durability claim.

Admitted SSE uses a different lifecycle. `BoundedStreamProxy` incrementally sanitizes
and emits canonical events through an item- and byte-bounded queue while maintaining a
SHA-256 digest over the exact bytes emitted. It retains only bounded queue contents, a
finite de-identification window, an event, and a preview rather than the full logical
stream. At termination it performs one summary WAL commit; the terminal marker is
withheld until that commit succeeds.

```text
client -> admission controls -> upstream
                              -> non-stream response -> authoritative WAL commit -> response
                              -> SSE sanitize -> bounded queue -> incremental events
                                                      -> terminal summary WAL commit
                                                      -> terminal marker
                              -> optional enrichment queue (non-authoritative)
```

Streaming response headers initially report `X-Aegis-Evidence-Status` and
`X-Aegis-Proof-Status` as `pending-terminal` and link the proof endpoint. The proof is
retrieved after terminal commit; it is not available in the initial streaming headers.
Backpressure, queue-byte, queue-event, event-size, cumulative-output,
de-identification-window, preview, and total-duration limits apply to each admitted
stream. Aggregate retained memory scales with concurrent admitted streams and must be
controlled by deployment admission/concurrency policy.

Sources of truth: `aegis/proxy/app.py`, `aegis/proxy/streaming.py`,
`tests/test_proxy_streaming.py`, and the per-stream arithmetic contract in
`specs/aegis_stream_buffer.smt2`. The scheduling figures in
[BENCHMARKS Claim 1](../BENCHMARKS.md#claim-1--zero-forensic-latency) characterize an
optional background-dispatch microbenchmark, not the authoritative evidence path or
end-to-end proxy latency.

---

## 2. Cryptographic Audit Chain

Implemented in `aegis/core/crypto_audit.py` (`CryptographicAuditLedger`).

### 2.1 Per-node hash

Each committed node binds its content to the entire prior history:

```
node_hash[i] = SHA256(
    prev_hash[i-1]  ‖  state_id   ‖  timestamp  ‖  entropy      ‖
    tenant_id       ‖  merkle_root ‖  signature  ‖  request_hash ‖  response_hash
)
```

`prev_hash` is the **first** input, so any reordering, insertion, or deletion of a
node changes `prev_hash` for every subsequent node — producing a detectable cascade
of mismatches rather than a single local error.

`request_hash` / `response_hash` are SHA-256 digests of the raw payloads; the raw
bodies are **not** retained in the node, only their digests (privacy-preserving by
construction — see [THREAT_MODEL](../security/THREAT_MODEL.md)).

### 2.2 Signing priority chain

`CryptographicAuditLedger` selects a signer in this order (first available wins):

| Priority | Scheme | Enabled by | Quantum-resistant | Admissibility |
|---|---|---|---|---|
| 1 | **HSM / PKCS#11** (RSA-PSS, ECDSA-SHA256) | `HSMSigningBackend` injected | depends on HSM | High |
| 2 | **ML-DSA-65** (FIPS 204) | Rust extension present | **Yes** | High |
| 3 | **HMAC-SHA256** | `AEGIS_SIGNING_KEY` set | No | High |
| 4 | **Ed25519** (ephemeral) | nothing configured | No | **Compromised** |

The signature covers `prev_hash ‖ merkle_root ‖ request_hash ‖ response_hash`, and is
verified with `hmac.compare_digest()` (constant-time) on the HMAC path.

> **Production invariant:** `AEGIS_SIGNING_KEY` must be set. Without it the chain
> falls back to ephemeral Ed25519 whose per-node keypair is discarded — signatures
> become non-verifiable across restarts and `legal_admissibility` is reported as
> `Compromised`. The signing key is held **separately** from `AEGIS_API_KEYS`.

### 2.3 `verify_integrity()`

An O(N) sweep that detects, per node:

1. **Field tampering** — recompute `node_hash`, compare.
2. **Chain break** — assert `node[i].prev_hash == node[i-1].node_hash`.
3. **Signature forgery** — re-derive the signature, constant-time compare.

Returns the first `error_index` on failure; the proxy keeps serving (integrity
failure is a forensic alarm, not a request-path fault).

---

## 3. Merkle Mountain Range (MMR)

Implemented in `aegis/core/mmr.py`; Rust-accelerated variant `MmrAccumulator`
(`aegis_rust`) with a pure-Python `MerkleMountainRange` fallback.

### 3.1 Why an MMR rather than a fixed Merkle tree

An MMR is an **append-only** accumulator: leaves are added with **O(log N)**
amortized work and **no rebalancing**, which matches the audit chain's append-only
nature. A classic balanced Merkle tree would require rebuilding internal nodes on
every append.

```
        peak                peak
         /\                  /\
        /  \                /  \      ← "mountains" (perfect binary trees)
       /\  /\              /\  /\        merged left-to-right as leaves arrive
      0 1 2 3            4 5 6 7   8     ← leaves (one per audit node)
```

Each commit:
1. Hashes the node bytes into a leaf.
2. `add_leaf()` merges equal-height peaks (carry-propagation, like binary increment).
3. The resulting **MMR root** ("bagged peaks") is stored in the node's `merkle_root`.

### 3.2 Proof types

| Proof | Cost | Use |
|---|---|---|
| **Inclusion** | O(log N) | "node X is in the chain at position i" — compliance bundle |
| **Consistency** | O(log N) | "chain state B is an append-only extension of state A" |

Measured Rust vs Python throughput (leaf insertion):
**avg 3.01× / max 3.34×** ([BENCHMARKS Claim 2](../BENCHMARKS.md#claim-2--rust-extension-performance-mmr)).

---

## 4. Persistence — Authoritative JSONL and Auxiliary RustWal

Implemented in `aegis/core/crypto_audit.py` with JSONL as the replay authority. When the native extension is available, the proxy additionally opens `<wal_path>.stream.rwal` as an optional 256 MiB Rust mmap WAL (`memmap2` + CRC32 framing) and appends a copy only after the authoritative terminal stream node commits. The native segment is auxiliary, not a replacement or replay fallback. If its post-commit append fails, the process records `aegis_native_stream_wal_errors_total`, disables the segment and retains the JSONL result as authoritative rather than suppressing a terminal marker that the JSONL node already binds.

### 4.1 Durability properties

- **File mode `0o600`** — owner read/write only. This does not protect against the
  file owner, host root, a compromised process, or offline device access.
- **Authoritative append path** — the Python JSONL ledger is the replay authority.
  The auxiliary RustWal may overwrite bytes beginning at the first invalid frame
  during bounded recovery; it is not an immutable archive.
- **CRC32 framing** (auxiliary RustWal) — each copied terminal stream frame is
  length-prefixed and CRC-framed. `read_all()` returns the valid prefix and stops
  at the first zero-length, out-of-range, CRC-invalid, or non-UTF-8 frame. CRC32
  detects accidental corruption under this parser; it is not authentication.
- **Post-flush write-position publication** — one in-process mutex serializes frame
  placement, synchronous flush requests, and publication. `write_pos` advances only
  after the flush succeeds, so readers of that instance do not cross a failed frame.
  This is not a multi-process coordination protocol.

### 4.2 Segment rotation & backpressure

- Size-bounded active WAL rotates into immutable, owner-only segments `<wal>.NNNNNN`;
  the full chain is replayed across all segments on startup. Rotation never drops nodes.
- `WALBackpressureMonitor` (`aegis/core/intermittent_connectivity.py`) counts entries
  and bytes across the active WAL + rotated segments and raises the
  `aegis_wal_backpressure_active` Prometheus gauge when either threshold is crossed
  (`AEGIS_WAL_BACKPRESSURE_THRESHOLD`, `AEGIS_WAL_BACKPRESSURE_BYTES`).

### 4.3 Crash recovery

On startup `_load_from_wal()` replays the authoritative JSONL segments and re-links the hash chain within
the implementation boundary. A process killed during non-streaming persistence does not
produce a governed success from that path. During SSE, non-terminal events may already
have reached the client, but the terminal marker is withheld if terminal summary commit
does not complete. `fsync` completion is a process-observed storage acknowledgement, not
a guarantee of power-loss survival on every target filesystem or device. On opening an
auxiliary RustWal, scanning stops at the first invalid frame and writes a flushed zero-frame
terminator at that offset. Each subsequent append also writes a terminator after the new
valid prefix, preventing a same-size replacement from making a stale valid suffix reachable
on the next open. This recovery behavior is tested in one process and inherits mmap,
filesystem, kernel, controller, and device semantics.

---

## 5. Evidence Export & Long-Term Retention

| Capability | Module | Note |
|---|---|---|
| ISO/IEC 27037 evidence package | `iso27037_evidence.py` | chain-of-custody + SHA-256 seal, offline-verifiable |
| RFC 3161 trusted timestamp | `rfc3161_timestamper.py` | TSA token bound to bundle imprint |
| Operator seal | `operator_seal.py` | HMAC/HSM attestation gate before export |
| Witness co-signing | `witness_cosign.py` | m-of-n threshold, per-witness derived keys |
| DFIR formats | `dfir_export.py` | PKCS#7 SignedData + EWF/E01 container |
| Long-term archival | `archival_bundle.py` | algorithm-agile multi-hash/HMAC manifest, migratable |

The archival bundle is the **algorithm-agility** mechanism: it stores parallel digests
(`sha2-256/384/512`, `sha3-256/512`) and HMAC signatures so a bundle sealed today stays
verifiable after an algorithm is deprecated — operators layer in a stronger algorithm
via `add_hash()` / `add_signature()` without invalidating old verifiers.

---

## 6. Acceleration Tiers (Rust ⇄ Python parity)

Every Rust tier has a functionally complete Python fallback; the extension is optional.

| Tier | Component | Rust | Python fallback |
|---|---|---|---|
| 1 | HTTP forwarder | Tokio + reqwest pool | `httpx.AsyncClient` |
| 2 | WAF pre-filter | Aho-Corasick SIMD | `re` |
| 3 | Rate limiter | lock-free CAS token bucket | `asyncio.Lock` + TTLCache |
| 4 | Session store | sharded DashMap | `OrderedDict` + `RLock` |
| 5 | Audit ring buffer | `crossbeam::ArrayQueue` | `asyncio.Queue` |
| 6 | Auxiliary stream WAL | `memmap2` + CRC32 copy | No auxiliary segment; authoritative `os.fsync()` JSONL is unchanged |
| 7 | Cryptography | BLAKE3 SIMD + ML-DSA-65 | `hashlib` + HMAC-SHA256 |

Only Tier 7 (MMR) has a committed benchmark today; Tiers 1–6 carry design-target
speedups that are **not yet measured** — see
[BENCHMARKS "Claims Without Benchmarks"](../BENCHMARKS.md#claims-without-benchmarks).

---

## 7. Cross-References

- Threat analysis & STRIDE: [`../security/THREAT_MODEL.md`](../security/THREAT_MODEL.md)
- Horizontal scaling, WAL tuning, Redis TLS: [`../performance/SCALING_GUIDE.md`](../performance/SCALING_GUIDE.md)
- Measured numbers & methodology: [`../BENCHMARKS.md`](../BENCHMARKS.md)
- Feature implementation status: [`../ROADMAP.md`](../ROADMAP.md)
