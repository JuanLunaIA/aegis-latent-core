<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Connector Ecosystem

**Audience:** platform engineers and architects deciding where Aegis sits in an existing stack.
**Scope:** what each connector does, what it costs you operationally, and what it does **not** move.

An enterprise already runs an ingress tier, a secrets manager and a SIEM. The connectors exist so Aegis meets that data where it travels rather than demanding another hop.

## What ships today

| Connector | Module | Dependency | Verified how |
|---|---|---|---|
| Splunk HEC | `aegis.connectors.siem.splunk_hec` | `httpx` (already a runtime dependency) | 16 tests against an in-process mock transport |
| Parquet lakehouse export | `aegis.connectors.lakehouse.parquet_exporter` | `pyarrow`, via the `lakehouse` extra | 12 tests over segments produced by a real ledger |
| HashiCorp Vault Transit | `aegis.connectors.vault.transit_signer` | `httpx` | 23 tests against an in-process mock transport |
| Envoy / Istio WASM filter | `connectors/envoy-wasm` | Rust, `proxy-wasm`, `wasm32-wasip1` | 7 unit tests; module builds to a `.wasm` artifact |

Everything else in the strategy deck — Kong, Cloudflare Workers, Datadog, S3 Object Lock bridges, LangChain callbacks — is **not implemented**. `aegis/storage/s3_worm.py` exists and is separate from this connector set. Do not present unimplemented integrations as available.

## The rule that governs all of them

**A connector must never be able to fail a governed request.** A SIEM outage is not an evidence outage, and a lakehouse export is not a commit. Two consequences are wired in rather than documented aspirationally:

- The Splunk client raises nothing into the caller. Delivery problems become counters and spool files. A full queue drops rather than blocking, because blocking would let a slow indexer apply backpressure to the evidence path.
- The Parquet exporter runs against **finalized** segments, off the commit path entirely.

The one deliberate exception is Vault Transit, and it is an exception worth naming: signing is **on** the commit path, so Vault's availability becomes yours. If evidence must be signed and Vault is unreachable, the commit fails. That is the fail-closed direction and it is correct, but it is a real coupling to size before deployment.

## Splunk HEC

```python
from aegis.connectors.siem.splunk_hec import SplunkHECClient, SplunkHECConfig

async with SplunkHECClient(SplunkHECConfig(
    url="https://splunk.internal:8088/services/collector",
    token=os.environ["SPLUNK_HEC_TOKEN"],
    index="aegis_evidence",
    spool_dir="/var/lib/aegis/splunk-spool",
)) as client:
    await client.emit({"event_type": "waf_block", "state_id": state_id})
```

**Bounded on both sides.** The in-memory queue has a maximum event count; the spool directory has a maximum byte size. When the spool is full the **oldest** batch is discarded first and a counter records it. Unbounded telemetry buffering is how a monitoring path takes down the process it was meant to observe.

**Delivery is at-least-once.** A batch that times out after the indexer accepted it is retried, so duplicates are expected. Handle that with Splunk-side de-duplication; do not assume exactly-once.

**Alert on these counters:** `dropped_queue_full` and `discarded_spool_batches` are both silent data loss into your SIEM, and neither is visible from Splunk itself — by definition, the events never arrived.

**A gap in Splunk is not a gap in the evidence.** Reconcile against the WAL. Counting events in Splunk to prove completeness inverts the trust direction.

## Parquet lakehouse export

```python
from aegis.connectors.lakehouse.parquet_exporter import export_segment

result = export_segment("/var/lib/aegis/wal.jsonl.1", "/mnt/lake/aegis/")
# result.parquet_path, result.manifest_path, result.segment_sha256
```

Emits a zstd-compressed Parquet file plus the segment's own `aegis-wal-segment-manifest-v1` manifest — built by the **same function the archival path uses**, so a warehouse partition and a WORM archive describe the segment identically rather than through two implementations that drift.

**The table is a projection, not the evidence.** This is the point most likely to be misread in a compliance review:

- Hashes, roots and signatures are carried. Request and response **bodies** are not, because the WAL does not hold them either.
- **Verification is against the WAL**, never the table. Parquet encoding, column pruning, engine-side type coercion and any later `OPTIMIZE` or compaction can all change bytes without changing SQL semantics — fine for analytics, fatal for a hash.
- The manifest is the join point: it pins the source segment's SHA-256, chain tip, MMR root and leaf count, so a reviewer can tie a partition back to the bytes and verify *those*.

Digest columns are `binary`, not hex `string`: raw 32-byte values halve the column and remove any chance of a case-sensitive comparison.

An unfinalized segment is **refused** before any Parquet file is written, so a partial export cannot be mistaken for a complete one.

## HashiCorp Vault Transit

```python
from aegis.connectors.vault.transit_signer import VaultTransitSigner

with VaultTransitSigner(url="https://vault:8200", token=..., key_name="aegis") as signer:
    signature = signer.sign(node_hash)
```

The private key stays in Vault. Aegis submits a digest and receives a signature; key material never enters the process's address space, which is the entire reason to use Transit rather than a local keyring.

**`prehashed=true` is load-bearing.** A node hash already *is* a SHA-256 digest. Submitting it without the flag makes Vault hash it again and sign the wrong value — a signature that verifies happily through Vault and matches nothing computed independently. The client sets it, and a test pins it.

**What this moves and what it does not:** it moves key *custody*, not trust. Vault signs for whoever presents a token carrying the policy, so this attests that something holding that token asked — not that a particular person did. It is not non-repudiation, and no timestamp authority is involved.

## Envoy / Istio WASM filter

```bash
cd connectors/envoy-wasm
cargo build --release --target wasm32-wasip1
# target/wasm32-wasip1/release/aegis_envoy_wasm.wasm
```

Runs inside the proxy the enterprise already operates: no extra hop, no extra container. It scans request bodies for declared critical patterns and refuses with `403`, and redacts declared identifier patterns from response chunks behind a bounded holdback so a pattern straddling a chunk boundary is still caught.

**It is a subset of the gateway, not a port of it.** The difference is the part most likely to be misread:

- **It commits no evidence.** No ledger, no MMR, no WAL, no signature. A deployment running only this filter has request governance and **no evidence trail**. Evidence requires the gateway or the Veracity engine.
- **Its pattern set is smaller.** The gateway's WAF normalises Unicode, strips zero-width characters, walks nested JSON and carries a far larger corpus. The filter matches literal byte patterns on the body as received.
- **It prevents no prompt injection.** Deterministic pattern matching, no semantic understanding — the same boundary as everywhere else in this project.
- **The holdback is bounded, and so is its recall.** A pattern padded past the frontier is not matched. That is the price of a bound that cannot be overrun.

Redaction runs to a **fixpoint** before the frontier is measured, which closes the composite-payload bypass: redacting only the first match and then releasing the buffer lets a second pattern behind it leave in the clear.

## Choosing a topology

| If you already run | Deploy | You get | You still do not get |
|---|---|---|---|
| Envoy or Istio | The WASM filter | Request refusal and response redaction, in-mesh | Any evidence trail |
| Any gateway, and need audit | Veracity engine as a library | Commitment and portable proofs | Streaming redaction |
| Any gateway, and need privacy | Sanctum engine as a library | Redaction and scanning | Any evidence trail |
| Nothing yet | The Aegis gateway | The full commit-before-emit path | Cross-replica ordering (`UC-005`) |

Engines and the filter are independent. Running the filter **and** the Veracity engine gives in-mesh enforcement with a real evidence trail; neither alone does.

## Related

- [`docs/architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md)
- [`docs/institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md`](../institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md) — topology boundaries
- [`docs/commercial/ENTERPRISE_PRICING_GUIDE.md`](ENTERPRISE_PRICING_GUIDE.md)
