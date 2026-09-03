# Storage Requirements for the Evidence Path

**Last verified:** 2026-09-01 UTC
**Release baseline:** checked-out source baseline/release target `4.1.0` with fourteen synchronized anchors

The evidence guarantee Aegis offers is *commit before response*: for a governed non-streaming call the record is written, flushed, and synchronized before the response returns, and for an admitted stream one terminal summary is committed before the terminal marker is emitted. That guarantee is only as strong as the storage underneath it. This document states what the gateway actually does, what the substrate must provide, and how to choose one.

## What the gateway does

On the authoritative JSONL path the commit sequence is: acquire the ledger lock, compute the chain node and signature, write the JSON line, flush the language-level buffer, then call `os.fsync()` on the file descriptor, and only then append the node to the in-memory window (`aegis/core/crypto_audit.py:417-419`). The awaiting request does not return until that sequence completes.

On the optional native segment the sequence is: reserve an offset, copy the CRC32-framed payload into the memory map, write a zero-length terminator after it, call `flush_range`, and publish the new write position with a release store only after the flush returns (`aegis_rust_v2/src/wal.rs:134-175`).

## What `fsync` actually guarantees

`fsync(2)` asks the kernel to write dirty pages for that file descriptor from the page cache to the storage device and to wait for the device to acknowledge. When it returns zero, the kernel has been told the data is durable.

It does not guarantee the bytes are on non-volatile media. Between the kernel and the NAND there is usually a volatile device write cache. If the drive acknowledges the write while the data still sits in that cache and power is lost before the cache is drained, the acknowledged write is gone. Nothing the application can do detects or prevents this — it is a property of the hardware.

This is why the evidence claim is scoped as "the process requested synchronization" rather than "the record survived power loss." Closing that gap is a procurement decision, not a code change.

## Required substrate properties

| Property | Requirement | Why it matters here |
|---|---|---|
| Power-loss protection | Enterprise SSD or NVMe with on-device capacitors that flush the write cache on power failure, or a battery/flash-backed RAID controller | Without it, an acknowledged `fsync` can still be lost, which breaks commit-before-response at the physical layer |
| Write cache policy | Volatile write cache disabled, or protected by the above | An unprotected cache silently converts a synchronous write into an asynchronous one |
| Journaling | A filesystem that orders metadata and data consistently under power loss | A torn tail is detectable by CRC, but a corrupted directory entry can lose the whole segment |
| Exclusive writer | One process per write-ahead log path | Concurrent writers to one path do not produce a single ordered chain; see the topology matrix in DOC-01 §8 |
| Free-space headroom | Provision so the segment cannot reach capacity during a retention window | A full segment fails the append, which fails the request closed rather than silently dropping evidence |

## Filesystem guidance

| Filesystem | Configuration | Trade-off |
|---|---|---|
| ext4 | `data=ordered` is the default and is acceptable. `data=journal` writes data through the journal, which narrows the window in which a crash can expose a partially written record | `data=journal` costs write throughput because payload bytes are written twice |
| XFS | Suitable with default settings; `nobarrier` must not be used | Disabling barriers removes the ordering that makes `fsync` meaningful |
| ZFS | Well suited. A separate intent-log device (SLOG) with power-loss protection absorbs synchronous writes. Keep `sync=standard` | `sync=disabled` makes `fsync` a no-op and silently voids the commit-before-response property. Never set it on an evidence volume |
| Btrfs | Usable, but validate the specific kernel and profile before adopting it for evidence | Historic issues have been profile-specific; test rather than assume |
| Network filesystems | NFS and SMB are not recommended for the authoritative log | `fsync` semantics depend on server and mount options, and a client-side cache can acknowledge writes the server has not committed |

## Cloud block storage

Managed volumes hide the physical layer, so the questions change. Verify each of these against your provider's current documentation rather than against community lore, because the answers change between volume generations.

1. **Does the volume acknowledge a synchronous write only after it is durably replicated?** This is the property that substitutes for on-device power-loss protection.
2. **What is the IOPS and throughput floor at your sustained commit rate?** Because commit latency is request latency, a burst-credit volume that exhausts its balance converts into user-visible latency and, for streams, into producer backpressure.
3. **Is the volume attached to exactly one instance?** Multi-attach breaks the exclusive-writer requirement.
4. **What happens on instance stop, live migration, or host maintenance?** Ephemeral and instance-store volumes do not survive these events and are unsuitable for authoritative evidence.

As a general shape: provisioned-IOPS volume classes are the appropriate starting point for an evidence path with a latency target, general-purpose classes are usually acceptable for evaluation and low-rate workloads, and local instance storage is appropriate only for throwaway environments.

## Verifying your substrate

Confirm the volume actually honors synchronous writes before trusting it. A synchronous write benchmark that reports latency far below the physical write latency of the device class is evidence that something in the stack is acknowledging early:

```bash
# Synchronous small-write latency on the evidence volume.
fio --name=fsync-check --filename=/path/to/evidence/probe \
    --rw=write --bs=4k --size=64M --fsync=1 --direct=1 \
    --runtime=30 --time_based --group_reporting
```

Then remove the probe file. Interpret the result against the device class you believe you have; suspiciously low latency warrants investigating the write cache before the number is trusted.

For power-loss behavior itself, the only real test is pulling power from the host under sustained write load and checking the tail afterwards. That test belongs in acceptance, not in production.

## Consequences for the evidence claims

If the substrate does not meet the requirements above, several statements weaken in specific ways, and the honest thing is to state which:

- Commit-before-response remains true as program order but no longer implies survival of a power cut.
- Inclusion proofs remain valid relative to a trusted root, but a truncated tail means some committed records may be absent from a later reconstruction, so completeness of the retained set is not established.
- Chain verification over the retained window still detects modification; it cannot detect the loss of a valid tail without an externally retained expected count or root.

None of this makes the evidence useless. It bounds what it demonstrates. Record the substrate you chose alongside the evidence it produced, so a later reviewer can evaluate both together.

## Related documents

- [`docs/institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md`](../institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md) — topology and failure semantics.
- [`docs/institutional/DOC-04_OPERATIONS_PLAYBOOK.md`](../institutional/DOC-04_OPERATIONS_PLAYBOOK.md) — WAL stall and corruption runbooks.
- [`docs/BOUNDARIES.md`](../BOUNDARIES.md) — consolidated evidence boundaries.
- [`DEPLOYMENT_GUIDE.md`](../../DEPLOYMENT_GUIDE.md) — deployment gates.
