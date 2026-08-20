# Native WAL Concurrency Hardening — 2026-08-20

**Epistemic tag:** `[HIGH_CONFIDENCE_INFERENCE]` for the diagnosed pre-patch race mechanism; `[ESTABLISHED_EMPIRICAL]` for the executed regression results
**Affected component:** `aegis_rust_v2/src/wal.rs`
**Operational scope:** One process, multiple threads, one memory-mapped WAL segment
**Non-goals:** Multi-process writer coordination, filesystem power-loss certification, storage-controller cache semantics, and performance certification

## Root cause

The previous append path incremented the global `write_pos` before acquiring the mmap mutex. Multiple threads could therefore reserve offsets out of order. If an earlier reservation failed during `flush_range`, subtracting its frame length from a position already advanced by later reservations could move `write_pos` onto the wrong frame boundary. A later thread could also flush and return before the earlier reserved frame became durable. The mechanism was:

> atomic reservation → out-of-order mutex acquisition → out-of-order persistence or rollback → published position no longer denotes a fully durable contiguous prefix.

This contradicted the stated causal contract that the published WAL prefix contains only complete, durably flushed frames.

## Implemented change

Reservation, bounds checking, frame copy, `flush_range`, and `write_pos` publication now occur under the same mmap mutex. `write_pos` advances with a release store only after a successful flush. Frame and offset additions use checked arithmetic, payload length is checked against the on-disk `u32` field, and recovery validates CRC32 plus UTF-8 before advancing past a frame. The implementation favors the causal durability invariant over unmeasured lock-free throughput.

| Input or failure mode | Expected behavior | Verification path |
|---|---|---|
| Eight concurrent writers, 100 records each | Exactly 800 readable complete frames | `concurrent_appends_publish_only_complete_frames` |
| Append beyond capacity | Return `PyOverflowError`; do not advance `write_pos` | `rejected_append_does_not_advance_write_position` |
| Corrupt or torn frame during reopen scan | Stop recovery at the first invalid CRC, length, or UTF-8 frame | `scan_write_pos` validation path plus existing read-path checks |
| Valid sequential records | Preserve existing round-trip behavior | `roundtrip` and `multiple_records` |

## Verification result

`cargo test --release --locked` completed with **28 passed, 0 failed** after the patch. The complete Python suite with the native extension installed completed with **5,442 passed, 37 skipped, and 47 warnings**. Ruff, the CI mypy profile, and Bandit at medium/high severity completed without failures. The ABI3 release wheel built successfully, imported in a clean Python 3.12 environment, and its focused native-extension subset passed **17 tests**. Its SHA-256 digest was `e349999f8121bf02045a988df624cc4c0b03c49808282b0a1bf6dd4cedddb232`.

## Threat notes

| Threat | Pre-patch exposure | Post-patch control | Residual risk |
|---|---|---|---|
| Concurrent ordering corruption | Offset reservation and persistence could be reordered. | Single critical section publishes only flushed contiguous prefixes. | A poisoned process or unsafe external writer can still mutate the mapped file. |
| Integer overflow | Frame and end offsets used unchecked `usize` addition. | Checked additions and explicit `u32` payload bound. | Segment capacity conversion from platform input remains deployment-controlled. |
| Torn-write acceptance on reopen | Recovery scan trusted non-zero length without checking CRC. | CRC and UTF-8 validation before advancing. | CRC32 detects random corruption but is not collision-resistant against an active attacker. Cryptographic chain verification remains mandatory. |
| Performance regression | Not applicable to correctness. | No unsupported latency claim remains in the modified WAL documentation. | Throughput and latency must be remeasured on named storage and concurrency profiles. |

## Rollback and kill criteria

Rollback is a Git revert of the WAL change and its two regression tests. Do not roll back if concurrent append is enabled unless an alternative implementation preserves ordered durability. Kill deployment if any test produces fewer readable records than successful appends, if a failed append advances `write_pos`, if integrity verification reports a chain break, or if target-filesystem fault injection demonstrates an emitted response before the corresponding durable evidence commit.
