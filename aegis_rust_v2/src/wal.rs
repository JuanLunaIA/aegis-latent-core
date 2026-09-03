// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Memory-mapped Write-Ahead Log for audit nodes.
//!
//! Replaces the Python WAL that called `os.fsync()` under a `threading.Lock`
//! (GIL-contended, serialised, blocking syscall).
//!
//! Frame format (little-endian):
//!   [crc32: 4 B][payload_len: 4 B][payload: payload_len B]
//!
//! Guarantees:
//!   - `flush_range` requests synchronous persistence after each frame; actual
//!     crash/power-loss durability still depends on the OS, filesystem, and device.
//!   - CRC32 on read → torn-write detection.
//!   - The mmap mutex serialises reservation, copy, flush, and publication, so
//!     concurrent appends cannot expose a later frame before an earlier frame.
//!   - Atomic `write_pos` publishes only fully flushed contiguous prefixes.
//!   - File permissions 0o600 set at open time.
//!
//! Performance is workload- and filesystem-dependent; use the repository's
//! benchmark harness before making latency or throughput claims.

use crc32fast::Hasher as Crc32Hasher;
use memmap2::MmapMut;
use parking_lot::Mutex;
use pyo3::prelude::*;
use std::{
    fs::OpenOptions,
    ops::Range,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// Default segment size: 256 MiB — holds ~500k typical audit nodes.
const DEFAULT_SEGMENT_BYTES: usize = 256 * 1024 * 1024;

/// [crc32: 4 B][len: 4 B]
const FRAME_HEADER: usize = 8;

/// Byte range of the frame header at `pos`, if the whole header fits in `limit`.
///
/// Every frame walk in this module bounds its slicing through this function and
/// [`payload_range`] rather than through open-coded `pos + FRAME_HEADER + len`
/// comparisons, so the arithmetic that decides whether a slice is in bounds
/// exists in exactly one place and can be model-checked. See the `kani` module
/// at the bottom of this file.
#[inline]
fn header_range(pos: usize, limit: usize) -> Option<Range<usize>> {
    let end = pos.checked_add(FRAME_HEADER)?;
    if end > limit {
        return None;
    }
    Some(pos..end)
}

/// Byte range of a `payload_len`-byte payload following the header at `pos`,
/// if the whole payload fits in `limit`.
///
/// A zero-length payload is refused: a zero length is the recovery terminator
/// written after the valid prefix, never a real frame.
#[inline]
fn payload_range(pos: usize, payload_len: usize, limit: usize) -> Option<Range<usize>> {
    if payload_len == 0 {
        return None;
    }
    let start = pos.checked_add(FRAME_HEADER)?;
    let end = start.checked_add(payload_len)?;
    if end > limit {
        return None;
    }
    Some(start..end)
}

struct WalInner {
    mmap: Mutex<MmapMut>,
    /// Monotonically increasing byte offset; shared across threads.
    write_pos: AtomicU64,
    capacity: usize,
}

// SAFETY: MmapMut is Send (the OS mapping is not thread-local).
// Mutex<MmapMut> makes it Sync.
unsafe impl Send for WalInner {}
unsafe impl Sync for WalInner {}

/// Persistent mmap-backed Write-Ahead Log.
#[pyclass]
pub struct RustWal {
    inner: Arc<WalInner>,
}

#[pymethods]
impl RustWal {
    /// Open (or create) the WAL at `path` with an optional capacity ceiling.
    #[staticmethod]
    #[pyo3(signature = (path, capacity_bytes = None))]
    pub fn open(path: &str, capacity_bytes: Option<usize>) -> PyResult<Self> {
        let capacity = capacity_bytes.unwrap_or(DEFAULT_SEGMENT_BYTES);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // A WAL must preserve existing frames across restarts for crash
            // recovery — never truncate an existing segment on open.
            .truncate(false)
            .open(path)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                    "RustWal open failed (path={path}): {e}"
                ))
            })?;

        // Owner-only read/write permissions (mirrors Python's 0o600 WAL)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }

        // A segment may only grow. `OpenOptions::truncate(false)` stops `open`
        // from clearing the file, but `set_len` to a smaller size truncates it
        // just the same: reopening a populated 256 MiB segment with a smaller
        // `capacity_bytes` discarded every frame past the new length. Take the
        // larger of the requested capacity and the existing file, so a
        // misconfigured or downgraded caller cannot destroy committed frames.
        let existing_len = file
            .metadata()
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("RustWal metadata: {e}"))
            })?
            .len();
        let capacity = usize::try_from(existing_len)
            .map_err(|_| {
                PyErr::new::<pyo3::exceptions::PyOverflowError, _>(
                    "RustWal segment is larger than this platform's address space",
                )
            })?
            .max(capacity);

        file.set_len(capacity as u64).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("RustWal resize: {e}"))
        })?;

        // SAFETY: we own the file and no other process writes to the region.
        let mut mmap = unsafe { MmapMut::map_mut(&file) }.map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("RustWal mmap: {e}"))
        })?;

        let write_pos = scan_write_pos(&mmap, capacity);
        if write_pos + FRAME_HEADER <= capacity {
            mmap[write_pos..write_pos + FRAME_HEADER].fill(0);
            mmap.flush_range(write_pos, FRAME_HEADER).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                    "RustWal recovery terminator flush: {e}"
                ))
            })?;
        }

        Ok(RustWal {
            inner: Arc::new(WalInner {
                mmap: Mutex::new(mmap),
                write_pos: AtomicU64::new(write_pos as u64),
                capacity,
            }),
        })
    }

    /// Append a JSON payload as a CRC32-framed record.
    /// Returns the byte offset of the written frame.
    pub fn append(&self, payload: &str) -> PyResult<u64> {
        let data = payload.as_bytes();
        let payload_len = u32::try_from(data.len()).map_err(|_| {
            PyErr::new::<pyo3::exceptions::PyOverflowError, _>(
                "RustWal payload exceeds the u32 frame-length limit",
            )
        })?;
        let frame = FRAME_HEADER.checked_add(data.len()).ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyOverflowError, _>("RustWal frame size overflow")
        })?;

        // The critical section deliberately includes offset reservation and
        // durability. Publishing write_pos before flush would let a concurrent
        // caller expose a non-contiguous prefix after an earlier flush failure.
        let mut mmap = self.inner.mmap.lock();
        let offset = self.inner.write_pos.load(Ordering::Acquire) as usize;
        let end = offset.checked_add(frame).ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyOverflowError, _>("RustWal offset overflow")
        })?;

        if end > self.inner.capacity {
            return Err(PyErr::new::<pyo3::exceptions::PyOverflowError, _>(
                "RustWal segment full — rotate WAL or increase capacity",
            ));
        }

        let mut crc = Crc32Hasher::new();
        crc.update(data);
        let checksum = crc.finalize();

        let buf = &mut mmap[offset..end];
        buf[..4].copy_from_slice(&checksum.to_le_bytes());
        buf[4..8].copy_from_slice(&payload_len.to_le_bytes());
        buf[8..].copy_from_slice(data);

        // Persist a zero-length sentinel after the new valid prefix. This
        // prevents a same-size replacement of a recovered corrupt frame from
        // making an older, otherwise valid suffix reachable on the next open.
        let flush_end = if end + FRAME_HEADER <= self.inner.capacity {
            mmap[end..end + FRAME_HEADER].fill(0);
            end + FRAME_HEADER
        } else {
            end
        };

        // Persist to storage — blocks until OS confirms durability. write_pos
        // remains unchanged on failure, so readers never cross this frame.
        if let Err(e) = mmap.flush_range(offset, flush_end - offset) {
            return Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                "RustWal flush: {e}"
            )));
        }

        self.inner.write_pos.store(end as u64, Ordering::Release);

        Ok(offset as u64)
    }

    /// Read and verify all valid frames from the beginning of the WAL.
    pub fn read_all(&self) -> PyResult<Vec<String>> {
        let mmap = self.inner.mmap.lock();
        let limit =
            (self.inner.write_pos.load(Ordering::Acquire) as usize).min(self.inner.capacity);
        let mut records = Vec::new();
        let mut pos = 0usize;

        while let Some(header) = header_range(pos, limit) {
            let stored_crc = u32::from_le_bytes(
                mmap[header.start..header.start + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let payload_len = u32::from_le_bytes(
                mmap[header.start + 4..header.end]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;

            let Some(body) = payload_range(pos, payload_len, limit) else {
                break;
            };

            let payload = &mmap[body.clone()];
            let mut crc = Crc32Hasher::new();
            crc.update(payload);
            if crc.finalize() != stored_crc {
                // First CRC mismatch = torn write or end of valid log; stop here.
                break;
            }
            if let Ok(s) = std::str::from_utf8(payload) {
                records.push(s.to_string());
            }

            pos = body.end;
        }

        Ok(records)
    }

    pub fn write_pos(&self) -> u64 {
        self.inner.write_pos.load(Ordering::Acquire)
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// Remaining bytes before the segment is full.
    pub fn remaining(&self) -> usize {
        let pos = self.inner.write_pos.load(Ordering::Acquire) as usize;
        self.inner.capacity.saturating_sub(pos)
    }
}

/// Scan the mmap to find the byte offset of the first unwritten frame.
fn scan_write_pos(mmap: &MmapMut, capacity: usize) -> usize {
    let mut pos = 0usize;
    while let Some(header) = header_range(pos, capacity) {
        let stored_crc = u32::from_le_bytes(
            mmap[header.start..header.start + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let len = u32::from_le_bytes(
            mmap[header.start + 4..header.end]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize;
        let Some(body) = payload_range(pos, len, capacity) else {
            break;
        };
        let payload = &mmap[body.clone()];
        let mut crc = Crc32Hasher::new();
        crc.update(payload);
        if crc.finalize() != stored_crc || std::str::from_utf8(payload).is_err() {
            break;
        }
        pos = body.end;
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn tmp_wal() -> RustWal {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_string();
        // Keep file alive by leaking tempfile (test only)
        std::mem::forget(f);
        RustWal::open(&path, Some(1024 * 1024)).unwrap()
    }

    #[test]
    fn roundtrip() {
        let wal = tmp_wal();
        let payload = r#"{"state_id":"abc","timestamp":1234567890.0}"#;
        wal.append(payload).unwrap();
        let records = wal.read_all().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], payload);
    }

    #[test]
    fn multiple_records() {
        let wal = tmp_wal();
        for i in 0..10 {
            wal.append(&format!(r#"{{"i":{i}}}"#)).unwrap();
        }
        let records = wal.read_all().unwrap();
        assert_eq!(records.len(), 10);
    }

    #[test]
    fn concurrent_appends_publish_only_complete_frames() {
        let wal = Arc::new(tmp_wal());
        let mut workers = Vec::new();

        for worker in 0..8 {
            let shared = Arc::clone(&wal);
            workers.push(std::thread::spawn(move || {
                let mut writes = Vec::new();
                for record in 0..100 {
                    let payload = format!(r#"{{"worker":{worker},"record":{record}}}"#);
                    let offset = shared.append(&payload).unwrap();
                    writes.push((offset, FRAME_HEADER + payload.len(), payload));
                }
                writes
            }));
        }

        let mut writes = Vec::new();
        for worker in workers {
            writes.extend(worker.join().unwrap());
        }

        writes.sort_by_key(|(offset, _, _)| *offset);
        let mut expected_offset = 0u64;
        for (offset, frame_len, _) in &writes {
            assert_eq!(*offset, expected_offset);
            expected_offset += *frame_len as u64;
        }
        assert_eq!(wal.write_pos(), expected_offset);
        let records = wal.read_all().unwrap();
        assert_eq!(records.len(), 800);
        let expected: Vec<String> = writes.into_iter().map(|(_, _, payload)| payload).collect();
        assert_eq!(records, expected);
    }

    #[test]
    fn rejected_append_does_not_advance_write_position() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let wal = RustWal::open(&path, Some(FRAME_HEADER + 4)).unwrap();

        wal.append("1234").unwrap();
        let committed = wal.write_pos();
        assert!(wal.append("5").is_err());
        assert_eq!(wal.write_pos(), committed);
        assert_eq!(wal.read_all().unwrap(), vec!["1234".to_string()]);
    }

    #[test]
    fn recovery_terminator_prevents_corrupt_suffix_resurrection() {
        use std::io::{Seek, SeekFrom, Write};

        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let frame_len = FRAME_HEADER + 4;
        {
            let wal = RustWal::open(&path, Some(4096)).unwrap();
            wal.append("AAAA").unwrap();
            wal.append("BBBB").unwrap();
            wal.append("CCCC").unwrap();
        }

        let mut raw = OpenOptions::new().write(true).open(&path).unwrap();
        raw.seek(SeekFrom::Start((frame_len + FRAME_HEADER) as u64))
            .unwrap();
        raw.write_all(b"X").unwrap();
        raw.sync_all().unwrap();

        {
            let recovered = RustWal::open(&path, Some(4096)).unwrap();
            assert_eq!(recovered.read_all().unwrap(), vec!["AAAA".to_string()]);
            let replacement_offset = recovered.append("DDDD").unwrap();
            assert_eq!(replacement_offset, frame_len as u64);
            assert_eq!(
                recovered.read_all().unwrap(),
                vec!["AAAA".to_string(), "DDDD".to_string()]
            );
        }

        let reopened = RustWal::open(&path, Some(4096)).unwrap();
        assert_eq!(
            reopened.read_all().unwrap(),
            vec!["AAAA".to_string(), "DDDD".to_string()]
        );
    }

    #[test]
    fn reopening_with_a_smaller_capacity_does_not_truncate_the_segment() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        let expected: Vec<String> = (0..20).map(|i| format!("record-{i:04}")).collect();
        let written_bytes;
        {
            let wal = RustWal::open(&path, Some(64 * 1024)).unwrap();
            for record in &expected {
                wal.append(record).unwrap();
            }
            written_bytes = wal.write_pos();
            assert_eq!(wal.read_all().unwrap(), expected);
        }

        // A caller that asks for less than the segment already holds must not
        // be able to discard committed frames. `set_len` shrinks a file just as
        // `truncate(true)` would, so the requested capacity is a floor, not a
        // resize instruction.
        let reopened = RustWal::open(&path, Some(64)).unwrap();
        assert_eq!(reopened.read_all().unwrap(), expected);
        assert_eq!(reopened.write_pos(), written_bytes);
        assert_eq!(reopened.capacity(), 64 * 1024);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 64 * 1024);
    }

    #[test]
    fn reopening_with_a_larger_capacity_still_grows_the_segment() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        {
            let wal = RustWal::open(&path, Some(4096)).unwrap();
            wal.append("AAAA").unwrap();
        }

        let grown = RustWal::open(&path, Some(16 * 1024)).unwrap();
        assert_eq!(grown.capacity(), 16 * 1024);
        assert_eq!(grown.read_all().unwrap(), vec!["AAAA".to_string()]);
    }
}

/// Bit-level model checking of the WAL's frame-bounds arithmetic.
///
/// Kani explores every value of the inputs symbolically rather than sampling
/// them, so these are proofs over the whole `usize` domain — not tests. They
/// cover exactly what is provable here: the arithmetic that decides whether a
/// slice is in bounds, and the walk's termination.
///
/// They do **not** cover the mmap itself. Kani cannot model `mmap`, `flush` or
/// the filesystem, so nothing here establishes durability, crash consistency,
/// concurrent-append behaviour, or that `capacity` equals the mapped length.
/// Those remain the responsibility of `open`, the mutex, and the unit tests.
///
/// Run with `cargo kani --harness <name>` from `aegis_rust_v2/`.
#[cfg(kani)]
mod verification {
    use super::{header_range, payload_range, FRAME_HEADER};

    /// A header range, when returned, is inside `limit` and is exactly one
    /// header long. Nothing else can produce an in-bounds slice.
    #[kani::proof]
    fn header_range_is_in_bounds() {
        let pos: usize = kani::any();
        let limit: usize = kani::any();

        match header_range(pos, limit) {
            Some(range) => {
                assert!(range.start == pos);
                assert!(range.end <= limit);
                assert!(range.end - range.start == FRAME_HEADER);
            }
            None => {
                // Refusal is only ever for overflow or for not fitting.
                assert!(pos.checked_add(FRAME_HEADER).is_none_or(|end| end > limit));
            }
        }
    }

    /// A payload range, when returned, is inside `limit`, starts immediately
    /// after the header, and is exactly `payload_len` bytes long.
    #[kani::proof]
    fn payload_range_is_in_bounds() {
        let pos: usize = kani::any();
        let payload_len: usize = kani::any();
        let limit: usize = kani::any();

        if let Some(range) = payload_range(pos, payload_len, limit) {
            assert!(range.end <= limit);
            assert!(range.start >= pos);
            assert!(range.start - pos == FRAME_HEADER);
            assert!(range.end - range.start == payload_len);
            assert!(payload_len > 0);
        }
    }

    /// The recovery terminator is never mistaken for a frame: a zero-length
    /// payload is refused at every position and every limit.
    #[kani::proof]
    fn zero_length_payload_is_never_a_frame() {
        let pos: usize = kani::any();
        let limit: usize = kani::any();

        assert!(payload_range(pos, 0, limit).is_none());
    }

    /// A frame walk strictly advances. `pos = body.end` with `body.end >
    /// pos` is what makes both `read_all` and `scan_write_pos` terminate; a
    /// frame that did not advance the cursor would loop forever on a mapping
    /// an attacker controls the bytes of.
    #[kani::proof]
    fn a_frame_walk_strictly_advances() {
        let pos: usize = kani::any();
        let payload_len: usize = kani::any();
        let limit: usize = kani::any();

        if let Some(body) = payload_range(pos, payload_len, limit) {
            assert!(body.end > pos);
            assert!(body.end <= limit);
        }
    }

    /// Header and payload ranges never overlap, so a frame's length field can
    /// never be read out of its own payload.
    #[kani::proof]
    fn header_and_payload_do_not_overlap() {
        let pos: usize = kani::any();
        let payload_len: usize = kani::any();
        let limit: usize = kani::any();

        if let (Some(header), Some(body)) = (
            header_range(pos, limit),
            payload_range(pos, payload_len, limit),
        ) {
            assert!(header.end <= body.start);
        }
    }
}
