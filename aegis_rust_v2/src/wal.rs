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
//!   - Single writer: `open` takes an exclusive advisory lock on the segment
//!     file, so a second handle is refused with a clear error instead of
//!     rescanning and overwriting already-committed frames (AUD-04). The lock
//!     is released when the handle drops or the process exits.
//!
//! Performance is workload- and filesystem-dependent; use the repository's
//! benchmark harness before making latency or throughput claims.

use crc32fast::Hasher as Crc32Hasher;
use memmap2::MmapMut;
use parking_lot::Mutex;
use pyo3::prelude::*;
use std::{
    fs::{File, OpenOptions, TryLockError},
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

/// Ceiling on a requested segment size: 2 GiB.
///
/// `capacity_bytes` sizes both the file (`set_len`) and the mapping, so an
/// unbounded value is a deferred failure rather than a rejected input:
/// `RustWal::open(path, 1 << 40)` was accepted, extended the file to a sparse
/// 1 TiB and only failed later — as address-space and disk commitment — with no
/// error at open (AUD-24 / AF-089). The ceiling is chosen as the largest
/// segment a 32-bit target in this crate's wheel matrix
/// (`armv7-unknown-linux-musleabihf`) can map at all, so one configuration is
/// valid on every wheel, and it is 8× the 256 MiB default.
///
/// Enforced on the *request*, before the file is created or resized. A segment
/// that already exists above the ceiling still opens read/write: refusing it
/// would lose committed frames to a limit that arrived after the fact.
const MAX_SEGMENT_BYTES: usize = 1 << 31;

/// Byte range of the frame header at `pos`, if the whole header fits in `limit`.
///
/// Frame-bounds arithmetic in the non-test code of this module goes through
/// this function, [`header_end`] and [`payload_range`], not through open-coded
/// `pos + FRAME_HEADER` adds, so
/// the arithmetic that decides whether a slice or a flush range is in bounds
/// exists in exactly one place and can be model-checked. The three helpers
/// cover the three shapes the module needs: a header *range* for a walk (this
/// function), a header *end offset* for a write (`header_end`, because a writer
/// slices `pos..end` and then flushes from `pos`), and a payload range for a
/// frame body. See the `kani` module at the bottom of this file; `CLM-054`
/// carries the scope of what is model-checked, which is `header_range` and
/// `payload_range` (everything here that decides a bound).
#[inline]
fn header_range(pos: usize, limit: usize) -> Option<Range<usize>> {
    let end = pos.checked_add(FRAME_HEADER)?;
    if end > limit {
        return None;
    }
    Some(pos..end)
}

/// End offset of the header written at `pos`, if the whole header fits in
/// `limit` — the same arithmetic as [`header_range`], in the shape a writer
/// needs. Kept as a wrapper rather than a second `checked_add` so the addition
/// still exists in exactly one place.
#[inline]
fn header_end(pos: usize, limit: usize) -> Option<usize> {
    header_range(pos, limit).map(|range| range.end)
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
    /// Exclusive advisory lock over the segment file, held for the life of the
    /// handle. This is what enforces the single-writer invariant the `SAFETY`
    /// note on the mmap below used to only assert: without it a second handle
    /// rescanned the segment, computed the same offsets, and overwrote
    /// committed frames through its own MAP_SHARED mapping (AUD-04). The lock
    /// is released when this field drops (handle drop, GC, process exit).
    _writer_lock: File,
}

// `WalInner`'s `Send` + `Sync` are derived by the compiler from its fields:
// memmap2 documents `MmapMut` as both, `Mutex<T: Send>` is `Sync`, and
// `AtomicU64`, `usize` and `File` are both. They were declared by hand until
// AUD-24 / AF-091, which suppressed the check that a future field of a type
// like `Rc` or a raw pointer would otherwise trip — the hand-written claim
// would have kept compiling while becoming false.

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
        // AUD-24 / AF-089: refuse an over-ceiling *request* before the file is
        // touched. This runs ahead of `OpenOptions::open`, so a refused call
        // creates nothing on disk.
        if capacity > MAX_SEGMENT_BYTES {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "RustWal capacity_bytes {capacity} exceeds the supported ceiling \
                 {MAX_SEGMENT_BYTES}; pass a smaller segment or rotate instead"
            )));
        }

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

        // Single-writer guard (AUD-04).  ``try_lock`` takes the same POSIX
        // ``flock`` the Python WAL already takes on its own descriptor
        // (aegis/core/crypto_audit.py::_lock_wal_fd), fails immediately instead
        // of waiting, and is released when this handle drops or the process
        // exits.  Taken before any resize or mapping so a losing handle cannot
        // touch the segment at all.  Advisory on POSIX, so a reader that never
        // writes is not refused; on Windows ``try_lock`` maps to LockFileEx
        // over the whole file, which is mandatory — the Python WAL routes
        // around that with a lock region past end-of-file, and the Rust
        // segment is only opened by the gateway on its Linux deployment.
        // Requires Rust >= 1.89 for ``std::fs::File::try_lock``.
        file.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "RustWal single-writer invariant: another handle already holds \"{path}\" \
                 (advisory lock busy); close that handle before opening a second one on the \
                 same segment"
            )),
            TryLockError::Error(io) => PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                "RustWal lock failed (path={path}): {io}"
            )),
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

        // SAFETY: exclusivity over this region is enforced by the writer lock
        // taken above, so no second handle can map and write it (AUD-04).
        // `mapping a file` is the one operation in this module that is unsafe by
        // nature; every other unsafe construct the crate used to carry is gone,
        // so the crate-level `unsafe_code = "deny"` reaches this attribute.
        #[allow(unsafe_code)]
        let mut mmap = unsafe { MmapMut::map_mut(&file) }.map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("RustWal mmap: {e}"))
        })?;

        let write_pos = scan_write_pos(&mmap, capacity);
        if let Some(header_stop) = header_end(write_pos, capacity) {
            mmap[write_pos..header_stop].fill(0);
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
                _writer_lock: file,
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
        let flush_end = match header_end(end, self.inner.capacity) {
            Some(header_stop) => {
                mmap[end..header_stop].fill(0);
                header_stop
            }
            None => end,
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

    /// A temp path that survives handle drops: the file is leaked on purpose
    /// so the same path can be reopened (the lock test depends on that).
    fn tmp_wal_path() -> String {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap().to_string();
        std::mem::forget(f);
        path
    }

    fn tmp_wal() -> RustWal {
        RustWal::open(&tmp_wal_path(), Some(1024 * 1024)).unwrap()
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
    fn second_handle_is_refused_while_a_writer_holds_the_segment() {
        // The refusal path builds a ``PyErr``, and this crate does not enable
        // pyo3's ``auto-initialize`` feature, so the interpreter must be up.
        pyo3::Python::initialize();
        let path = tmp_wal_path();
        let first = RustWal::open(&path, Some(1024 * 1024)).unwrap();

        // A second handle on the same segment must fail closed instead of
        // rescanning and overwriting the first handle's committed frames.
        let second = RustWal::open(&path, Some(1024 * 1024));
        match second {
            Err(e) => {
                let message = e.to_string();
                assert!(
                    message.contains("single-writer"),
                    "unexpected error message: {message}"
                );
            }
            Ok(_) => panic!("a second writer handle was allowed on the same segment"),
        }

        // Dropping the first handle releases the lock.
        drop(first);
        let third = RustWal::open(&path, Some(1024 * 1024));
        assert!(third.is_ok(), "lock was not released on drop: {:?}", third.err());
    }

    #[test]
    fn reopen_after_drop_preserves_committed_frames() {
        let path = tmp_wal_path();
        {
            let first = RustWal::open(&path, Some(1024 * 1024)).unwrap();
            first.append(r#"{"seq":1}"#).unwrap();
            first.append(r#"{"seq":2}"#).unwrap();
        }
        let second = RustWal::open(&path, Some(1024 * 1024)).unwrap();
        let records = second.read_all().unwrap();
        assert_eq!(records, vec![r#"{"seq":1}"#.to_string(), r#"{"seq":2}"#.to_string()]);
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

    // ── AUD-24 / AF-089, AF-090, AF-091 ──────────────────────────────────────

    /// The writer-facing helper is the walk helper, so a bound it reports is
    /// the bound `header_range` proved — and nothing wraps on the way.
    #[test]
    fn header_end_is_bounded_and_never_wraps() {
        assert_eq!(header_end(0, FRAME_HEADER), Some(FRAME_HEADER));
        assert_eq!(header_end(0, FRAME_HEADER - 1), None);
        // Exact fit at the top of the address space, then one past it.
        assert_eq!(header_end(usize::MAX - FRAME_HEADER, usize::MAX), Some(usize::MAX));
        assert_eq!(header_end(usize::MAX, usize::MAX), None);
        assert_eq!(header_end(usize::MAX - FRAME_HEADER + 1, usize::MAX), None);
    }

    /// The measured finding: `1 << 40` was accepted, `set_len` extended the file
    /// to a sparse 1 TiB, and the failure surfaced later as address-space and
    /// disk commitment instead of as an error at open.
    #[test]
    fn segment_ceiling_is_enforced_before_the_file_is_created() {
        // The refusal path builds a ``PyErr``; see the lock test above.
        pyo3::Python::initialize();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("over-ceiling.rwal");
        let path_str = path.to_str().unwrap();

        for requested in [MAX_SEGMENT_BYTES + 1, 1 << 40] {
            let refused = RustWal::open(path_str, Some(requested));
            assert!(
                refused.is_err(),
                "capacity_bytes {requested} is above the ceiling and must be refused"
            );
            assert!(
                !path.exists(),
                "the ceiling must be checked before the file is created or resized"
            );
        }

        // The ceiling is a bound on the request, not on the default: a normal
        // open still works and still creates the segment.
        let ok = RustWal::open(path_str, Some(1024 * 1024));
        assert!(ok.is_ok(), "a request under the ceiling must still open");
        assert!(path.exists());
    }

    /// AF-091 removed the hand-written `unsafe impl Send/Sync` for `WalInner`.
    /// This asserts the property those impls claimed, now derived by the
    /// compiler from the fields: if a future edit adds a field that is not
    /// `Send + Sync`, this stops compiling instead of quietly staying true.
    #[test]
    fn wal_inner_auto_traits_come_from_the_compiler() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WalInner>();
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

    /// The writer-facing helper is the same arithmetic as `header_range`, so
    /// it inherits that proof; this harness states what the writer relies on.
    #[kani::proof]
    fn header_end_is_the_same_bound() {
        let pos: usize = kani::any();
        let limit: usize = kani::any();

        if let Some(end) = super::header_end(pos, limit) {
            assert!(end <= limit);
            assert!(end.checked_sub(pos) == Some(FRAME_HEADER));
        }
    }

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
