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
//!   - `flush_range` (msync MS_SYNC) after each frame → crash-consistent.
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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// Default segment size: 256 MiB — holds ~500k typical audit nodes.
const DEFAULT_SEGMENT_BYTES: usize = 256 * 1024 * 1024;

/// [crc32: 4 B][len: 4 B]
const FRAME_HEADER: usize = 8;

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

        file.set_len(capacity as u64).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("RustWal resize: {e}"))
        })?;

        // SAFETY: we own the file and no other process writes to the region.
        let mmap = unsafe { MmapMut::map_mut(&file) }.map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("RustWal mmap: {e}"))
        })?;

        let write_pos = scan_write_pos(&mmap, capacity);

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

        // Persist to storage — blocks until OS confirms durability. write_pos
        // remains unchanged on failure, so readers never cross this frame.
        if let Err(e) = mmap.flush_range(offset, frame) {
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

        while pos + FRAME_HEADER <= limit {
            let stored_crc = u32::from_le_bytes(mmap[pos..pos + 4].try_into().unwrap_or([0; 4]));
            let payload_len =
                u32::from_le_bytes(mmap[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;

            if payload_len == 0 || pos + FRAME_HEADER + payload_len > limit {
                break;
            }

            let payload = &mmap[pos + FRAME_HEADER..pos + FRAME_HEADER + payload_len];
            let mut crc = Crc32Hasher::new();
            crc.update(payload);
            if crc.finalize() != stored_crc {
                // First CRC mismatch = torn write or end of valid log; stop here.
                break;
            }
            if let Ok(s) = std::str::from_utf8(payload) {
                records.push(s.to_string());
            }

            pos += FRAME_HEADER + payload_len;
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
    while pos + FRAME_HEADER <= capacity {
        let stored_crc = u32::from_le_bytes(mmap[pos..pos + 4].try_into().unwrap_or([0; 4]));
        let len = u32::from_le_bytes(mmap[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
        if len == 0 {
            break;
        }
        let Some(end) = pos
            .checked_add(FRAME_HEADER)
            .and_then(|payload_start| payload_start.checked_add(len))
        else {
            break;
        };
        if end > capacity {
            break;
        }
        let payload = &mmap[pos + FRAME_HEADER..end];
        let mut crc = Crc32Hasher::new();
        crc.update(payload);
        if crc.finalize() != stored_crc || std::str::from_utf8(payload).is_err() {
            break;
        }
        pos = end;
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
                for record in 0..100 {
                    shared
                        .append(&format!(r#"{{"worker":{worker},"record":{record}}}"#))
                        .unwrap();
                }
            }));
        }

        for worker in workers {
            worker.join().unwrap();
        }

        let records = wal.read_all().unwrap();
        assert_eq!(records.len(), 800);
        assert!(records
            .iter()
            .all(|record| record.starts_with('{') && record.ends_with('}')));
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
}
