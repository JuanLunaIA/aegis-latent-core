// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Lock-free MPSC ring buffer for audit events.
//!
//! Request handlers enqueue JSON-serialised audit events in <1 µs (no syscall,
//! no lock on the hot path). A background drainer thread (Python asyncio task
//! or Rust thread) batches WAL writes, completely decoupling signing/WAL
//! latency from request latency.
//!
//! Backed by `crossbeam_queue::ArrayQueue` — a bounded MPMC queue implemented
//! with a Michael-Scott queue variant optimised for bounded capacity.
//!
//! Drop policy: when full, the oldest event is dropped and `drop_count` is
//! incremented. A Prometheus counter (`aegis_audit_drops_total`) should alert
//! operators when the drainer falls behind.

use crossbeam_queue::ArrayQueue;
use pyo3::prelude::*;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Default ring buffer capacity: 64k events (~50 MB at ~800 B/event).
const DEFAULT_CAPACITY: usize = 65_536;

/// Lock-free MPSC audit ring buffer.
#[pyclass]
pub struct AuditRingBuffer {
    queue: Arc<ArrayQueue<String>>,
    enqueue_count: Arc<AtomicU64>,
    drop_count: Arc<AtomicU64>,
    capacity: usize,
}

#[pymethods]
impl AuditRingBuffer {
    #[new]
    #[pyo3(signature = (capacity = DEFAULT_CAPACITY))]
    pub fn new(capacity: usize) -> Self {
        AuditRingBuffer {
            queue: Arc::new(ArrayQueue::new(capacity)),
            enqueue_count: Arc::new(AtomicU64::new(0)),
            drop_count: Arc::new(AtomicU64::new(0)),
            capacity,
        }
    }

    /// Non-blocking enqueue. Returns `true` on success, `false` on overflow.
    ///
    /// On overflow the **oldest** event is evicted to make room for the new one,
    /// matching ring-buffer semantics (always retain the most recent N events).
    /// `drop_count` is incremented and `false` is returned to signal the eviction.
    pub fn enqueue(&self, json: &str) -> bool {
        // Fast path: queue has space.
        if self.queue.push(json.to_string()).is_ok() {
            self.enqueue_count.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        // Slow path: queue full — evict oldest to make room.
        let _ = self.queue.pop(); // may be a no-op if another thread drained first
        self.drop_count.fetch_add(1, Ordering::Relaxed);
        // Best-effort re-push; may still fail under extreme concurrent producer load.
        let _ = self.queue.push(json.to_string());
        self.enqueue_count.fetch_add(1, Ordering::Relaxed);
        false // overflow occurred (an event was dropped)
    }

    /// Non-blocking drain: returns up to `max_items` events in FIFO order.
    pub fn drain(&self, max_items: usize) -> Vec<String> {
        let mut batch = Vec::with_capacity(max_items.min(512));
        for _ in 0..max_items {
            match self.queue.pop() {
                Some(item) => batch.push(item),
                None => break,
            }
        }
        batch
    }

    /// Drain all available events (used on shutdown flush).
    pub fn drain_all(&self) -> Vec<String> {
        let cap = self.queue.len();
        self.drain(cap.max(1))
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Fill ratio 0.0–1.0. Trigger back-pressure when > 0.8.
    pub fn fill_ratio(&self) -> f64 {
        self.queue.len() as f64 / self.capacity as f64
    }

    pub fn enqueue_count(&self) -> u64 {
        self.enqueue_count.load(Ordering::Relaxed)
    }

    pub fn drop_count(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
    }

    /// Reset counters (e.g. after metrics scrape).
    pub fn reset_counters(&self) {
        self.enqueue_count.store(0, Ordering::Relaxed);
        self.drop_count.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_drain_roundtrip() {
        let buf = AuditRingBuffer::new(8);
        assert!(buf.enqueue(r#"{"id":"1"}"#));
        assert!(buf.enqueue(r#"{"id":"2"}"#));
        let drained = buf.drain(10);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0], r#"{"id":"1"}"#);
    }

    #[test]
    fn overflow_drops_oldest_keeps_newest() {
        let buf = AuditRingBuffer::new(2);
        buf.enqueue("a");
        buf.enqueue("b");
        // Overflow: "a" (oldest) is evicted, "c" (newest) is enqueued.
        let signalled_overflow = buf.enqueue("c");
        assert!(!signalled_overflow, "overflow must return false");
        assert_eq!(buf.drop_count(), 1, "one event dropped");
        // Queue should contain the two most-recent events in FIFO order.
        let remaining = buf.drain(10);
        assert_eq!(remaining, vec!["b", "c"]);
    }

    #[test]
    fn fill_ratio() {
        let buf = AuditRingBuffer::new(4);
        buf.enqueue("x");
        buf.enqueue("x");
        assert!((buf.fill_ratio() - 0.5).abs() < 1e-9);
    }
}
