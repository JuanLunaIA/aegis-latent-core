// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Lock-free MPSC ring buffer for audit events.
//!
//! Request handlers enqueue JSON-serialised audit events without a syscall and
//! without a lock on the hot path (no timing figure is stated here: the `<1 µs`
//! that used to sit in this sentence has no measurement record — AUD-24). A
//! background drainer thread (Python asyncio task or Rust thread) batches WAL
//! writes, decoupling signing/WAL latency from request latency.
//!
//! Backed by `crossbeam_queue::ArrayQueue` — a bounded MPMC queue implemented
//! with a Michael-Scott queue variant optimised for bounded capacity.
//!
//! Drop policy: when full, the **oldest** event is replaced by the incoming one
//! (`ArrayQueue::force_push` does the replacement atomically) and `drop_count`
//! is incremented. A Prometheus counter (`aegis_audit_drops_total`) should alert
//! operators when the drainer falls behind. Until AUD-24 this was a
//! `pop`-then-`push` pair that evicted whichever element was at the head at that
//! instant — not necessarily the oldest — and could lose the *incoming* event
//! while reporting only that "an event was dropped".

use crossbeam_queue::ArrayQueue;
use pyo3::prelude::*;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Default ring buffer capacity: 64k events (~50 MB at ~800 B/event).
const DEFAULT_CAPACITY: usize = 65_536;

/// Hard ceiling for a caller-supplied ring capacity.
///
/// The default above is only a default: the value arrives from Python (config
/// or a caller) and used to reach `ArrayQueue::new` unvalidated, so `0` panicked
/// inside crossbeam and a huge value died in the allocator — both abort the
/// process under the release profile's `panic = "abort"` (AUD-05 / AF-014).
/// 64 × the default keeps the worst case a bounded allocation.
const MAX_CAPACITY: usize = 1 << 22;

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
    pub fn new(capacity: usize) -> PyResult<Self> {
        if capacity == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "AuditRingBuffer capacity must be at least 1",
            ));
        }
        if capacity > MAX_CAPACITY {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "AuditRingBuffer capacity {capacity} exceeds the supported ceiling {MAX_CAPACITY}"
            )));
        }
        Ok(AuditRingBuffer {
            queue: Arc::new(ArrayQueue::new(capacity)),
            enqueue_count: Arc::new(AtomicU64::new(0)),
            drop_count: Arc::new(AtomicU64::new(0)),
            capacity,
        })
    }

    /// Non-blocking enqueue. Returns `true` on success, `false` on eviction.
    ///
    /// On overflow the **oldest** event is evicted to make room for the new one,
    /// matching ring-buffer semantics (always retain the most recent N events).
    /// `drop_count` is incremented and `false` is returned to signal the
    /// eviction. The replacement is the queue's own atomic `force_push`, so the
    /// incoming event is always accepted and exactly one older event is lost
    /// (AUD-24 — the previous `pop`-then-`push` pair could lose the incoming
    /// event instead, and could evict a non-oldest head under concurrency).
    pub fn enqueue(&self, json: &str) -> bool {
        // Fast path: queue has space.
        if self.queue.push(json.to_string()).is_ok() {
            self.enqueue_count.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        // Slow path: queue full — replace the oldest element in one step.
        let _ = self.queue.force_push(json.to_string());
        self.drop_count.fetch_add(1, Ordering::Relaxed);
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

    // AUD-05 / AF-014: `capacity` arrives from Python (config or a caller) and
    // used to reach `ArrayQueue::new` unvalidated — 0 panicked inside
    // crossbeam and a huge value died in the allocator, both aborting the
    // process under the release profile's `panic = "abort"`.
    #[test]
    fn zero_capacity_is_rejected() {
        pyo3::Python::initialize();
        let err = match AuditRingBuffer::new(0) {
            Ok(_) => panic!("zero capacity was accepted"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("at least 1"), "{err}");
    }

    #[test]
    fn capacity_above_the_ceiling_is_rejected() {
        pyo3::Python::initialize();
        let err = match AuditRingBuffer::new(MAX_CAPACITY + 1) {
            Ok(_) => panic!("capacity above the ceiling was accepted"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("ceiling"), "{err}");
    }

    #[test]
    fn capacity_within_range_is_accepted() {
        assert!(AuditRingBuffer::new(16).is_ok());
    }

    // AUD-24: the documented contract is "keep the most recent N, drop the
    // oldest", and it is now the code's behaviour — one atomic `force_push`
    // instead of a `pop`-then-`push` pair that could lose the *incoming* event.
    #[test]
    fn overflow_evicts_the_oldest_and_keeps_the_newest() {
        let buf = AuditRingBuffer::new(3).unwrap();
        for id in 1..=3 {
            assert!(buf.enqueue(&format!(r#"{{"id":{id}}}"#)));
        }
        assert_eq!(buf.len(), 3);

        // Full: the incoming event is accepted, the oldest is evicted, and the
        // caller is told an event was dropped.
        assert!(!buf.enqueue(r#"{"id":4}"#));
        assert_eq!(buf.len(), 3);
        let drained = buf.drain_all();
        assert_eq!(
            drained,
            vec![r#"{"id":2}"#, r#"{"id":3}"#, r#"{"id":4}"#],
            "the newest event must survive and the oldest must be the one evicted"
        );
        assert_eq!(buf.drop_count(), 1);
        // Four events were accepted into the buffer (three + the replacement),
        // one of which did not survive the eviction.
        assert_eq!(buf.enqueue_count(), 4);
    }

    #[test]
    fn enqueue_drain_roundtrip() {
        let buf = AuditRingBuffer::new(8).unwrap();
        assert!(buf.enqueue(r#"{"id":"1"}"#));
        assert!(buf.enqueue(r#"{"id":"2"}"#));
        let drained = buf.drain(10);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0], r#"{"id":"1"}"#);
    }

    #[test]
    fn overflow_drops_oldest_keeps_newest() {
        let buf = AuditRingBuffer::new(2).unwrap();
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
        let buf = AuditRingBuffer::new(4).unwrap();
        buf.enqueue("x");
        buf.enqueue("x");
        assert!((buf.fill_ratio() - 0.5).abs() < 1e-9);
    }
}
