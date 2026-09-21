// Copyright (c) 2026 Juan Luna. All rights reserved.
// Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
// Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

//! Lock-free token-bucket rate limiter.
//!
//! Architecture:
//!   - Per-tenant `BucketState` held in a `DashMap` (sharded RwLock).
//!   - Tokens represented as millitoken integers to avoid floating-point atomics.
//!   - Refill is claimed via CAS on `last_refill_us` — exactly one thread refills
//!     per epoch, all others proceed with the (slightly stale) token count.
//!   - Consume is a CAS spin-loop: constant-time under low contention,
//!     O(contenders) worst-case with fast backoff due to AtomicI64.
//!
//! Latency: **not stated here.** The figure that used to sit in this line
//! (`~50 ns per check on x86-64` versus `~5 µs`) has no measurement record in
//! this repository (AUD-24); the design facts above are what is verifiable from
//! the source. See `docs/benchmarks/BENCHMARK_METHOD.md` for where a number
//! belongs and what must accompany it.

use dashmap::DashMap;
use pyo3::prelude::*;
use std::sync::{
    atomic::{AtomicI64, AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Refill target for a bucket: `cur + gain`, clamped to the capacity.
///
/// The addition is saturating on purpose. `gain` is `elapsed_ms ×
/// refill_per_ms` — both bounded but unbounded in product — so a bucket left
/// untouched long enough (weeks at a high refill rate) could otherwise overflow
/// `i64`; with the release profile's `overflow-checks = true` that panics, and
/// `panic = "abort"` turns it into a process abort (AUD-05 / AF-041).
#[inline]
fn refill_target(cur: i64, gain: i64, capacity_milli: i64) -> i64 {
    cur.saturating_add(gain).min(capacity_milli)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct BucketState {
    /// Token count × 1000 (millitoken units) to avoid floats in atomics.
    tokens_milli: AtomicI64,
    /// Last refill time in milliseconds.
    last_refill_ms: AtomicU64,
}

impl BucketState {
    fn new(capacity_milli: i64) -> Self {
        Self {
            tokens_milli: AtomicI64::new(capacity_milli),
            last_refill_ms: AtomicU64::new(now_millis()),
        }
    }

    /// Try to consume `cost_milli` millitokens.
    ///
    /// `refill_per_ms`: millitokens added per millisecond.
    /// Conversion: tokens/sec = millitokens/ms (1 token/sec × 1000 milli/token ÷ 1000 ms/sec).
    /// So `refill_per_ms = refill_rate` (tokens/sec) — no scaling required.
    fn try_consume(&self, capacity_milli: i64, refill_per_ms: i64, cost_milli: i64) -> bool {
        // ── Refill phase ──────────────────────────────────────────────────
        let now_ms = now_millis();
        let last = self.last_refill_ms.load(Ordering::Relaxed);
        let elapsed = now_ms.saturating_sub(last) as i64;

        if elapsed > 0 && refill_per_ms > 0 {
            // CAS: only one winner refills per time period.
            if self
                .last_refill_ms
                .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let gain = elapsed.saturating_mul(refill_per_ms);
                // Add gain and clamp to capacity.
                let mut cur = self.tokens_milli.load(Ordering::Acquire);
                loop {
                    let next = refill_target(cur, gain, capacity_milli);
                    match self.tokens_milli.compare_exchange_weak(
                        cur,
                        next,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => cur = actual,
                    }
                }
            }
        }

        // ── Consume phase ─────────────────────────────────────────────────
        let mut cur = self.tokens_milli.load(Ordering::Acquire);
        loop {
            if cur < cost_milli {
                return false;
            }
            match self.tokens_milli.compare_exchange_weak(
                cur,
                cur - cost_milli,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Lock-free per-tenant token-bucket rate limiter.
///
/// Exposed to Python as a sync call (releases GIL via `py.allow_threads()`
/// in the caller if needed — but the check is so fast that blocking is fine).
#[pyclass]
pub struct RustRateLimiter {
    buckets: Arc<DashMap<String, Arc<BucketState>>>,
    capacity_milli: i64,
    refill_per_ms: i64,
}

#[pymethods]
impl RustRateLimiter {
    /// `capacity`: burst capacity in tokens.
    /// `refill_rate`: sustained rate in tokens/second.
    #[new]
    #[pyo3(signature = (capacity, refill_rate))]
    pub fn new(capacity: u32, refill_rate: u32) -> Self {
        RustRateLimiter {
            buckets: Arc::new(DashMap::new()),
            capacity_milli: (capacity as i64) * 1000,
            // tokens/sec = millitokens/ms (identities cancel: ×1000 milli/token ÷ 1000 ms/sec).
            // Direct assignment preserves correct refill speed for rates as low as 1 token/sec.
            refill_per_ms: (refill_rate as i64).max(0),
        }
    }

    /// Attempt to consume one token for `key`.
    /// Returns `true` if allowed, `false` if rate-limited.
    pub fn check_and_consume(&self, key: &str) -> bool {
        let bucket = {
            self.buckets
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(BucketState::new(self.capacity_milli)))
                .clone()
        };
        bucket.try_consume(self.capacity_milli, self.refill_per_ms, 1000)
    }

    /// Evict buckets inactive for more than `max_age_secs` seconds.
    /// Call periodically (e.g. every 60 s) to prevent unbounded map growth.
    pub fn evict_stale(&self, max_age_secs: u64) -> usize {
        // Saturating: `max_age_secs` is caller-supplied, and the product used
        // to be evaluated unchecked — `evict_stale(2**63)` panicked here and
        // aborted the process (AUD-05 / AF-041).
        let cutoff = now_millis().saturating_sub(max_age_secs.saturating_mul(1_000));
        let before = self.buckets.len();
        self.buckets
            .retain(|_, b| b.last_refill_ms.load(Ordering::Relaxed) > cutoff);
        before.saturating_sub(self.buckets.len())
    }

    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // AUD-05 / AF-041: the refill sum and the eviction cutoff were evaluated
    // unchecked, and both operands are reachable from caller-supplied values.
    #[test]
    fn refill_target_saturates_instead_of_overflowing() {
        assert_eq!(refill_target(i64::MAX, i64::MAX, 1_000), 1_000);
        assert_eq!(refill_target(5, 7, 1_000), 12);
    }

    #[test]
    fn evict_stale_tolerates_an_absurd_max_age() {
        let rl = RustRateLimiter::new(5, 1);
        assert!(rl.check_and_consume("tenant-a"));
        // u64::MAX seconds used to overflow the seconds→millis conversion:
        // overflow-checks = true panics, panic = "abort" killed the process.
        rl.evict_stale(u64::MAX);
    }

    #[test]
    fn allows_up_to_burst() {
        let rl = RustRateLimiter::new(5, 1);
        for _ in 0..5 {
            assert!(rl.check_and_consume("tenant-a"));
        }
        // 6th should be rejected
        assert!(!rl.check_and_consume("tenant-a"));
    }

    #[test]
    fn tenants_isolated() {
        let rl = RustRateLimiter::new(2, 1);
        assert!(rl.check_and_consume("a"));
        assert!(rl.check_and_consume("a"));
        assert!(!rl.check_and_consume("a"));
        // tenant b unaffected
        assert!(rl.check_and_consume("b"));
    }
}
