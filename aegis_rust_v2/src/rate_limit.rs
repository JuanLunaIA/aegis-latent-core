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

/// Millitokens earned over `elapsed_ms`: saturating for the same reason as
/// [`refill_target`] — a bucket idle for about 25 days at the largest `u32`
/// rate would overflow `i64` here.
#[inline]
fn refill_gain(elapsed_ms: i64, refill_per_ms: i64) -> i64 {
    elapsed_ms.saturating_mul(refill_per_ms)
}

/// Balance after admitting one request of `cost_milli`, or `None` to reject.
///
/// Factored out of the consume CAS loop so that the arithmetic the loop
/// commits is the arithmetic `mod verification` checks.
#[inline]
fn consume_target(cur: i64, cost_milli: i64) -> Option<i64> {
    if cur < cost_milli {
        None
    } else {
        Some(cur - cost_milli)
    }
}

/// `capacity` tokens in millitokens. `u32::MAX * 1000` is far inside `i64`.
#[inline]
fn capacity_milli(capacity: u32) -> i64 {
    (capacity as i64) * 1000
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
                let gain = refill_gain(elapsed, refill_per_ms);
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
            let Some(next) = consume_target(cur, cost_milli) else {
                return false;
            };
            match self.tokens_milli.compare_exchange_weak(
                cur,
                next,
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
            capacity_milli: capacity_milli(capacity),
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
    fn a_long_idle_bucket_refills_to_capacity_without_overflow() {
        // 2^31 + 1 ms (~24.9 days) at the largest rate is past i64::MAX.
        let gain = refill_gain(2_147_483_649, i64::from(u32::MAX));
        assert_eq!(gain, i64::MAX);
        let cap = capacity_milli(u32::MAX);
        assert_eq!(refill_target(0, gain, cap), cap);
    }

    #[test]
    fn consume_rejects_below_cost_and_debits_at_or_above_it() {
        assert_eq!(consume_target(999, 1_000), None);
        assert_eq!(consume_target(1_000, 1_000), Some(0));
        assert_eq!(consume_target(5_500, 1_000), Some(4_500));
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

/// Kani proofs over the limiter's arithmetic, the same functions the CAS loops
/// call. `specs/aegis_invariants.smt2` states these properties over the
/// mathematical integers; these harnesses check them bit-precisely in the code
/// itself, where an overflow is a verification failure (Kani checks every
/// arithmetic operation). Scope: arithmetic only. No atomics, memory ordering,
/// clock or `DashMap` is modelled.
#[cfg(kani)]
mod verification {
    use super::{capacity_milli, consume_target, refill_gain, refill_target};

    /// A balance `0 <= cur <= capacity_milli(capacity)` for a symbolic `u32`
    /// capacity: the invariant both CAS steps must preserve.
    fn bucket() -> (i64, i64) {
        let capacity: u32 = kani::any();
        let cap = capacity_milli(capacity);
        let cur: i64 = kani::any();
        kani::assume(0 <= cur && cur <= cap);
        (cur, cap)
    }

    /// The constructor never overflows and a fresh bucket, which starts full,
    /// satisfies the invariant.
    #[kani::proof]
    fn capacity_milli_is_exact_and_non_negative() {
        let capacity: u32 = kani::any();
        let cap = capacity_milli(capacity);
        assert!(cap >= 0);
        assert!(cap as i128 == capacity as i128 * 1000);
    }

    /// The refill CAS preserves `0 <= tokens <= capacity` for every
    /// non-negative gain, which `refill_gain_is_positive` shows is every gain
    /// `try_consume` can compute.
    #[kani::proof]
    fn refill_preserves_the_bounds() {
        let (cur, cap) = bucket();
        let gain: i64 = kani::any();
        kani::assume(gain >= 0);
        let next = refill_target(cur, gain, cap);
        assert!(0 <= next && next <= cap);
        assert!(next >= cur);
    }

    /// Saturation only prevents an overflow; it never loses or invents a
    /// token. For any non-negative gain the refill result equals
    /// `min(cur + gain, capacity)` over the integers, the sum taken in `i128`.
    /// A saturated gain is `i64::MAX`, which is at least `capacity`, so this
    /// also covers the idle-bucket case: the exact result is the capacity.
    /// The gain is symbolic here, and `refill_gain_is_positive` covers the
    /// multiplication that produces it; one harness over both did not finish
    /// in 30 minutes of CBMC time.
    #[kani::proof]
    fn refill_equals_the_unbounded_result() {
        let (cur, cap) = bucket();
        let gain: i64 = kani::any();
        kani::assume(gain >= 0);
        let next = refill_target(cur, gain, cap);
        let exact = (cur as i128 + gain as i128).min(cap as i128);
        assert!(next as i128 == exact);
    }

    /// For every elapsed time and rate that pass `try_consume`'s guard the
    /// gain is positive and never less than the elapsed time, so a refill
    /// never debits a bucket and never stalls one. That the gain is the exact
    /// product below `i64::MAX` is `saturating_mul`'s documented contract,
    /// checked at the overflow boundary by the unit test
    /// `a_long_idle_bucket_refills_to_capacity_without_overflow`; a harness
    /// comparing it against a second 64-bit multiplication did not finish in
    /// 10 minutes of CBMC time.
    #[kani::proof]
    fn refill_gain_is_positive() {
        let elapsed: i64 = kani::any();
        let rate: u32 = kani::any();
        let refill_per_ms = rate as i64;
        kani::assume(elapsed > 0 && refill_per_ms > 0);
        let gain = refill_gain(elapsed, refill_per_ms);
        assert!(gain >= elapsed);
    }

    /// The consume CAS preserves the invariant, debits exactly the cost when
    /// it admits, and rejects exactly when the balance is below the cost.
    #[kani::proof]
    fn consume_preserves_the_bounds() {
        let (cur, cap) = bucket();
        let cost: i64 = kani::any();
        kani::assume(cost >= 0);
        match consume_target(cur, cost) {
            Some(next) => {
                assert!(cur >= cost);
                assert!(next == cur - cost);
                assert!(0 <= next && next <= cap);
            }
            None => assert!(cur < cost),
        }
    }
}
