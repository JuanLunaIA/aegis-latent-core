; Copyright (c) 2026 Juan Luna. All rights reserved.
; Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
; Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
;
; Token-bucket arithmetic of aegis_rust_v2/src/rate_limit.rs.
;
; The previous version of this file asserted a predicate together with its
; negation, so it returned `unsat` whatever the arithmetic was: replacing the
; refill with a subtraction still produced `unsat`. This version states the
; implementation's own operations over the mathematical integers, which is how
; Rust defines them: `saturating_mul` and `saturating_add` are the exact result
; clamped to i64, `min` is min, a `u64 as i64` cast is the exact value reduced
; modulo 2^64 into the signed range, and a plain `-` or `*` must stay inside the
; i64 range because the release profile sets `overflow-checks = true` (an
; overflow panics, and `panic = "abort"` ends the process).
;
; The limiter changes its balance in exactly two atomic steps, each a
; compare-and-swap: the refill CAS writes `refill_target(cur, gain, cap)` and
; the consume CAS writes `cur - cost` only when `cur >= cost`. The balance
; starts at `capacity_milli`. If the start satisfies 0 <= tokens <= capacity
; and each step preserves it, every interleaving does, which is why the
; obligations below are stated per step rather than per request.
;
; Scope: arithmetic only. No atomics, memory ordering, clock or DashMap is
; modelled. `cargo kani` checks `refill_target` and the consume step
; bit-precisely in the Rust source itself (rate_limit.rs, mod verification).
;
; Every check is labelled with its expected result. The gate compares Z3's whole
; output with the line below, so a `sat` where `unsat` is expected (a broken
; property) and an `unsat` where `sat` is expected (a vacuous model) both fail.
;
; expect: sat unsat unsat unsat unsat unsat sat sat
(set-logic QF_NIA)

(define-fun I64_MIN () Int (- 9223372036854775808))
(define-fun I64_MAX () Int 9223372036854775807)
(define-fun U32_MAX () Int 4294967295)
(define-fun U64_MAX () Int 18446744073709551615)
(define-fun in_i64 ((x Int)) Bool (and (<= I64_MIN x) (<= x I64_MAX)))
(define-fun clamp_i64 ((x Int)) Int
  (ite (> x I64_MAX) I64_MAX (ite (< x I64_MIN) I64_MIN x)))
; `x as i64` for a u64 value x.
(define-fun u64_as_i64 ((x Int)) Int
  (ite (> x I64_MAX) (- x 18446744073709551616) x))
(define-fun min_i64 ((a Int) (b Int)) Int (ite (<= a b) a b))

; RustRateLimiter::new(capacity: u32, refill_rate: u32)
(declare-const capacity Int)
(declare-const refill_rate Int)
(assert (and (<= 0 capacity) (<= capacity U32_MAX)))
(assert (and (<= 0 refill_rate) (<= refill_rate U32_MAX)))
; (capacity as i64) * 1000 and (refill_rate as i64).max(0)
(define-fun capacity_milli () Int (* capacity 1000))
(define-fun refill_per_ms () Int (ite (> refill_rate 0) refill_rate 0))
; check_and_consume passes 1000.
(define-fun cost_milli () Int 1000)

; try_consume: `now_ms.saturating_sub(last) as i64`
(declare-const now_ms Int)
(declare-const last_ms Int)
(assert (and (<= 0 now_ms) (<= now_ms U64_MAX)))
(assert (and (<= 0 last_ms) (<= last_ms U64_MAX)))
(define-fun elapsed () Int
  (u64_as_i64 (ite (>= now_ms last_ms) (- now_ms last_ms) 0)))

; The balance a CAS reads.
(declare-const cur Int)

(define-fun invariant ((t Int)) Bool (and (<= 0 t) (<= t capacity_milli)))
; `if elapsed > 0 && refill_per_ms > 0`
(define-fun refill_guard () Bool (and (> elapsed 0) (> refill_per_ms 0)))
; elapsed.saturating_mul(refill_per_ms)
(define-fun gain () Int (clamp_i64 (* elapsed refill_per_ms)))
; refill_target: cur.saturating_add(gain).min(capacity_milli). One definition
; per Rust operation, so T4 can require each intermediate to be an i64.
(define-fun refill_sum () Int (clamp_i64 (+ cur gain)))
(define-fun refilled () Int (min_i64 refill_sum capacity_milli))

; V0 (expect sat): the hypotheses are satisfiable, and an empty bucket that a
; refill makes admissible again is a real behaviour, so the unsat results below
; are not produced by contradictory assumptions.
(push 1)
(assert (invariant cur))
(assert refill_guard)
(assert (> capacity 0))
(assert (< cur cost_milli))
(assert (>= refilled cost_milli))
(check-sat)
(pop 1)

; T0 (expect unsat): the constructor cannot overflow, and a fresh bucket, which
; starts at capacity_milli, satisfies the invariant.
(push 1)
(assert (or (not (in_i64 capacity_milli)) (not (invariant capacity_milli))))
(check-sat)
(pop 1)

; T1 (expect unsat): the refill CAS preserves 0 <= tokens <= capacity.
(push 1)
(assert (invariant cur))
(assert refill_guard)
(assert (not (invariant refilled)))
(check-sat)
(pop 1)

; T2 (expect unsat): the consume CAS preserves the invariant, and `cur - cost`
; stays inside i64, so it cannot panic.
(push 1)
(assert (invariant cur))
(assert (>= cur cost_milli))
(assert (or (not (in_i64 (- cur cost_milli))) (not (invariant (- cur cost_milli)))))
(check-sat)
(pop 1)

; T3 (expect unsat): saturation never changes the answer. The refilled balance
; equals min(cur + elapsed * rate, capacity) computed without any bound, so the
; clamps only prevent an overflow; they never lose or invent tokens.
(push 1)
(assert (invariant cur))
(assert refill_guard)
(assert (not (= refilled (min_i64 (+ cur (* elapsed refill_per_ms)) capacity_milli))))
(check-sat)
(pop 1)

; T4 (expect unsat): every value the refill step computes is an i64. This is
; the typing obligation that makes a model of a non-saturating operator fail:
; drop a clamp above and this check becomes sat.
(push 1)
(assert (invariant cur))
(assert refill_guard)
(assert (not (and (in_i64 elapsed) (in_i64 gain) (in_i64 refill_sum) (in_i64 refilled))))
(check-sat)
(pop 1)

; W1 (expect sat): the saturation is load-bearing. With a plain `+` in place of
; saturating_add - the code before AUD-05 / AF-041 - some reachable balance and
; gain overflow i64, which in a release build panics and aborts the process.
(push 1)
(assert (invariant cur))
(assert refill_guard)
(assert (not (in_i64 (+ cur gain))))
(check-sat)
(pop 1)

; W2 (expect sat): the multiplication's saturation is load-bearing too. With a
; plain `*` in place of saturating_mul, some reachable elapsed time and rate
; overflow i64. The elapsed time needed is about 2^63 / 4294967295 ms, roughly
; 25 days at the largest rate, so this is reachable on a real clock.
(push 1)
(assert refill_guard)
(assert (not (in_i64 (* elapsed refill_per_ms))))
(check-sat)
(pop 1)
