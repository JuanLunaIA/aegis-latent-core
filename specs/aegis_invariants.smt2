; Copyright (c) 2026 Juan Luna. All rights reserved.
; Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
; Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
;
; Property: a token-bucket admission predicate cannot be true when the
; saturated post-refill balance is strictly below the requested cost.
(set-logic QF_BV)
(set-info :status unsat)

(declare-const capacity_milli (_ BitVec 64))
(declare-const tokens_milli (_ BitVec 64))
(declare-const refill_per_ms (_ BitVec 64))
(declare-const elapsed_ms (_ BitVec 64))
(declare-const cost_milli (_ BitVec 64))

(assert (bvugt capacity_milli #x0000000000000000))
(assert (bvugt cost_milli #x0000000000000000))
(assert (bvule tokens_milli capacity_milli))

; Widen both multiplication and addition to 128 bits so the mathematical
; saturation rule is not weakened by 64-bit modular wraparound.
(define-fun capacity_128 () (_ BitVec 128)
  ((_ zero_extend 64) capacity_milli))

(define-fun token_128 () (_ BitVec 128)
  ((_ zero_extend 64) tokens_milli))

(define-fun gain_128 () (_ BitVec 128)
  (bvmul ((_ zero_extend 64) refill_per_ms)
         ((_ zero_extend 64) elapsed_ms)))

(define-fun sum_128 () (_ BitVec 128)
  (bvadd token_128 gain_128))

(define-fun refilled_128 () (_ BitVec 128)
  (ite (bvugt sum_128 capacity_128) capacity_128 sum_128))

(define-fun refilled_tokens () (_ BitVec 64)
  ((_ extract 63 0) refilled_128))

(define-fun can_consume () Bool
  (bvuge refilled_tokens cost_milli))

; Negated safety property: admission succeeds although balance < cost.
(assert (bvult refilled_tokens cost_milli))
(assert can_consume)

(check-sat)
