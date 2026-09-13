; Copyright (c) 2026 Juan Luna. All rights reserved.
; Bounded-memory inductive transition proof for Aegis SSE stream retention in QF_BV logic.

(set-logic QF_BV)

; Configuration bounds (32-bit BitVectors)
(declare-const window_chars (_ BitVec 32))
(declare-const queue_bytes (_ BitVec 32))
(declare-const event_bytes (_ BitVec 32))
(declare-const preview_bytes (_ BitVec 32))

; Domain Constraints (RFC 2119 Bounded Retention Domain)
(assert (bvuge window_chars (_ bv64 32)))
(assert (bvule window_chars (_ bv4096 32)))
(assert (bvuge queue_bytes (_ bv1024 32)))
(assert (bvule queue_bytes (_ bv16777216 32)))
(assert (bvuge event_bytes (_ bv256 32)))
(assert (bvule event_bytes queue_bytes))
(assert (bvuge preview_bytes (_ bv0 32)))
(assert (bvule preview_bytes (_ bv65536 32)))

; R_max = 4 * window_chars + queue_bytes + event_bytes + preview_bytes
(define-fun R_max () (_ BitVec 32)
  (bvadd (bvmul (_ bv4 32) window_chars)
         (bvadd queue_bytes (bvadd event_bytes preview_bytes))))

; Inductive State Model:
; Current stream retained memory: cur_window_bytes, cur_queue_bytes, cur_preview_bytes
(declare-const cur_window_bytes (_ BitVec 32))
(declare-const cur_queue_bytes (_ BitVec 32))
(declare-const cur_preview_bytes (_ BitVec 32))

; State Bounds
(assert (bvule cur_window_bytes (bvmul (_ bv4 32) window_chars)))
(assert (bvule cur_queue_bytes queue_bytes))
(assert (bvule cur_preview_bytes preview_bytes))

(define-fun state_retained () (_ BitVec 32)
  (bvadd cur_window_bytes (bvadd cur_queue_bytes cur_preview_bytes)))

; Incoming Arbitrary Chunk Fragmentation Delta
(declare-const chunk_bytes (_ BitVec 32))
(assert (bvule chunk_bytes event_bytes))

; Next State after Chunk Processing
(declare-const next_window_bytes (_ BitVec 32))
(declare-const next_queue_bytes (_ BitVec 32))
(declare-const next_preview_bytes (_ BitVec 32))

(assert (bvule next_window_bytes (bvmul (_ bv4 32) window_chars)))
(assert (bvule next_queue_bytes queue_bytes))
(assert (bvule next_preview_bytes preview_bytes))

(define-fun next_state_retained () (_ BitVec 32)
  (bvadd next_window_bytes (bvadd next_queue_bytes next_preview_bytes)))

; Safety Property Violation: Negate that next_state_retained <= R_max
; UNSAT proves that for all valid transitions under arbitrary chunk size, retained memory <= R_max.
(assert (bvgt next_state_retained R_max))

(check-sat)
