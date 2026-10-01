; Copyright (c) 2026 Juan Luna.
; SPDX-License-Identifier: Apache-2.0
; Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
;
; Bounded-memory arithmetic contract for one active SSE stream:
;
;     R_max = 4W + Q + E + P
;
; W is the de-identification holdback in characters, Q the byte-accounted queue
; budget, E the largest single canonical SSE event, and P the retained response
; preview; below they are window_chars, queue_bytes, event_bytes and
; preview_bytes. aegis/core/stream_bounds.py computes the same expression over
; the same declared ranges, and tests/test_stream_bounds.py reads the ranges and
; the expression out of this file to check that they have not drifted apart.
;
; The previous version of this file defined `retained_bytes` as R_max and then
; asserted `retained_bytes > R_max`, which is `unsat` for any expression at all:
; replacing 4W with 0W still produced `unsat`. This version bounds an observed
; retention by its components and checks the expression against it, and adds
; checks whose expected result is `sat` so a vacuous domain also fails.
;
; Scope: arithmetic only. That each observed component stays within its budget
; (the holdback within W characters, the queue within Q bytes, one event within
; E, the preview within P) is enforced by the streaming code and its tests, not
; by this file; nothing here models CPython's allocator or process memory, and
; aggregate memory across concurrent streams is outside every bound here.
;
; expect: sat unsat unsat sat unsat sat
(set-logic QF_LIA)

(declare-const window_chars Int)
(declare-const queue_bytes Int)
(declare-const event_bytes Int)
(declare-const preview_bytes Int)

; Declared ranges (stream_bounds.py: WINDOW_CHARS_*, QUEUE_BYTES_*,
; EVENT_BYTES_MIN, PREVIEW_BYTES_*).
(assert (and (>= window_chars 64) (<= window_chars 4096)))
(assert (and (>= queue_bytes 1024) (<= queue_bytes 16777216)))
(assert (and (>= event_bytes 256) (<= event_bytes queue_bytes)))
(assert (and (>= preview_bytes 0) (<= preview_bytes 65536)))

; UTF-8 stores one code point in at most four bytes.
(define-fun R_max () Int (+ (* 4 window_chars) queue_bytes event_bytes preview_bytes))

; One observation of what a stream retains between feed calls: h held-back
; characters stored in hb bytes, qb queued bytes, eb bytes of the event being
; assembled, and pb preview bytes.
(declare-const h Int)
(declare-const hb Int)
(declare-const qb Int)
(declare-const eb Int)
(declare-const pb Int)
(define-fun within_budgets () Bool
  (and (<= 0 h) (<= h window_chars)
       (<= h hb) (<= hb (* 4 h))
       (<= 0 qb) (<= qb queue_bytes)
       (<= 0 eb) (<= eb event_bytes)
       (<= 0 pb) (<= pb preview_bytes)))
(define-fun retained () Int (+ hb qb eb pb))

; V0 (expect sat): the domain is non-empty and an observation can sit exactly
; at the ceiling, so the ceiling is attained rather than loose.
(push 1)
(assert within_budgets)
(assert (= retained R_max))
(check-sat)
(pop 1)

; S1 (expect unsat): no observation within its budgets exceeds R_max.
(push 1)
(assert within_budgets)
(assert (> retained R_max))
(check-sat)
(pop 1)

; S2 (expect unsat): over the whole declared domain the ceiling is at most
; 33,636,352 bytes (4 x 4096 + 16777216 + 16777216 + 65536).
(push 1)
(assert (> R_max 33636352))
(check-sat)
(pop 1)

; S3 (expect sat): that maximum is attained, so S2's constant is exact.
(push 1)
(assert (= R_max 33636352))
(check-sat)
(pop 1)

; S4 (expect unsat): the in-process ceiling, 4W with no queue, event or
; preview, never exceeds the ceiling of a declared-domain stream with the same W.
(push 1)
(assert (> (* 4 window_chars) R_max))
(check-sat)
(pop 1)

; W1 (expect sat): the factor 4 is load-bearing. With 3 bytes per character a
; holdback of four-byte code points (emoji, for instance) exceeds the ceiling.
(push 1)
(assert within_budgets)
(assert (> retained (+ (* 3 window_chars) queue_bytes event_bytes preview_bytes)))
(check-sat)
(pop 1)
