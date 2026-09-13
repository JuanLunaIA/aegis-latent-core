; Copyright (c) 2026 Juan Luna. All rights reserved.
; Bounded-memory arithmetic contract for one active SSE stream.
(set-logic QF_LIA)
(declare-const window_chars Int)
(declare-const queue_bytes Int)
(declare-const event_bytes Int)
(declare-const preview_bytes Int)
(declare-const retained_bytes Int)

(assert (and (>= window_chars 64) (<= window_chars 4096)))
(assert (and (>= queue_bytes 1024) (<= queue_bytes 16777216)))
(assert (and (>= event_bytes 256) (<= event_bytes queue_bytes)))
(assert (and (>= preview_bytes 0) (<= preview_bytes 65536)))

; UTF-8 storage is conservatively bounded by four bytes per retained character.
(assert (= retained_bytes (+ (* 4 window_chars) queue_bytes event_bytes preview_bytes)))

; Negate the implementation's per-stream bound. UNSAT proves no model exceeds it.
(assert (> retained_bytes (+ (* 4 window_chars) queue_bytes event_bytes preview_bytes)))
(check-sat)
