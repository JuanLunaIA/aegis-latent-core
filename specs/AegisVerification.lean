/-
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-/

/-!
# Evidence-before-emission, with failure paths

An abstraction of one request slot in the gateway and the ledger fault latch
(`CryptographicAuditLedger._fault_state`). The previous version of this file had
four straight-line transitions and no failure path, so its theorem could not
say anything about what happens when a commit fails, and nothing showed that an
emitting state was reachable at all.

This version models admission gated on a healthy ledger, refusal while it is
not, an upstream failure, a commit that succeeds or fails and latches a fault,
a fault latched by any other writer at any time, operator repair between
requests, and the next request. It proves the safety properties by induction
over every reachable state, proves step properties by case analysis over every
transition, and proves witness theorems showing that emission, refusal and
failure are all reachable, so no theorem holds merely because its hypothesis is
unreachable.

Scope: a bounded abstraction, not a refinement proof of `aegis/proxy/app.py`,
`aegis/core/crypto_audit.py` or the filesystem. It does not model incremental
SSE events, concurrency between request slots, or durability of the medium.
-/

namespace AegisVerification

/-- The ledger's latched fault states (`crypto_audit.py`, `_fault_state`). -/
inductive Fault where
  | healthy
  | signingFailed
  | walPersistFailed
  | walCorrupt
  | mmrSchemeMismatch
  | mmrReplayMismatch
  deriving DecidableEq, Repr

inductive Phase where
  | idle
  | controlled
  | upstream
  | committed
  | emitted
  | refused
  | failed
  deriving DecidableEq, Repr

structure AuditState where
  phase : Phase
  fault : Fault
  durable : Bool
  responseEmitted : Bool
  deriving DecidableEq, Repr

inductive Action where
  | admit
  | refuse
  | forward
  | upstreamFail
  | commit
  | commitFail
  | emit
  | latch
  | repair
  | nextRequest
  deriving DecidableEq, Repr

open Phase Fault

def initial : AuditState := ⟨idle, healthy, false, false⟩

/-- A request's outcome is settled: emitted, refused, or failed. -/
def Settled (p : Phase) : Prop := p = emitted ∨ p = refused ∨ p = failed

inductive Step : Action → AuditState → AuditState → Prop where
  /-- Admission is gated on a healthy ledger (`_require_intact_ledger`). -/
  | admit {s : AuditState} :
      s.phase = idle → s.fault = healthy →
      Step .admit s { s with phase := controlled }
  /-- An unhealthy ledger refuses the request before the provider is called. -/
  | refuse {s : AuditState} :
      s.phase = idle → s.fault ≠ healthy →
      Step .refuse s { s with phase := refused }
  | forward {s : AuditState} :
      s.phase = controlled →
      Step .forward s { s with phase := upstream }
  | upstreamFail {s : AuditState} :
      s.phase = upstream →
      Step .upstreamFail s { s with phase := failed }
  /-- The ledger commits only while healthy; the record is then durable. -/
  | commit {s : AuditState} :
      s.phase = upstream → s.fault = healthy →
      Step .commit s { s with phase := committed, durable := true }
  /-- A failed signature or WAL write latches its fault and ends the request. -/
  | commitFail {s : AuditState} (f : Fault) :
      s.phase = upstream → f ≠ healthy →
      Step .commitFail s { s with phase := failed, fault := f }
  | emit {s : AuditState} :
      s.phase = committed → s.durable = true →
      Step .emit s { s with phase := emitted, responseEmitted := true }
  /-- Any other writer, or replay, may latch a fault at any moment. -/
  | latch {s : AuditState} (f : Fault) :
      f ≠ healthy →
      Step .latch s { s with fault := f }
  /-- Operator repair, only between requests (`tools/wal_repair.py`, restart). -/
  | repair {s : AuditState} :
      s.phase = idle → s.fault ≠ healthy →
      Step .repair s { s with fault := healthy }
  | nextRequest {s : AuditState} :
      Settled s.phase →
      Step .nextRequest s { s with phase := idle, durable := false, responseEmitted := false }

inductive Reachable : AuditState → Prop where
  | initial : Reachable initial
  | next {a : Action} {s t : AuditState} : Reachable s → Step a s t → Reachable t

/-- The inductive invariant: a response is emitted exactly in the emitted
phase, and a committed or emitted request has a durable record. -/
def Inv (s : AuditState) : Prop :=
  (s.responseEmitted = true ↔ s.phase = emitted) ∧
  ((s.phase = committed ∨ s.phase = emitted) → s.durable = true)

theorem initial_satisfies_invariant : Inv initial := by
  simp [Inv, initial]

theorem step_preserves_invariant {a : Action} {s t : AuditState}
    (h : Inv s) (step : Step a s t) : Inv t := by
  obtain ⟨hEmit, hDurable⟩ := h
  cases step with
  | admit hp _ =>
      refine ⟨?_, ?_⟩
      · simp only [hp] at hEmit
        simp [hEmit]
      · simp
  | refuse hp _ =>
      refine ⟨?_, ?_⟩
      · simp only [hp] at hEmit
        simp [hEmit]
      · simp
  | forward hp =>
      refine ⟨?_, ?_⟩
      · simp only [hp] at hEmit
        simp [hEmit]
      · simp
  | upstreamFail hp =>
      refine ⟨?_, ?_⟩
      · simp only [hp] at hEmit
        simp [hEmit]
      · simp
  | commit hp _ =>
      refine ⟨?_, ?_⟩
      · simp only [hp] at hEmit
        simp [hEmit]
      · simp
  | commitFail f hp _ =>
      refine ⟨?_, ?_⟩
      · simp only [hp] at hEmit
        simp [hEmit]
      · simp
  | emit _ hd =>
      exact ⟨by simp, fun _ => hd⟩
  | latch f _ =>
      exact ⟨hEmit, hDurable⟩
  | repair _ _ =>
      exact ⟨hEmit, hDurable⟩
  | nextRequest _ =>
      exact ⟨by simp, by simp⟩

theorem reachable_invariant {s : AuditState} (r : Reachable s) : Inv s := by
  induction r with
  | initial => exact initial_satisfies_invariant
  | next _ step ih => exact step_preserves_invariant ih step

/-! ## Safety over every reachable state -/

/-- No response is emitted without a durable record. -/
theorem reachable_states_satisfy_invariant {s : AuditState} (r : Reachable s) :
    s.responseEmitted = true → s.durable = true := by
  intro hEmitted
  obtain ⟨hEmit, hDurable⟩ := reachable_invariant r
  exact hDurable (Or.inr (hEmit.mp hEmitted))

/-- A request whose commit failed, or whose upstream failed, emits nothing. -/
theorem failed_requests_emit_nothing {s : AuditState} (r : Reachable s)
    (hp : s.phase = failed) : s.responseEmitted = false := by
  obtain ⟨hEmit, _⟩ := reachable_invariant r
  cases hE : s.responseEmitted with
  | false => rfl
  | true =>
      have := hEmit.mp hE
      rw [hp] at this
      cases this

/-- A refused request emits nothing. -/
theorem refused_requests_emit_nothing {s : AuditState} (r : Reachable s)
    (hp : s.phase = refused) : s.responseEmitted = false := by
  obtain ⟨hEmit, _⟩ := reachable_invariant r
  cases hE : s.responseEmitted with
  | false => rfl
  | true =>
      have := hEmit.mp hE
      rw [hp] at this
      cases this

/-! ## Properties of every transition -/

/-- Work reaches the controlled phase only from a healthy ledger. -/
theorem admission_requires_healthy {a : Action} {s t : AuditState}
    (step : Step a s t) (hs : s.phase ≠ controlled) (ht : t.phase = controlled) :
    s.fault = healthy := by
  cases step with
  | admit _ hf => exact hf
  | latch _ _ => exact absurd ht hs
  | repair hp _ => simp [hp] at ht
  | refuse _ _ => simp at ht
  | forward _ => simp at ht
  | upstreamFail _ => simp at ht
  | commit _ _ => simp at ht
  | commitFail _ _ _ => simp at ht
  | emit _ _ => simp at ht
  | nextRequest _ => simp at ht

/-- A record becomes durable only through a commit on a healthy ledger. -/
theorem durability_requires_healthy_commit {a : Action} {s t : AuditState}
    (step : Step a s t) (hs : s.durable = false) (ht : t.durable = true) :
    a = .commit ∧ s.fault = healthy := by
  cases step with
  | commit _ hf => exact ⟨rfl, hf⟩
  | admit _ _ => simp [hs] at ht
  | refuse _ _ => simp [hs] at ht
  | forward _ => simp [hs] at ht
  | upstreamFail _ => simp [hs] at ht
  | commitFail _ _ _ => simp [hs] at ht
  | emit _ _ => simp [hs] at ht
  | latch _ _ => simp [hs] at ht
  | repair _ _ => simp [hs] at ht
  | nextRequest _ => simp at ht

/-- A latched fault is cleared only by operator repair, between requests. -/
theorem fault_clears_only_by_repair {a : Action} {s t : AuditState}
    (step : Step a s t) (hs : s.fault ≠ healthy) (ht : t.fault = healthy) :
    a = .repair ∧ s.phase = idle := by
  cases step with
  | repair hp _ => exact ⟨rfl, hp⟩
  | admit _ _ => exact absurd ht hs
  | refuse _ _ => exact absurd ht hs
  | forward _ => exact absurd ht hs
  | upstreamFail _ => exact absurd ht hs
  | commit _ _ => exact absurd ht hs
  | commitFail _ _ hf => exact absurd ht hf
  | emit _ _ => exact absurd ht hs
  | latch _ hf => exact absurd ht hf
  | nextRequest _ => exact absurd ht hs

/-! ## Non-vacuity: every outcome the theorems talk about is reachable -/

theorem emission_is_reachable :
    Reachable ⟨emitted, healthy, true, true⟩ :=
  .next (.next (.next (.next .initial
    (Step.admit (s := initial) rfl rfl))
    (Step.forward rfl))
    (Step.commit rfl rfl))
    (Step.emit rfl rfl)

theorem commit_failure_is_reachable :
    Reachable ⟨failed, walPersistFailed, false, false⟩ :=
  .next (.next (.next .initial
    (Step.admit (s := initial) rfl rfl))
    (Step.forward rfl))
    (Step.commitFail walPersistFailed rfl (by decide))

/-- A latched ledger refuses, and repair makes the next request admissible. -/
theorem refusal_and_recovery_are_reachable :
    Reachable ⟨refused, walCorrupt, false, false⟩ ∧
    Reachable ⟨controlled, healthy, false, false⟩ := by
  have latched : Reachable ⟨idle, walCorrupt, false, false⟩ :=
    .next .initial (Step.latch (s := initial) walCorrupt (by decide))
  have refusedState : Reachable ⟨refused, walCorrupt, false, false⟩ :=
    .next latched (Step.refuse rfl (by decide))
  have nextIdle : Reachable ⟨idle, walCorrupt, false, false⟩ :=
    .next refusedState (Step.nextRequest (Or.inr (Or.inl rfl)))
  have repaired : Reachable ⟨idle, healthy, false, false⟩ :=
    .next nextIdle (Step.repair rfl (by decide))
  exact ⟨refusedState, .next repaired (Step.admit rfl rfl)⟩

end AegisVerification

#print axioms AegisVerification.reachable_states_satisfy_invariant
#print axioms AegisVerification.failed_requests_emit_nothing
#print axioms AegisVerification.refused_requests_emit_nothing
#print axioms AegisVerification.admission_requires_healthy
#print axioms AegisVerification.durability_requires_healthy_commit
#print axioms AegisVerification.fault_clears_only_by_repair
#print axioms AegisVerification.emission_is_reachable
#print axioms AegisVerification.commit_failure_is_reachable
#print axioms AegisVerification.refusal_and_recovery_are_reachable
