/-
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-/

inductive Phase where
  | received
  | controlled
  | upstream
  | committed
  | emitted
  deriving DecidableEq, Repr

structure AuditState where
  phase : Phase
  durable : Bool
  responseEmitted : Bool
  deriving DecidableEq, Repr

namespace AegisVerification

open Phase

inductive Step : AuditState → AuditState → Prop where
  | admit : Step ⟨received, false, false⟩ ⟨controlled, false, false⟩
  | forward : Step ⟨controlled, false, false⟩ ⟨upstream, false, false⟩
  | commit : Step ⟨upstream, false, false⟩ ⟨committed, true, false⟩
  | emit : Step ⟨committed, true, false⟩ ⟨emitted, true, true⟩

inductive Reachable : AuditState → Prop where
  | initial : Reachable ⟨received, false, false⟩
  | next {source target : AuditState} : Reachable source → Step source target → Reachable target

def DurableEmissionInvariant (state : AuditState) : Prop :=
  state.responseEmitted = true → state.durable = true

theorem initial_satisfies_invariant :
    DurableEmissionInvariant ⟨received, false, false⟩ := by
  simp [DurableEmissionInvariant]

theorem step_preserves_invariant
    {source target : AuditState}
    (_sourceInvariant : DurableEmissionInvariant source)
    (transition : Step source target) :
    DurableEmissionInvariant target := by
  cases transition <;> simp [DurableEmissionInvariant]

theorem reachable_states_satisfy_invariant
    {state : AuditState}
    (reachable : Reachable state) :
    DurableEmissionInvariant state := by
  induction reachable with
  | initial => exact initial_satisfies_invariant
  | next sourceReachable transition inductionHypothesis =>
      exact step_preserves_invariant inductionHypothesis transition

end AegisVerification
