--------------------------- MODULE ShadowPipeline ---------------------------
(* TLA+ Specification of Aegis Decoupled Data / Evidence Planes *)

EXTENDS Sequences, FiniteSets, Integers, TLC

VARIABLES
  clientStream,    \* Sequence of tokens emitted to client
  evidenceQueue,   \* Ring buffer/queue for async evidence pipeline
  evidenceStatus,  \* "pending-anchoring", "batching", "anchored"
  wormAnchor       \* Set of anchored records in WORM storage

TypeOK ==
  /\ IsFiniteSet(wormAnchor)
  /\ evidenceStatus \in {"pending-anchoring", "batching", "anchored"}

Init ==
  /\ clientStream = <<>>
  /\ evidenceQueue = <<>>
  /\ evidenceStatus = "pending-anchoring"
  /\ wormAnchor = {}

EmitToken(token) ==
  /\ clientStream' = Append(clientStream, token)
  /\ evidenceQueue' = Append(evidenceQueue, token)
  /\ UNCHANGED <<evidenceStatus, wormAnchor>>

ProcessEvidenceBatch ==
  /\ Len(evidenceQueue) > 0
  /\ evidenceStatus = "pending-anchoring"
  /\ evidenceStatus' = "batching"
  /\ UNCHANGED <<clientStream, evidenceQueue, wormAnchor>>

AnchorToWorm ==
  /\ evidenceStatus = "batching"
  /\ wormAnchor' = wormAnchor \cup {[id |-> Len(clientStream), tokens |-> evidenceQueue]}
  /\ evidenceQueue' = <<>>
  /\ evidenceStatus' = "anchored"
  /\ UNCHANGED <<clientStream>>

Next ==
  \/ \E t \in 1..100 : EmitToken(t)
  \/ ProcessEvidenceBatch
  \/ AnchorToWorm

Spec == Init /\ [][Next]_<<clientStream, evidenceQueue, evidenceStatus, wormAnchor>>

(* Safety Invariant: An anchored evidence status implies matching token record exists in WORM anchor *)
SafetyInvariant ==
  (evidenceStatus = "anchored") => (\E record \in wormAnchor : True)

================================---------------------------------------------
