(* Copyright (c) 2026 Juan Luna. All rights reserved.
   Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
   Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms. *)
--------------------------- MODULE aegis_invariants ---------------------------
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Requests, MaxCapacity

VARIABLES state, wal_log, response_emitted

vars == <<state, wal_log, response_emitted>>

SequenceRange(sequence) ==
    {sequence[index] : index \in 1..Len(sequence)}

TypeOK ==
    /\ Requests # {}
    /\ MaxCapacity \in Nat \ {0}
    /\ state \in [Requests -> {"RECEIVED", "CONTROLLED", "UPSTREAM", "COMMITTED", "EMITTED"}]
    /\ wal_log \in Seq(Requests)
    /\ Len(wal_log) <= MaxCapacity
    /\ response_emitted \subseteq Requests

Init ==
    /\ state = [request \in Requests |-> "RECEIVED"]
    /\ wal_log = <<>>
    /\ response_emitted = {}

Admit(request) ==
    /\ state[request] = "RECEIVED"
    /\ state' = [state EXCEPT ![request] = "CONTROLLED"]
    /\ UNCHANGED <<wal_log, response_emitted>>

ForwardUpstream(request) ==
    /\ state[request] = "CONTROLLED"
    /\ state' = [state EXCEPT ![request] = "UPSTREAM"]
    /\ UNCHANGED <<wal_log, response_emitted>>

DurableCommit(request) ==
    /\ state[request] = "UPSTREAM"
    /\ Len(wal_log) < MaxCapacity
    /\ wal_log' = Append(wal_log, request)
    /\ state' = [state EXCEPT ![request] = "COMMITTED"]
    /\ UNCHANGED response_emitted

EmitResponse(request) ==
    /\ state[request] = "COMMITTED"
    /\ response_emitted' = response_emitted \cup {request}
    /\ state' = [state EXCEPT ![request] = "EMITTED"]
    /\ UNCHANGED wal_log

Next ==
    \E request \in Requests:
        \/ Admit(request)
        \/ ForwardUpstream(request)
        \/ DurableCommit(request)
        \/ EmitResponse(request)

SafetyInvariant ==
    response_emitted \subseteq SequenceRange(wal_log)

Spec == Init /\ [][Next]_vars

THEOREM Spec => []SafetyInvariant
=============================================================================
