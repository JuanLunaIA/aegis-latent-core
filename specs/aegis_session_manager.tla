(* Copyright (c) 2026 Juan Luna. All rights reserved.
   Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
   Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms. *)
 ------------------------ MODULE aegis_session_manager ------------------------
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS SessionIds, Roots, NoRoot, MaxCommits

VARIABLES sessions, binding, ledger, network_status, insecure_processing

vars == <<sessions, binding, ledger, network_status, insecure_processing>>

SequenceRange(sequence) ==
    {sequence[index] : index \in 1..Len(sequence)}

TypeOK ==
    /\ SessionIds # {}
    /\ Roots # {}
    /\ NoRoot \notin Roots
    /\ MaxCommits \in Nat \ {0}
    /\ sessions \subseteq SessionIds
    /\ binding \in [SessionIds -> Roots \cup {NoRoot}]
    /\ ledger \in Seq(Roots)
    /\ Len(ledger) <= MaxCommits
    /\ network_status \in {"SECURE", "COMPROMISED"}
    /\ insecure_processing \in BOOLEAN

Init ==
    /\ sessions = {}
    /\ binding = [session \in SessionIds |-> NoRoot]
    /\ ledger = <<>>
    /\ network_status = "SECURE"
    /\ insecure_processing = FALSE

CommitToLedger(root) ==
    /\ Len(ledger) < MaxCommits
    /\ ledger' = Append(ledger, root)
    /\ UNCHANGED <<sessions, binding, network_status, insecure_processing>>

CreateSession(session) ==
    /\ session \notin sessions
    /\ Len(ledger) > 0
    /\ sessions' = sessions \cup {session}
    /\ binding' = [binding EXCEPT ![session] = ledger[Len(ledger)]]
    /\ UNCHANGED <<ledger, network_status, insecure_processing>>

ProcessRequest(session) ==
    /\ session \in sessions
    /\ network_status = "SECURE"
    /\ UNCHANGED vars

NetworkFailure ==
    /\ network_status = "SECURE"
    /\ network_status' = "COMPROMISED"
    /\ UNCHANGED <<sessions, binding, ledger, insecure_processing>>

NetworkRecovery ==
    /\ network_status = "COMPROMISED"
    /\ network_status' = "SECURE"
    /\ UNCHANGED <<sessions, binding, ledger, insecure_processing>>

Next ==
    \/ \E root \in Roots: CommitToLedger(root)
    \/ \E session \in SessionIds: CreateSession(session)
    \/ \E session \in SessionIds: ProcessRequest(session)
    \/ NetworkFailure
    \/ NetworkRecovery

SessionBinding ==
    \A session \in sessions: binding[session] \in SequenceRange(ledger)

ZeroTrustEnforced ==
    insecure_processing = FALSE

Spec == Init /\ [][Next]_vars

THEOREM Spec => []SessionBinding
THEOREM Spec => []ZeroTrustEnforced
=============================================================================
