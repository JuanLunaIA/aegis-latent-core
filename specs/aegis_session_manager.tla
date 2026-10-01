(* Copyright (c) 2026 Juan Luna.
   SPDX-License-Identifier: Apache-2.0
   Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE. *)
 ------------------------ MODULE aegis_session_manager ------------------------
(***************************************************************************)
(* SessionLifecycleManager (aegis/core/session_manager.py): an LRU-bounded *)
(* map from session ID to its own LogitEntropyMonitor.                     *)
(*                                                                         *)
(* The previous model described sessions bound to ledger roots and a       *)
(* network status. The code has neither, and its ZeroTrustEnforced        *)
(* invariant read a variable that no action ever changed. This model is   *)
(* the code's actual contract: get_monitor, terminate_session and close,   *)
(* under the single RLock that serialises them.                            *)
(*                                                                         *)
(* PoolMonitors models a tempting optimisation - hand the evicted session's*)
(* monitor to the new one instead of allocating - which would carry one    *)
(* user's EMA state into another's. MonitorOwnership fails under it         *)
(* (aegis_session_manager_pooled.cfg); the code allocates, and             *)
(* tests/test_session_manager_conformance.py checks the same invariants on *)
(* the real class.                                                         *)
(*                                                                         *)
(* Scope: the Python mapping only. The optional Rust metadata store is a   *)
(* mirror for metrics and is not modelled.                                 *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS SessionIds, MaxSessions, MaxMonitors, NoMonitor, NoOwner, PoolMonitors

ASSUME MaxSessions \in Nat \ {0}
ASSUME PoolMonitors \in BOOLEAN

VARIABLES order, monitor_of, owner, created, last_get, evicted_once,
          reaccessed_once

vars == <<order, monitor_of, owner, created, last_get, evicted_once,
          reaccessed_once>>

Monitors == 1..MaxMonitors

Range(s) == {s[i] : i \in 1..Len(s)}
Without(s, x) == SelectSeq(s, LAMBDA y: y # x)
Live == Range(order)

TypeOK ==
    /\ order \in Seq(SessionIds)
    /\ monitor_of \in [SessionIds -> Monitors \cup {NoMonitor}]
    /\ owner \in [Monitors -> SessionIds \cup {NoOwner}]
    /\ created \in 0..MaxMonitors
    /\ last_get \in {<<>>} \cup (SessionIds \X Monitors)
    /\ evicted_once \in BOOLEAN
    /\ reaccessed_once \in BOOLEAN

Init ==
    /\ order = <<>>
    /\ monitor_of = [s \in SessionIds |-> NoMonitor]
    /\ owner = [m \in Monitors |-> NoOwner]
    /\ created = 0
    /\ last_get = <<>>
    /\ evicted_once = FALSE
    /\ reaccessed_once = FALSE

\* get_monitor(s) for a live session: move it to the MRU end, return its monitor.
Reaccess(s) ==
    /\ s \in Live
    /\ order' = Append(Without(order, s), s)
    /\ last_get' = <<s, monitor_of[s]>>
    /\ reaccessed_once' = TRUE
    /\ UNCHANGED <<monitor_of, owner, created, evicted_once>>

\* get_monitor(s) for a new session: evict the LRU entry at capacity, then
\* insert a monitor for s.
Create(s) ==
    /\ s \notin Live
    /\ LET full == Len(order) >= MaxSessions
           victim == Head(order)
           pooled == full /\ PoolMonitors
           m == IF pooled THEN monitor_of[victim] ELSE created + 1
       IN /\ pooled \/ created < MaxMonitors
          /\ order' = Append(IF full THEN Tail(order) ELSE order, s)
          /\ monitor_of' = [x \in SessionIds |->
                               IF x = s THEN m
                               ELSE IF full /\ x = victim THEN NoMonitor
                               ELSE monitor_of[x]]
          /\ owner' = IF pooled THEN owner ELSE [owner EXCEPT ![m] = s]
          /\ created' = IF pooled THEN created ELSE created + 1
          /\ last_get' = <<s, m>>
          /\ evicted_once' = (evicted_once \/ full)
    /\ UNCHANGED reaccessed_once

Terminate(s) ==
    /\ order' = Without(order, s)
    /\ monitor_of' = [monitor_of EXCEPT ![s] = NoMonitor]
    /\ last_get' = <<>>
    /\ UNCHANGED <<owner, created, evicted_once, reaccessed_once>>

Close ==
    /\ order' = <<>>
    /\ monitor_of' = [s \in SessionIds |-> NoMonitor]
    /\ last_get' = <<>>
    /\ UNCHANGED <<owner, created, evicted_once, reaccessed_once>>

Next ==
    \/ \E s \in SessionIds: Reaccess(s) \/ Create(s) \/ Terminate(s)
    \/ Close

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety.                                                                 *)
(***************************************************************************)

\* max_sessions is a hard bound (BUG-05: the map used to grow without limit).
Bounded == Len(order) <= MaxSessions

NoDuplicates == Len(order) = Cardinality(Live)

LiveIffMonitor == \A s \in SessionIds: (s \in Live) <=> (monitor_of[s] # NoMonitor)

\* Two live sessions never share a monitor.
Isolation ==
    \A s1, s2 \in Live: s1 # s2 => monitor_of[s1] # monitor_of[s2]

\* A live session's monitor was created for that session and no other, so no
\* EMA state crosses from one session to another, even through eviction.
MonitorOwnership == \A s \in Live: owner[monitor_of[s]] = s

\* What get_monitor returns belongs to the session it was asked for.
ReturnedOwned == last_get # <<>> => owner[last_get[2]] = last_get[1]

\* Re-accessing a live session returns the monitor it already had.
StableOnReaccess ==
    [][\A s \in SessionIds:
         (s \in Live /\ last_get' # <<>> /\ last_get'[1] = s)
            => last_get'[2] = monitor_of[s]]_vars

\* The only session get_monitor ever removes is the least recently used one.
EvictsLeastRecentlyUsed ==
    [][\A s \in SessionIds:
         (s \in Live /\ s \notin Range(order') /\ last_get' # <<>>
            /\ last_get'[1] # s)
            => s = Head(order)]_vars

THEOREM Spec => [](Bounded /\ Isolation /\ MonitorOwnership /\ ReturnedOwned)

(***************************************************************************)
(* Witnesses: each is expected to be VIOLATED.                             *)
(***************************************************************************)

WitnessNeverFull == Len(order) < MaxSessions
WitnessNoEviction == ~evicted_once
WitnessNoReaccess == ~reaccessed_once
=============================================================================
