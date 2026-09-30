(* Copyright (c) 2026 Juan Luna. All rights reserved.
   Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
   Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms. *)
--------------------------- MODULE aegis_invariants ---------------------------
(***************************************************************************)
(* Evidence before emission, across failures, crashes, replay and repair. *)
(*                                                                         *)
(* The previous model was a straight line from RECEIVED to EMITTED with    *)
(* no failure, so its invariant held because no alternative existed. This  *)
(* model adds what the code actually has to survive:                       *)
(*                                                                         *)
(*  - admission gated on the ledger's fault latch (_require_intact_ledger);*)
(*  - a failed write or fsync that latches wal_persist_failed and may      *)
(*    leave a partial line on disk (_persist_node, _await_durable);         *)
(*  - process death, which may leave a torn tail when a write is in flight;*)
(*  - restart, where replay stops at the first unparseable line and        *)
(*    latches wal_corrupt (_replay_wal);                                   *)
(*  - offline repair, which truncates only a torn *last* line              *)
(*    (tools/wal_repair.py).                                               *)
(*                                                                         *)
(* LedgerGatesCommits says whether CryptographicAuditLedger itself refuses *)
(* to commit while its latch is not healthy. With it FALSE, a request      *)
(* admitted before another request's failure latched can still commit;     *)
(* its record lands after the partial line, replay stops before it, and a  *)
(* commit that returned success is not replayable. TLC finds that          *)
(* counterexample (aegis_invariants_ungated.cfg), which is why the ledger  *)
(* gates its own commits.                                                  *)
(*                                                                         *)
(* Scope: a bounded abstraction. Records are opaque identifiers, a commit  *)
(* that returns is durable (the code awaits fsync before returning), and   *)
(* no filesystem, page cache or device semantics are modelled.             *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Requests, MaxRecords, MaxCrashes, LedgerGatesCommits, TORN

ASSUME TORN \notin Requests
ASSUME LedgerGatesCommits \in BOOLEAN

VARIABLES phase, disk, fault, up, committed, emitted, crashes, repaired,
          emitted_after_repair

vars == <<phase, disk, fault, up, committed, emitted, crashes, repaired,
          emitted_after_repair>>

Phases == {"RECEIVED", "CONTROLLED", "UPSTREAM", "COMMITTED", "EMITTED",
           "REFUSED", "FAILED"}
Faults == {"healthy", "wal_persist_failed", "wal_corrupt"}

Range(s) == {s[i] : i \in 1..Len(s)}

\* Replay reads records up to the first unparseable line and stops there.
FirstTorn ==
    IF TORN \in Range(disk)
    THEN CHOOSE i \in 1..Len(disk):
            disk[i] = TORN /\ \A j \in 1..(i - 1): disk[j] # TORN
    ELSE Len(disk) + 1

Replayable == Range(SubSeq(disk, 1, FirstTorn - 1))

TypeOK ==
    /\ phase \in [Requests -> Phases]
    /\ disk \in Seq(Requests \cup {TORN})
    /\ Len(disk) <= MaxRecords
    /\ fault \in Faults
    /\ up \in BOOLEAN
    /\ committed \subseteq Requests
    /\ emitted \subseteq Requests
    /\ crashes \in 0..MaxCrashes
    /\ repaired \in BOOLEAN
    /\ emitted_after_repair \subseteq Requests

Init ==
    /\ phase = [r \in Requests |-> "RECEIVED"]
    /\ disk = <<>>
    /\ fault = "healthy"
    /\ up = TRUE
    /\ committed = {}
    /\ emitted = {}
    /\ crashes = 0
    /\ repaired = FALSE
    /\ emitted_after_repair = {}

SetPhase(r, p) == phase' = [phase EXCEPT ![r] = p]

Admit(r) ==
    /\ up /\ phase[r] = "RECEIVED" /\ fault = "healthy"
    /\ SetPhase(r, "CONTROLLED")
    /\ UNCHANGED <<disk, fault, up, committed, emitted, crashes, repaired,
                   emitted_after_repair>>

Refuse(r) ==
    /\ up /\ phase[r] = "RECEIVED" /\ fault # "healthy"
    /\ SetPhase(r, "REFUSED")
    /\ UNCHANGED <<disk, fault, up, committed, emitted, crashes, repaired,
                   emitted_after_repair>>

Forward(r) ==
    /\ up /\ phase[r] = "CONTROLLED"
    /\ SetPhase(r, "UPSTREAM")
    /\ UNCHANGED <<disk, fault, up, committed, emitted, crashes, repaired,
                   emitted_after_repair>>

UpstreamFail(r) ==
    /\ up /\ phase[r] = "UPSTREAM"
    /\ SetPhase(r, "FAILED")
    /\ UNCHANGED <<disk, fault, up, committed, emitted, crashes, repaired,
                   emitted_after_repair>>

\* Whether the ledger accepts a commit at all.
LedgerAccepts == LedgerGatesCommits => fault = "healthy"

\* The record is appended and fsynced before the commit returns.
Commit(r) ==
    /\ up /\ phase[r] = "UPSTREAM" /\ LedgerAccepts
    /\ Len(disk) < MaxRecords
    /\ disk' = Append(disk, r)
    /\ committed' = committed \cup {r}
    /\ SetPhase(r, "COMMITTED")
    /\ UNCHANGED <<fault, up, emitted, crashes, repaired, emitted_after_repair>>

\* A write or fsync error latches wal_persist_failed; the write may have left
\* a partial line.
CommitFail(r) ==
    /\ up /\ phase[r] = "UPSTREAM" /\ LedgerAccepts
    /\ \/ disk' = disk
       \/ Len(disk) < MaxRecords /\ disk' = Append(disk, TORN)
    /\ fault' = "wal_persist_failed"
    /\ SetPhase(r, "FAILED")
    /\ UNCHANGED <<up, committed, emitted, crashes, repaired,
                   emitted_after_repair>>

\* The ledger refuses without writing anything.
CommitRefused(r) ==
    /\ up /\ phase[r] = "UPSTREAM" /\ ~LedgerAccepts
    /\ SetPhase(r, "FAILED")
    /\ UNCHANGED <<disk, fault, up, committed, emitted, crashes, repaired,
                   emitted_after_repair>>

Emit(r) ==
    /\ up /\ phase[r] = "COMMITTED"
    /\ SetPhase(r, "EMITTED")
    /\ emitted' = emitted \cup {r}
    /\ emitted_after_repair' =
           IF repaired THEN emitted_after_repair \cup {r} ELSE emitted_after_repair
    /\ UNCHANGED <<disk, fault, up, committed, crashes, repaired>>

\* Process death. A write in flight may leave a torn tail; every request not
\* yet settled loses its client.
Crash ==
    /\ up /\ crashes < MaxCrashes
    /\ up' = FALSE
    /\ crashes' = crashes + 1
    /\ \/ disk' = disk
       \/ /\ \E r \in Requests: phase[r] = "UPSTREAM"
          /\ Len(disk) < MaxRecords
          /\ disk' = Append(disk, TORN)
    /\ phase' = [r \in Requests |->
                    IF phase[r] \in {"CONTROLLED", "UPSTREAM", "COMMITTED"}
                    THEN "FAILED" ELSE phase[r]]
    /\ UNCHANGED <<fault, committed, emitted, repaired, emitted_after_repair>>

\* A new process starts healthy and replays; replay latches wal_corrupt when
\* it stops at an unparseable line.
Restart ==
    /\ ~up
    /\ up' = TRUE
    /\ fault' = IF TORN \in Range(disk) THEN "wal_corrupt" ELSE "healthy"
    /\ UNCHANGED <<phase, disk, committed, emitted, crashes, repaired,
                   emitted_after_repair>>

\* tools/wal_repair.py, offline: truncates the last line only when it is the
\* only unparseable one.
Repair ==
    /\ ~up
    /\ Len(disk) > 0
    /\ disk[Len(disk)] = TORN
    /\ TORN \notin Range(SubSeq(disk, 1, Len(disk) - 1))
    /\ disk' = SubSeq(disk, 1, Len(disk) - 1)
    /\ repaired' = TRUE
    /\ UNCHANGED <<phase, fault, up, committed, emitted, crashes,
                   emitted_after_repair>>

\* A new request arrives in a slot whose previous request has settled.
NextRequest(r) ==
    /\ up /\ phase[r] \in {"EMITTED", "REFUSED", "FAILED"}
    /\ Len(disk) < MaxRecords
    /\ SetPhase(r, "RECEIVED")
    /\ UNCHANGED <<disk, fault, up, committed, emitted, crashes, repaired,
                   emitted_after_repair>>

Next ==
    \/ \E r \in Requests:
          \/ Admit(r) \/ Refuse(r) \/ Forward(r) \/ UpstreamFail(r)
          \/ Commit(r) \/ CommitFail(r) \/ CommitRefused(r) \/ Emit(r)
          \/ NextRequest(r)
    \/ Crash \/ Restart \/ Repair

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety.                                                                 *)
(***************************************************************************)

\* Every commit that returned success is on disk and inside the prefix replay
\* reads back.
CommittedReplayable == committed \subseteq Replayable

\* Every emitted response has a replayable record.
SafetyInvariant == emitted \subseteq Replayable

\* Repair never removes a committed record.
CommittedOnDisk == committed \subseteq Range(disk)

THEOREM Spec => [](CommittedReplayable /\ SafetyInvariant /\ CommittedOnDisk)

(***************************************************************************)
(* Witnesses: each is expected to be VIOLATED, which shows the state it    *)
(* excludes is reachable and the invariants above are not vacuous.         *)
(***************************************************************************)

WitnessNoEmission == emitted = {}
WitnessNoTornTail == TORN \notin Range(disk)
WitnessNoRefusal == \A r \in Requests: phase[r] # "REFUSED"
WitnessNoEmissionAfterRepair == emitted_after_repair = {}
=============================================================================
