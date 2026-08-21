(* Copyright (c) 2026 Juan Luna. All rights reserved.
   Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
   Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms. *)
 ---------------------- MODULE aegis_ledger_immutability ----------------------
EXTENDS Naturals, Sequences

CONSTANTS Data, MaxLeaves

VARIABLES leaves, history

vars == <<leaves, history>>

IsPrefix(prefix, sequence) ==
    /\ Len(prefix) <= Len(sequence)
    /\ \A index \in 1..Len(prefix): prefix[index] = sequence[index]

TypeOK ==
    /\ Data # {}
    /\ MaxLeaves \in Nat \ {0}
    /\ leaves \in Seq(Data)
    /\ Len(leaves) <= MaxLeaves
    /\ history \in Seq(Seq(Data))

Init ==
    /\ leaves = <<>>
    /\ history = <<leaves>>

AddLeaf(data) ==
    /\ Len(leaves) < MaxLeaves
    /\ leaves' = Append(leaves, data)
    /\ history' = Append(history, leaves')

Next ==
    \E data \in Data: AddLeaf(data)

AppendOnlyProperty ==
    \A older, newer \in 1..Len(history):
        older <= newer => IsPrefix(history[older], history[newer])

CurrentStateRecorded ==
    history[Len(history)] = leaves

Spec == Init /\ [][Next]_vars

THEOREM Spec => []AppendOnlyProperty
THEOREM Spec => []CurrentStateRecorded
=============================================================================
