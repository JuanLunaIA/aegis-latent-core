(* Copyright (c) 2026 Juan Luna. All rights reserved.
   Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
   Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms. *)
 ---------------------- MODULE aegis_ledger_immutability ----------------------
(***************************************************************************)
(* Tamper evidence of the hash-linked, signed evidence chain.              *)
(*                                                                         *)
(* The previous model had one action, Append, and checked that the ledger *)
(* only ever grew: true by construction, with no adversary to resist. This *)
(* model gives an adversary write access to the WAL file and checks what   *)
(* verify_integrity() actually buys against it.                            *)
(*                                                                         *)
(* Abstractions. A record carries its data, the commitment to the prefix   *)
(* before it (prev_hash, and the MMR root, abstracted as an injective      *)
(* commitment: the prefix itself), and the key that signed it. The ledger  *)
(* signs <<data, prefix>> pairs; nobody else can produce a signature under *)
(* the ledger's key unless AdversaryHasKey. Any key the adversary makes    *)
(* signs whatever it likes.                                                *)
(*                                                                         *)
(* KeysPinned says whether the verifier accepts only the ledger's key.     *)
(* With it FALSE - a signature checked against the public key recorded in *)
(* the node itself - the adversary re-signs a rewritten chain with its own *)
(* key and verification passes (aegis_ledger_immutability_unpinned.cfg).   *)
(*                                                                         *)
(* What holds with pinned keys and an uncompromised key: any file that     *)
(* verifies is a prefix of the true history. Modification, insertion,      *)
(* deletion and reordering are all detected; truncation of the tail is     *)
(* not, unless the verifier also holds an external anchor for the length   *)
(* (WitnessTruncationUndetected shows it).                                 *)
(*                                                                         *)
(* Scope: perfect hashing and signatures; no key lifecycle, time, or       *)
(* storage semantics.                                                      *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Data, MaxLen, KeysPinned, AdversaryHasKey

ASSUME KeysPinned \in BOOLEAN /\ AdversaryHasKey \in BOOLEAN

VARIABLES honest, log, signed

vars == <<honest, log, signed>>

Keys == {"ledger", "adversary"}

Rec(d, p, k) == [data |-> d, prev |-> p, key |-> k]

DataOf(s) == [i \in 1..Len(s) |-> s[i].data]

\* Commitment to the first n records of s, as a verifier recomputes it.
Commit(s, n) == SubSeq(DataOf(s), 1, n)

IsPrefix(p, s) == Len(p) <= Len(s) /\ p = SubSeq(s, 1, Len(p))

SignatureValid(r) ==
    IF r.key = "ledger" THEN <<r.data, r.prev>> \in signed ELSE TRUE

KeyAccepted(r) == KeysPinned => r.key = "ledger"

\* verify_integrity(): every link recomputes and every signature verifies.
Verifies(s) ==
    \A i \in 1..Len(s):
        /\ s[i].prev = Commit(s, i - 1)
        /\ SignatureValid(s[i])
        /\ KeyAccepted(s[i])

Prefixes == UNION {[1..n -> Data] : n \in 0..(MaxLen - 1)}
Records == {Rec(d, p, k) : d \in Data, p \in Prefixes, k \in Keys}

TypeOK ==
    /\ honest \in Seq(Data) /\ Len(honest) <= MaxLen
    /\ log \in Seq(Records) /\ Len(log) <= MaxLen
    /\ signed \subseteq Data \X Prefixes

Init ==
    /\ honest = <<>>
    /\ log = <<>>
    /\ signed = {}

\* The ledger signs over its in-memory chain and appends to the file.
LedgerAppend(d) ==
    /\ Len(honest) < MaxLen /\ Len(log) < MaxLen
    /\ honest' = Append(honest, d)
    /\ signed' = signed \cup {<<d, honest>>}
    /\ log' = Append(log, Rec(d, honest, "ledger"))

RemoveAt(s, i) == SubSeq(s, 1, i - 1) \o SubSeq(s, i + 1, Len(s))
InsertAt(s, i, r) == SubSeq(s, 1, i - 1) \o <<r>> \o SubSeq(s, i, Len(s))

\* Adversary with write access to the file.
Modify(i, d) ==
    /\ log' = [log EXCEPT ![i] = [@ EXCEPT !.data = d]]
    /\ UNCHANGED <<honest, signed>>

Relink(i) ==
    /\ log' = [log EXCEPT ![i] = [@ EXCEPT !.prev = Commit(log, i - 1)]]
    /\ UNCHANGED <<honest, signed>>

Delete(i) ==
    /\ log' = RemoveAt(log, i)
    /\ UNCHANGED <<honest, signed>>

Duplicate(i, j) ==
    /\ Len(log) < MaxLen
    /\ log' = InsertAt(log, j, log[i])
    /\ UNCHANGED <<honest, signed>>

ResignOwnKey(i, d) ==
    /\ log' = [log EXCEPT ![i] = Rec(d, Commit(log, i - 1), "adversary")]
    /\ UNCHANGED <<honest, signed>>

ResignLedgerKey(i, d) ==
    /\ AdversaryHasKey
    /\ log' = [log EXCEPT ![i] = Rec(d, Commit(log, i - 1), "ledger")]
    /\ signed' = signed \cup {<<d, Commit(log, i - 1)>>}
    /\ UNCHANGED honest

Adversary ==
    \/ \E i \in 1..Len(log), d \in Data: Modify(i, d) \/ ResignOwnKey(i, d)
                                          \/ ResignLedgerKey(i, d)
    \/ \E i \in 1..Len(log): Relink(i) \/ Delete(i)
    \/ \E i \in 1..Len(log), j \in 1..(Len(log) + 1): Duplicate(i, j)

Next == (\E d \in Data: LedgerAppend(d)) \/ Adversary

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety.                                                                 *)
(***************************************************************************)

\* Whatever the adversary did, a file that verifies is a prefix of the true
\* history: nothing in it was altered, inserted, reordered or removed from
\* the middle.
ChainEvidence == Verifies(log) => IsPrefix(DataOf(log), honest)

\* With an external anchor for the length n, the first n records are exactly
\* the true ones.
AnchoredEvidence ==
    \A n \in 0..Len(honest):
        (Verifies(log) /\ Len(log) >= n) =>
            SubSeq(DataOf(log), 1, n) = SubSeq(honest, 1, n)


THEOREM Spec => [](ChainEvidence /\ AnchoredEvidence)

(***************************************************************************)
(* Witnesses: each is expected to be VIOLATED.                             *)
(***************************************************************************)

\* Tampering is reachable.
WitnessNoTampering == IsPrefix(DataOf(log), honest)

\* Truncation of the tail verifies: without an external anchor, deletion of
\* the newest records is not detectable.
WitnessTruncationUndetected == Verifies(log) => DataOf(log) = honest
=============================================================================
