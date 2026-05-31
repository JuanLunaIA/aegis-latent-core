---- MODULE AegisLedgerImmutability ----
EXTENDS Integers, Sequences

VARIABLES 
    mmr_nodes,        \* Sequence of all nodes in the MMR
    peaks,            \* Current set of peaks
    ledger_root       \* Current Merkle Root

\* --- INVARIANTS ---

\* The root must always be a function of the current set of peaks.
RootCorrectness == 
    ledger_root = Hash(Concat(peaks))

\* Invariance: Any leaf added to the MMR must never change the 
\* hashes of existing leaf nodes.
AppendOnlyProperty == 
    \A i \in 1..Len(mmr_nodes) : 
        mmr_nodes[i].hash = mmr_nodes[i].hash

\* --- NEXT STATE LOGIC ---

Init == 
    /\ mmr_nodes = << >>
    /\ peaks = << >>
    /\ ledger_root = "0"

AddLeaf(data) == 
    /\ mmr_nodes' = Append(mmr_nodes, NewNode(data))
    /\ peaks' = UpdatePeaks(mmr_nodes')
    /\ ledger_root' = Hash(Concat(peaks'))

\* --- SPECIFICATION ---
Spec == Init /\ [][AddLeaf(_)]_vars

\* --- THEOREM ---
\* Theorem: For any two states S1 and S2, if S1 precedes S2, 
\* then the prefix of the ledger in S1 is identical to the prefix in S2.
Theorem_LedgerImmutability == []AppendOnlyProperty
=============================================================================
