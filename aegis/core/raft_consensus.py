# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.raft_consensus — Domain 4.1 Raft consensus state machine.

Pure-Python Raft (Ongaro & Ousterhout, 2014) data model and state machine.
Handles leader election, log replication RPCs, and commit-index advancement.

Real network I/O requires openraft Rust crate integration — this module
enables comprehensive unit testing of Raft logic without network dependencies.

References:
  - Ongaro, D. & Ousterhout, J. (2014). "In Search of an Understandable
    Consensus Algorithm." USENIX ATC '14.
  - https://raft.github.io/raft.pdf
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Role enumeration ──────────────────────────────────────────────────────────


class RaftRole(str, Enum):
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


# ── Exceptions ────────────────────────────────────────────────────────────────


class RaftError(Exception):
    """Base class for Raft state machine errors."""


class NotLeaderError(RaftError):
    """Raised when a leader-only operation is invoked on a non-leader node."""


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass
class RaftLogEntry:
    """A single entry in the Raft replicated log.

    ``entry_hash`` commits the content of the entry; any mutation to
    index, term, or command will produce a different hash, enabling
    tamper detection on stored logs.
    """

    index: int          # 1-based log index
    term: int           # Election term when this entry was appended
    command: str        # Opaque command string (WAL entry JSON or similar)
    entry_hash: str     # SHA-256 of (index ‖ term ‖ command)

    @classmethod
    def create(cls, index: int, term: int, command: str) -> "RaftLogEntry":
        """Construct a RaftLogEntry, computing entry_hash automatically."""
        raw = f"{index}|{term}|{command}"
        entry_hash = hashlib.sha256(raw.encode()).hexdigest()
        return cls(index=index, term=term, command=command, entry_hash=entry_hash)

    def recompute_hash(self) -> str:
        """Return the expected hash for this entry's current fields."""
        raw = f"{self.index}|{self.term}|{self.command}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def is_hash_valid(self) -> bool:
        """True if entry_hash matches the hash of the current field values."""
        return self.entry_hash == self.recompute_hash()

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "term": self.term,
            "command": self.command,
            "entry_hash": self.entry_hash,
        }


@dataclass
class RaftState:
    """Complete persistent and volatile state of a Raft node.

    Persistent state (must survive restarts):
      - current_term, voted_for, log

    Volatile state (reset on restart):
      - commit_index, last_applied, role, leader_id
    """

    node_id: str
    current_term: int
    voted_for: str | None           # node_id voted for in current_term; None if not voted
    log: list[RaftLogEntry]
    commit_index: int               # Highest log index known to be committed
    last_applied: int               # Highest log index applied to state machine
    role: RaftRole
    leader_id: str | None           # Current known leader

    def last_log_index(self) -> int:
        """Return the index of the last log entry, or 0 if log is empty."""
        return self.log[-1].index if self.log else 0

    def last_log_term(self) -> int:
        """Return the term of the last log entry, or 0 if log is empty."""
        return self.log[-1].term if self.log else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "current_term": self.current_term,
            "voted_for": self.voted_for,
            "log": [e.to_dict() for e in self.log],
            "commit_index": self.commit_index,
            "last_applied": self.last_applied,
            "role": self.role.value,
            "leader_id": self.leader_id,
        }


# ── RPC types ─────────────────────────────────────────────────────────────────


@dataclass
class VoteRequest:
    """RequestVote RPC — broadcast by candidates to solicit votes."""

    term: int
    candidate_id: str
    last_log_index: int
    last_log_term: int


@dataclass
class VoteResponse:
    """Response to RequestVote RPC."""

    term: int
    vote_granted: bool
    voter_id: str


@dataclass
class AppendEntriesRequest:
    """AppendEntries RPC — sent by leader for both heartbeat and log replication."""

    term: int
    leader_id: str
    prev_log_index: int             # Log index immediately preceding new entries
    prev_log_term: int              # Term of prev_log_index entry
    entries: list[RaftLogEntry]     # Empty for heartbeats
    leader_commit: int              # Leader's current commit_index


@dataclass
class AppendEntriesResponse:
    """Response to AppendEntries RPC."""

    term: int
    success: bool
    follower_id: str
    match_index: int                # Highest index known to be replicated on this follower


# ── Core node ─────────────────────────────────────────────────────────────────


class RaftNode:
    """
    Pure-Python Raft state machine. Handles RPCs and produces state transitions.

    Real network I/O requires openraft Rust crate integration — this
    implementation enables comprehensive unit testing of Raft logic without
    network dependencies.

    Invariants:
    - commit_index >= last_applied (log entries are applied in order).
    - A node only votes once per term.
    - Only a LEADER appends new entries or sends AppendEntries RPCs.
    - Stale terms discovered in any RPC trigger a reversion to FOLLOWER.
    """

    def __init__(self, node_id: str, peers: list[str]) -> None:
        self._state = RaftState(
            node_id=node_id,
            current_term=0,
            voted_for=None,
            log=[],
            commit_index=0,
            last_applied=0,
            role=RaftRole.FOLLOWER,
            leader_id=None,
        )
        self._peers: set[str] = set(peers)
        self._votes_received: set[str] = set()
        # Leader-only: next log index to send to each peer (initialized to
        # last_log_index + 1 on becoming leader).
        self._next_index: dict[str, int] = {}
        # Leader-only: highest log index known to be replicated on each peer.
        self._match_index: dict[str, int] = {}

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def state(self) -> RaftState:
        """Read-only snapshot of the current Raft state."""
        return self._state

    @property
    def is_leader(self) -> bool:
        return self._state.role == RaftRole.LEADER

    # ── Election ──────────────────────────────────────────────────────────

    def start_election(self) -> tuple[RaftState, VoteRequest]:
        """Transition to CANDIDATE, increment term, vote for self.

        Returns the updated state and a VoteRequest that should be broadcast
        to all peers.
        """
        self._state.current_term += 1
        self._state.role = RaftRole.CANDIDATE
        self._state.voted_for = self._state.node_id
        self._state.leader_id = None
        self._votes_received = {self._state.node_id}  # vote for self

        req = VoteRequest(
            term=self._state.current_term,
            candidate_id=self._state.node_id,
            last_log_index=self._state.last_log_index(),
            last_log_term=self._state.last_log_term(),
        )
        return self._state, req

    def handle_vote_request(self, req: VoteRequest) -> VoteResponse:
        """Process an incoming RequestVote RPC.

        Grant the vote if ALL of the following hold:
        1. req.term >= current_term (we revert to follower if req.term > ours)
        2. Haven't voted for anyone else in this term (or voted for req.candidate_id)
        3. Candidate's log is at least as up-to-date as ours (§5.4.1)
        """
        # Revert to follower on higher term
        if req.term > self._state.current_term:
            self._state.current_term = req.term
            self._state.role = RaftRole.FOLLOWER
            self._state.voted_for = None
            self._state.leader_id = None
            self._votes_received.clear()

        if req.term < self._state.current_term:
            return VoteResponse(
                term=self._state.current_term,
                vote_granted=False,
                voter_id=self._state.node_id,
            )

        # Check if we can vote for this candidate
        already_voted_for_other = (
            self._state.voted_for is not None
            and self._state.voted_for != req.candidate_id
        )
        if already_voted_for_other:
            return VoteResponse(
                term=self._state.current_term,
                vote_granted=False,
                voter_id=self._state.node_id,
            )

        # Log up-to-date check (§5.4.1):
        # Candidate's last entry must be at least as recent as ours.
        our_last_term = self._state.last_log_term()
        our_last_index = self._state.last_log_index()
        log_ok = (
            req.last_log_term > our_last_term
            or (req.last_log_term == our_last_term and req.last_log_index >= our_last_index)
        )
        if not log_ok:
            return VoteResponse(
                term=self._state.current_term,
                vote_granted=False,
                voter_id=self._state.node_id,
            )

        # Grant vote
        self._state.voted_for = req.candidate_id
        return VoteResponse(
            term=self._state.current_term,
            vote_granted=True,
            voter_id=self._state.node_id,
        )

    def handle_vote_response(self, resp: VoteResponse) -> RaftRole:
        """Process a VoteResponse and potentially become LEADER.

        If we are no longer a CANDIDATE (e.g. already became leader or reverted
        to follower), this is a no-op.  If a majority of the cluster
        (including self) has granted votes, transition to LEADER and initialise
        leader volatile state.

        Returns the current role after processing.
        """
        # Higher term seen → revert to follower
        if resp.term > self._state.current_term:
            self._state.current_term = resp.term
            self._state.role = RaftRole.FOLLOWER
            self._state.voted_for = None
            self._state.leader_id = None
            self._votes_received.clear()
            return self._state.role

        if self._state.role != RaftRole.CANDIDATE:
            return self._state.role

        if resp.vote_granted:
            self._votes_received.add(resp.voter_id)

        # Majority = ceil((cluster_size) / 2) + 1 of cluster_size
        cluster_size = 1 + len(self._peers)  # self + peers
        majority = cluster_size // 2 + 1

        if len(self._votes_received) >= majority:
            self._become_leader()

        return self._state.role

    def _become_leader(self) -> None:
        """Transition to LEADER; initialise leader volatile state."""
        self._state.role = RaftRole.LEADER
        self._state.leader_id = self._state.node_id
        next_idx = self._state.last_log_index() + 1
        for peer in self._peers:
            self._next_index[peer] = next_idx
            self._match_index[peer] = 0

    # ── Log replication ───────────────────────────────────────────────────

    def handle_append_entries(self, req: AppendEntriesRequest) -> AppendEntriesResponse:
        """Process an AppendEntries RPC from the leader.

        Standard Raft log replication (§5.3):
        1. Reject if req.term < current_term.
        2. Revert to follower if req.term >= current_term.
        3. Reject if log doesn't contain req.prev_log_index at req.prev_log_term.
        4. Append new entries, deleting conflicting trailing entries.
        5. Advance commit_index up to min(leader_commit, last_new_entry_index).
        """
        # Rule 1: reject stale leader
        if req.term < self._state.current_term:
            return AppendEntriesResponse(
                term=self._state.current_term,
                success=False,
                follower_id=self._state.node_id,
                match_index=self._state.last_log_index(),
            )

        # Rule 2: higher or equal term → revert to follower
        if req.term >= self._state.current_term:
            self._state.current_term = req.term
            self._state.role = RaftRole.FOLLOWER
            self._state.leader_id = req.leader_id
            self._votes_received.clear()

        # Rule 3: consistency check
        if req.prev_log_index > 0:
            if self._state.last_log_index() < req.prev_log_index:
                # We don't have the entry at prev_log_index
                return AppendEntriesResponse(
                    term=self._state.current_term,
                    success=False,
                    follower_id=self._state.node_id,
                    match_index=self._state.last_log_index(),
                )
            # Find the entry at prev_log_index (1-based → 0-based)
            entry_at_prev = self._state.log[req.prev_log_index - 1]
            if entry_at_prev.term != req.prev_log_term:
                # Conflict: remove the entry and everything after it
                self._state.log = self._state.log[: req.prev_log_index - 1]
                return AppendEntriesResponse(
                    term=self._state.current_term,
                    success=False,
                    follower_id=self._state.node_id,
                    match_index=self._state.last_log_index(),
                )

        # Rule 4: append new entries, handling conflicts
        for new_entry in req.entries:
            idx = new_entry.index  # 1-based
            if idx <= len(self._state.log):
                existing = self._state.log[idx - 1]
                if existing.term != new_entry.term:
                    # Conflict: truncate from here
                    self._state.log = self._state.log[: idx - 1]
                    self._state.log.append(new_entry)
                # else: already have this entry; skip
            else:
                self._state.log.append(new_entry)

        # Rule 5: advance commit_index
        if req.leader_commit > self._state.commit_index:
            last_new = self._state.last_log_index()
            self._state.commit_index = min(req.leader_commit, last_new)

        return AppendEntriesResponse(
            term=self._state.current_term,
            success=True,
            follower_id=self._state.node_id,
            match_index=self._state.last_log_index(),
        )

    def handle_append_entries_response(self, resp: AppendEntriesResponse) -> int:
        """Process AppendEntriesResponse from a follower (leader-side).

        Updates next_index and match_index for the follower.  Advances the
        leader's commit_index when a majority have replicated an entry in the
        current term.

        Returns the new commit_index.
        """
        # Higher term → revert to follower
        if resp.term > self._state.current_term:
            self._state.current_term = resp.term
            self._state.role = RaftRole.FOLLOWER
            self._state.voted_for = None
            self._state.leader_id = None
            self._votes_received.clear()
            return self._state.commit_index

        if self._state.role != RaftRole.LEADER:
            return self._state.commit_index

        peer = resp.follower_id
        if resp.success:
            self._match_index[peer] = max(
                self._match_index.get(peer, 0), resp.match_index
            )
            self._next_index[peer] = self._match_index[peer] + 1
        else:
            # Decrement next_index and retry (simplified back-off)
            self._next_index[peer] = max(1, self._next_index.get(peer, 1) - 1)

        # Advance commit_index: find the highest N such that a majority of
        # nodes have match_index >= N AND log[N-1].term == current_term.
        cluster_size = 1 + len(self._peers)
        majority = cluster_size // 2 + 1

        for n in range(self._state.last_log_index(), self._state.commit_index, -1):
            if n < 1:
                break
            entry = self._state.log[n - 1]
            if entry.term != self._state.current_term:
                continue
            # Count how many nodes (leader + followers) have replicated entry at n
            replicated = 1  # leader itself
            for p in self._peers:
                if self._match_index.get(p, 0) >= n:
                    replicated += 1
            if replicated >= majority:
                self._state.commit_index = n
                break

        return self._state.commit_index

    # ── Leader API ────────────────────────────────────────────────────────

    def append_command(self, command: str) -> RaftLogEntry:
        """Leader only: append a command to the local log.

        Raises NotLeaderError if this node is not the LEADER.
        """
        if not self.is_leader:
            raise NotLeaderError(
                f"Node {self._state.node_id} is {self._state.role.value}, not leader"
            )
        new_index = self._state.last_log_index() + 1
        entry = RaftLogEntry.create(
            index=new_index,
            term=self._state.current_term,
            command=command,
        )
        self._state.log.append(entry)
        return entry

    def build_append_entries(self, peer_id: str) -> AppendEntriesRequest:
        """Leader only: build the AppendEntries RPC for a given peer.

        Uses next_index[peer_id] to determine which entries to send.
        Raises NotLeaderError if not leader.
        Raises KeyError if peer_id is not a known peer.
        """
        if not self.is_leader:
            raise NotLeaderError(
                f"Node {self._state.node_id} is {self._state.role.value}, not leader"
            )
        if peer_id not in self._peers:
            raise KeyError(f"Unknown peer: {peer_id!r}")

        next_idx = self._next_index.get(peer_id, 1)
        prev_log_index = next_idx - 1
        prev_log_term = 0
        if prev_log_index > 0 and prev_log_index <= len(self._state.log):
            prev_log_term = self._state.log[prev_log_index - 1].term

        entries = [e for e in self._state.log if e.index >= next_idx]

        return AppendEntriesRequest(
            term=self._state.current_term,
            leader_id=self._state.node_id,
            prev_log_index=prev_log_index,
            prev_log_term=prev_log_term,
            entries=entries,
            leader_commit=self._state.commit_index,
        )
