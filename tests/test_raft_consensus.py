# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for Domain 4.1 Raft consensus state machine."""

from __future__ import annotations

import pytest

from aegis.core.raft_consensus import (
    AppendEntriesRequest,
    AppendEntriesResponse,
    NotLeaderError,
    RaftLogEntry,
    RaftNode,
    RaftRole,
    VoteRequest,
    VoteResponse,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


def make_node(node_id: str = "n1", peers: list[str] | None = None) -> RaftNode:
    return RaftNode(node_id=node_id, peers=peers or ["n2", "n3"])


def three_node_cluster() -> tuple[RaftNode, RaftNode, RaftNode]:
    n1 = RaftNode("n1", peers=["n2", "n3"])
    n2 = RaftNode("n2", peers=["n1", "n3"])
    n3 = RaftNode("n3", peers=["n1", "n2"])
    return n1, n2, n3


# ── RaftLogEntry ──────────────────────────────────────────────────────────────


def test_raft_log_entry_hash_deterministic():
    e1 = RaftLogEntry.create(index=1, term=1, command="cmd")
    e2 = RaftLogEntry.create(index=1, term=1, command="cmd")
    assert e1.entry_hash == e2.entry_hash


def test_raft_log_entry_hash_changes_with_command():
    e1 = RaftLogEntry.create(index=1, term=1, command="cmd-a")
    e2 = RaftLogEntry.create(index=1, term=1, command="cmd-b")
    assert e1.entry_hash != e2.entry_hash


def test_raft_log_entry_hash_changes_with_index():
    e1 = RaftLogEntry.create(index=1, term=1, command="cmd")
    e2 = RaftLogEntry.create(index=2, term=1, command="cmd")
    assert e1.entry_hash != e2.entry_hash


def test_raft_log_entry_hash_changes_with_term():
    e1 = RaftLogEntry.create(index=1, term=1, command="cmd")
    e2 = RaftLogEntry.create(index=1, term=2, command="cmd")
    assert e1.entry_hash != e2.entry_hash


def test_raft_log_entry_is_hash_valid():
    e = RaftLogEntry.create(index=1, term=1, command="cmd")
    assert e.is_hash_valid()


def test_raft_log_entry_hash_invalid_after_mutation():
    e = RaftLogEntry.create(index=1, term=1, command="cmd")
    e.command = "tampered"
    assert not e.is_hash_valid()


def test_raft_log_entry_to_dict():
    e = RaftLogEntry.create(index=1, term=1, command="cmd")
    d = e.to_dict()
    assert d["index"] == 1
    assert d["term"] == 1
    assert d["command"] == "cmd"
    assert "entry_hash" in d


# ── Initial state ─────────────────────────────────────────────────────────────


def test_initial_role_is_follower():
    node = make_node()
    assert node.state.role == RaftRole.FOLLOWER


def test_initial_term_is_zero():
    node = make_node()
    assert node.state.current_term == 0


def test_initial_log_empty():
    node = make_node()
    assert node.state.log == []


def test_initial_voted_for_is_none():
    node = make_node()
    assert node.state.voted_for is None


def test_initial_commit_index_is_zero():
    node = make_node()
    assert node.state.commit_index == 0


def test_initial_last_applied_is_zero():
    node = make_node()
    assert node.state.last_applied == 0


def test_initial_is_leader_false():
    node = make_node()
    assert not node.is_leader


# ── Election ──────────────────────────────────────────────────────────────────


def test_start_election_increments_term():
    node = make_node()
    node.start_election()
    assert node.state.current_term == 1


def test_start_election_returns_candidate():
    node = make_node()
    state, _ = node.start_election()
    assert state.role == RaftRole.CANDIDATE


def test_start_election_returns_vote_request():
    node = make_node()
    _, req = node.start_election()
    assert isinstance(req, VoteRequest)
    assert req.term == 1
    assert req.candidate_id == "n1"


def test_start_election_votes_for_self():
    node = make_node()
    node.start_election()
    assert node.state.voted_for == "n1"


def test_second_election_increments_term_again():
    node = make_node()
    node.start_election()
    node.start_election()
    assert node.state.current_term == 2


# ── Vote request handling ─────────────────────────────────────────────────────


def test_handle_vote_request_grants_when_log_current():
    voter = make_node("n2", peers=["n1", "n3"])
    req = VoteRequest(term=1, candidate_id="n1", last_log_index=0, last_log_term=0)
    resp = voter.handle_vote_request(req)
    assert resp.vote_granted
    assert resp.voter_id == "n2"


def test_handle_vote_request_denies_stale_term():
    voter = make_node("n2", peers=["n1", "n3"])
    voter.start_election()  # term → 1
    req = VoteRequest(term=0, candidate_id="n1", last_log_index=0, last_log_term=0)
    resp = voter.handle_vote_request(req)
    assert not resp.vote_granted


def test_handle_vote_request_denies_double_vote():
    voter = make_node("n2", peers=["n1", "n3"])
    req1 = VoteRequest(term=1, candidate_id="n1", last_log_index=0, last_log_term=0)
    voter.handle_vote_request(req1)
    req2 = VoteRequest(term=1, candidate_id="n3", last_log_index=0, last_log_term=0)
    resp = voter.handle_vote_request(req2)
    assert not resp.vote_granted


def test_handle_vote_request_denies_stale_log():
    voter = make_node("n2", peers=["n1", "n3"])
    # Give voter a longer log (term 1, index 5)
    voter._state.current_term = 1
    voter._state.log = [RaftLogEntry.create(i, 1, f"cmd{i}") for i in range(1, 6)]
    req = VoteRequest(term=2, candidate_id="n1", last_log_index=2, last_log_term=1)
    resp = voter.handle_vote_request(req)
    assert not resp.vote_granted


def test_handle_vote_request_reverts_to_follower_on_higher_term():
    voter = make_node("n2", peers=["n1", "n3"])
    voter.start_election()  # term → 1, CANDIDATE
    req = VoteRequest(term=3, candidate_id="n1", last_log_index=0, last_log_term=0)
    voter.handle_vote_request(req)
    assert voter.state.role == RaftRole.FOLLOWER
    assert voter.state.current_term == 3


# ── Vote response / leader election ──────────────────────────────────────────


def test_handle_vote_response_majority_becomes_leader():
    node = make_node("n1", peers=["n2", "n3"])
    node.start_election()  # term=1, voted for self
    resp = VoteResponse(term=1, vote_granted=True, voter_id="n2")
    role = node.handle_vote_response(resp)
    assert role == RaftRole.LEADER


def test_handle_vote_response_no_majority_stays_candidate():
    node = RaftNode("n1", peers=["n2", "n3", "n4", "n5"])
    node.start_election()
    resp = VoteResponse(term=1, vote_granted=True, voter_id="n2")
    role = node.handle_vote_response(resp)
    # 2 out of 5 is not majority
    assert role == RaftRole.CANDIDATE


def test_handle_vote_response_higher_term_reverts():
    node = make_node()
    node.start_election()
    resp = VoteResponse(term=99, vote_granted=False, voter_id="n2")
    role = node.handle_vote_response(resp)
    assert role == RaftRole.FOLLOWER
    assert node.state.current_term == 99


# ── Append entries ────────────────────────────────────────────────────────────


def test_handle_append_entries_rejects_stale_term():
    follower = make_node("n2", peers=["n1", "n3"])
    follower._state.current_term = 5
    req = AppendEntriesRequest(
        term=3,
        leader_id="n1",
        prev_log_index=0,
        prev_log_term=0,
        entries=[],
        leader_commit=0,
    )
    resp = follower.handle_append_entries(req)
    assert not resp.success
    assert resp.term == 5


def test_handle_append_entries_rejects_log_inconsistency():
    follower = make_node("n2", peers=["n1", "n3"])
    # follower has an empty log; leader claims prev_log_index=2
    req = AppendEntriesRequest(
        term=1,
        leader_id="n1",
        prev_log_index=2,
        prev_log_term=1,
        entries=[],
        leader_commit=0,
    )
    resp = follower.handle_append_entries(req)
    assert not resp.success


def test_handle_append_entries_appends_entries():
    follower = make_node("n2", peers=["n1", "n3"])
    entries = [RaftLogEntry.create(1, 1, "cmd1")]
    req = AppendEntriesRequest(
        term=1,
        leader_id="n1",
        prev_log_index=0,
        prev_log_term=0,
        entries=entries,
        leader_commit=0,
    )
    resp = follower.handle_append_entries(req)
    assert resp.success
    assert len(follower.state.log) == 1
    assert follower.state.log[0].command == "cmd1"


def test_handle_append_entries_advances_commit_index():
    follower = make_node("n2", peers=["n1", "n3"])
    entries = [
        RaftLogEntry.create(1, 1, "cmd1"),
        RaftLogEntry.create(2, 1, "cmd2"),
    ]
    req = AppendEntriesRequest(
        term=1,
        leader_id="n1",
        prev_log_index=0,
        prev_log_term=0,
        entries=entries,
        leader_commit=2,
    )
    resp = follower.handle_append_entries(req)
    assert resp.success
    assert follower.state.commit_index == 2


def test_handle_append_entries_conflict_truncates_log():
    follower = make_node("n2", peers=["n1", "n3"])
    # Old entries at term 1
    follower._state.log = [
        RaftLogEntry.create(1, 1, "old1"),
        RaftLogEntry.create(2, 1, "old2"),
    ]
    follower._state.current_term = 2
    # Leader sends term=2 entries starting at index 1
    entries = [
        RaftLogEntry.create(1, 2, "new1"),
        RaftLogEntry.create(2, 2, "new2"),
    ]
    req = AppendEntriesRequest(
        term=2,
        leader_id="n1",
        prev_log_index=0,
        prev_log_term=0,
        entries=entries,
        leader_commit=0,
    )
    resp = follower.handle_append_entries(req)
    assert resp.success
    assert follower.state.log[0].term == 2
    assert follower.state.log[0].command == "new1"


# ── Append entries response ────────────────────────────────────────────────────


def test_handle_append_entries_response_advance_commit():
    """Leader's commit_index advances when majority replicates."""
    leader = make_node("n1", peers=["n2", "n3"])
    leader.start_election()
    # n2 granted vote → n1 becomes leader
    leader.handle_vote_response(VoteResponse(term=1, vote_granted=True, voter_id="n2"))
    assert leader.is_leader

    leader.append_command("cmd1")
    # n2 replicates up to index 1
    resp = AppendEntriesResponse(term=1, success=True, follower_id="n2", match_index=1)
    new_commit = leader.handle_append_entries_response(resp)
    # Leader (has idx 1) + n2 (match_index=1) = majority of 3; commit advances
    assert new_commit == 1


def test_handle_append_entries_response_no_commit_without_majority():
    leader = RaftNode("n1", peers=["n2", "n3", "n4", "n5"])
    leader._state.role = RaftRole.LEADER
    leader._state.current_term = 1
    leader._state.leader_id = "n1"
    for p in ["n2", "n3", "n4", "n5"]:
        leader._next_index[p] = 1
        leader._match_index[p] = 0
    leader.append_command("cmd1")

    # Only 1 follower responds (need 3 for majority of 5)
    resp = AppendEntriesResponse(term=1, success=True, follower_id="n2", match_index=1)
    new_commit = leader.handle_append_entries_response(resp)
    assert new_commit == 0  # not enough for majority


def test_handle_append_entries_response_higher_term_reverts():
    leader = make_node("n1", peers=["n2", "n3"])
    leader.start_election()
    leader.handle_vote_response(VoteResponse(term=1, vote_granted=True, voter_id="n2"))
    resp = AppendEntriesResponse(term=99, success=False, follower_id="n2", match_index=0)
    leader.handle_append_entries_response(resp)
    assert leader.state.role == RaftRole.FOLLOWER
    assert leader.state.current_term == 99


# ── Leader commands ────────────────────────────────────────────────────────────


def test_append_command_raises_if_not_leader():
    node = make_node()
    with pytest.raises(NotLeaderError):
        node.append_command("cmd")


def test_append_command_creates_entry_with_correct_index():
    leader = make_node("n1", peers=["n2", "n3"])
    leader.start_election()
    leader.handle_vote_response(VoteResponse(term=1, vote_granted=True, voter_id="n2"))
    assert leader.is_leader
    entry = leader.append_command("cmd1")
    assert entry.index == 1


def test_append_command_uses_current_term():
    leader = make_node("n1", peers=["n2", "n3"])
    leader.start_election()
    leader.handle_vote_response(VoteResponse(term=1, vote_granted=True, voter_id="n2"))
    entry = leader.append_command("cmd1")
    assert entry.term == 1


def test_append_command_increments_index():
    leader = make_node("n1", peers=["n2", "n3"])
    leader.start_election()
    leader.handle_vote_response(VoteResponse(term=1, vote_granted=True, voter_id="n2"))
    e1 = leader.append_command("cmd1")
    e2 = leader.append_command("cmd2")
    assert e2.index == e1.index + 1


def test_build_append_entries_correct_prev():
    leader = make_node("n1", peers=["n2", "n3"])
    leader.start_election()
    leader.handle_vote_response(VoteResponse(term=1, vote_granted=True, voter_id="n2"))
    leader.append_command("cmd1")
    leader.append_command("cmd2")
    req = leader.build_append_entries("n2")
    assert isinstance(req, AppendEntriesRequest)
    assert req.prev_log_index == 0  # next_index starts at 1
    assert req.entries[0].command == "cmd1"


def test_build_append_entries_raises_if_not_leader():
    node = make_node()
    with pytest.raises(NotLeaderError):
        node.build_append_entries("n2")


def test_build_append_entries_raises_unknown_peer():
    leader = make_node("n1", peers=["n2", "n3"])
    leader.start_election()
    leader.handle_vote_response(VoteResponse(term=1, vote_granted=True, voter_id="n2"))
    with pytest.raises(KeyError):
        leader.build_append_entries("n99")


# ── RaftState helpers ─────────────────────────────────────────────────────────


def test_raft_state_last_log_index_empty():
    node = make_node()
    assert node.state.last_log_index() == 0


def test_raft_state_last_log_term_empty():
    node = make_node()
    assert node.state.last_log_term() == 0


def test_raft_state_to_dict_has_required_keys():
    node = make_node()
    d = node.state.to_dict()
    for key in (
        "node_id",
        "current_term",
        "voted_for",
        "log",
        "commit_index",
        "last_applied",
        "role",
        "leader_id",
    ):
        assert key in d


# ── Full 3-node leader election simulation ────────────────────────────────────


def test_full_leader_election_three_nodes():
    """Simulate a complete leader election in a 3-node cluster."""
    n1, n2, n3 = three_node_cluster()

    # n1 starts election
    state, vote_req = n1.start_election()
    assert state.role == RaftRole.CANDIDATE
    assert vote_req.term == 1

    # n2 grants vote
    resp_from_n2 = n2.handle_vote_request(vote_req)
    assert resp_from_n2.vote_granted

    # n3 grants vote
    resp_from_n3 = n3.handle_vote_request(vote_req)
    assert resp_from_n3.vote_granted

    # n1 processes n2's vote → has self + n2 = majority of 3 → LEADER
    role_after_n2 = n1.handle_vote_response(resp_from_n2)
    assert role_after_n2 == RaftRole.LEADER
    assert n1.is_leader

    # n1 appends a command
    entry = n1.append_command("genesis-command")
    assert entry.index == 1
    assert entry.term == 1

    # n1 builds AppendEntries for n2
    ae_req = n1.build_append_entries("n2")
    ae_resp = n2.handle_append_entries(ae_req)
    assert ae_resp.success
    assert len(n2.state.log) == 1

    # Commit advances after n2 acknowledges
    new_commit = n1.handle_append_entries_response(ae_resp)
    assert new_commit == 1
