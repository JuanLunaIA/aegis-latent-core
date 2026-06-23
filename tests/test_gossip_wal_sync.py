# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.gossip_wal_sync — gossip-based WAL sync stub."""

from __future__ import annotations

import time

import pytest

from aegis.core.gossip_wal_sync import (
    GossipMessage,
    GossipPeer,
    GossipSyncResult,
    GossipWALSyncer,
    SyncDecision,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def syncer() -> GossipWALSyncer:
    return GossipWALSyncer(node_id="node-A", interval_s=5.0)


# ── add_peer ──────────────────────────────────────────────────────────────────


def test_add_peer_returns_gossip_peer(syncer):
    peer = syncer.add_peer("node-B", "10.0.0.2:7946")
    assert isinstance(peer, GossipPeer)


def test_add_peer_stores_peer_id(syncer):
    peer = syncer.add_peer("node-B", "10.0.0.2:7946")
    assert peer.peer_id == "node-B"


def test_add_peer_stores_address(syncer):
    peer = syncer.add_peer("node-C", "192.168.1.5:9000")
    assert peer.address == "192.168.1.5:9000"


def test_add_peer_initial_node_count_zero(syncer):
    peer = syncer.add_peer("node-B", "10.0.0.2:7946")
    assert peer.node_count == 0


def test_add_peer_initial_wal_size_zero(syncer):
    peer = syncer.add_peer("node-B", "10.0.0.2:7946")
    assert peer.wal_size_bytes == 0


def test_add_peer_appears_in_list(syncer):
    syncer.add_peer("node-B", "10.0.0.2:7946")
    ids = [p.peer_id for p in syncer.list_peers()]
    assert "node-B" in ids


# ── remove_peer ───────────────────────────────────────────────────────────────


def test_remove_peer_removes_from_list(syncer):
    syncer.add_peer("node-B", "10.0.0.2:7946")
    syncer.remove_peer("node-B")
    ids = [p.peer_id for p in syncer.list_peers()]
    assert "node-B" not in ids


def test_remove_peer_unknown_no_error(syncer):
    syncer.remove_peer("nonexistent")  # should not raise


# ── list_peers ────────────────────────────────────────────────────────────────


def test_list_peers_empty_initially(syncer):
    assert syncer.list_peers() == []


def test_list_peers_returns_all(syncer):
    syncer.add_peer("B", "10.0.0.2:1")
    syncer.add_peer("C", "10.0.0.3:1")
    assert len(syncer.list_peers()) == 2


# ── build_message ─────────────────────────────────────────────────────────────


def test_build_message_sender_id(syncer):
    msg = syncer.build_message("abc123", 4096, 10)
    assert msg.sender_id == "node-A"


def test_build_message_wal_head_hash(syncer):
    msg = syncer.build_message("deadbeef", 1024, 5)
    assert msg.wal_head_hash == "deadbeef"


def test_build_message_wal_size_bytes(syncer):
    msg = syncer.build_message("hash", 8192, 7)
    assert msg.wal_size_bytes == 8192


def test_build_message_node_count(syncer):
    msg = syncer.build_message("hash", 0, 42)
    assert msg.node_count == 42


def test_build_message_timestamp_is_recent(syncer):
    before = time.time()
    msg = syncer.build_message("h", 0, 0)
    after = time.time()
    assert before <= msg.timestamp <= after


# ── GossipMessage to_json / from_json ────────────────────────────────────────


def test_gossip_message_to_json_roundtrip():
    msg = GossipMessage(
        sender_id="node-X",
        wal_head_hash="abc",
        wal_size_bytes=512,
        node_count=7,
        timestamp=1_700_000_000.0,
    )
    restored = GossipMessage.from_json(msg.to_json())
    assert restored.sender_id == msg.sender_id
    assert restored.wal_head_hash == msg.wal_head_hash
    assert restored.wal_size_bytes == msg.wal_size_bytes
    assert restored.node_count == msg.node_count
    assert restored.timestamp == msg.timestamp


def test_gossip_message_to_dict_has_keys():
    msg = GossipMessage("id", "hash", 0, 0, 1.0)
    d = msg.to_dict()
    for key in ("sender_id", "wal_head_hash", "wal_size_bytes", "node_count", "timestamp"):
        assert key in d


def test_gossip_message_to_json_is_string():
    msg = GossipMessage("id", "hash", 0, 0, 1.0)
    assert isinstance(msg.to_json(), str)


# ── process_message ───────────────────────────────────────────────────────────


def test_process_message_sync_needed(syncer):
    syncer.add_peer("node-B", "10.0.0.2:7946")
    msg = GossipMessage("node-B", "hash", 1024, 100, time.time())
    result = syncer.process_message(msg, our_node_count=50)
    assert result.decision is SyncDecision.SYNC_NEEDED


def test_process_message_peer_stale(syncer):
    syncer.add_peer("node-B", "10.0.0.2:7946")
    msg = GossipMessage("node-B", "hash", 0, 10, time.time())
    result = syncer.process_message(msg, our_node_count=100)
    assert result.decision is SyncDecision.PEER_STALE


def test_process_message_no_sync_needed(syncer):
    syncer.add_peer("node-B", "10.0.0.2:7946")
    msg = GossipMessage("node-B", "hash", 0, 42, time.time())
    result = syncer.process_message(msg, our_node_count=42)
    assert result.decision is SyncDecision.NO_SYNC_NEEDED


def test_process_message_updates_peer_node_count(syncer):
    syncer.add_peer("node-B", "10.0.0.2:7946")
    msg = GossipMessage("node-B", "hash", 0, 77, time.time())
    syncer.process_message(msg, our_node_count=0)
    peer = next(p for p in syncer.list_peers() if p.peer_id == "node-B")
    assert peer.node_count == 77


def test_process_message_auto_registers_unknown_peer(syncer):
    msg = GossipMessage("brand-new", "hash", 0, 5, time.time())
    syncer.process_message(msg, our_node_count=3)
    ids = [p.peer_id for p in syncer.list_peers()]
    assert "brand-new" in ids


def test_process_message_returns_gossip_sync_result(syncer):
    msg = GossipMessage("node-B", "hash", 0, 10, time.time())
    result = syncer.process_message(msg, our_node_count=5)
    assert isinstance(result, GossipSyncResult)


def test_process_message_result_contains_counts(syncer):
    msg = GossipMessage("node-B", "hash", 0, 20, time.time())
    result = syncer.process_message(msg, our_node_count=15)
    assert result.our_node_count == 15
    assert result.peer_node_count == 20


def test_process_message_to_dict_has_decision(syncer):
    msg = GossipMessage("node-B", "hash", 0, 5, time.time())
    result = syncer.process_message(msg, our_node_count=3)
    d = result.to_dict()
    assert "decision" in d


# ── select_sync_target ────────────────────────────────────────────────────────


def test_select_sync_target_none_when_no_peers(syncer):
    assert syncer.select_sync_target() is None


def test_select_sync_target_returns_peer_with_most_nodes(syncer):
    syncer.add_peer("B", "h:1")
    syncer.add_peer("C", "h:2")
    # seed node counts via process_message
    syncer.process_message(GossipMessage("B", "h", 0, 10, time.time()), our_node_count=0)
    syncer.process_message(GossipMessage("C", "h", 0, 50, time.time()), our_node_count=0)
    target = syncer.select_sync_target()
    assert target is not None
    assert target.peer_id == "C"


def test_select_sync_target_none_when_all_zero(syncer):
    syncer.add_peer("B", "h:1")
    # B's node_count is still 0 (never received a message)
    assert syncer.select_sync_target() is None


# ── from_env ──────────────────────────────────────────────────────────────────


def test_from_env_reads_node_id(monkeypatch):
    monkeypatch.setenv("AEGIS_GOSSIP_NODE_ID", "env-node")
    s = GossipWALSyncer.from_env()
    assert s.node_id == "env-node"


def test_from_env_reads_peers(monkeypatch):
    monkeypatch.setenv("AEGIS_GOSSIP_NODE_ID", "me")
    monkeypatch.setenv("AEGIS_GOSSIP_PEERS", "peerA@10.0.0.1:7946,peerB@10.0.0.2:7946")
    s = GossipWALSyncer.from_env()
    ids = {p.peer_id for p in s.list_peers()}
    assert ids == {"peerA", "peerB"}


def test_from_env_reads_interval(monkeypatch):
    monkeypatch.setenv("AEGIS_GOSSIP_NODE_ID", "me")
    monkeypatch.setenv("AEGIS_GOSSIP_INTERVAL_S", "10.5")
    monkeypatch.delenv("AEGIS_GOSSIP_PEERS", raising=False)
    s = GossipWALSyncer.from_env()
    assert s.interval_s == pytest.approx(10.5)


def test_from_env_reads_wal_path(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_GOSSIP_NODE_ID", "me")
    monkeypatch.delenv("AEGIS_GOSSIP_PEERS", raising=False)
    wal = str(tmp_path / "test.wal")
    monkeypatch.setenv("AEGIS_GOSSIP_WAL_PATH", wal)
    s = GossipWALSyncer.from_env()
    assert s.local_wal_path == wal


def test_from_env_empty_peers_no_error(monkeypatch):
    monkeypatch.setenv("AEGIS_GOSSIP_NODE_ID", "me")
    monkeypatch.setenv("AEGIS_GOSSIP_PEERS", "")
    s = GossipWALSyncer.from_env()
    assert s.list_peers() == []


# ── mark_peer_alive / mark_peer_failed / get_peer_health ─────────────────────


def test_mark_peer_alive_updates_last_seen(syncer):
    syncer.add_peer("B", "h:1")
    before = time.time()
    syncer.mark_peer_alive("B")
    after = time.time()
    peer = next(p for p in syncer.list_peers() if p.peer_id == "B")
    assert before <= peer.last_seen <= after


def test_mark_peer_failed_unknown_no_error(syncer):
    syncer.mark_peer_failed("ghost")  # should not raise


def test_get_peer_health_alive_after_mark(syncer):
    syncer.add_peer("B", "h:1")
    syncer.mark_peer_alive("B")
    health = syncer.get_peer_health()
    assert health["B"] is True


def test_get_peer_health_failed_peer_is_false(syncer):
    syncer.add_peer("B", "h:1")
    syncer.mark_peer_alive("B")
    syncer.mark_peer_failed("B")
    health = syncer.get_peer_health()
    assert health["B"] is False


def test_get_peer_health_stale_peer_is_false(syncer):
    syncer.add_peer("B", "h:1")
    # last_seen remains 0 — peer has never been seen
    health = syncer.get_peer_health()
    assert health["B"] is False
