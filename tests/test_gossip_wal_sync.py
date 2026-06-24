# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.gossip_wal_sync — gossip-based WAL sync stub."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.gossip_wal_sync import (
    GossipMessage,
    GossipPeer,
    GossipSyncResult,
    GossipUDPTransport,
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


# ── GossipUDPTransport ────────────────────────────────────────────────────────


class TestGossipUDPTransportSend:
    """send() is tested with a mocked socket to avoid network I/O."""

    def _make_transport(self):
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_socket_cls.return_value = mock_sock
            t = GossipUDPTransport(bind_address="127.0.0.1", bind_port=19460)
        t._sock = mock_sock
        return t, mock_sock

    def test_send_calls_sendto_with_json_payload(self):
        t, sock = self._make_transport()
        msg = GossipMessage(
            sender_id="node-A",
            wal_head_hash="abc123",
            wal_size_bytes=512,
            node_count=10,
            timestamp=0.0,
        )
        result = t.send("10.0.0.2:7946", msg)
        assert result is True
        sock.sendto.assert_called_once()
        args = sock.sendto.call_args[0]
        payload = args[0]
        dest = args[1]
        assert dest == ("10.0.0.2", 7946)
        parsed = GossipMessage.from_json(payload.decode())
        assert parsed.sender_id == "node-A"
        assert parsed.wal_head_hash == "abc123"

    def test_send_returns_false_on_oserror(self):
        t, sock = self._make_transport()
        sock.sendto.side_effect = OSError("network unreachable")
        msg = GossipMessage("x", "h", 0, 0, 0.0)
        result = t.send("10.0.0.1:7946", msg)
        assert result is False

    def test_send_returns_false_on_malformed_address(self):
        t, _ = self._make_transport()
        msg = GossipMessage("x", "h", 0, 0, 0.0)
        result = t.send("no-port-here", msg)
        assert result is False


class TestGossipUDPTransportReceive:
    def _make_transport(self):
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_socket_cls.return_value = mock_sock
            t = GossipUDPTransport(bind_address="127.0.0.1", bind_port=19461)
        t._sock = mock_sock
        return t, mock_sock

    def test_receive_returns_gossip_message_on_valid_json(self):
        t, sock = self._make_transport()
        msg = GossipMessage("node-B", "def456", 1024, 5, 1.0)
        sock.recvfrom.return_value = (msg.to_json().encode(), ("127.0.0.1", 7946))
        result = t.receive(timeout_s=0.1)
        assert result is not None
        assert result.sender_id == "node-B"
        assert result.wal_head_hash == "def456"

    def test_receive_returns_none_on_timeout(self):
        t, sock = self._make_transport()
        sock.recvfrom.side_effect = TimeoutError("timed out")
        result = t.receive(timeout_s=0.01)
        assert result is None

    def test_receive_returns_none_on_invalid_json(self):
        t, sock = self._make_transport()
        sock.recvfrom.return_value = (b"not-json", ("127.0.0.1", 7946))
        result = t.receive(timeout_s=0.1)
        assert result is None

    def test_close_calls_sock_close(self):
        t, sock = self._make_transport()
        t.close()
        sock.close.assert_called_once()


class TestGossipUDPTransportFromEnv:
    def test_from_env_uses_defaults(self):
        with patch("socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value = MagicMock()
            with patch.dict("os.environ", {}, clear=False):
                import os

                os.environ.pop("AEGIS_GOSSIP_BIND_ADDR", None)
                os.environ.pop("AEGIS_GOSSIP_BIND_PORT", None)
                t = GossipUDPTransport.from_env()
        assert t.bind_address == "0.0.0.0"
        assert t.bind_port == 7946

    def test_from_env_respects_env_vars(self):
        with patch("socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value = MagicMock()
            with patch.dict(
                "os.environ",
                {"AEGIS_GOSSIP_BIND_ADDR": "127.0.0.1", "AEGIS_GOSSIP_BIND_PORT": "19500"},
            ):
                t = GossipUDPTransport.from_env()
        assert t.bind_address == "127.0.0.1"
        assert t.bind_port == 19500


# ── GossipWALSyncer.broadcast ─────────────────────────────────────────────────


class TestBroadcast:
    def _make_transport(self, send_ok: bool = True) -> GossipUDPTransport:
        t = MagicMock(spec=GossipUDPTransport)
        t.send.return_value = send_ok
        return t

    def test_broadcast_sends_to_all_peers(self, syncer):
        syncer.add_peer("B", "10.0.0.2:7946")
        syncer.add_peer("C", "10.0.0.3:7946")
        transport = self._make_transport(send_ok=True)
        results = syncer.broadcast(transport, "abc", 512, 10)
        assert results == {"B": True, "C": True}
        assert transport.send.call_count == 2

    def test_broadcast_skips_failed_peers(self, syncer):
        syncer.add_peer("B", "10.0.0.2:7946")
        syncer.mark_peer_failed("B")
        transport = self._make_transport()
        results = syncer.broadcast(transport, "abc", 512, 10)
        assert results["B"] is False
        transport.send.assert_not_called()

    def test_broadcast_records_send_failure(self, syncer):
        syncer.add_peer("B", "10.0.0.2:7946")
        transport = self._make_transport(send_ok=False)
        results = syncer.broadcast(transport, "abc", 512, 10)
        assert results["B"] is False

    def test_broadcast_message_has_correct_fields(self, syncer):
        syncer.add_peer("B", "10.0.0.2:7946")
        transport = self._make_transport()
        syncer.broadcast(transport, "deephash", 999, 42)
        sent_msg = transport.send.call_args[0][1]
        assert sent_msg.wal_head_hash == "deephash"
        assert sent_msg.wal_size_bytes == 999
        assert sent_msg.node_count == 42
        assert sent_msg.sender_id == "node-A"


# ── GossipWALSyncer.receive_one ───────────────────────────────────────────────


class TestReceiveOne:
    def test_receive_one_processes_valid_message(self, syncer):
        syncer.add_peer("node-B", "10.0.0.2:7946")
        msg = GossipMessage("node-B", "xyz", 100, 20, time.time())
        transport = MagicMock(spec=GossipUDPTransport)
        transport.receive.return_value = msg
        result = syncer.receive_one(transport, our_node_count=10)
        assert result is not None
        assert result.decision == SyncDecision.SYNC_NEEDED
        assert result.peer_node_count == 20

    def test_receive_one_returns_none_on_timeout(self, syncer):
        transport = MagicMock(spec=GossipUDPTransport)
        transport.receive.return_value = None
        result = syncer.receive_one(transport, our_node_count=10)
        assert result is None

    def test_receive_one_ignores_own_messages(self, syncer):
        msg = GossipMessage("node-A", "xyz", 100, 20, time.time())
        transport = MagicMock(spec=GossipUDPTransport)
        transport.receive.return_value = msg
        result = syncer.receive_one(transport, our_node_count=10)
        assert result is None
