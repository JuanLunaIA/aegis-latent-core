# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.gossip_wal_sync — SWIM-inspired gossip WAL sync.

Implements a SWIM-inspired gossip protocol for WAL synchronization between
Aegis nodes.  Two layers are provided:

``GossipUDPTransport``
    Real UDP send/receive transport.  Binds to a local address and port,
    sends JSON-encoded :class:`GossipMessage` datagrams to peers, and
    receives them with a configurable timeout.  When no transport is
    provided, :class:`GossipWALSyncer` operates in in-process mode
    (useful for unit tests and single-node deployments).

``GossipWALSyncer``
    Peer state manager and sync-decision engine.  Call
    :meth:`GossipWALSyncer.broadcast` to fan out the local WAL state to all
    registered peers via the transport.  Call
    :meth:`GossipWALSyncer.receive_one` to read a single inbound message
    from the transport and update peer state.

Multi-node HA with strong consistency is provided by the Raft layer
(DX-Enterprise).  Gossip complements Raft by providing eventual-convergence
failure detection and WAL-head comparison across a cluster.

Environment variables (read by :meth:`GossipWALSyncer.from_env`):
  AEGIS_GOSSIP_NODE_ID       this node's ID (default: hostname)
  AEGIS_GOSSIP_PEERS         CSV of "peer_id@host:port"
  AEGIS_GOSSIP_INTERVAL_S    gossip interval in seconds (default: 5.0)
  AEGIS_GOSSIP_WAL_PATH      path to local WAL file
  AEGIS_GOSSIP_BIND_ADDR     local bind address for UDP transport (default: 0.0.0.0)
  AEGIS_GOSSIP_BIND_PORT     local bind port for UDP transport (default: 7946)
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from dataclasses import asdict, dataclass
from enum import Enum

# Max UDP datagram size accepted (prevents amplification; gossip messages are small)
_MAX_DGRAM = 65_535

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_INTERVAL_S: float = 5.0
_STALE_MULTIPLIER: int = 3  # peer is stale if last_seen > interval * 3

# ── Data types ────────────────────────────────────────────────────────────────


@dataclass
class GossipPeer:
    """Snapshot of a remote Aegis peer's gossip state."""

    peer_id: str
    address: str  # "host:port"
    last_seen: float  # UTC epoch
    wal_head_hash: str  # Last known WAL head hash
    wal_size_bytes: int
    node_count: int


@dataclass
class GossipMessage:
    """Wire message broadcast by a gossip round."""

    sender_id: str
    wal_head_hash: str
    wal_size_bytes: int
    node_count: int
    timestamp: float

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable dict representation."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize to a compact JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_json(cls, s: str) -> GossipMessage:
        """Deserialize from a JSON string produced by :meth:`to_json`."""
        d = json.loads(s)
        return cls(
            sender_id=d["sender_id"],
            wal_head_hash=d["wal_head_hash"],
            wal_size_bytes=int(d["wal_size_bytes"]),
            node_count=int(d["node_count"]),
            timestamp=float(d["timestamp"]),
        )


# ── SyncDecision ──────────────────────────────────────────────────────────────


class SyncDecision(str, Enum):  # noqa: UP042 — roadmap API requires str+Enum signature
    """Decision returned by :meth:`GossipWALSyncer.process_message`."""

    NO_SYNC_NEEDED = "no_sync_needed"  # Peer is not ahead
    SYNC_NEEDED = "sync_needed"  # Peer has more nodes than us
    PEER_STALE = "peer_stale"  # Peer has fewer nodes (we are ahead)
    DIVERGED = "diverged"  # Equal-length chains have different known heads
    UNKNOWN = "unknown"  # Can't compare (different chains)


# ── GossipUDPTransport ────────────────────────────────────────────────────────


class GossipUDPTransport:
    """Real UDP transport for gossip messages.

    Binds a UDP socket to ``bind_address:bind_port`` and provides
    ``send`` / ``receive`` primitives.  Each call to ``receive`` returns
    at most one :class:`GossipMessage`, with a configurable timeout so
    callers can drive their own event loop.

    The transport is intentionally minimal: no encryption, no framing,
    no sequence numbers — the gossip layer is designed for best-effort,
    eventually-consistent dissemination.  Confidentiality must be provided
    at the network layer (VPN / WireGuard / IPsec).
    """

    def __init__(
        self,
        bind_address: str = "0.0.0.0",
        bind_port: int = 7946,
    ) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_address, bind_port))
        self.bind_address = bind_address
        self.bind_port = bind_port
        logger.info("GossipUDPTransport: bound to %s:%d", bind_address, bind_port)

    @classmethod
    def from_env(cls) -> GossipUDPTransport:
        """Construct from ``AEGIS_GOSSIP_BIND_ADDR`` / ``AEGIS_GOSSIP_BIND_PORT``."""
        bind_addr = os.environ.get("AEGIS_GOSSIP_BIND_ADDR", "0.0.0.0")
        bind_port = int(os.environ.get("AEGIS_GOSSIP_BIND_PORT", "7946"))
        return cls(bind_address=bind_addr, bind_port=bind_port)

    def send(self, address: str, message: GossipMessage) -> bool:
        """Send ``message`` to ``address`` (``"host:port"``).

        Returns ``True`` on success, ``False`` on network error.
        """
        try:
            host, port_str = address.rsplit(":", 1)
            payload = message.to_json().encode()
            self._sock.sendto(payload, (host, int(port_str)))
            return True
        except (OSError, ValueError) as exc:
            logger.warning("GossipUDPTransport: send to %s failed: %s", address, exc)
            return False

    def receive(self, timeout_s: float = 1.0) -> GossipMessage | None:
        """Receive one gossip message, blocking up to ``timeout_s`` seconds.

        Returns ``None`` on timeout or parse error.
        """
        self._sock.settimeout(timeout_s)
        try:
            data, _ = self._sock.recvfrom(_MAX_DGRAM)
            return GossipMessage.from_json(data.decode())
        except TimeoutError:
            return None
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.warning("GossipUDPTransport: receive error: %s", exc)
            return None

    def close(self) -> None:
        """Release the underlying UDP socket."""
        try:
            self._sock.close()
        except OSError:
            pass


# ── GossipSyncResult ──────────────────────────────────────────────────────────


@dataclass
class GossipSyncResult:
    """Result produced by processing a single gossip message."""

    decision: SyncDecision
    peer: GossipPeer
    our_node_count: int
    peer_node_count: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable dict representation."""
        return {
            "decision": self.decision.value,
            "peer_id": self.peer.peer_id,
            "our_node_count": self.our_node_count,
            "peer_node_count": self.peer_node_count,
        }


# ── GossipWALSyncer ───────────────────────────────────────────────────────────


class GossipWALSyncer:
    """
    SWIM-inspired gossip protocol stub for WAL synchronization between Aegis nodes.

    Real implementation requires UDP multicast or memberlist integration.
    This stub manages peer state and sync decisions using in-process data
    structures, enabling unit testing without actual network I/O.

    Usage::

        syncer = GossipWALSyncer(node_id="node-A")
        syncer.add_peer("node-B", "10.0.0.2:7946")
        msg = syncer.build_message(wal_head_hash="abc...", wal_size_bytes=1024, node_count=42)
        result = syncer.process_message(msg, our_node_count=10)
    """

    def __init__(
        self,
        node_id: str,
        local_wal_path: str | None = None,
        interval_s: float = _DEFAULT_INTERVAL_S,
    ) -> None:
        self.node_id = node_id
        self.local_wal_path = local_wal_path
        self.interval_s = interval_s
        self._peers: dict[str, GossipPeer] = {}
        self._failed: set[str] = set()

    # ── Construction helpers ──────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> GossipWALSyncer:
        """
        Construct a GossipWALSyncer from environment variables.

        AEGIS_GOSSIP_NODE_ID   — node identifier (default: system hostname)
        AEGIS_GOSSIP_PEERS     — CSV of "peer_id@host:port" pairs
        AEGIS_GOSSIP_INTERVAL_S — gossip interval in seconds (default: 5.0)
        AEGIS_GOSSIP_WAL_PATH  — path to local WAL file
        """
        node_id = os.environ.get("AEGIS_GOSSIP_NODE_ID") or socket.gethostname()
        interval_s = float(os.environ.get("AEGIS_GOSSIP_INTERVAL_S", _DEFAULT_INTERVAL_S))
        wal_path = os.environ.get("AEGIS_GOSSIP_WAL_PATH") or None

        syncer = cls(node_id=node_id, local_wal_path=wal_path, interval_s=interval_s)

        peers_raw = os.environ.get("AEGIS_GOSSIP_PEERS", "")
        for token in peers_raw.split(","):
            token = token.strip()
            if not token:
                continue
            if "@" not in token:
                logger.warning(
                    "Skipping malformed peer token (expected peer_id@host:port): %r", token
                )
                continue
            peer_id, address = token.split("@", 1)
            syncer.add_peer(peer_id.strip(), address.strip())

        return syncer

    # ── Peer management ───────────────────────────────────────────────────────

    def add_peer(self, peer_id: str, address: str) -> GossipPeer:
        """Register a new peer and return its initial :class:`GossipPeer` record."""
        peer = GossipPeer(
            peer_id=peer_id,
            address=address,
            last_seen=0.0,
            wal_head_hash="",
            wal_size_bytes=0,
            node_count=0,
        )
        self._peers[peer_id] = peer
        logger.debug("GossipWALSyncer: added peer %s @ %s", peer_id, address)
        return peer

    def remove_peer(self, peer_id: str) -> None:
        """Remove a peer from the known-peers registry."""
        self._peers.pop(peer_id, None)
        self._failed.discard(peer_id)

    def list_peers(self) -> list[GossipPeer]:
        """Return all currently registered peers in insertion order."""
        return list(self._peers.values())

    # ── Message construction ──────────────────────────────────────────────────

    def build_message(
        self,
        wal_head_hash: str,
        wal_size_bytes: int,
        node_count: int,
    ) -> GossipMessage:
        """Build a :class:`GossipMessage` representing our current WAL state."""
        return GossipMessage(
            sender_id=self.node_id,
            wal_head_hash=wal_head_hash,
            wal_size_bytes=wal_size_bytes,
            node_count=node_count,
            timestamp=time.time(),
        )

    # ── Message processing ────────────────────────────────────────────────────

    def process_message(
        self,
        msg: GossipMessage,
        our_node_count: int,
        our_wal_head_hash: str = "",
    ) -> GossipSyncResult:
        """
        Process an incoming gossip message from a peer.

        Updates the peer's state record and returns a :class:`GossipSyncResult`
        indicating whether we need to sync, are ahead, equal, or have diverged.

        This is a metadata-only comparison. It never reads, writes, or transfers WAL bytes.
        A divergence is knowable only when equal node counts have two non-empty head hashes.
        """
        now = time.time()
        peer = self._peers.get(msg.sender_id)
        if peer is None:
            # Auto-register previously unknown peer
            peer = GossipPeer(
                peer_id=msg.sender_id,
                address="",
                last_seen=now,
                wal_head_hash=msg.wal_head_hash,
                wal_size_bytes=msg.wal_size_bytes,
                node_count=msg.node_count,
            )
            self._peers[msg.sender_id] = peer
        else:
            self._peers[msg.sender_id] = GossipPeer(
                peer_id=peer.peer_id,
                address=peer.address,
                last_seen=now,
                wal_head_hash=msg.wal_head_hash,
                wal_size_bytes=msg.wal_size_bytes,
                node_count=msg.node_count,
            )
        self._failed.discard(msg.sender_id)

        peer_count = msg.node_count
        if peer_count > our_node_count:
            decision = SyncDecision.SYNC_NEEDED
        elif peer_count < our_node_count:
            decision = SyncDecision.PEER_STALE
        elif our_wal_head_hash and msg.wal_head_hash:
            decision = (
                SyncDecision.NO_SYNC_NEEDED
                if msg.wal_head_hash == our_wal_head_hash
                else SyncDecision.DIVERGED
            )
        else:
            decision = SyncDecision.UNKNOWN

        return GossipSyncResult(
            decision=decision,
            peer=self._peers[msg.sender_id],
            our_node_count=our_node_count,
            peer_node_count=peer_count,
        )

    # ── Sync target selection ─────────────────────────────────────────────────

    def select_sync_target(self) -> GossipPeer | None:
        """
        Return the peer with the most nodes that we are behind on.

        Returns ``None`` if there are no peers or all peers have an equal or
        smaller node count relative to each other (node count 0 means unknown).
        The caller should compare our own node count against the returned peer's
        ``node_count`` before initiating a sync.
        """
        candidates = [
            p for p in self._peers.values() if p.node_count > 0 and p.peer_id not in self._failed
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda p: p.node_count)

    # ── Transport integration ─────────────────────────────────────────────────

    def broadcast(
        self,
        transport: GossipUDPTransport,
        wal_head_hash: str,
        wal_size_bytes: int,
        node_count: int,
    ) -> dict[str, bool]:
        """Send our current WAL state to all registered peers via ``transport``.

        Returns a ``{peer_id: success}`` map indicating which sends succeeded.
        Failed peers are NOT automatically marked failed — the caller should
        drive failure detection (SWIM probe/probe-req) independently.
        """
        msg = self.build_message(
            wal_head_hash=wal_head_hash,
            wal_size_bytes=wal_size_bytes,
            node_count=node_count,
        )
        results: dict[str, bool] = {}
        for peer_id, peer in list(self._peers.items()):
            if peer_id in self._failed:
                results[peer_id] = False
                continue
            ok = transport.send(peer.address, msg)
            results[peer_id] = ok
            if not ok:
                logger.warning(
                    "GossipWALSyncer: broadcast to peer %s @ %s failed",
                    peer_id,
                    peer.address,
                )
        return results

    def receive_one(
        self,
        transport: GossipUDPTransport,
        our_node_count: int,
        timeout_s: float = 1.0,
        our_wal_head_hash: str = "",
    ) -> GossipSyncResult | None:
        """Receive one inbound gossip message from ``transport`` and process it.

        Returns a :class:`GossipSyncResult` when a valid message arrives,
        or ``None`` on timeout.
        """
        msg = transport.receive(timeout_s=timeout_s)
        if msg is None:
            return None
        if msg.sender_id == self.node_id:
            return None  # ignore our own reflected broadcasts
        return self.process_message(
            msg,
            our_node_count=our_node_count,
            our_wal_head_hash=our_wal_head_hash,
        )

    # ── Health tracking ───────────────────────────────────────────────────────

    def mark_peer_alive(self, peer_id: str) -> None:
        """Record that a peer was observed alive right now."""
        peer = self._peers.get(peer_id)
        if peer is None:
            logger.warning("mark_peer_alive: unknown peer %r", peer_id)
            return
        self._peers[peer_id] = GossipPeer(
            peer_id=peer.peer_id,
            address=peer.address,
            last_seen=time.time(),
            wal_head_hash=peer.wal_head_hash,
            wal_size_bytes=peer.wal_size_bytes,
            node_count=peer.node_count,
        )
        self._failed.discard(peer_id)

    def mark_peer_failed(self, peer_id: str) -> None:
        """Record that a peer probe failed (SWIM failure detection)."""
        if peer_id in self._peers:
            self._failed.add(peer_id)

    def get_peer_health(self) -> dict[str, bool]:
        """
        Return ``{peer_id: is_alive}`` for all known peers.

        A peer is considered alive if ``last_seen`` is within the last
        ``interval_s * STALE_MULTIPLIER`` seconds AND it has not been
        explicitly marked failed via :meth:`mark_peer_failed`.
        """
        now = time.time()
        threshold = self.interval_s * _STALE_MULTIPLIER
        return {
            peer_id: (
                peer_id not in self._failed
                and peer.last_seen > 0
                and (now - peer.last_seen) < threshold
            )
            for peer_id, peer in self._peers.items()
        }
