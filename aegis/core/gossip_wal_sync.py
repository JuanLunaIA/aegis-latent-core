# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.gossip_wal_sync — Domain 3.3 gossip-based WAL sync stub.

Implements a SWIM-inspired gossip protocol stub for WAL synchronization between
Aegis nodes.  Real implementation requires UDP multicast or a memberlist
integration.  This stub manages peer state and sync decisions using in-process
data structures, enabling unit testing without actual network I/O.

Environment variables (read by :meth:`GossipWALSyncer.from_env`):
  AEGIS_GOSSIP_NODE_ID       this node's ID (default: hostname)
  AEGIS_GOSSIP_PEERS         CSV of "peer_id@host:port"
  AEGIS_GOSSIP_INTERVAL_S    gossip interval in seconds (default: 5.0)
  AEGIS_GOSSIP_WAL_PATH      path to local WAL file
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from dataclasses import asdict, dataclass
from enum import Enum

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

    def to_dict(self) -> dict:
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
    UNKNOWN = "unknown"  # Can't compare (different chains)


# ── GossipSyncResult ──────────────────────────────────────────────────────────


@dataclass
class GossipSyncResult:
    """Result produced by processing a single gossip message."""

    decision: SyncDecision
    peer: GossipPeer
    our_node_count: int
    peer_node_count: int

    def to_dict(self) -> dict:
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
    ) -> GossipSyncResult:
        """
        Process an incoming gossip message from a peer.

        Updates the peer's state record and returns a :class:`GossipSyncResult`
        indicating whether we need to sync, are ahead, or are equal.
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
        else:
            decision = SyncDecision.NO_SYNC_NEEDED

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
