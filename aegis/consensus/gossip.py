# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Anti-entropy gossip over the Causal-Merkle CRDT.

`CausalMmr` reconciles replicas that disagree about ordering: `join` is
idempotent, commutative and associative, so replicas that exchange leaf sets
reach one root whatever order they merge in. That is an algebra, not a
deployment. This module is the part that makes it run — a peer set, a
transport, a schedule, and the failure handling a network forces on all three.

The exchange
------------

Each round, per peer:

1. **Compare roots.** A `GET` returns the peer's root, 32 bytes of hex. If it
   equals ours, the replicas already agree and the round ends. In a converged
   cluster — the steady state — this is all that happens, so the cost of
   staying converged is one small request per peer per interval rather than a
   full state transfer.
2. **Exchange state.** When the roots differ, we `POST` our encoded leaf set;
   the peer merges it and returns its own. We merge that in turn. One round
   therefore moves information in both directions, which is what keeps a
   partition heal to O(diameter) rounds rather than O(n).

Anti-entropy rather than a log: there is no sequence to be at the end of, no
leader to be behind, and a replica that misses any number of rounds catches up
completely on its next successful one.

What this establishes
---------------------

Replicas that can reach one another converge on a single root, and a replica
that was partitioned converges once the partition heals. Convergence is not
agreement about truth: `join` reconciles replicas that disagree about
*ordering*, not replicas that *lie*. A replica that fabricates leaves has them
merged like any other, and mTLS establishes only that a peer holds a
certificate the operator issued — not that what it says is true. This is not
Byzantine fault tolerance, it is not consensus, and it does not make a
fabricated leaf detectable. Nor does it give the *ledger* cross-replica
ordering: this accumulator is a separate structure, and each replica's WAL
remains its own chain (`CLM-012`).

Two costs that are properties of the design rather than of this
implementation. A full exchange is O(state), so the bytes on the wire grow
with history and the digest check above is what keeps that off the steady
path. And there is no membership protocol: the peer set is static
configuration, so a replica that is added, removed or renamed is an operator
action, not something the cluster discovers.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

# A peer's encoded state is bounded before it is parsed. The Rust decoder
# bounds the leaf count, but that check happens after the body is in memory;
# this one happens before, so a peer cannot spend our RAM to reach it.
MAX_STATE_BYTES = 64 * 1024 * 1024

# Roots are hex-encoded SHA-256.
ROOT_HEX_LENGTH = 64


class PeerStateRejectedError(ValueError):
    """A peer's state was refused, and this replica did not advance.

    Always total: a state that does not decode wholly is not merged at all, so
    a truncated, oversized or malformed exchange leaves the replica exactly
    where it was rather than half-advanced.
    """


class CausalAccumulator(Protocol):
    """The slice of `CausalMmr` this module needs.

    A protocol rather than the concrete class so the daemon can be exercised
    against the Rust accumulator and against a pure-Python stand-in with the
    same algebra — and so this module does not require the native extension to
    import.
    """

    @property
    def root(self) -> str:
        """The bagged root over every leaf held, as lowercase hex."""

    @property
    def leaf_count(self) -> int:
        """How many leaves this replica holds."""

    def encode_state(self) -> bytes:
        """This replica's leaf set in the canonical wire form."""

    def merge_encoded(self, state: bytes) -> CausalAccumulator:
        """Join a peer's encoded state, returning the merged accumulator."""


@dataclass(frozen=True, slots=True)
class GossipPeer:
    """One reachable replica.

    `name` is matched against the peer certificate, so it is an identity
    rather than a label: a peer that presents a certificate for someone else
    is refused by the TLS layer before this module sees a byte.
    """

    name: str
    url: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("peer name must not be empty")
        if not self.url.startswith("https://"):
            # Plain HTTP would carry leaf digests and the cluster's topology
            # in the clear and authenticate nobody. There is no opt-out,
            # because a gossip mesh that can be joined by anyone who can route
            # to it is not a mesh, it is an input.
            raise ValueError(f"peer {self.name!r} must be reached over https, got {self.url!r}")


@dataclass(frozen=True, slots=True)
class GossipSettings:
    """Static configuration for one replica's participation."""

    replica_id: int
    peers: tuple[GossipPeer, ...] = ()
    interval_seconds: float = 5.0
    request_timeout_seconds: float = 3.0
    client_certificate: str = ""
    client_private_key: str = ""
    certificate_authority: str = ""
    max_state_bytes: int = MAX_STATE_BYTES

    def __post_init__(self) -> None:
        if self.interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if self.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if self.max_state_bytes <= 0:
            raise ValueError("max_state_bytes must be positive")
        names = [peer.name for peer in self.peers]
        if len(set(names)) != len(names):
            raise ValueError("peer names must be unique")

    @property
    def mutual_tls_configured(self) -> bool:
        return bool(self.client_certificate and self.client_private_key)


@dataclass(frozen=True, slots=True)
class GossipStats:
    """What happened, so an operator can tell converged from unreachable.

    A cluster that is quiet because everyone agrees and a cluster that is
    quiet because nobody can connect look identical from the root alone.
    `rounds_converged` rising while `peer_failures` stays flat is the first;
    the reverse is the second.
    """

    rounds_started: int = 0
    rounds_converged: int = 0
    states_merged: int = 0
    peer_failures: int = 0
    states_rejected: int = 0
    leaves_learned: int = 0

    def _with(self, **changes: int) -> GossipStats:
        return replace(self, **changes)


@dataclass
class _PeerHealth:
    """Backoff state for one peer.

    A peer that is down must not be retried at the gossip interval forever:
    that turns an outage into a load source aimed at whatever is trying to
    recover. Backoff is capped so a peer that returns is picked up promptly.
    """

    consecutive_failures: int = 0
    skip_rounds: int = 0

    def succeeded(self) -> None:
        self.consecutive_failures = 0
        self.skip_rounds = 0

    def failed(self, cap: int = 6) -> None:
        self.consecutive_failures += 1
        self.skip_rounds = min(2**self.consecutive_failures, 2**cap)

    def should_skip(self) -> bool:
        if self.skip_rounds > 0:
            self.skip_rounds -= 1
            return True
        return False


class GossipTransport(Protocol):
    """How a round reaches a peer.

    Separated from the daemon so the scheduling and merge logic can be tested
    without sockets, and so a deployment can substitute a transport without
    touching the reconciliation.
    """

    async def fetch_root(self, peer: GossipPeer) -> str:
        """Ask a peer for its current root, so a round can skip when equal."""

    async def exchange_state(self, peer: GossipPeer, state: bytes) -> bytes:
        """Send this replica's state to a peer and return the peer's own."""

    async def aclose(self) -> None:
        """Release whatever the transport holds open."""


class GossipDaemon:
    """Runs anti-entropy rounds against a static peer set.

    The accumulator is replaced rather than mutated on every merge, because
    `join` returns a new value: the daemon holds the current one under a lock
    so a round in flight cannot publish a state that a concurrent local append
    has already superseded.
    """

    def __init__(
        self,
        accumulator: CausalAccumulator,
        settings: GossipSettings,
        transport: GossipTransport,
    ) -> None:
        self._accumulator = accumulator
        self._settings = settings
        self._transport = transport
        self._lock = asyncio.Lock()
        self._health: dict[str, _PeerHealth] = {peer.name: _PeerHealth() for peer in settings.peers}
        self._stats = GossipStats()
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    @property
    def accumulator(self) -> CausalAccumulator:
        return self._accumulator

    @property
    def settings(self) -> GossipSettings:
        return self._settings

    @property
    def stats(self) -> GossipStats:
        return self._stats

    @property
    def root(self) -> str:
        return self._accumulator.root

    async def encode_state(self) -> bytes:
        """This replica's state, taken under the lock.

        Serving a state while a merge is publishing would hand a peer a
        snapshot that never existed as a whole.
        """
        async with self._lock:
            return self._accumulator.encode_state()

    async def merge_state(self, state: bytes) -> bool:
        """Merge a peer's encoded state. Returns whether anything was learned.

        Fail-closed on the peer's behalf as well as our own: a state that the
        decoder refuses raises rather than being partially applied, and the
        caller — a round, or the inbound handler — decides what to do about a
        peer that sends one.
        """
        if len(state) > self._settings.max_state_bytes:
            self._stats = self._stats._with(states_rejected=self._stats.states_rejected + 1)
            raise PeerStateRejectedError(
                f"state is {len(state)} bytes; the ceiling is {self._settings.max_state_bytes}"
            )
        async with self._lock:
            before_root = self._accumulator.root
            before_leaves = self._accumulator.leaf_count
            try:
                merged = self._accumulator.merge_encoded(state)
            except (ValueError, TypeError) as exc:
                self._stats = self._stats._with(states_rejected=self._stats.states_rejected + 1)
                raise PeerStateRejectedError(str(exc)) from exc
            self._accumulator = merged
            learned = merged.leaf_count - before_leaves
            changed = merged.root != before_root
            if changed:
                self._stats = self._stats._with(
                    states_merged=self._stats.states_merged + 1,
                    leaves_learned=self._stats.leaves_learned + max(learned, 0),
                )
            return changed

    async def run_round(self) -> GossipStats:
        """One anti-entropy pass over every peer.

        A peer that fails is counted and backed off; it never aborts the
        round, because one unreachable replica must not stop the others from
        converging.
        """
        self._stats = self._stats._with(rounds_started=self._stats.rounds_started + 1)
        converged = True

        for peer in self._settings.peers:
            health = self._health[peer.name]
            if health.should_skip():
                continue
            try:
                peer_root = await self._transport.fetch_root(peer)
                if _is_root(peer_root) and peer_root == self._accumulator.root:
                    health.succeeded()
                    continue

                converged = False
                ours = await self.encode_state()
                theirs = await self._transport.exchange_state(peer, ours)
                await self.merge_state(theirs)
                health.succeeded()
            except PeerStateRejectedError as exc:
                # A peer that sends something we refuse is a peer whose
                # operator needs to know; it is not a transport failure and it
                # is not backed off, because the next round may be fine.
                logger.warning("gossip: peer %s sent a state we refused: %s", peer.name, exc)
            except Exception as exc:  # noqa: BLE001 - one peer must not stop the round
                health.failed()
                self._stats = self._stats._with(peer_failures=self._stats.peer_failures + 1)
                logger.warning(
                    "gossip: round with peer %s failed (%s); backing off %d round(s)",
                    peer.name,
                    exc,
                    health.skip_rounds,
                )

        if converged and self._settings.peers:
            self._stats = self._stats._with(rounds_converged=self._stats.rounds_converged + 1)
        return self._stats

    async def _loop(self) -> None:
        while not self._stopping.is_set():
            try:
                await self.run_round()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the loop outlives any one round
                logger.exception("gossip: round raised; continuing")
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self._settings.interval_seconds
                )
            except TimeoutError:
                continue

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop(), name="aegis-gossip")

    async def stop(self) -> None:
        """Stop the loop and release the transport.

        Idempotent, because a shutdown path that fails when called twice turns
        one error into two.
        """
        self._stopping.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        await self._transport.aclose()

    async def __aenter__(self) -> GossipDaemon:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.stop()


def _is_root(value: object) -> bool:
    """Whether `value` is plausibly a root, before it is compared to ours.

    A peer that returns an empty body, an error page or a truncated digest
    must produce a state exchange rather than an accidental match. Comparing
    unvalidated strings would let `""` from a broken peer equal `""` from a
    broken us.
    """
    return (
        isinstance(value, str)
        and len(value) == ROOT_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def build_client_ssl_context(settings: GossipSettings) -> ssl.SSLContext:
    """The client side of the mesh's mutual TLS.

    Verification is not optional and there is no flag to turn it off. A gossip
    peer supplies leaves that enter every replica's accumulator, so "who is
    this" is the whole security boundary; a mesh that accepts an unverified
    peer has no boundary at all. `check_hostname` stays on, so the certificate
    must actually name the peer rather than merely chain to the CA.
    """
    if not settings.certificate_authority:
        raise ValueError(
            "gossip requires a certificate authority: peers supply leaves that "
            "enter this replica's accumulator, so they must be authenticated"
        )
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=settings.certificate_authority
    )
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if settings.mutual_tls_configured:
        context.load_cert_chain(settings.client_certificate, settings.client_private_key)
    return context


def build_server_ssl_context(
    certificate: str, private_key: str, certificate_authority: str
) -> ssl.SSLContext:
    """The server side: a peer must present a certificate we can verify.

    `CERT_REQUIRED` on the server is what makes this mutual. Without it the
    endpoint would accept state from anyone who could route to it, and the
    client-side verification above would be protecting only one direction of a
    two-way exchange.
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=certificate_authority)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certificate, private_key)
    return context


def peer_names(settings: GossipSettings) -> Sequence[str]:
    """Configured peer names, for logging and readiness reporting."""
    return [peer.name for peer in settings.peers]


def parse_peers(specification: str) -> tuple[GossipPeer, ...]:
    """Parse `name=url,name=url` into peers.

    Fails closed on every malformed entry rather than skipping it. A peer
    silently dropped because of a typo is a replica that never converges and
    reports nothing wrong — the failure this mesh is least able to notice on
    its own, since a peer that is absent from the configuration is
    indistinguishable from a cluster that has none.
    """
    peers: list[GossipPeer] = []
    for raw in specification.split(","):
        entry = raw.strip()
        if not entry:
            continue
        name, separator, url = entry.partition("=")
        if not separator:
            raise ValueError(f"peer {entry!r} is not in 'name=url' form")
        peers.append(GossipPeer(name=name.strip(), url=url.strip()))
    return tuple(peers)


def settings_from_config(config: object) -> GossipSettings:
    """Build `GossipSettings` from an `AegisSettings`-shaped object.

    Takes the object structurally rather than importing `AegisSettings`, so
    this package stays independent of the gateway's configuration model and
    can be driven from a test or a standalone runner.
    """
    # The peer list is rendered from the replica count, so it names every
    # replica including this one. A replica that gossips with itself would
    # burn a round per interval proving it agrees with itself, and would
    # report a converged mesh on the strength of that agreement alone.
    self_name = str(getattr(config, "gossip_self_name", "") or "")
    peers = tuple(
        peer
        for peer in parse_peers(str(getattr(config, "gossip_peers", "") or ""))
        if peer.name != self_name
    )
    return GossipSettings(
        replica_id=int(getattr(config, "gossip_replica_id", 0)),
        peers=peers,
        interval_seconds=float(getattr(config, "gossip_interval_seconds", 5.0)),
        client_certificate=str(getattr(config, "gossip_client_certificate", "") or ""),
        client_private_key=str(getattr(config, "gossip_client_private_key", "") or ""),
        certificate_authority=str(getattr(config, "gossip_certificate_authority", "") or ""),
    )
