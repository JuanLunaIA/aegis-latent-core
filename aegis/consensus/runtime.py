# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.consensus.runtime — start and stop the gossip mesh alongside the gateway.

`gossip.py` runs anti-entropy rounds and `transport.py` carries them; neither
knows anything about the gateway. This module is the only place that does, and
it exists so `aegis/proxy/app.py` gains a start call and a stop call rather than
a subsystem.

Two things are started, and both halves are needed for a mesh: the daemon, which
reaches *out* to peers on a timer, and a listener, which lets peers reach *in*.
The listener is its own ASGI app on its own port with its own TLS material —
never routes on the gateway's listener. The gateway's listener carries customer
traffic and is reachable from wherever clients are; this one demands a client
certificate issued by the cluster CA. Sharing a listener would mean one
misconfiguration exposes both.

What this does not change
-------------------------
Nothing about the audit ledger. The mesh reconciles the ``CausalMmr``
accumulator, which is a separate structure with a separate root; each replica's
WAL remains its own single-writer chain and no receipt, root or inclusion proof
the ledger issues is affected by enabling this. That boundary is the whole
reason the daemon does not touch `CryptographicAuditLedger`, and
`aegis.core.a2a.verify_cluster_receipt` documents the verifier-side half of it.

Startup ordering
----------------
This must start **before** the seccomp filter in the gateway's lifespan. Reading
the certificate, the key and the CA bundle needs `openat`, and binding the
listener needs a socket the filter is not expecting; doing it afterwards fails
in a way that looks like a TLS problem and is not.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.consensus.gossip import (
    GossipDaemon,
    GossipSettings,
    peer_names,
    settings_from_config,
)
from aegis.consensus.transport import HttpGossipTransport, build_gossip_app

if TYPE_CHECKING:  # pragma: no cover - typing only
    import uvicorn

logger = logging.getLogger(__name__)

__all__ = ["GossipRuntime", "GossipStartupError", "start_gossip"]

_STARTUP_POLL_SECONDS = 0.02
_STARTUP_ATTEMPTS = 250
_SHUTDOWN_TIMEOUT_SECONDS = 5.0


class GossipStartupError(RuntimeError):
    """Gossip was enabled but could not be started.

    Raised rather than logged-and-skipped because the two states are not
    equivalent to an operator: a replica that was asked to join a mesh and
    silently did not will look healthy while diverging from every peer. The
    caller decides whether that is fatal — the gateway treats it as fatal under
    strict enforcement and as a loud error otherwise, matching how it already
    treats an unavailable LSM or seccomp filter.
    """


@dataclass
class GossipRuntime:
    """A running mesh: the outbound daemon, and the listener peers reach."""

    daemon: GossipDaemon
    server: uvicorn.Server
    task: asyncio.Task[None]

    async def aclose(self) -> None:
        """Stop both halves, tolerating either already being down.

        Ordered daemon-first: stopping the listener while a round is in flight
        would have this replica fail its own peer's exchange and log a round
        failure on the way out, which reads like a fault and is just shutdown.
        """
        with contextlib.suppress(Exception):
            await self.daemon.stop()
        self.server.should_exit = True
        with contextlib.suppress(TimeoutError, asyncio.CancelledError, Exception):
            await asyncio.wait_for(self.task, timeout=_SHUTDOWN_TIMEOUT_SECONDS)
        if not self.task.done():
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self.task


def _require_readable(label: str, path: str) -> str:
    """Fail on missing TLS material here, with the field name, not inside TLS.

    ``load_cert_chain`` on an absent file raises an ``OSError`` naming a path
    and not which setting produced it, which for three separate PEM settings is
    a genuinely slow thing to diagnose.
    """
    if not path:
        raise GossipStartupError(
            f"gossip is enabled but {label} is not set; the mesh requires mutual TLS "
            "and there is no option to skip verification"
        )
    if not Path(path).is_file():
        raise GossipStartupError(f"gossip {label} does not exist or is not a file: {path}")
    return path


async def start_gossip(config: Any) -> GossipRuntime | None:
    """Start the mesh for this replica, or return ``None`` when it is off.

    Args:
        config: An ``AegisSettings``-shaped object. Read structurally, as
            ``settings_from_config`` does, so this stays testable without the
            gateway's configuration model.

    Returns:
        The running mesh, or ``None`` when ``gossip_enabled`` is false.

    Raises:
        GossipStartupError: Gossip is enabled but cannot run — the native
            accumulator is missing, TLS material is absent, or the listener
            did not come up.
    """
    if not bool(getattr(config, "gossip_enabled", False)):
        return None

    settings = settings_from_config(config)
    certificate = _require_readable(
        "gossip_client_certificate", str(getattr(config, "gossip_client_certificate", "") or "")
    )
    private_key = _require_readable(
        "gossip_client_private_key", str(getattr(config, "gossip_client_private_key", "") or "")
    )
    authority = _require_readable(
        "gossip_certificate_authority",
        str(getattr(config, "gossip_certificate_authority", "") or ""),
    )

    accumulator = _new_accumulator(settings.replica_id)
    daemon = GossipDaemon(
        accumulator=accumulator,
        settings=settings,
        transport=HttpGossipTransport(settings),
    )
    server = _build_server(
        daemon,
        host=str(getattr(config, "gossip_bind_host", "0.0.0.0") or "0.0.0.0"),  # noqa: S104
        port=int(getattr(config, "gossip_bind_port", 9443)),
        certificate=certificate,
        private_key=private_key,
        authority=authority,
    )

    task = asyncio.create_task(server.serve(), name="aegis-gossip-listener")
    await _await_listening(server, task)
    await daemon.start()

    logger.info(
        "gossip mesh started: replica_id=%d listening on %s:%d, peers=%s",
        settings.replica_id,
        getattr(config, "gossip_bind_host", "0.0.0.0"),  # noqa: S104
        int(getattr(config, "gossip_bind_port", 9443)),
        list(peer_names(settings)) or "<none configured>",
    )
    if not settings.peers:
        # Not fatal — a one-replica cluster is a legitimate deployment, and a
        # rollout can reach this state briefly — but silence here would look
        # exactly like a converged mesh, so say it once.
        logger.warning(
            "gossip is enabled with no peers to reconcile against; this replica "
            "will report a converged mesh on the strength of agreeing with itself"
        )
    return GossipRuntime(daemon=daemon, server=server, task=task)


def _new_accumulator(replica_id: int) -> Any:
    """The native ``CausalMmr``, or a startup failure naming what to build.

    Deliberately no Python stand-in. An accumulator that produced roots the
    other replicas do not compute would converge on nothing while reporting
    rounds as successful.
    """
    from aegis.engines.agentis import AgentisEngine, CausalMmrUnavailableError

    try:
        return AgentisEngine.new_causal_accumulator(replica_id)
    except CausalMmrUnavailableError as exc:
        raise GossipStartupError(
            f"gossip requires the native CausalMmr accumulator: {exc}"
        ) from exc


def _build_server(
    daemon: GossipDaemon,
    *,
    host: str,
    port: int,
    certificate: str,
    private_key: str,
    authority: str,
) -> uvicorn.Server:
    """The inbound listener, with mutual TLS that cannot be turned off.

    ``ssl_cert_reqs=CERT_REQUIRED`` is what makes it mutual: without it the
    endpoint would accept state from anyone who could route to it, and the
    client-side verification the daemon performs would be protecting one
    direction of a two-way exchange.
    """
    import uvicorn

    return uvicorn.Server(
        uvicorn.Config(
            build_gossip_app(daemon),
            host=host,
            port=port,
            log_level="warning",
            ssl_certfile=certificate,
            ssl_keyfile=private_key,
            ssl_ca_certs=authority,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
        )
    )


async def _await_listening(server: uvicorn.Server, task: asyncio.Task[None]) -> None:
    """Block until the listener is actually serving, or fail saying so.

    ``server.started`` and not a connect probe: the kernel accepts into the
    backlog as soon as the socket is bound, so a replica that bound but never
    scheduled its handler answers a probe and then times out every real
    request — a failure mode this repository has already been bitten by in the
    gossip test harness.
    """
    for _ in range(_STARTUP_ATTEMPTS):
        if server.started:
            return
        if task.done():
            # serve() returned or raised before it ever started; surface the
            # real cause (a bind failure, bad PEM) rather than a timeout.
            exc = task.exception()
            raise GossipStartupError(f"gossip listener exited during startup: {exc}") from exc
        await asyncio.sleep(_STARTUP_POLL_SECONDS)
    task.cancel()
    raise GossipStartupError(
        f"gossip listener did not start within {_STARTUP_ATTEMPTS * _STARTUP_POLL_SECONDS:.1f}s"
    )


def describe(
    runtime: GossipRuntime | None, settings: GossipSettings | None = None
) -> dict[str, Any]:
    """Operator-facing view of the mesh, for `/health` and `/metrics`.

    Reports peers configured alongside rounds completed, because a cluster that
    is quiet because everyone agrees and a cluster that is quiet because nobody
    is reachable look identical from the root alone.
    """
    if runtime is None:
        return {"enabled": False}
    stats = runtime.daemon.stats
    active = settings or runtime.daemon.settings
    return {
        "enabled": True,
        "replica_id": active.replica_id,
        "peers_configured": len(active.peers),
        "root": runtime.daemon.root,
        "rounds_started": stats.rounds_started,
        "rounds_converged": stats.rounds_converged,
        "states_merged": stats.states_merged,
        "states_rejected": stats.states_rejected,
        "leaves_learned": stats.leaves_learned,
        "peer_failures": stats.peer_failures,
    }
