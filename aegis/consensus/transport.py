# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""The wire for gossip: mutual-TLS HTTP, and the endpoint that answers it.

Two halves of one exchange. `HttpGossipTransport` is what a replica uses to
reach its peers; `build_gossip_app` is what answers when a peer reaches it.
Both sides require a client certificate, so a replica proves who it is in
whichever direction it happens to be facing.

Why HTTP rather than gRPC
-------------------------

`httpx` is already a hard dependency of the gateway, and `ssl` already carries
the mutual-TLS machinery. gRPC would add a large binary dependency, protobuf
code generation, and a new lockfile entry to a repository that triages every
component it ships (`docs/security/DEPENDENCY_TRIAGE.md`). The exchange itself
is two requests with opaque bodies — there is no streaming, no bidirectional
session, and no schema evolution to speak of — so gRPC would buy nothing the
supply-chain cost could be charged against. The transport is a Protocol, so a
deployment that wants gRPC can supply it without touching reconciliation.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from aegis.consensus.gossip import (
    GossipDaemon,
    GossipPeer,
    GossipSettings,
    PeerStateRejectedError,
    build_client_ssl_context,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from starlette.applications import Starlette
    from starlette.requests import Request

logger = logging.getLogger(__name__)

STATE_CONTENT_TYPE = "application/vnd.aegis.crdt-state"

ROOT_PATH = "/gossip/root"
STATE_PATH = "/gossip/state"


class HttpGossipTransport:
    """Reaches peers over mutual TLS.

    One `httpx.AsyncClient` for the daemon's lifetime, so connections are
    reused across rounds: at a five-second interval, a fresh TLS handshake per
    peer per round would cost more than the exchange it carries.
    """

    def __init__(self, settings: GossipSettings, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._client = client or httpx.AsyncClient(
            verify=build_client_ssl_context(settings),
            timeout=httpx.Timeout(settings.request_timeout_seconds),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=max(len(settings.peers), 1) * 2),
        )

    async def fetch_root(self, peer: GossipPeer) -> str:
        response = await self._client.get(f"{peer.url.rstrip('/')}{ROOT_PATH}")
        response.raise_for_status()
        return response.text.strip()

    async def exchange_state(self, peer: GossipPeer, state: bytes) -> bytes:
        """Send ours, receive theirs, in one round trip.

        The response is size-checked from the declared length *and* from the
        bytes actually read, because `Content-Length` is the peer's claim
        rather than a fact.
        """
        ceiling = self._settings.max_state_bytes
        async with self._client.stream(
            "POST",
            f"{peer.url.rstrip('/')}{STATE_PATH}",
            content=state,
            headers={"content-type": STATE_CONTENT_TYPE},
        ) as response:
            response.raise_for_status()
            declared = response.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > ceiling:
                raise PeerStateRejectedError(
                    f"peer {peer.name} declared {declared} bytes; the ceiling is {ceiling}"
                )
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > ceiling:
                    raise PeerStateRejectedError(
                        f"peer {peer.name} sent more than {ceiling} bytes; refused mid-stream"
                    )
                chunks.append(chunk)
        return b"".join(chunks)

    async def aclose(self) -> None:
        await self._client.aclose()


def build_gossip_app(daemon: GossipDaemon) -> Starlette:
    """The inbound half: two routes, no governed traffic.

    Deliberately its own ASGI app rather than routes on the gateway. The
    gateway's listener carries customer requests and is reachable from
    wherever clients are; this one is reachable only from other replicas and
    demands a client certificate. Sharing a listener would mean one
    misconfiguration exposes both.
    """
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse, Response
    from starlette.routing import Route

    async def read_root(_request: Request) -> Response:
        return PlainTextResponse(daemon.root, media_type="text/plain")

    async def exchange(request: Request) -> Response:
        ceiling = daemon.settings.max_state_bytes
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > ceiling:
            return PlainTextResponse("state too large", status_code=413)

        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > ceiling:
                # Refused while reading rather than after: the point of a
                # ceiling is not to have held the bytes in the first place.
                return PlainTextResponse("state too large", status_code=413)
            chunks.append(chunk)

        # Answer with our pre-merge state before merging theirs. The peer
        # needs what we hold, and merging first would send back its own leaves
        # for it to re-merge — correct, since join is idempotent, but it
        # doubles the bytes on every exchange.
        ours = await daemon.encode_state()
        try:
            await daemon.merge_state(b"".join(chunks))
        except PeerStateRejectedError as exc:
            logger.warning("gossip: refused inbound state: %s", exc)
            return PlainTextResponse(f"state rejected: {exc}", status_code=422)
        return Response(ours, media_type=STATE_CONTENT_TYPE)

    return Starlette(
        routes=[
            Route(ROOT_PATH, read_root, methods=["GET"]),
            Route(STATE_PATH, exchange, methods=["POST"]),
        ]
    )
