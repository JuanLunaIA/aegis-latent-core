# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Three replicas, real TLS sockets, a partition, and a heal.

These are not unit tests over a stub. Each replica runs a uvicorn server on a
loopback port with mutual TLS — its own certificate, the cluster CA, and
`CERT_REQUIRED` in both directions — and the daemons reach each other through
`httpx` over that. What is exercised is the thing that would run in a cluster,
minus the cluster.

A partition is simulated by making a peer unreachable, which is what a
partition *is* from a replica's point of view: the peer stops answering. The
heal is the peer answering again. Nothing about the reconciliation is stubbed.

Calls with side effects are assigned before being asserted on, never called
inside the ``assert`` itself (``python -O`` strips asserts; CodeQL flags this
as py/side-effect-in-assert).
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import ipaddress
import socket
import ssl
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import AsyncIterator

pytest.importorskip("aegis_rust")
pytest.importorskip("uvicorn")

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from aegis.consensus.gossip import GossipDaemon, GossipPeer, GossipSettings  # noqa: E402
from aegis.consensus.transport import HttpGossipTransport, build_gossip_app  # noqa: E402

pytestmark = pytest.mark.anyio

# How a refused TLS handshake surfaces depends on which side gives up first:
# a reset during the handshake, a read on a closed socket, or an SSL alert.
#
# A *timeout* is deliberately not in this tuple. A server that is listening but
# not serving refuses everyone by timing out, so accepting a timeout here would
# let a broken harness masquerade as a working access control — which is
# exactly what happened before `_require_serving` existed.
_REFUSED = (
    httpx.ConnectError,
    httpx.ReadError,
    ssl.SSLError,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# ── A throwaway cluster CA ──────────────────────────────────────────────


def _issue_ca(directory: Path) -> tuple[Path, ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aegis-test-ca")])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = directory / "ca.pem"
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return path, key, certificate


def _issue_replica(
    directory: Path,
    name: str,
    ca_key: ec.EllipticCurvePrivateKey,
    ca_certificate: x509.Certificate,
) -> tuple[Path, Path]:
    """One replica's certificate, valid for both client and server use.

    A gossip replica is both: it dials peers and it answers them, and the same
    identity has to serve in each direction.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(
            # Both forms. The tests dial the literal 127.0.0.1 so that no name
            # resolution is involved: a runner where "localhost" also resolves
            # to ::1 would otherwise have httpx try the v6 address first, find
            # nothing listening on it, and hang until the connect timeout —
            # which reads as "the mesh did not converge" rather than as the
            # addressing mistake it is.
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    certificate_path = directory / f"{name}.crt"
    key_path = directory / f"{name}.key"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _Replica:
    """One replica: an accumulator, a daemon, and a TLS server for its peers."""

    def __init__(
        self,
        replica_id: int,
        port: int,
        certificate: Path,
        key: Path,
        ca: Path,
        peers: tuple[GossipPeer, ...],
    ) -> None:
        import aegis_rust

        self.replica_id = replica_id
        self.port = port
        self.settings = GossipSettings(
            replica_id=replica_id,
            peers=peers,
            interval_seconds=0.05,
            request_timeout_seconds=2.0,
            client_certificate=str(certificate),
            client_private_key=str(key),
            certificate_authority=str(ca),
        )
        self.daemon = GossipDaemon(
            accumulator=aegis_rust.CausalMmr(replica_id),
            settings=self.settings,
            transport=HttpGossipTransport(self.settings),
        )
        config = uvicorn.Config(
            build_gossip_app(self.daemon),
            host="127.0.0.1",
            port=port,
            log_level="error",
            ssl_certfile=str(certificate),
            ssl_keyfile=str(key),
            ssl_ca_certs=str(ca),
            ssl_cert_reqs=ssl.CERT_REQUIRED,  # mutual: a peer must present one
        )
        self.server = uvicorn.Server(config)
        self._task: asyncio.Task[None] | None = None

    async def serve(self) -> None:
        self._task = asyncio.create_task(self.server.serve())
        for _ in range(200):
            if self.server.started:
                return
            await asyncio.sleep(0.02)
        raise RuntimeError(f"replica {self.replica_id} did not start")

    async def shutdown(self) -> None:
        self.server.should_exit = True
        if self._task is not None:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(self._task, timeout=5)
        await self.daemon.stop()

    def append(self, payload: bytes) -> None:
        self.daemon.accumulator.append(payload)  # type: ignore[attr-defined]

    @property
    def root(self) -> str:
        return self.daemon.root

    @property
    def leaf_count(self) -> int:
        return self.daemon.accumulator.leaf_count


async def _converge(replicas: list[_Replica], rounds: int = 40) -> bool:
    """Drive rounds until every replica agrees, or give up."""
    for _ in range(rounds):
        for replica in replicas:
            await replica.daemon.run_round()
        roots = {replica.root for replica in replicas}
        if len(roots) == 1:
            return True
    return False


@asynccontextmanager
async def three_replicas(tmp_path: Path) -> AsyncIterator[list[_Replica]]:
    """Three replicas, started inside the caller's event loop.

    A context manager rather than an async fixture, and that is the whole
    point. On some pytest/anyio combinations an async fixture runs in a
    *different* event loop from the test that consumes it. A uvicorn server
    started in the fixture's loop then never gets scheduled once the test's
    loop takes over: the kernel still completes the TCP handshake into the
    listen backlog, so a socket connect succeeds and everything looks alive,
    while no TLS handshake ever happens and every request dies on the connect
    timeout. That reads as "the mesh did not converge" and is really "the
    servers were never running".

    Entering the context manager from inside the test binds setup, the servers
    and teardown to one loop by construction.
    """
    ca_path, ca_key, ca_certificate = _issue_ca(tmp_path)
    ports = [_free_port() for _ in range(3)]
    names = ["replica-0", "replica-1", "replica-2"]
    material = [_issue_replica(tmp_path, name, ca_key, ca_certificate) for name in names]

    replicas: list[_Replica] = []
    for index, (certificate, key) in enumerate(material):
        peers = tuple(
            GossipPeer(name=names[other], url=f"https://127.0.0.1:{ports[other]}")
            for other in range(3)
            if other != index
        )
        replicas.append(_Replica(index + 1, ports[index], certificate, key, ca_path, peers))

    for replica in replicas:
        await replica.serve()
    try:
        await _require_serving(replicas)
        yield replicas
    finally:
        for replica in replicas:
            await replica.shutdown()


async def _require_serving(replicas: list[_Replica]) -> None:
    """Fail loudly if the servers are listening but not actually serving.

    Without this, a harness fault is indistinguishable from a convergence
    failure — and worse, the tests that assert a stranger is *refused* pass
    for the wrong reason, because a dead server refuses everyone.
    """
    for replica in replicas:
        peer = replica.settings.peers[0]
        try:
            root = await replica.daemon._transport.fetch_root(peer)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001 - any failure here is fatal
            raise AssertionError(
                f"replica {replica.replica_id} could not reach {peer.name}: "
                f"{type(exc).__name__}: {exc!r}. The servers are not serving; "
                "this is a harness fault, not a convergence result."
            ) from exc
        if len(root) != 64:
            raise AssertionError(f"peer {peer.name} returned a non-root: {root!r}")


class TestThreeReplicasConverge:
    async def test_independent_appends_reach_one_root(self, tmp_path: Path) -> None:
        async with three_replicas(tmp_path) as replicas:
            # Each replica writes only its own records, as replicas actually
            # do: there is no shared writer and no leader.
            for index, replica in enumerate(replicas):
                for sequence in range(3):
                    replica.append(f"replica-{index}-record-{sequence}".encode())

            assert len({replica.root for replica in replicas}) == 3

            converged = await _converge(replicas)

            assert converged is True
            assert {replica.leaf_count for replica in replicas} == {9}

    async def test_a_partition_heals(self, tmp_path: Path) -> None:
        async with three_replicas(tmp_path) as replicas:
            first, second, isolated = replicas

            # Partition: the third replica stops answering. From the others'
            # point of view that is exactly what a partition looks like.
            isolated.server.should_exit = True
            await asyncio.sleep(0.2)

            first.append(b"written-during-partition-a")
            second.append(b"written-during-partition-b")
            isolated.append(b"written-in-isolation")

            # The reachable pair converges without the isolated replica and
            # does not block waiting for it — no quorum, no leader election.
            for _ in range(20):
                await first.daemon.run_round()
                await second.daemon.run_round()
            assert first.root == second.root
            assert first.leaf_count == 2
            assert isolated.leaf_count == 1
            assert isolated.root != first.root

            # Heal: bring it back and let anti-entropy do its job. There is no
            # catch-up log to replay — one successful round transfers all of it.
            restored = _Replica(
                isolated.replica_id,
                isolated.port,
                Path(isolated.settings.client_certificate),
                Path(isolated.settings.client_private_key),
                Path(isolated.settings.certificate_authority),
                isolated.settings.peers,
            )
            restored.append(b"written-in-isolation")
            await restored.serve()
            try:
                healed = await _converge([first, second, restored])
                assert healed is True
                assert first.leaf_count == 3
                assert restored.leaf_count == 3
            finally:
                await restored.shutdown()

    async def test_convergence_is_reached_whatever_order_rounds_run_in(
        self, tmp_path: Path
    ) -> None:
        # The algebra promises order-independence; the transport must not
        # reintroduce an ordering dependence on top of it.
        async with three_replicas(tmp_path) as replicas:
            for index, replica in enumerate(replicas):
                replica.append(f"payload-{index}".encode())

            for replica in reversed(replicas):
                await replica.daemon.run_round()
            for replica in replicas:
                await replica.daemon.run_round()
            converged = await _converge(replicas)

            assert converged is True
            assert {replica.leaf_count for replica in replicas} == {3}


class TestTheMeshRefusesStrangers:
    """Refusal tests, each with a positive control.

    A server that is listening but not serving refuses everyone, so "the
    stranger was refused" means nothing on its own. Every test here first
    proves that a *legitimate* client succeeds against the same server, so the
    refusal that follows is attributable to the credential rather than to a
    dead listener.
    """

    async def test_a_peer_without_a_certificate_is_refused(self, tmp_path: Path) -> None:
        # The mesh's entire security boundary is "who is this": a peer supplies
        # leaves that enter every replica's accumulator.
        async with three_replicas(tmp_path) as replicas:
            target = replicas[0]

            # Positive control: a peer holding a valid certificate gets in.
            admitted = await replicas[1].daemon._transport.fetch_root(  # noqa: SLF001
                replicas[1].settings.peers[0]
            )
            assert len(admitted) == 64

            context = ssl.create_default_context(
                cafile=target.settings.certificate_authority
            )  # trusts the CA, presents nothing
            async with httpx.AsyncClient(verify=context, timeout=5.0) as anonymous:
                with pytest.raises(_REFUSED):
                    await anonymous.get(f"https://127.0.0.1:{target.port}/gossip/root")

    async def test_a_certificate_from_another_ca_is_refused(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        stranger_dir = tmp_path / "stranger"
        stranger_dir.mkdir()
        ca_path, ca_key, ca_certificate = _issue_ca(real_dir)
        _, other_key, other_certificate = _issue_ca(stranger_dir)
        stranger_cert, stranger_key = _issue_replica(
            stranger_dir, "impostor", other_key, other_certificate
        )

        port = _free_port()
        certificate, key = _issue_replica(real_dir, "replica-0", ca_key, ca_certificate)
        replica = _Replica(1, port, certificate, key, ca_path, ())
        await replica.serve()
        try:
            # Positive control: the replica's own certificate is admitted.
            trusted = ssl.create_default_context(cafile=str(ca_path))
            trusted.load_cert_chain(str(certificate), str(key))
            async with httpx.AsyncClient(verify=trusted, timeout=5.0) as legitimate:
                response = await legitimate.get(f"https://127.0.0.1:{port}/gossip/root")
                assert response.status_code == 200

            context = ssl.create_default_context(cafile=str(ca_path))
            context.load_cert_chain(str(stranger_cert), str(stranger_key))
            async with httpx.AsyncClient(verify=context, timeout=5.0) as impostor:
                with pytest.raises(_REFUSED):
                    await impostor.get(f"https://127.0.0.1:{port}/gossip/root")
        finally:
            await replica.shutdown()
