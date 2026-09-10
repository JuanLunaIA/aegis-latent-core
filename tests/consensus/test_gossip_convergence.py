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
import socket
import ssl
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Iterator

pytest.importorskip("aegis_rust")
pytest.importorskip("uvicorn")

import uvicorn  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from aegis.consensus.gossip import GossipDaemon, GossipPeer, GossipSettings  # noqa: E402
from aegis.consensus.transport import HttpGossipTransport, build_gossip_app  # noqa: E402

pytestmark = pytest.mark.anyio


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
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
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


@pytest.fixture
async def three_replicas(tmp_path: Path) -> Iterator[list[_Replica]]:
    ca_path, ca_key, ca_certificate = _issue_ca(tmp_path)
    ports = [_free_port() for _ in range(3)]
    names = ["replica-0", "replica-1", "replica-2"]
    material = [_issue_replica(tmp_path, name, ca_key, ca_certificate) for name in names]

    replicas: list[_Replica] = []
    for index, (certificate, key) in enumerate(material):
        peers = tuple(
            GossipPeer(name=names[other], url=f"https://localhost:{ports[other]}")
            for other in range(3)
            if other != index
        )
        replicas.append(_Replica(index + 1, ports[index], certificate, key, ca_path, peers))

    for replica in replicas:
        await replica.serve()
    try:
        yield replicas
    finally:
        for replica in replicas:
            await replica.shutdown()


class TestThreeReplicasConverge:
    async def test_independent_appends_reach_one_root(self, three_replicas: list[_Replica]) -> None:
        # Each replica writes only its own records, as replicas actually do:
        # there is no shared writer and no leader.
        for index, replica in enumerate(three_replicas):
            for sequence in range(3):
                replica.append(f"replica-{index}-record-{sequence}".encode())

        assert len({replica.root for replica in three_replicas}) == 3

        converged = await _converge(three_replicas)

        assert converged is True
        assert {replica.leaf_count for replica in three_replicas} == {9}

    async def test_a_partition_heals(self, three_replicas: list[_Replica]) -> None:
        first, second, isolated = three_replicas

        # Partition: the third replica stops answering. From the others' point
        # of view that is exactly what a network partition looks like.
        isolated.server.should_exit = True
        await asyncio.sleep(0.2)

        first.append(b"written-during-partition-a")
        second.append(b"written-during-partition-b")
        isolated.append(b"written-in-isolation")

        # The reachable majority converges without the isolated replica, and
        # does not block waiting for it — no quorum, no leader election.
        for _ in range(20):
            await first.daemon.run_round()
            await second.daemon.run_round()
        assert first.root == second.root
        assert first.leaf_count == 2
        assert isolated.leaf_count == 1
        assert isolated.root != first.root

        # Heal: bring it back and let anti-entropy do its job. There is no
        # catch-up log to replay — one successful round transfers everything.
        restored = _Replica(
            isolated.replica_id,
            isolated.port,
            Path(isolated.settings.client_certificate),
            Path(isolated.settings.client_private_key),
            Path(isolated.settings.certificate_authority),
            isolated.settings.peers,
        )
        for payload in (b"written-in-isolation",):
            restored.append(payload)
        await restored.serve()
        try:
            healed = await _converge([first, second, restored])
            assert healed is True
            assert first.leaf_count == 3
            assert restored.leaf_count == 3
        finally:
            await restored.shutdown()

    async def test_convergence_is_reached_whatever_order_rounds_run_in(
        self, three_replicas: list[_Replica]
    ) -> None:
        # The algebra promises order-independence; the transport must not
        # reintroduce an ordering dependence on top of it.
        for index, replica in enumerate(three_replicas):
            replica.append(f"payload-{index}".encode())

        for replica in reversed(three_replicas):
            await replica.daemon.run_round()
        for replica in three_replicas:
            await replica.daemon.run_round()
        converged = await _converge(three_replicas)

        assert converged is True
        assert {replica.leaf_count for replica in three_replicas} == {3}


class TestTheMeshRefusesStrangers:
    async def test_a_peer_without_a_certificate_is_refused(
        self, three_replicas: list[_Replica]
    ) -> None:
        # The mesh's entire security boundary is "who is this": a peer supplies
        # leaves that enter every replica's accumulator. A client with no
        # certificate must not get to the handler.
        import httpx

        target = three_replicas[0]
        context = ssl.create_default_context(
            cafile=target.settings.certificate_authority
        )  # trusts the CA, presents nothing
        async with httpx.AsyncClient(verify=context, timeout=5.0) as anonymous:
            with pytest.raises((httpx.ConnectError, httpx.ReadError, ssl.SSLError)):
                await anonymous.get(f"https://localhost:{target.port}/gossip/root")

    async def test_a_certificate_from_another_ca_is_refused(self, tmp_path: Path) -> None:
        import httpx

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
            context = ssl.create_default_context(cafile=str(ca_path))
            context.load_cert_chain(str(stranger_cert), str(stranger_key))
            async with httpx.AsyncClient(verify=context, timeout=5.0) as impostor:
                with pytest.raises((httpx.ConnectError, httpx.ReadError, ssl.SSLError)):
                    await impostor.get(f"https://localhost:{port}/gossip/root")
        finally:
            await replica.shutdown()
