# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Fault injection against a real Redis: a partition and a restart that loses state.

These are the failures the writer lease exists for. The partition test cuts the
holder's connection to Redis while a standby stays connected, and checks the
invariant that matters, at every sample: never two replicas that both believe
they may write. The restart test records what a Redis without persistence does to
the epoch counter, because the sequence fence depends on epochs increasing.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import time
import uuid
from collections.abc import Iterator

import pytest

from aegis.core.ha import (
    ChainLease,
    LeaseKeeper,
    PendingNode,
    SequenceDivergedError,
    SequenceEntry,
    plan_append,
)

REQUIRED = os.environ.get("AEGIS_TEST_REQUIRE_HA_BACKENDS") == "1"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _need_redis_binary() -> str:
    binary = shutil.which("redis-server")
    if binary is None:
        if REQUIRED:
            pytest.fail("AEGIS_TEST_REQUIRE_HA_BACKENDS=1 but redis-server is not installed")
        pytest.skip("no redis-server binary")
    return binary


class Blackhole:
    """A TCP forwarder that can be cut: while cut, bytes are read and dropped."""

    def __init__(self, target_port: int) -> None:
        self.port = free_port()
        self._target = target_port
        self.cut = False
        self._server = socket.socket()
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", self.port))
        self._server.listen(16)
        self._stop = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        self._server.settimeout(0.2)
        while not self._stop.is_set():
            try:
                client, _ = self._server.accept()
            except (TimeoutError, OSError):
                continue
            upstream = socket.create_connection(("127.0.0.1", self._target))
            for src, dst in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pump, args=(src, dst), daemon=True).start()

    def _pump(self, src: socket.socket, dst: socket.socket) -> None:
        try:
            while not self._stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                if not self.cut:
                    dst.sendall(data)
        except OSError:
            pass  # a peer reset or our own close ends the pump; nothing to recover
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass  # already closed by the other pump

    def close(self) -> None:
        self._stop.set()
        self._server.close()


@pytest.fixture
def private_redis() -> Iterator[tuple[int, list[subprocess.Popen[bytes]]]]:
    """A Redis with no persistence that a test may kill and restart."""
    binary = _need_redis_binary()
    port = free_port()
    procs: list[subprocess.Popen[bytes]] = []

    def start() -> subprocess.Popen[bytes]:
        proc = subprocess.Popen(  # noqa: S603  # nosec B603 - fixed argv, shell=False
            [
                binary,
                "--port",
                str(port),
                "--bind",
                "127.0.0.1",
                "--save",
                "",
                "--appendonly",
                "no",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(proc)
        import redis

        deadline = time.monotonic() + 10
        while True:
            try:
                redis.Redis(port=port).ping()
                return proc
            except redis.ConnectionError:
                if time.monotonic() > deadline:
                    proc.kill()
                    pytest.fail("spawned redis-server never answered")
                time.sleep(0.05)

    start()
    yield port, procs
    for proc in procs:
        proc.kill()
        proc.wait(timeout=10)


def test_a_partitioned_holder_fences_itself_before_a_standby_can_take_over(private_redis) -> None:  # type: ignore[no-untyped-def]
    import redis

    port, _ = private_redis
    proxy = Blackhole(port)
    chain = f"chaos-{uuid.uuid4().hex[:8]}"
    try:
        holder_client = redis.Redis(port=proxy.port, socket_timeout=0.5)
        standby_client = redis.Redis(port=port, socket_timeout=0.5)
        holder = ChainLease(holder_client, chain, "holder:1", 2.0)
        standby = ChainLease(standby_client, chain, "standby:2", 2.0)
        lost: list[str] = []
        first_epoch = holder.acquire()
        assert first_epoch == 1
        keeper = LeaseKeeper(holder, lost.append)
        keeper.start()

        proxy.cut = True
        cut_at = time.monotonic()
        both_held = 0
        holder_gave_up_at: float | None = None
        standby_epoch: int | None = None
        deadline = cut_at + 8.0
        while time.monotonic() < deadline and standby_epoch is None:
            if holder.holds() and standby.holds():
                both_held += 1
            if holder_gave_up_at is None and not holder.holds():
                holder_gave_up_at = time.monotonic() - cut_at
            standby_epoch = standby.acquire()
            time.sleep(0.05)
        keeper.stop()

        assert both_held == 0, "two replicas believed they held the writer lease"
        assert holder_gave_up_at is not None, "the partitioned holder never stopped admitting"
        assert holder_gave_up_at <= 2.0, f"holder kept admitting {holder_gave_up_at:.2f}s (ttl 2s)"
        assert standby_epoch == 2, "the standby must take over with a higher epoch"

        proxy.cut = False
        assert holder.renew() is False, "a healed old holder must not renew its way back"
        assert standby.holds()
    finally:
        proxy.close()


def test_a_redis_restart_without_persistence_fences_holders_but_resets_the_epoch_counter(  # type: ignore[no-untyped-def]
    private_redis,
) -> None:
    """Characterisation, not an endorsement: the counter is not durable.

    After Redis loses its data no old holder can renew (good), but the next holder is
    drawn an epoch *below* one already sequenced. The global sequence refuses a writer
    whose epoch is older than its last entry, so the chain stops admitting rather than
    forking: fail-closed, and an availability incident until the operator intervenes.
    Redis must therefore keep the epoch counter (append-only file or a managed service
    with persistence).
    """
    import redis

    port, procs = private_redis
    chain = f"chaos-{uuid.uuid4().hex[:8]}"
    old = ChainLease(redis.Redis(port=port, socket_timeout=1), chain, "old:1", 2.0)
    assert old.acquire() == 1
    old.release()
    second = ChainLease(redis.Redis(port=port, socket_timeout=1), chain, "second:2", 2.0)
    assert second.acquire() == 2

    procs[-1].kill()
    procs[-1].wait(timeout=10)
    # restart on the same port with no data
    binary = _need_redis_binary()
    procs.append(
        subprocess.Popen(  # noqa: S603  # nosec B603 - fixed argv, shell=False
            [
                binary,
                "--port",
                str(port),
                "--bind",
                "127.0.0.1",
                "--save",
                "",
                "--appendonly",
                "no",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    )
    deadline = time.monotonic() + 10
    while True:
        try:
            redis.Redis(port=port).ping()
            break
        except redis.ConnectionError:
            assert time.monotonic() < deadline
            time.sleep(0.05)

    assert second.renew() is False, "a holder must be fenced when Redis loses its lease"
    assert not second.holds()
    third = ChainLease(redis.Redis(port=port, socket_timeout=1), chain, "third:3", 2.0)
    new_epoch = third.acquire()
    assert new_epoch == 1, "the epoch counter is expected to restart without persistence"

    last = SequenceEntry(
        seq=7, prev_entry_hash="h0", chain_id=chain, chain_epoch=2, local_seq=7,
        node_hash="n7", local_prev_hash="n6", recorded_at="2026-01-01T00:00:00Z", entry_hash="e7",
    )  # fmt: skip
    with pytest.raises(SequenceDivergedError):
        plan_append(
            last, new_epoch, [PendingNode(local_seq=8, node_hash="n8", local_prev_hash="n7")]
        )
