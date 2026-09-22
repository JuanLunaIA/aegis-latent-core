# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Starting and stopping the gossip mesh, and every way it refuses to start.

`aegis/consensus/runtime.py` is the only place the gateway learns about the mesh,
and its failure mode is the one that must never be silent: a replica asked to join
a mesh that quietly did not would look healthy while diverging from every peer.
So the module raises `GossipStartupError` instead of logging and continuing, and
these tests drive each refusal — missing TLS material (named by *setting*, not by
path), a listener that exits during startup, a listener that never comes up, and
the native accumulator being absent — plus the shutdown ordering that stops the
daemon before the listener.

Nothing here needs a network: the listener, the daemon and their tasks are fakes,
and the only real object is the asyncio task the shutdown path has to await.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aegis.consensus import runtime as runtime_module
from aegis.consensus.runtime import (
    GossipRuntime,
    GossipStartupError,
    _await_listening,
    _require_readable,
    describe,
    start_gossip,
)


class _FakeDaemon:
    def __init__(self) -> None:
        self.stopped = 0
        self.started = 0
        self.settings = SimpleNamespace(replica_id=3, peers=("peer-a", "peer-b"))
        self.root = "root-digest"
        self.stats = SimpleNamespace(
            rounds_started=4,
            rounds_converged=3,
            states_merged=2,
            states_rejected=1,
            leaves_learned=7,
            peer_failures=0,
        )

    async def start(self) -> None:
        self.started += 1

    async def stop(self) -> None:
        self.stopped += 1


class _RefusingDaemon(_FakeDaemon):
    async def stop(self) -> None:
        self.stopped += 1
        raise RuntimeError("daemon already down")


def _config(**overrides: Any) -> Any:
    """An `AegisSettings`-shaped object; the runtime reads it structurally."""
    base: dict[str, Any] = {
        "gossip_enabled": True,
        "gossip_replica_id": 3,
        "gossip_peers": "",
        "gossip_self_name": "self",
        "gossip_client_certificate": "",
        "gossip_client_private_key": "",
        "gossip_certificate_authority": "",
        "gossip_bind_host": "127.0.0.1",
        "gossip_bind_port": 9443,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class TestTlsMaterialChecks:
    def test_an_unset_setting_is_refused_by_name(self) -> None:
        with pytest.raises(GossipStartupError, match="gossip_client_certificate is not set"):
            _require_readable("gossip_client_certificate", "")

    def test_a_missing_file_is_refused_with_its_path(self) -> None:
        with pytest.raises(GossipStartupError, match="does not exist or is not a file"):
            _require_readable("gossip_client_certificate", "/nonexistent/gossip.pem")

    def test_a_directory_is_not_a_readable_certificate(self, tmp_path: Path) -> None:
        with pytest.raises(GossipStartupError, match="does not exist or is not a file"):
            _require_readable("gossip_certificate_authority", str(tmp_path))

    def test_an_existing_file_is_returned_unchanged(self, tmp_path: Path) -> None:
        material = tmp_path / "client.pem"
        material.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
        assert _require_readable("gossip_client_certificate", str(material)) == str(material)


class TestStartRefusals:
    async def test_a_disabled_mesh_starts_nothing(self) -> None:
        assert await start_gossip(_config(gossip_enabled=False)) is None

    async def test_enabling_the_mesh_without_tls_is_refused(self) -> None:
        with pytest.raises(GossipStartupError, match="gossip_client_certificate is not set"):
            await start_gossip(_config())

    async def test_an_absent_native_accumulator_is_refused_with_its_reason(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No Python stand-in: an accumulator whose roots peers cannot compute
        would report converged rounds while agreeing with nobody."""
        # Arrange the absence rather than assume it: where the extension is
        # built (the Forensic workflow), start_gossip would otherwise get past
        # the accumulator and fail on the placeholder PEM below instead.
        monkeypatch.setitem(sys.modules, "aegis_rust", None)
        material = tmp_path / "material.pem"
        material.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
        with pytest.raises(GossipStartupError, match="requires the native CausalMmr accumulator"):
            await start_gossip(
                _config(
                    gossip_client_certificate=str(material),
                    gossip_client_private_key=str(material),
                    gossip_certificate_authority=str(material),
                )
            )


class _FakeServer:
    def __init__(self, *, started: bool) -> None:
        self.started = started
        self.should_exit = False


class TestListenerReadiness:
    async def test_a_started_listener_returns_immediately(self) -> None:
        await _await_listening(_FakeServer(started=True), asyncio.ensure_future(asyncio.sleep(0)))  # type: ignore[arg-type]

    async def test_a_listener_that_exited_surfaces_its_own_cause(self) -> None:
        async def _die() -> None:
            raise OSError("address already in use")

        task = asyncio.ensure_future(_die())
        with pytest.raises(GossipStartupError, match="exited during startup.*address already"):
            await _await_listening(_FakeServer(started=False), task)  # type: ignore[arg-type]

    async def test_a_listener_that_never_starts_times_out_and_is_cancelled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`server.started` and not a connect probe: a bound socket answers a
        probe and then times out every real request."""
        monkeypatch.setattr(runtime_module, "_STARTUP_ATTEMPTS", 2)
        monkeypatch.setattr(runtime_module, "_STARTUP_POLL_SECONDS", 0.001)

        async def _hang() -> None:
            await asyncio.sleep(60)

        task = asyncio.ensure_future(_hang())
        with pytest.raises(GossipStartupError, match="did not start within"):
            await _await_listening(_FakeServer(started=False), task)  # type: ignore[arg-type]
        # `cancel()` requests the transition; it lands on the next loop step.
        await asyncio.sleep(0)
        assert task.cancelled()
        with contextlib.suppress(asyncio.CancelledError):
            await task


class TestShutdownOrdering:
    async def test_the_daemon_stops_before_the_listener_and_the_task_is_joined(self) -> None:
        daemon = _FakeDaemon()
        server = _FakeServer(started=True)
        task = asyncio.ensure_future(asyncio.sleep(0))
        runtime = GossipRuntime(daemon=daemon, server=server, task=task)  # type: ignore[arg-type]
        await runtime.aclose()
        assert daemon.stopped == 1
        assert server.should_exit is True
        assert task.done()

    async def test_a_daemon_that_fails_to_stop_does_not_block_shutdown(self) -> None:
        daemon = _RefusingDaemon()
        server = _FakeServer(started=True)
        task = asyncio.ensure_future(asyncio.sleep(0))
        runtime = GossipRuntime(daemon=daemon, server=server, task=task)  # type: ignore[arg-type]
        await runtime.aclose()
        assert daemon.stopped == 1
        assert server.should_exit is True

    async def test_a_listener_that_outlasts_the_shutdown_timeout_is_cancelled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(runtime_module, "_SHUTDOWN_TIMEOUT_SECONDS", 0.01)
        daemon = _FakeDaemon()
        server = _FakeServer(started=True)

        async def _hang() -> None:
            await asyncio.sleep(60)

        task = asyncio.ensure_future(_hang())
        runtime = GossipRuntime(daemon=daemon, server=server, task=task)  # type: ignore[arg-type]
        await runtime.aclose()
        assert task.cancelled()


class TestDescribe:
    def test_a_disabled_mesh_reports_only_that(self) -> None:
        assert describe(None) == {"enabled": False}

    def test_a_running_mesh_reports_peers_beside_its_rounds(self) -> None:
        """Peers configured and rounds converged are reported together: a quiet
        cluster that agrees and a quiet cluster nobody can reach look alike."""
        daemon = _FakeDaemon()
        runtime = GossipRuntime(daemon=daemon, server=_FakeServer(started=True), task=None)  # type: ignore[arg-type]
        described = describe(runtime)
        assert described["enabled"] is True
        assert described["replica_id"] == 3
        assert described["peers_configured"] == 2
        assert described["rounds_converged"] == 3
        assert described["peer_failures"] == 0

    def test_settings_can_be_supplied_explicitly(self) -> None:
        daemon = _FakeDaemon()
        runtime = GossipRuntime(daemon=daemon, server=_FakeServer(started=True), task=None)  # type: ignore[arg-type]
        described = describe(runtime, SimpleNamespace(replica_id=9, peers=()))  # type: ignore[arg-type]
        assert described["replica_id"] == 9
        assert described["peers_configured"] == 0
