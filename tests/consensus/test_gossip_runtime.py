# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Starting and stopping the mesh from the gateway's lifespan.

`test_gossip_convergence.py` proves the protocol converges. This file covers the
seam between that protocol and the gateway: gossip is off unless asked for, and
when it is asked for and cannot run, the replica is told loudly rather than
coming up looking healthy while reconciling with nobody.

The misconfiguration cases matter more than they look. A replica that silently
skipped the mesh reports the same root, the same health and the same metrics as
one that joined it — the divergence only becomes visible later, in the evidence.
So each of the three PEM settings is checked by name.

Calls with side effects are assigned before being asserted on, never called
inside the ``assert`` itself (``python -O`` strips asserts; CodeQL flags this as
py/side-effect-in-assert).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

from aegis.consensus.runtime import GossipStartupError, describe, start_gossip

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pathlib import Path

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Config:
    """The `AegisSettings` slice `start_gossip` reads, structurally."""

    gossip_enabled: bool = True
    gossip_replica_id: int = 0
    gossip_self_name: str = "replica-0"
    gossip_peers: str = ""
    gossip_interval_seconds: float = 5.0
    gossip_bind_host: str = "127.0.0.1"
    gossip_bind_port: int = 0
    gossip_client_certificate: str = ""
    gossip_client_private_key: str = ""
    gossip_certificate_authority: str = ""


def _touch(tmp_path: Path, name: str) -> str:
    path = tmp_path / name
    path.write_text("not a real PEM", encoding="utf-8")
    return str(path)


class TestGossipIsOffUnlessAskedFor:
    async def test_disabled_starts_nothing(self, tmp_path: Path) -> None:
        runtime = await start_gossip(_Config(gossip_enabled=False))
        assert runtime is None

    async def test_disabled_is_the_default_for_a_config_that_never_heard_of_gossip(self) -> None:
        """`start_gossip` is read structurally, so absent fields must mean off."""

        class Bare:
            pass

        runtime = await start_gossip(Bare())
        assert runtime is None

    async def test_describe_reports_disabled_without_inventing_a_root(self) -> None:
        assert describe(None) == {"enabled": False}


class TestMisconfigurationIsLoud:
    """Each PEM setting is named, because three unlabelled paths are slow to debug."""

    async def test_missing_certificate_names_the_setting(self, tmp_path: Path) -> None:
        with pytest.raises(GossipStartupError, match="gossip_client_certificate"):
            await start_gossip(_Config())

    async def test_missing_private_key_names_the_setting(self, tmp_path: Path) -> None:
        config = _Config(gossip_client_certificate=_touch(tmp_path, "tls.crt"))
        with pytest.raises(GossipStartupError, match="gossip_client_private_key"):
            await start_gossip(config)

    async def test_missing_authority_names_the_setting(self, tmp_path: Path) -> None:
        config = _Config(
            gossip_client_certificate=_touch(tmp_path, "tls.crt"),
            gossip_client_private_key=_touch(tmp_path, "tls.key"),
        )
        with pytest.raises(GossipStartupError, match="gossip_certificate_authority"):
            await start_gossip(config)

    async def test_a_path_that_does_not_exist_is_refused(self, tmp_path: Path) -> None:
        config = _Config(
            gossip_client_certificate=str(tmp_path / "absent.crt"),
            gossip_client_private_key=_touch(tmp_path, "tls.key"),
            gossip_certificate_authority=_touch(tmp_path, "ca.crt"),
        )
        with pytest.raises(GossipStartupError, match="does not exist"):
            await start_gossip(config)

    async def test_there_is_no_way_to_disable_peer_verification(self) -> None:
        """The CA is mandatory, and this pins that it stays mandatory.

        A peer supplies leaves that enter this replica's accumulator, so
        authenticating peers *is* the security boundary. If a future change
        adds an insecure-skip-verify escape hatch, the CA would stop being
        required and this test is what notices.
        """
        with pytest.raises(GossipStartupError, match="requires mutual TLS"):
            await start_gossip(_Config())
