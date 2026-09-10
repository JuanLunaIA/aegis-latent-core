# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Configuration for the gossip mesh, and what it refuses to accept.

The peer list is the mesh's membership. There is no discovery protocol, so a
mistake here is not corrected at runtime: a peer that is dropped, duplicated or
misspelled produces a replica that never converges and reports nothing wrong.
Each of these pins a way that could happen.

Calls with side effects are assigned before being asserted on, never called
inside the ``assert`` itself (``python -O`` strips asserts; CodeQL flags this
as py/side-effect-in-assert).
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from aegis.consensus import GossipPeer, GossipSettings, parse_peers, settings_from_config


@dataclass
class _Config:
    """The shape `settings_from_config` reads, without the gateway's model."""

    gossip_replica_id: int = 0
    gossip_self_name: str = ""
    gossip_peers: str = ""
    gossip_interval_seconds: float = 5.0
    gossip_client_certificate: str = ""
    gossip_client_private_key: str = ""
    gossip_certificate_authority: str = ""


class TestParsingThePeerList:
    def test_a_well_formed_list_parses(self) -> None:
        peers = parse_peers("a=https://a:9443, b=https://b:9443")
        assert peers == (
            GossipPeer(name="a", url="https://a:9443"),
            GossipPeer(name="b", url="https://b:9443"),
        )

    def test_an_entry_without_a_name_is_refused_rather_than_skipped(self) -> None:
        # Skipping would silently shrink the mesh. A replica missing a peer
        # converges with everyone except that peer and looks healthy doing it.
        with pytest.raises(ValueError, match="not in 'name=url' form"):
            parse_peers("https://a:9443")

    def test_plain_http_is_refused(self) -> None:
        # Gossip carries leaf digests and the cluster's topology, and the peer
        # on the other end supplies leaves that enter our accumulator.
        with pytest.raises(ValueError, match="must be reached over https"):
            parse_peers("a=http://a:9443")

    def test_blank_entries_are_ignored(self) -> None:
        # A trailing comma from a template loop is not a configuration error.
        peers = parse_peers("a=https://a:9443,")
        assert len(peers) == 1

    def test_an_empty_list_is_a_mesh_of_one(self) -> None:
        assert parse_peers("") == ()


class TestBuildingSettings:
    def test_a_replica_removes_itself_from_the_rendered_list(self) -> None:
        # Helm renders one manifest for every ordinal and cannot know which one
        # it is being rendered for, so the list names every replica including
        # this one. Left in, a replica would spend a round per interval
        # confirming it agrees with itself — and would count that as converged.
        settings = settings_from_config(
            _Config(
                gossip_self_name="aegis-1",
                gossip_peers="aegis-0=https://a:9443,aegis-1=https://b:9443,aegis-2=https://c:9443",
            )
        )
        assert [peer.name for peer in settings.peers] == ["aegis-0", "aegis-2"]

    def test_without_a_self_name_nothing_is_removed(self) -> None:
        settings = settings_from_config(
            _Config(gossip_peers="aegis-0=https://a:9443,aegis-1=https://b:9443")
        )
        assert len(settings.peers) == 2

    def test_duplicate_peer_names_are_refused(self) -> None:
        # Two entries with one name means one of them is unreachable and the
        # operator believes both are up.
        with pytest.raises(ValueError, match="peer names must be unique"):
            settings_from_config(_Config(gossip_peers="a=https://a:9443,a=https://b:9443"))

    def test_a_non_positive_interval_is_refused(self) -> None:
        with pytest.raises(ValueError, match="interval_seconds must be positive"):
            GossipSettings(replica_id=1, interval_seconds=0.0)


class TestVerificationCannotBeTurnedOff:
    def test_a_context_without_a_certificate_authority_is_refused(self) -> None:
        # There is deliberately no "insecure" flag. A peer supplies leaves that
        # enter this replica's accumulator, so authenticating peers is the
        # whole security boundary — an unverified mesh is an open input.
        from aegis.consensus.gossip import build_client_ssl_context

        with pytest.raises(ValueError, match="requires a certificate authority"):
            build_client_ssl_context(GossipSettings(replica_id=1))
