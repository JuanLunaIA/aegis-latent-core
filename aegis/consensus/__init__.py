# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.

"""Cross-replica reconciliation over the Causal-Merkle CRDT.

Each Aegis replica owns a private WAL and therefore a private chain. This
package supplies the layer that was missing between `CausalMmr` — the
join-semilattice that reconciles replicas without a leader — and a running
deployment: a transport, a peer set, and a schedule.

What it establishes and what it does not is stated in `gossip.GossipDaemon`.
The short version: replicas that can reach each other converge on one root.
That is agreement about *ordering*, not about *honesty*.
"""

from aegis.consensus.gossip import (
    GossipDaemon,
    GossipPeer,
    GossipSettings,
    GossipStats,
    PeerStateRejectedError,
    parse_peers,
    settings_from_config,
)

__all__ = [
    "GossipDaemon",
    "GossipPeer",
    "GossipSettings",
    "GossipStats",
    "PeerStateRejectedError",
    "parse_peers",
    "settings_from_config",
]
