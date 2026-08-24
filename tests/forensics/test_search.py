"""Tests for metadata-only search over fixed retained-node tuple snapshots."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from aegis.forensics import (
    MAX_PAGE_LIMIT,
    ForensicSearchQuery,
    SearchOrder,
    search_retained_nodes,
)


@dataclass(frozen=True)
class Node:
    state_id: str
    node_hash: str
    timestamp: float
    tenant_id: str = "tenant-a"
    model: str = "model-a"
    endpoint: str = "chat.completions"
    phi_scrubbed: bool = False
    sampling_params: dict[str, object] = field(default_factory=dict)


def _snapshot() -> tuple[Node, ...]:
    return (
        Node(
            state_id="state-3",
            node_hash="hash-c",
            timestamp=30.0,
            tenant_id="tenant-b",
            model="model-b",
            endpoint="responses",
            phi_scrubbed=True,
            sampling_params={"terminal_outcome": "timeout", "elapsed_seconds": 0.250},
        ),
        Node(
            state_id="state-2",
            node_hash="hash-b",
            timestamp=20.0,
            sampling_params={"terminal_outcome": "complete", "elapsed_seconds": 0.125},
        ),
        Node(
            state_id="state-1",
            node_hash="hash-a",
            timestamp=10.0,
            sampling_params={"terminal_outcome": "complete", "elapsed_seconds": 0.025},
        ),
    )


def test_combines_exact_metadata_predicates() -> None:
    snapshot = _snapshot()
    query = ForensicSearchQuery(
        tenant_id="tenant-b",
        model="model-b",
        endpoint="responses",
        state_id="state-3",
        node_hash="hash-c",
        outcome="timeout",
        phi_scrubbed=True,
        min_latency_ms=250.0,
        start_time=30.0,
        end_time=30.0,
    )

    page = search_retained_nodes(snapshot, query)

    assert page.items == (snapshot[0],)
    assert page.total == 1
    assert not page.has_more


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (ForensicSearchQuery(tenant_id="TENANT-B"), ()),
        (ForensicSearchQuery(model="model"), ()),
        (ForensicSearchQuery(endpoint="response"), ()),
        (ForensicSearchQuery(state_id="state"), ()),
        (ForensicSearchQuery(node_hash="hash"), ()),
        (ForensicSearchQuery(outcome="TIMEOUT"), ()),
        (ForensicSearchQuery(phi_scrubbed=False), ("state-1", "state-2")),
        (ForensicSearchQuery(min_latency_ms=125.0), ("state-2", "state-3")),
        (ForensicSearchQuery(start_time=20.0, end_time=30.0), ("state-2", "state-3")),
    ],
)
def test_predicates_are_exact_and_bounds_are_inclusive(
    query: ForensicSearchQuery, expected: tuple[str, ...]
) -> None:
    page = search_retained_nodes(_snapshot(), query)
    assert tuple(node.state_id for node in page.items) == expected


def test_order_is_deterministic_with_identity_and_source_tie_breakers() -> None:
    nodes = (
        Node(state_id="same", node_hash="b", timestamp=10.0),
        Node(state_id="same", node_hash="a", timestamp=10.0),
        Node(state_id="same", node_hash="a", timestamp=10.0),
    )

    ascending = search_retained_nodes(nodes, ForensicSearchQuery())
    descending = search_retained_nodes(nodes, ForensicSearchQuery(order=SearchOrder.NEWEST_FIRST))

    assert ascending.items == (nodes[1], nodes[2], nodes[0])
    assert descending.items == (nodes[0], nodes[2], nodes[1])


def test_pagination_is_bounded_and_reports_total() -> None:
    page = search_retained_nodes(_snapshot(), ForensicSearchQuery(offset=1, limit=1))

    assert tuple(node.state_id for node in page.items) == ("state-2",)
    assert page.total == 3
    assert page.offset == 1
    assert page.limit == 1
    assert page.has_more


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"tenant_id": ""}, ValueError),
        ({"model": 3}, TypeError),
        ({"phi_scrubbed": 1}, TypeError),
        ({"min_latency_ms": -0.1}, ValueError),
        ({"min_latency_ms": float("inf")}, ValueError),
        ({"start_time": 2.0, "end_time": 1.0}, ValueError),
        ({"offset": True}, TypeError),
        ({"offset": -1}, ValueError),
        ({"limit": 0}, ValueError),
        ({"limit": MAX_PAGE_LIMIT + 1}, ValueError),
        ({"order": "oldest_first"}, TypeError),
    ],
)
def test_query_validation(kwargs: dict[str, Any], error: type[Exception]) -> None:
    with pytest.raises(error):
        ForensicSearchQuery(**kwargs)


def test_requires_an_immutable_tuple_snapshot() -> None:
    with pytest.raises(TypeError, match="immutable tuple"):
        search_retained_nodes(list(_snapshot()), ForensicSearchQuery())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "params",
    [
        {"terminal_outcome": 1},
        {"elapsed_seconds": True},
        {"elapsed_seconds": -1.0},
        {"elapsed_seconds": float("nan")},
    ],
)
def test_rejects_malformed_relevant_node_metadata(params: dict[str, object]) -> None:
    nodes = (Node("state", "hash", 1.0, sampling_params=params),)
    with pytest.raises((TypeError, ValueError)):
        search_retained_nodes(nodes, ForensicSearchQuery())


def test_nodes_without_latency_do_not_match_minimum_latency() -> None:
    nodes = (Node("state", "hash", 1.0),)
    assert search_retained_nodes(nodes, ForensicSearchQuery(min_latency_ms=0.0)).items == ()


def test_rejects_latency_conversion_overflow() -> None:
    nodes = (Node("state", "hash", 1.0, sampling_params={"elapsed_seconds": 1e308}),)

    with pytest.raises(ValueError, match="node latency_ms must be finite"):
        search_retained_nodes(nodes, ForensicSearchQuery())


def test_result_and_input_snapshot_remain_immutable_and_nodes_keep_identity() -> None:
    snapshot = _snapshot()
    page = search_retained_nodes(snapshot, ForensicSearchQuery(limit=1))

    assert isinstance(page.items, tuple)
    assert page.items[0] is snapshot[2]
    with pytest.raises((AttributeError, TypeError)):
        page.total = 4  # type: ignore[misc]
