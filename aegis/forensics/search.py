"""Typed metadata-only search over retained audit-node snapshots.

This module deliberately operates on an immutable in-memory ``tuple``.  It does
not read the audit WAL and does not inspect request or response content.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, Protocol, TypeVar

MAX_PAGE_LIMIT = 1_000
DEFAULT_PAGE_LIMIT = 100


class AuditNodeLike(Protocol):
    """Structural metadata required from a retained audit node."""

    @property
    def state_id(self) -> str: ...

    @property
    def node_hash(self) -> str: ...

    @property
    def timestamp(self) -> float: ...

    @property
    def tenant_id(self) -> str: ...

    @property
    def model(self) -> str: ...

    @property
    def endpoint(self) -> str: ...

    @property
    def phi_scrubbed(self) -> bool: ...

    @property
    def sampling_params(self) -> Mapping[str, object]: ...


AuditNodeT = TypeVar("AuditNodeT", bound=AuditNodeLike)


class SearchOrder(StrEnum):
    """Supported deterministic timestamp orderings."""

    OLDEST_FIRST = "oldest_first"
    NEWEST_FIRST = "newest_first"


@dataclass(frozen=True, slots=True)
class ForensicSearchQuery:
    """Exact metadata predicates and bounded offset pagination.

    Time bounds and the minimum latency are inclusive. ``outcome`` and latency
    are read from ``sampling_params['terminal_outcome']`` and
    ``sampling_params['elapsed_seconds']`` respectively. All string predicates
    use exact, case-sensitive equality; there is no text or regular-expression
    search.
    """

    tenant_id: str | None = None
    model: str | None = None
    endpoint: str | None = None
    state_id: str | None = None
    node_hash: str | None = None
    outcome: str | None = None
    phi_scrubbed: bool | None = None
    min_latency_ms: float | None = None
    start_time: float | None = None
    end_time: float | None = None
    offset: int = 0
    limit: int = DEFAULT_PAGE_LIMIT
    order: SearchOrder = SearchOrder.OLDEST_FIRST

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "model",
            "endpoint",
            "state_id",
            "node_hash",
            "outcome",
        ):
            _validate_optional_predicate(name, getattr(self, name))

        if self.phi_scrubbed is not None and type(self.phi_scrubbed) is not bool:
            raise TypeError("phi_scrubbed must be bool or None")
        _validate_optional_number("min_latency_ms", self.min_latency_ms, non_negative=True)
        _validate_optional_number("start_time", self.start_time, non_negative=False)
        _validate_optional_number("end_time", self.end_time, non_negative=False)
        if (
            self.start_time is not None
            and self.end_time is not None
            and self.start_time > self.end_time
        ):
            raise ValueError("start_time must be less than or equal to end_time")
        if type(self.offset) is not int:
            raise TypeError("offset must be an int")
        if self.offset < 0:
            raise ValueError("offset must be non-negative")
        if type(self.limit) is not int:
            raise TypeError("limit must be an int")
        if not 1 <= self.limit <= MAX_PAGE_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_LIMIT}")
        if type(self.order) is not SearchOrder:
            raise TypeError("order must be a SearchOrder")


@dataclass(frozen=True, slots=True)
class SearchPage(Generic[AuditNodeT]):
    """One immutable page and pagination metadata."""

    items: tuple[AuditNodeT, ...]
    total: int
    offset: int
    limit: int

    @property
    def has_more(self) -> bool:
        """Whether another matching item exists after this page."""

        return self.offset + len(self.items) < self.total


@dataclass(frozen=True, slots=True)
class _NodeMetadata(Generic[AuditNodeT]):
    node: AuditNodeT
    source_index: int
    state_id: str
    node_hash: str
    timestamp: float
    tenant_id: str
    model: str
    endpoint: str
    phi_scrubbed: bool
    outcome: str | None
    latency_ms: float | None


def search_retained_nodes(
    nodes: tuple[AuditNodeT, ...],
    query: ForensicSearchQuery,
) -> SearchPage[AuditNodeT]:
    """Search one fixed tuple of retained-node references.

    The result is sorted by timestamp and exact identity metadata rather than
    relying on caller iteration behavior. Original snapshot position is the
    final tie-breaker. The input nodes are returned by identity in an immutable
    tuple; they are never copied or mutated.

    Raises:
        TypeError: If the snapshot, query, or node metadata has an invalid type.
        ValueError: If numeric node metadata is not finite or is negative where
            negative values are invalid.
    """

    if type(nodes) is not tuple:
        raise TypeError("nodes must be an immutable tuple snapshot")
    if type(query) is not ForensicSearchQuery:
        raise TypeError("query must be a ForensicSearchQuery")

    metadata = tuple(_read_metadata(node, index) for index, node in enumerate(nodes))
    matches = [item for item in metadata if _matches(item, query)]
    matches.sort(
        key=lambda item: (
            item.timestamp,
            item.state_id,
            item.node_hash,
            item.source_index,
        ),
        reverse=query.order is SearchOrder.NEWEST_FIRST,
    )
    page = matches[query.offset : query.offset + query.limit]
    return SearchPage(
        items=tuple(item.node for item in page),
        total=len(matches),
        offset=query.offset,
        limit=query.limit,
    )


def _read_metadata(node: AuditNodeT, source_index: int) -> _NodeMetadata[AuditNodeT]:
    state_id = _require_node_string(node, "state_id")
    node_hash = _require_node_string(node, "node_hash")
    tenant_id = _require_node_string(node, "tenant_id")
    model = _require_node_string(node, "model")
    endpoint = _require_node_string(node, "endpoint")

    raw_timestamp = getattr(node, "timestamp", None)
    timestamp = _require_finite_number("node.timestamp", raw_timestamp, non_negative=False)

    phi_scrubbed = getattr(node, "phi_scrubbed", None)
    if type(phi_scrubbed) is not bool:
        raise TypeError("node.phi_scrubbed must be a bool")

    sampling_params = getattr(node, "sampling_params", None)
    if not isinstance(sampling_params, Mapping):
        raise TypeError("node.sampling_params must be a mapping")

    raw_outcome = sampling_params.get("terminal_outcome")
    if raw_outcome is not None and type(raw_outcome) is not str:
        raise TypeError("node terminal_outcome must be a str or None")
    outcome = raw_outcome if isinstance(raw_outcome, str) else None

    raw_elapsed = sampling_params.get("elapsed_seconds")
    latency_ms: float | None = None
    if raw_elapsed is not None:
        elapsed_seconds = _require_finite_number(
            "node elapsed_seconds", raw_elapsed, non_negative=True
        )
        latency_ms = _require_finite_number(
            "node latency_ms", elapsed_seconds * 1_000.0, non_negative=True
        )

    return _NodeMetadata(
        node=node,
        source_index=source_index,
        state_id=state_id,
        node_hash=node_hash,
        timestamp=timestamp,
        tenant_id=tenant_id,
        model=model,
        endpoint=endpoint,
        phi_scrubbed=phi_scrubbed,
        outcome=outcome,
        latency_ms=latency_ms,
    )


def _matches(item: _NodeMetadata[AuditNodeT], query: ForensicSearchQuery) -> bool:
    return (
        (query.tenant_id is None or item.tenant_id == query.tenant_id)
        and (query.model is None or item.model == query.model)
        and (query.endpoint is None or item.endpoint == query.endpoint)
        and (query.state_id is None or item.state_id == query.state_id)
        and (query.node_hash is None or item.node_hash == query.node_hash)
        and (query.outcome is None or item.outcome == query.outcome)
        and (query.phi_scrubbed is None or item.phi_scrubbed is query.phi_scrubbed)
        and (
            query.min_latency_ms is None
            or (item.latency_ms is not None and item.latency_ms >= query.min_latency_ms)
        )
        and (query.start_time is None or item.timestamp >= query.start_time)
        and (query.end_time is None or item.timestamp <= query.end_time)
    )


def _validate_optional_predicate(name: str, value: object) -> None:
    if value is None:
        return
    if type(value) is not str:
        raise TypeError(f"{name} must be a str or None")
    if not value:
        raise ValueError(f"{name} must not be empty")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain a NULL byte")


def _validate_optional_number(name: str, value: object, *, non_negative: bool) -> None:
    if value is None:
        return
    _require_finite_number(name, value, non_negative=non_negative)


def _require_finite_number(name: str, value: object, *, non_negative: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be an int or float")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    if non_negative and result < 0:
        raise ValueError(f"{name} must be non-negative")
    return result


def _require_node_string(node: object, name: str) -> str:
    value = getattr(node, name, None)
    if type(value) is not str:
        raise TypeError(f"node.{name} must be a str")
    return value


__all__ = [
    "DEFAULT_PAGE_LIMIT",
    "MAX_PAGE_LIMIT",
    "AuditNodeLike",
    "ForensicSearchQuery",
    "SearchOrder",
    "SearchPage",
    "search_retained_nodes",
]
