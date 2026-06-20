# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.storage.base — Abstract storage provider interface and shared data models.

Defines the ``StorageProvider`` ABC that every concrete backend must implement,
plus ``StorageNode`` and ``IntegrityReport`` value objects shared across the system.

All persistence I/O is asynchronous.  Implementations must be safe for concurrent
usage from multiple asyncio tasks without external locking.

Dependencies: Python 3.11+ stdlib only.
"""

from __future__ import annotations

import abc
import datetime
from dataclasses import asdict, dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StorageNode:
    """
    Immutable audit node as stored in / retrieved from a ``StorageProvider``.

    ``node_id`` is the SHA-256 hex of the structured node content (the chain
    link); it acts as the primary key in every backend.
    """

    node_id: str
    """SHA-256 hex that uniquely identifies and links this node in the chain."""

    timestamp: str
    """ISO 8601 UTC string, e.g. ``"2026-06-01T12:00:00.123456Z"``."""

    request_hash: str
    """SHA-256 hex of the raw request body bytes."""

    response_hash: str
    """SHA-256 hex of the raw response body bytes.  Empty string for partial commits."""

    merkle_root: str
    """MMR root after this node's leaf was inserted."""

    signature: str
    """Hex-encoded cryptographic signature covering ``merkle_root``."""

    client_id: str
    """Redacted API-key prefix (8 chars) or tenant identifier."""

    node_data: dict[str, Any] = field(default_factory=dict)
    """
    Extended forensic metadata serialized as JSON in the backend.

    Typical keys: ``prev_hash``, ``entropy``, ``kl_divergence``, ``model``,
    ``endpoint``, ``token_trail_count``, ``is_fallback``.
    """

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StorageNode:
        """
        Reconstruct from a storage row dict.

        Scalar fields are extracted explicitly; any unknown keys are merged
        into ``node_data`` so forward-compatibility is preserved.

        Args:
            data: Raw dict from a storage backend row.

        Returns:
            Populated ``StorageNode``.
        """
        _SCALAR_FIELDS = frozenset(
            {
                "node_id",
                "timestamp",
                "request_hash",
                "response_hash",
                "merkle_root",
                "signature",
                "client_id",
            }
        )
        scalars: dict[str, str] = {k: str(data.get(k, "")) for k in _SCALAR_FIELDS}
        stored_node_data: dict[str, Any] = data.get("node_data", {})
        if isinstance(stored_node_data, str):
            import json

            try:
                stored_node_data = json.loads(stored_node_data)
            except (json.JSONDecodeError, ValueError):
                stored_node_data = {}
        overflow: dict[str, Any] = {
            k: v for k, v in data.items() if k not in _SCALAR_FIELDS and k != "node_data"
        }
        return cls(**scalars, node_data={**stored_node_data, **overflow})

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict suitable for export bundles."""
        return asdict(self)


@dataclass
class IntegrityReport:
    """
    Result of a full chain-linkage verification sweep across all stored nodes.

    This checks that each node's ``node_data["prev_hash"]`` correctly references
    its predecessor's ``node_id``.  It does *not* re-derive node hashes from
    content (that requires knowing the exact upstream hash schema); use the
    ``/v1/audit/integrity`` endpoint on a running proxy for full cryptographic
    verification.
    """

    is_valid: bool
    """``True`` iff every chain link is intact and no gaps were detected."""

    node_count: int
    """Total number of nodes examined."""

    first_node_id: str | None
    """``node_id`` of the genesis (oldest) node, or ``None`` when empty."""

    last_node_id: str | None
    """``node_id`` of the tail (newest) node, or ``None`` when empty."""

    broken_link_index: int | None
    """Zero-based position of the first broken link, or ``None`` when valid."""

    error_message: str | None
    """Human-readable description of the first failure, or ``None`` when valid."""

    checked_at: str
    """ISO 8601 UTC timestamp of when the check was executed."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class StorageProvider(abc.ABC):
    """
    Abstract interface for Aegis audit node persistence backends.

    Lifecycle contract
    ------------------
    1. Call ``await provider.initialize()`` once before any read/write.
    2. Use ``write_node`` / ``get_node`` / ``list_nodes`` / ``check_integrity``
       freely from concurrent asyncio tasks.
    3. Call ``await provider.close()`` on application shutdown.

    All implementations must be idempotent on duplicate ``node_id`` writes —
    a second write for the same node must not raise.
    """

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def initialize(self) -> None:
        """
        Create tables, indexes, connection pools, or any one-time setup.

        Must be called exactly once before any other method.
        Implementations must be idempotent (safe to call on an existing schema).
        """

    @abc.abstractmethod
    async def close(self) -> None:
        """
        Release all connections, file handles, and background resources.

        Must be safe to call even if ``initialize`` was never invoked.
        """

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def write_node(
        self,
        node_id: str,
        timestamp: str,
        node_data: dict[str, Any],
        request_hash: str,
        response_hash: str,
        merkle_root: str,
        signature: str,
        client_id: str,
    ) -> None:
        """
        Persist a single audit node.

        Args:
            node_id:       SHA-256 hex of the node content — primary key.
            timestamp:     ISO 8601 UTC string (``"YYYY-MM-DDTHH:MM:SS.ffffffZ"``).
            node_data:     Serialisable dict of extended forensic metadata.
                           Must contain ``prev_hash`` for chain linkage.
            request_hash:  SHA-256 hex of the raw request body.
            response_hash: SHA-256 hex of the raw response body.
                           Empty string for request-only commits.
            merkle_root:   MMR root at commit time.
            signature:     Hex-encoded signature (scheme recorded in ``node_data``).
            client_id:     Redacted API-key prefix or tenant identifier.

        Raises:
            RuntimeError: On unrecoverable persistence failures.
        """

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    @abc.abstractmethod
    async def get_latest_node(self) -> dict[str, Any] | None:
        """
        Return the most recently inserted audit node, or ``None`` if empty.

        This is used exclusively by the chain-linkage logic in
        ``_run_forensic_analytics`` to retrieve the correct ``prev_hash``
        for the next node.  Implementations MUST return the node with the
        highest insertion sequence number (i.e. ``ORDER BY seq DESC LIMIT 1``).

        Returns:
            A dict compatible with ``StorageNode.from_dict``, or ``None``
            when the storage is empty (genesis condition).

        Note:
            Reading ``prev_hash`` and writing the next node are NOT atomic
            across this call boundary.  For single-process deployments this
            is safe because the enterprise layer serialises background tasks.
            For multi-process deployments use a storage backend (PostgreSQL)
            that supports the atomic CTE insert pattern.
        """

    @abc.abstractmethod
    async def get_node(self, node_hash: str) -> dict[str, Any] | None:
        """
        Retrieve a single audit node by its SHA-256 hash identifier.

        Args:
            node_hash: Exact ``node_id`` to look up.

        Returns:
            A dict compatible with ``StorageNode.from_dict``, or ``None``
            if no record with that hash exists.
        """

    @abc.abstractmethod
    async def list_nodes(
        self,
        limit: int,
        offset: int,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return a paginated list of audit nodes ordered by timestamp ascending.

        Args:
            limit:     Maximum number of records (1–1000 inclusive).
            offset:    Zero-based record offset for cursor-style pagination.
            tenant_id: When provided, restrict results to this client identifier.

        Returns:
            List of node dicts, each compatible with ``StorageNode.from_dict``.
            Empty list when no records match.
        """

    @abc.abstractmethod
    async def check_integrity(self) -> dict[str, Any]:
        """
        Verify the hash-link chain across all stored nodes.

        Iterates every node in insertion order and confirms that each node's
        ``node_data["prev_hash"]`` matches the preceding node's ``node_id``.

        Returns:
            JSON-serialisable dict matching ``IntegrityReport.to_dict()``.
        """

    # ------------------------------------------------------------------
    # Helpers available to all sub-classes
    # ------------------------------------------------------------------

    @staticmethod
    def _utcnow_iso() -> str:
        """Return the current UTC time as an ISO 8601 string with microseconds."""
        return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    @staticmethod
    def _clamp_limit(limit: int, *, max_limit: int = 1000) -> int:
        """Clamp ``limit`` to the range [1, max_limit]."""
        return max(1, min(limit, max_limit))

    @staticmethod
    def _validate_offset(offset: int) -> int:
        """Ensure ``offset`` is non-negative."""
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")
        return offset
