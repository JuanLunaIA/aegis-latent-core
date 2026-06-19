# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.storage.postgres_provider — PostgreSQL audit node persistence.

Uses ``asyncpg`` for high-throughput async I/O with connection pooling.  The
pool is created during ``initialize()`` and held for the process lifetime,
giving sub-millisecond connection acquisition after warm-up.

Schema (created on ``initialize()``)::

    CREATE TABLE IF NOT EXISTS audit_nodes (
        seq           BIGSERIAL PRIMARY KEY,
        node_id       TEXT      NOT NULL,
        timestamp     TIMESTAMPTZ NOT NULL,        -- stored as text, displayed as tz-aware
        request_hash  TEXT      NOT NULL DEFAULT '',
        response_hash TEXT      NOT NULL DEFAULT '',
        merkle_root   TEXT      NOT NULL DEFAULT '',
        signature     TEXT      NOT NULL DEFAULT '',
        client_id     TEXT      NOT NULL DEFAULT '',
        node_data     JSONB     NOT NULL DEFAULT '{}'
    );

``JSONB`` is used for ``node_data`` because it allows the server to index
individual keys (e.g. for future ``CREATE INDEX … USING GIN``) and stores the
JSON in a compact binary form that avoids re-parsing on every read.

``BIGSERIAL`` gives stable insertion-order pagination without clock-skew
ambiguity on distributed writers.

Dependencies:
    asyncpg>=0.29.0
"""

from __future__ import annotations

import json
import logging
from typing import Any

import asyncpg
from asyncpg import Pool

from aegis_server.storage.base import IntegrityReport, StorageProvider

logger = logging.getLogger(__name__)

_DDL_TABLE = """
CREATE TABLE IF NOT EXISTS audit_nodes (
    seq           BIGSERIAL PRIMARY KEY,
    node_id       TEXT        NOT NULL,
    timestamp     TEXT        NOT NULL,
    request_hash  TEXT        NOT NULL DEFAULT '',
    response_hash TEXT        NOT NULL DEFAULT '',
    merkle_root   TEXT        NOT NULL DEFAULT '',
    signature     TEXT        NOT NULL DEFAULT '',
    client_id     TEXT        NOT NULL DEFAULT '',
    node_data     JSONB       NOT NULL DEFAULT '{}'
);
"""

_DDL_UNIQUE_IDX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_node_id
    ON audit_nodes (node_id);
"""

_DDL_TIMESTAMP_IDX = """
CREATE INDEX IF NOT EXISTS idx_audit_timestamp
    ON audit_nodes (timestamp);
"""

_DDL_CLIENT_IDX = """
CREATE INDEX IF NOT EXISTS idx_audit_client
    ON audit_nodes (client_id);
"""

_INSERT_SQL = """
INSERT INTO audit_nodes
    (node_id, timestamp, request_hash, response_hash,
     merkle_root, signature, client_id, node_data)
VALUES
    ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (node_id) DO NOTHING;
"""

_SELECT_BY_ID_SQL = """
SELECT node_id, timestamp, request_hash, response_hash,
       merkle_root, signature, client_id, node_data
FROM audit_nodes
WHERE node_id = $1;
"""

_LIST_ALL_SQL = """
SELECT node_id, timestamp, request_hash, response_hash,
       merkle_root, signature, client_id, node_data
FROM audit_nodes
ORDER BY seq ASC
LIMIT $1 OFFSET $2;
"""

_LIST_TENANT_SQL = """
SELECT node_id, timestamp, request_hash, response_hash,
       merkle_root, signature, client_id, node_data
FROM audit_nodes
WHERE client_id = $1
ORDER BY seq ASC
LIMIT $2 OFFSET $3;
"""

_ALL_FOR_INTEGRITY_SQL = """
SELECT node_id, node_data
FROM audit_nodes
ORDER BY seq ASC;
"""

# BLOCKER-NEW fix: correct query for get_latest_node() — ORDER BY seq DESC LIMIT 1
_LATEST_NODE_SQL = """
SELECT node_id, timestamp, request_hash, response_hash,
       merkle_root, signature, client_id, node_data
FROM audit_nodes
ORDER BY seq DESC
LIMIT 1;
"""


class PostgreSQLStorageProvider(StorageProvider):
    """
    Async PostgreSQL audit node storage using ``asyncpg`` connection pools.

    This provider is safe for multi-worker Uvicorn deployments because every
    worker holds its own pool and PostgreSQL serialises concurrent writes at
    the server level.  For maximum write throughput consider partitioning the
    ``audit_nodes`` table by month using PostgreSQL declarative partitioning.

    Args:
        dsn:          asyncpg DSN, e.g.
                      ``"postgresql://user:pass@host:5432/aegis_audit"``.
        min_size:     Minimum connections kept alive in the pool.
        max_size:     Maximum connections the pool will open.
    """

    def __init__(
        self,
        dsn: str,
        min_size: int = 2,
        max_size: int = 10,
    ) -> None:
        if not dsn:
            raise ValueError("PostgreSQLStorageProvider requires a non-empty DSN")
        self._dsn = dsn
        self._min_size = min_size
        self._max_size = max_size
        self._pool: Pool | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """
        Create the connection pool and run DDL migrations.

        Idempotent: safe to call on a database with an existing schema.

        Raises:
            RuntimeError: On connection failure or DDL errors.
        """
        try:
            self._pool = await asyncpg.create_pool(
                dsn=self._dsn,
                min_size=self._min_size,
                max_size=self._max_size,
                command_timeout=30.0,
                statement_cache_size=100,
            )
        except Exception as exc:
            raise RuntimeError(f"PostgreSQLStorageProvider: failed to create pool: {exc}") from exc

        try:
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(_DDL_TABLE)
                    await conn.execute(_DDL_UNIQUE_IDX)
                    await conn.execute(_DDL_TIMESTAMP_IDX)
                    await conn.execute(_DDL_CLIENT_IDX)
        except Exception as exc:
            await self._pool.close()
            self._pool = None
            raise RuntimeError(
                f"PostgreSQLStorageProvider: schema migration failed: {exc}"
            ) from exc

        logger.info(
            "PostgreSQLStorageProvider initialised: pool_size=%d–%d",
            self._min_size,
            self._max_size,
        )

    async def close(self) -> None:
        """
        Gracefully close all pooled connections.

        Waits for in-flight queries to complete before closing.
        """
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            logger.debug("PostgreSQLStorageProvider pool closed")

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

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
        Insert an audit node.  Uses ``ON CONFLICT DO NOTHING`` for idempotency.

        Raises:
            RuntimeError: When the pool is not initialized or on I/O failure.
        """
        self._require_pool()
        node_data_json = json.dumps(node_data, separators=(",", ":"), default=str)

        try:
            async with self._pool.acquire() as conn:  # type: ignore[union-attr]
                await conn.execute(
                    _INSERT_SQL,
                    node_id,
                    timestamp,
                    request_hash,
                    response_hash,
                    merkle_root,
                    signature,
                    client_id,
                    node_data_json,
                )
        except Exception as exc:
            raise RuntimeError(
                f"PostgreSQLStorageProvider.write_node failed for node_id={node_id!r}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_latest_node(self) -> dict[str, Any] | None:
        """
        Return the most recently inserted audit node (highest seq), or None.

        BLOCKER-NEW fix: implements the abstract method added to StorageProvider
        in v2.2.0.  PostgreSQL uses ORDER BY seq DESC LIMIT 1 — same semantics
        as the SQLite provider.

        Note: no write lock is held here.  For multi-process / multi-worker
        deployments, use PostgreSQL advisory locks or a Redis Redlock to
        serialise the read-prev → write-node sequence across workers.
        """
        self._require_pool()
        try:
            async with self._pool.acquire() as conn:  # type: ignore[union-attr]
                row = await conn.fetchrow(_LATEST_NODE_SQL)
            if row is None:
                return None
            raw = dict(row)
            if raw.get("node_data"):
                try:
                    raw["node_data"] = json.loads(raw["node_data"])
                except (json.JSONDecodeError, TypeError):
                    pass
            return raw
        except Exception as exc:
            raise RuntimeError(f"PostgreSQLStorageProvider.get_latest_node failed: {exc}") from exc

    async def get_node(self, node_hash: str) -> dict[str, Any] | None:
        """
        Retrieve a node by SHA-256 hash.

        Returns:
            Dict compatible with ``StorageNode.from_dict``, or ``None``.

        Raises:
            RuntimeError: On pool or I/O failure.
        """
        self._require_pool()

        try:
            async with self._pool.acquire() as conn:  # type: ignore[union-attr]
                row = await conn.fetchrow(_SELECT_BY_ID_SQL, node_hash)
        except Exception as exc:
            raise RuntimeError(
                f"PostgreSQLStorageProvider.get_node failed for hash={node_hash!r}: {exc}"
            ) from exc

        if row is None:
            return None
        return self._record_to_dict(dict(row))

    async def list_nodes(
        self,
        limit: int,
        offset: int,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return a paginated list of nodes in insertion order.

        Raises:
            ValueError:   If ``offset < 0``.
            RuntimeError: On pool or I/O failure.
        """
        self._require_pool()
        clamped = self._clamp_limit(limit)
        offset = self._validate_offset(offset)

        try:
            async with self._pool.acquire() as conn:  # type: ignore[union-attr]
                if tenant_id:
                    rows = await conn.fetch(_LIST_TENANT_SQL, tenant_id, clamped, offset)
                else:
                    rows = await conn.fetch(_LIST_ALL_SQL, clamped, offset)
        except Exception as exc:
            raise RuntimeError(f"PostgreSQLStorageProvider.list_nodes failed: {exc}") from exc

        return [self._record_to_dict(dict(r)) for r in rows]

    async def check_integrity(self) -> dict[str, Any]:
        """
        Verify chain linkage across all stored nodes (ordered by seq).

        Returns:
            ``IntegrityReport.to_dict()``-compatible dict.

        Raises:
            RuntimeError: On pool or I/O failure.
        """
        self._require_pool()
        checked_at = self._utcnow_iso()

        try:
            async with self._pool.acquire() as conn:  # type: ignore[union-attr]
                rows = await conn.fetch(_ALL_FOR_INTEGRITY_SQL)
        except Exception as exc:
            raise RuntimeError(f"PostgreSQLStorageProvider.check_integrity failed: {exc}") from exc

        if not rows:
            return IntegrityReport(
                is_valid=True,
                node_count=0,
                first_node_id=None,
                last_node_id=None,
                broken_link_index=None,
                error_message=None,
                checked_at=checked_at,
            ).to_dict()

        first_id: str = rows[0]["node_id"]
        last_id: str = rows[-1]["node_id"]
        prev_node_id: str = "0" * 64

        for i, row in enumerate(rows):
            current_node_id: str = row["node_id"]
            raw_nd = row["node_data"]
            # asyncpg decodes JSONB columns as dicts automatically
            node_data: dict[str, Any] = raw_nd if isinstance(raw_nd, dict) else {}

            stored_prev: str = node_data.get("prev_hash", "")

            if stored_prev != prev_node_id:
                return IntegrityReport(
                    is_valid=False,
                    node_count=len(rows),
                    first_node_id=first_id,
                    last_node_id=last_id,
                    broken_link_index=i,
                    error_message=(
                        f"Node {i} (id={current_node_id[:16]}…): "
                        f"prev_hash mismatch — "
                        f"expected={prev_node_id[:16]}…, "
                        f"stored={stored_prev[:16] if stored_prev else '(empty)'}…"
                    ),
                    checked_at=checked_at,
                ).to_dict()

            prev_node_id = current_node_id

        return IntegrityReport(
            is_valid=True,
            node_count=len(rows),
            first_node_id=first_id,
            last_node_id=last_id,
            broken_link_index=None,
            error_message=None,
            checked_at=checked_at,
        ).to_dict()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_pool(self) -> None:
        if self._pool is None:
            raise RuntimeError("PostgreSQLStorageProvider.initialize() was not called")

    @staticmethod
    def _record_to_dict(record: dict[str, Any]) -> dict[str, Any]:
        """Normalise an asyncpg record dict for downstream consumers."""
        nd = record.get("node_data", {})
        if isinstance(nd, str):
            try:
                nd = json.loads(nd)
            except (json.JSONDecodeError, ValueError):
                nd = {}
        record["node_data"] = nd
        record.pop("seq", None)
        return record
