# Copyright (c) 2026 Juan Luna. All rights reserved.
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

from aegis_server.storage.base import (
    GENESIS_PREV_HASH,
    ConcurrentChainMutationError,
    IntegrityReport,
    StorageProvider,
)

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

# The chain link, lifted out of node_data into a column PostgreSQL can
# constrain. In a linear chain each node has exactly one successor, so no two
# nodes share a prev_hash — and a fork is exactly two nodes that do. The unique
# index therefore makes a fork unrepresentable rather than merely detectable,
# with no lock, across every worker and host pointed at this database.
#
# It also covers what a compare-and-append cannot: on an empty table there is
# no row for SELECT ... FOR UPDATE to lock, so two genesis writers would
# otherwise both pass the check and both commit.
_DDL_PREV_HASH_COLUMN = """
ALTER TABLE audit_nodes ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '';
"""

_DDL_BACKFILL_PREV_HASH = """
UPDATE audit_nodes
   SET prev_hash = COALESCE(node_data ->> 'prev_hash', '')
 WHERE prev_hash = '';
"""

_DDL_PREV_HASH_IDX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_prev_hash
    ON audit_nodes (prev_hash) WHERE prev_hash <> '';
"""

_DUPLICATE_PREV_HASH_SQL = """
SELECT prev_hash FROM audit_nodes
WHERE prev_hash <> ''
GROUP BY prev_hash HAVING COUNT(*) > 1
LIMIT 1;
"""

# Compare-and-append. The insert happens only when the current tip is still the
# one the caller linked to; RETURNING is empty otherwise, which is how the
# caller learns the tip moved. FOR UPDATE holds the tip row for the duration of
# the transaction so a concurrent appender blocks rather than reading a tip that
# is about to change.
_INSERT_ATOMIC_SQL = """
WITH tip AS (
    SELECT node_id FROM audit_nodes ORDER BY seq DESC LIMIT 1 FOR UPDATE
)
INSERT INTO audit_nodes
    (node_id, timestamp, request_hash, response_hash,
     merkle_root, signature, client_id, node_data, prev_hash)
SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
WHERE (NOT EXISTS (SELECT 1 FROM tip) AND $9 = $10)
   OR ((SELECT node_id FROM tip) = $9)
ON CONFLICT (node_id) DO NOTHING
RETURNING node_id;
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
                    await self._migrate_prev_hash(conn)
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

    @staticmethod
    async def _migrate_prev_hash(conn: Any) -> None:
        """Lift ``prev_hash`` into a column and index it uniquely.

        Idempotent. Loud on exactly one case: if the unique index cannot be
        built, two rows already name the same predecessor, so this chain has
        **already forked**. Starting anyway would mean appending to a history
        with two pasts, which no verifier can resolve afterwards. The error
        names the duplicate; choosing the authoritative branch is an operator
        decision this code has no basis to make.
        """
        await conn.execute(_DDL_PREV_HASH_COLUMN)
        await conn.execute(_DDL_BACKFILL_PREV_HASH)
        try:
            await conn.execute(_DDL_PREV_HASH_IDX)
        except asyncpg.UniqueViolationError as exc:
            duplicate = await conn.fetchval(_DUPLICATE_PREV_HASH_SQL)
            raise RuntimeError(
                "audit chain is already forked: more than one node names "
                f"prev_hash={duplicate!r} as its predecessor. Refusing to "
                "initialise, because appending to a chain with two histories "
                "produces evidence that cannot be verified. Resolve which "
                "branch is authoritative before restarting."
            ) from exc

    async def write_node_atomic(
        self,
        node_id: str,
        timestamp: str,
        node_data: dict[str, Any],
        request_hash: str,
        response_hash: str,
        merkle_root: str,
        signature: str,
        client_id: str,
        expected_prev_hash: str,
    ) -> None:
        """Append only if the tip is still ``expected_prev_hash``.

        One statement, inside one transaction: the tip is read under
        ``FOR UPDATE`` and the insert is conditional on it, so there is no
        window between the check and the append for another worker to slip
        into. An empty ``RETURNING`` means the tip moved and nothing was
        written.

        Raises:
            ConcurrentChainMutationError: The tip moved; nothing was written.
            RuntimeError: When the pool is not initialized or on I/O failure.
        """
        self._require_pool()
        node_data_json = json.dumps(node_data, separators=(",", ":"), default=str)

        try:
            async with self._pool.acquire() as conn:  # type: ignore[union-attr]
                async with conn.transaction():
                    written = await conn.fetchval(
                        _INSERT_ATOMIC_SQL,
                        node_id,
                        timestamp,
                        request_hash,
                        response_hash,
                        merkle_root,
                        signature,
                        client_id,
                        node_data_json,
                        expected_prev_hash,
                        GENESIS_PREV_HASH,
                    )
        except asyncpg.UniqueViolationError as exc:
            # The prev_hash index fired: another node already links here. Same
            # meaning as a moved tip, caught by the backstop instead of the
            # check — which is what covers the empty-table genesis race.
            raise ConcurrentChainMutationError(
                f"another node already links to {expected_prev_hash[:16]}…; nothing was written"
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"PostgreSQLStorageProvider.write_node_atomic failed for node_id={node_id!r}: {exc}"
            ) from exc

        if written is None:
            raise ConcurrentChainMutationError(
                f"chain tip moved: caller linked to {expected_prev_hash[:16]}…; nothing was written"
            )

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
