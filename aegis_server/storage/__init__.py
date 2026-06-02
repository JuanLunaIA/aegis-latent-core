# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.storage — Pluggable async audit node persistence layer.

Public API::

    from aegis_server.storage import StorageProvider, get_provider

    provider = get_provider(settings)
    await provider.initialize()
    await provider.write_node(...)
    await provider.close()
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from aegis_server.storage.base import IntegrityReport, StorageNode, StorageProvider
from aegis_server.storage.dynamodb_provider import DynamoDBStorageProvider
from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider
from aegis_server.storage.sqlite_provider import SQLiteStorageProvider

if TYPE_CHECKING:
    from aegis_server.config import EnterpriseSettings

__all__ = [
    "StorageProvider",
    "StorageNode",
    "IntegrityReport",
    "SQLiteStorageProvider",
    "PostgreSQLStorageProvider",
    "DynamoDBStorageProvider",
    "get_provider",
]


def get_provider(settings: EnterpriseSettings) -> StorageProvider:
    """
    Factory: return the correct ``StorageProvider`` for the given settings.

    Args:
        settings: Validated ``EnterpriseSettings`` instance.

    Returns:
        An uninitialised ``StorageProvider``.  Call ``await provider.initialize()``
        before use.

    Raises:
        ValueError: For unknown ``storage_provider`` values.
    """
    backend = settings.storage_provider.lower()

    if backend == "sqlite":
        return SQLiteStorageProvider(db_path=settings.sqlite_path)

    if backend == "postgres":
        return PostgreSQLStorageProvider(
            dsn=settings.postgres_dsn,
            min_size=settings.postgres_min_pool_size,
            max_size=settings.postgres_max_pool_size,
        )

    if backend == "dynamodb":
        return DynamoDBStorageProvider(
            table_name=settings.dynamodb_table,
            region=settings.dynamodb_region,
            endpoint_url=settings.dynamodb_endpoint_url,
        )

    raise ValueError(
        f"Unknown storage_provider={backend!r}. Valid values: 'sqlite', 'postgres', 'dynamodb'."
    )
