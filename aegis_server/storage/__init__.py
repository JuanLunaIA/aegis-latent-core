# Copyright (c) 2026 Juan Luna. All rights reserved.
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

from typing import TYPE_CHECKING, Any

from aegis_server.storage.base import IntegrityReport, StorageNode, StorageProvider

if TYPE_CHECKING:
    from aegis_server.config import EnterpriseSettings
    from aegis_server.storage.dynamodb_provider import DynamoDBStorageProvider
    from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider
    from aegis_server.storage.sqlite_provider import SQLiteStorageProvider

__all__ = [
    "StorageProvider",
    "StorageNode",
    "IntegrityReport",
    "SQLiteStorageProvider",
    "PostgreSQLStorageProvider",
    "DynamoDBStorageProvider",
    "get_provider",
]

# Lazy provider re-exports (PEP 562): each backend pulls in an optional extra
# (aioboto3 for DynamoDB, asyncpg for Postgres). Importing the package must not
# require every extra — only the backend actually accessed is imported.
_LAZY_PROVIDERS = {
    "SQLiteStorageProvider": "aegis_server.storage.sqlite_provider",
    "PostgreSQLStorageProvider": "aegis_server.storage.postgres_provider",
    "DynamoDBStorageProvider": "aegis_server.storage.dynamodb_provider",
}


def __getattr__(name: str) -> Any:
    module_path = _LAZY_PROVIDERS.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    return getattr(importlib.import_module(module_path), name)


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
        from aegis_server.storage.sqlite_provider import SQLiteStorageProvider

        return SQLiteStorageProvider(db_path=settings.sqlite_path)

    if backend == "postgres":
        from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider

        return PostgreSQLStorageProvider(
            dsn=settings.postgres_dsn,
            min_size=settings.postgres_min_pool_size,
            max_size=settings.postgres_max_pool_size,
        )

    if backend == "dynamodb":
        from aegis_server.storage.dynamodb_provider import DynamoDBStorageProvider

        return DynamoDBStorageProvider(
            table_name=settings.dynamodb_table,
            region=settings.dynamodb_region,
            endpoint_url=settings.dynamodb_endpoint_url,
        )

    raise ValueError(
        f"Unknown storage_provider={backend!r}. Valid values: 'sqlite', 'postgres', 'dynamodb'."
    )
