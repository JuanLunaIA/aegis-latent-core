# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.

"""
Unit tests for RLS SQL generation — no database required.

These tests verify that the RLS DDL statements in postgres_provider.py
are correctly formed. They run without a database.
"""

from __future__ import annotations


class TestRLSSQLGeneration:
    """Verify RLS DDL statements are correctly formed."""

    def test_ddl_tenant_id_column(self) -> None:
        """Tenant ID column DDL must be present and correct."""
        from aegis_server.storage.postgres_provider import _DDL_TENANT_ID_COLUMN

        sql = _DDL_TENANT_ID_COLUMN.strip()
        assert "ALTER TABLE audit_nodes ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT ''" in sql

    def test_ddl_backfill_tenant_id(self) -> None:
        """Backfill DDL must update existing rows."""
        from aegis_server.storage.postgres_provider import _DDL_BACKFILL_TENANT_ID

        sql = _DDL_BACKFILL_TENANT_ID.strip()
        assert "UPDATE audit_nodes" in sql
        assert "SET tenant_id = COALESCE(client_id, '')" in sql
        assert "WHERE tenant_id = ''" in sql

    def test_ddl_enable_rls(self) -> None:
        """Enable RLS DDL must be present."""
        from aegis_server.storage.postgres_provider import _DDL_ENABLE_RLS

        sql = _DDL_ENABLE_RLS.strip()
        assert "ALTER TABLE audit_nodes ENABLE ROW LEVEL SECURITY" in sql

    def test_rls_policy_select(self) -> None:
        """SELECT policy must use current_setting for tenant_id."""
        from aegis_server.storage.postgres_provider import _DDL_RLS_POLICY_SELECT

        sql = _DDL_RLS_POLICY_SELECT.strip()
        assert "CREATE POLICY audit_nodes_tenant_isolation_select ON audit_nodes" in sql
        assert "FOR SELECT USING (tenant_id = current_setting('aegis.tenant_id', true))" in sql

    def test_rls_policy_insert(self) -> None:
        """INSERT policy must use current_setting for tenant_id."""
        from aegis_server.storage.postgres_provider import _DDL_RLS_POLICY_INSERT

        sql = _DDL_RLS_POLICY_INSERT.strip()
        assert "CREATE POLICY audit_nodes_tenant_isolation_insert ON audit_nodes" in sql
        assert "FOR INSERT WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true))" in sql

    def test_rls_policy_update(self) -> None:
        """UPDATE policy must use current_setting for tenant_id."""
        from aegis_server.storage.postgres_provider import _DDL_RLS_POLICY_UPDATE

        sql = _DDL_RLS_POLICY_UPDATE.strip()
        assert "CREATE POLICY audit_nodes_tenant_isolation_update ON audit_nodes" in sql
        assert "FOR UPDATE USING (tenant_id = current_setting('aegis.tenant_id', true))" in sql
        assert "WITH CHECK (tenant_id = current_setting('aegis.tenant_id', true))" in sql

    def test_rls_policy_delete(self) -> None:
        """DELETE policy must use current_setting for tenant_id."""
        from aegis_server.storage.postgres_provider import _DDL_RLS_POLICY_DELETE

        sql = _DDL_RLS_POLICY_DELETE.strip()
        assert "CREATE POLICY audit_nodes_tenant_isolation_delete ON audit_nodes" in sql
        assert "FOR DELETE USING (tenant_id = current_setting('aegis.tenant_id', true))" in sql

    def test_set_tenant_context_function(self) -> None:
        """set_tenant_context function must be SECURITY DEFINER."""
        from aegis_server.storage.postgres_provider import _DDL_SET_TENANT_FUNCTION

        sql = _DDL_SET_TENANT_FUNCTION.strip()
        assert "CREATE OR REPLACE FUNCTION set_tenant_context(p_tenant_id text) RETURNS void" in sql
        assert "LANGUAGE plpgsql SECURITY DEFINER" in sql
        assert "set_config('aegis.tenant_id', p_tenant_id, false)" in sql

    def test_reset_tenant_context_function(self) -> None:
        """reset_tenant_context function must be SECURITY DEFINER."""
        from aegis_server.storage.postgres_provider import _DDL_RESET_TENANT_FUNCTION

        sql = _DDL_RESET_TENANT_FUNCTION.strip()
        assert "CREATE OR REPLACE FUNCTION reset_tenant_context() RETURNS void" in sql
        assert "LANGUAGE plpgsql SECURITY DEFINER" in sql
        assert "set_config('aegis.tenant_id', '', false)" in sql

    def test_all_rls_ddls_present_in_initialize(self) -> None:
        """All RLS DDLs must be executed in initialize()."""
        import inspect

        from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider

        source = inspect.getsource(PostgreSQLStorageProvider.initialize)

        # All RLS DDL constants must be referenced
        required_ddls = [
            "_DDL_TENANT_ID_COLUMN",
            "_DDL_BACKFILL_TENANT_ID",
            "_DDL_ENABLE_RLS",
            "_DDL_RLS_POLICY_SELECT",
            "_DDL_RLS_POLICY_INSERT",
            "_DDL_RLS_POLICY_UPDATE",
            "_DDL_RLS_POLICY_DELETE",
            "_DDL_SET_TENANT_FUNCTION",
            "_DDL_RESET_TENANT_FUNCTION",
        ]

        for ddl in required_ddls:
            assert ddl in source, f"{ddl} not executed in initialize()"

    def test_write_node_sets_tenant_context(self) -> None:
        """write_node must call set_tenant_context when client_id provided."""
        import inspect

        from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider

        source = inspect.getsource(PostgreSQLStorageProvider.write_node)
        assert "set_tenant_context" in source
        assert "client_id" in source

    def test_write_node_atomic_sets_tenant_context(self) -> None:
        """write_node_atomic must call set_tenant_context when client_id provided."""
        import inspect

        from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider

        source = inspect.getsource(PostgreSQLStorageProvider.write_node_atomic)
        assert "set_tenant_context" in source
        assert "client_id" in source

    def test_list_nodes_sets_tenant_context(self) -> None:
        """list_nodes must call set_tenant_context when tenant_id provided."""
        import inspect

        from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider

        source = inspect.getsource(PostgreSQLStorageProvider.list_nodes)
        assert "set_tenant_context" in source
        assert "tenant_id" in source

    def test_get_node_sets_tenant_context(self) -> None:
        """get_node must call set_tenant_context when tenant_id provided."""
        import inspect

        from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider

        source = inspect.getsource(PostgreSQLStorageProvider.get_node)
        assert "set_tenant_context" in source
        assert "tenant_id" in source

    def test_get_latest_node_sets_tenant_context(self) -> None:
        """get_latest_node must call set_tenant_context when tenant_id provided."""
        import inspect

        from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider

        source = inspect.getsource(PostgreSQLStorageProvider.get_latest_node)
        assert "set_tenant_context" in source
        assert "tenant_id" in source

    def test_no_direct_header_tenant_in_storage(self) -> None:
        """Storage layer must not reference X-Tenant-ID or x-tenant-id headers."""
        import inspect

        from aegis_server.storage import base, dynamodb_provider, postgres_provider, sqlite_provider

        for mod in [postgres_provider, sqlite_provider, dynamodb_provider, base]:
            source = inspect.getsource(mod)
            # Headers should never appear in storage layer
            assert "X-Tenant-ID" not in source
            assert "x-tenant-id" not in source
            assert "X-User-ID" not in source
            assert "x-user-id" not in source

    def test_tenant_id_parameter_in_base_interface(self) -> None:
        """StorageProvider base class must have tenant_id parameter on read methods."""
        import inspect

        from aegis_server.storage.base import StorageProvider

        # get_node
        sig = inspect.signature(StorageProvider.get_node)
        assert "tenant_id" in sig.parameters
        param = sig.parameters["tenant_id"]
        assert param.default is None or param.default == inspect.Parameter.empty

        # get_latest_node
        sig = inspect.signature(StorageProvider.get_latest_node)
        assert "tenant_id" in sig.parameters
        param = sig.parameters["tenant_id"]
        assert param.default is None or param.default == inspect.Parameter.empty

        # list_nodes
        sig = inspect.signature(StorageProvider.list_nodes)
        assert "tenant_id" in sig.parameters
        param = sig.parameters["tenant_id"]
        assert param.default is None or param.default == inspect.Parameter.empty
