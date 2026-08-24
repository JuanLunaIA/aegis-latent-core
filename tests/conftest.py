# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Shared pytest fixtures and global import-time stubs.

The optional storage backends (DynamoDB via ``aioboto3``/``boto3``/``botocore``
and PostgreSQL via ``asyncpg``) are *extras* that are not installed in the dev
test environment.  Several test modules stub them in ``sys.modules`` so that
``aegis_server.storage.*`` can be imported without the real packages.

Installing those stubs here — in ``conftest.py``, which pytest imports **before**
collecting any test module — guarantees a single, deterministic stub set
regardless of test collection order or sharding.  Crucially,
``botocore.exceptions.ClientError`` is bound to a *real* exception class that is
shared across every test module.  This prevents the order-dependent failure
where one module installs a bare ``MagicMock`` stub (with ``ClientError`` as an
auto-generated ``MagicMock`` attribute rather than a raisable/catchable
exception), causing ``aegis_server.storage.dynamodb_provider`` to bind
``except ClientError`` to a non-exception object.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

# Tests are isolated development-mode consumers; production defaults remain strict.
os.environ.setdefault("AEGIS_SECURITY_ENFORCEMENT_MODE", "development")
# Historical endpoint tests use valid API keys without enterprise principal maps.
# Production remains deny-by-default; focused auth tests remove or override this.
os.environ.setdefault("AEGIS_ALLOW_LEGACY_UNMAPPED_API_KEY_PRINCIPALS", "true")


class _StubClientError(Exception):
    """Stand-in for ``botocore.exceptions.ClientError``.

    Mirrors the attributes the production code inspects (``response["Error"]
    ["Code"]``) so provider error-handling paths behave like the real SDK.
    """

    def __init__(self, code: str = "TestError", msg: str = "test") -> None:
        self.response = {"Error": {"Code": code, "Message": msg}}
        super().__init__(msg)


def _install_optional_backend_stubs() -> None:
    """Install ``sys.modules`` stubs for optional backends if not already present.

    Idempotent: only stubs modules that are absent, so a real installation (if
    ever present) is never shadowed once imported.
    """
    if "aioboto3" not in sys.modules:
        sys.modules["aioboto3"] = MagicMock()
    if "boto3" not in sys.modules:
        sys.modules["boto3"] = MagicMock()
    if "boto3.dynamodb" not in sys.modules:
        sys.modules["boto3.dynamodb"] = MagicMock()
    if "boto3.dynamodb.conditions" not in sys.modules:
        _cond = MagicMock()
        _cond.Key = MagicMock(return_value=MagicMock())
        _cond.Attr = MagicMock(return_value=MagicMock())
        sys.modules["boto3.dynamodb.conditions"] = _cond
    if "botocore" not in sys.modules:
        sys.modules["botocore"] = MagicMock()
    if "botocore.exceptions" not in sys.modules:
        _bexc = MagicMock()
        _bexc.ClientError = _StubClientError
        sys.modules["botocore.exceptions"] = _bexc
    else:
        # Module already present (e.g. a bare MagicMock from another import):
        # ensure ClientError is a real, raisable exception class.
        _existing = sys.modules["botocore.exceptions"]
        if not isinstance(getattr(_existing, "ClientError", None), type):
            _existing.ClientError = _StubClientError
    if "asyncpg" not in sys.modules:
        sys.modules["asyncpg"] = MagicMock()


_install_optional_backend_stubs()
