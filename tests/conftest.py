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


def _real_or_stub(module_name: str) -> None:
    """Prefer a genuine install over the stub; only fall back on ImportError.

    Checking ``sys.modules`` alone cannot distinguish "really absent" from
    "installed but nothing has imported it yet" — conftest.py runs before any
    test module gets the chance to. A REG-011-style real-server integration
    test needs the actual package, so attempt the import first and stub only
    when it genuinely is not installed.
    """
    if module_name in sys.modules:
        return
    try:
        __import__(module_name)
    except ImportError:
        sys.modules[module_name] = MagicMock()


def _install_optional_backend_stubs() -> None:
    """Install ``sys.modules`` stubs for optional backends if not already present.

    Idempotent: only stubs modules that are absent, so a real installation (if
    ever present) is never shadowed once imported.
    """
    _real_or_stub("aioboto3")
    _real_or_stub("boto3")
    _real_or_stub("boto3.dynamodb")
    if "boto3.dynamodb.conditions" not in sys.modules:
        try:
            __import__("boto3.dynamodb.conditions")
        except ImportError:
            _cond = MagicMock()
            _cond.Key = MagicMock(return_value=MagicMock())
            _cond.Attr = MagicMock(return_value=MagicMock())
            sys.modules["boto3.dynamodb.conditions"] = _cond
    if "botocore" not in sys.modules:
        try:
            __import__("botocore")
        except ImportError:
            sys.modules["botocore"] = MagicMock()
    if "botocore.exceptions" not in sys.modules:
        try:
            __import__("botocore.exceptions")
        except ImportError:
            _bexc = MagicMock()
            _bexc.ClientError = _StubClientError
            sys.modules["botocore.exceptions"] = _bexc
    else:
        # Module already present (e.g. a bare MagicMock from another import):
        # ensure ClientError is a real, raisable exception class.
        _existing = sys.modules["botocore.exceptions"]
        if not isinstance(getattr(_existing, "ClientError", None), type):
            _existing.ClientError = _StubClientError
    _real_or_stub("asyncpg")


_install_optional_backend_stubs()
