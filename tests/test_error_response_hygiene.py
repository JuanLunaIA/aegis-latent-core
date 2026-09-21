# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""HTTP error responses must not carry internals (MISSION ORDER §PHASE 2.4).

Two claims are pinned here, and the second is the one that had no test:

* the three endpoints that catch a storage/export ``RuntimeError`` return a
  **fixed** detail string, while the exception text goes to the process log
  (`logger.error("compliance export failed: %s", exc)` and siblings in
  `aegis_server/main.py`) — the client learns that it failed, not why the
  server failed;
* an exception the route does *not* expect is answered by the ASGI stack's
  generic ``500`` with a body that names no exception class, no message and no
  traceback. Nothing in the repository pinned this before, so a future
  ``add_exception_handler`` that echoed ``str(exc)`` would have been invisible
  to the suite.

The assertion is on the *body*, not the status code: an earlier generation of
tests asserted ``status_code == 500`` and would have stayed green through any
amount of leaked detail. `test_main_new.py` keeps those status-only tests; this
file is the body-level half.
"""

from __future__ import annotations

import sys
from contextlib import ExitStack, contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

# ── sys.modules stubs for optional backends (must be before any import) ────────
# Identical to tests/test_main_new.py: this module builds its own app rather
# than importing that test module (tests/ is not a package).
for _mod in ["aioboto3", "boto3", "boto3.dynamodb", "botocore"]:
    sys.modules.setdefault(_mod, MagicMock())
if "boto3.dynamodb.conditions" not in sys.modules:
    _cond = MagicMock()
    _cond.Key = MagicMock()
    sys.modules["boto3.dynamodb.conditions"] = _cond
if "botocore.exceptions" not in sys.modules:
    sys.modules["botocore.exceptions"] = MagicMock()
if "asyncpg" not in sys.modules:
    sys.modules["asyncpg"] = MagicMock()

from starlette.testclient import TestClient  # noqa: E402

from aegis_server.config import EnterpriseSettings  # noqa: E402
from aegis_server.main import create_app  # noqa: E402

# The string that must never reach a client. Deliberately distinctive so a leak
# cannot be mistaken for incidental text in the body.
SECRET = "SECRET-INTERNAL-9f3a"

STORAGE_ERROR_CASES = (
    ("/v1/enterprise/audit/nodes/" + "c" * 64, "get_node", "audit node lookup failed"),
    ("/v1/enterprise/audit/integrity", "check_integrity", "audit integrity check failed"),
)


def _settings() -> EnterpriseSettings:
    return EnterpriseSettings(
        signer_provider="hmac",
        hmac_signing_key="a" * 32,
        storage_provider="sqlite",
        sqlite_path="/tmp/test_error_hygiene.db",
        auth_disabled=True,
        compliance_export_dir="/tmp/aegis_test_error_hygiene",
    )


def _storage() -> MagicMock:
    storage = MagicMock()
    storage.initialize = AsyncMock()
    storage.close = AsyncMock()
    storage.check_integrity = AsyncMock(
        return_value={
            "is_valid": True,
            "node_count": 5,
            "checked_at": "2024-01-01T00:00:00.000000Z",
        }
    )
    storage.list_nodes = AsyncMock(return_value=[])
    storage.get_latest_node = AsyncMock(return_value=None)
    storage.get_node = AsyncMock(return_value=None)
    storage.write_node = AsyncMock()
    storage.write_node_atomic = AsyncMock()
    return storage


def _signer() -> MagicMock:
    signer = MagicMock()
    signer.scheme = "hmac"
    signer.sign_payload = AsyncMock(return_value="abc123def456")
    return signer


@contextmanager
def _client(storage: MagicMock, *, raise_server_exceptions: bool):
    """Build the real app around a mock storage, exactly as production does."""
    settings = _settings()
    signer = _signer()
    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=settings))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=storage))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=signer))
        app = create_app(settings=settings)
        with TestClient(app, raise_server_exceptions=raise_server_exceptions) as client:
            yield client


def _assert_no_internals(text: str, *, context: str) -> None:
    """The body must name no exception, no traceback and no internal message."""
    for forbidden in (SECRET, "Traceback", "RuntimeError", "ValueError", 'File "'):
        assert forbidden not in text, f"{context}: body leaked {forbidden!r}: {text[:400]!r}"


def test_handled_storage_errors_return_fixed_details_only() -> None:
    """The three fixed-detail 500 paths return their constant, not the exception."""
    for path, method, expected_detail in STORAGE_ERROR_CASES:
        storage = _storage()
        setattr(storage, method, AsyncMock(side_effect=RuntimeError(SECRET)))
        with _client(storage, raise_server_exceptions=False) as client:
            response = client.get(path)
        assert response.status_code == 500, (path, response.status_code)
        assert response.json() == {"detail": expected_detail}, (path, response.text)
        _assert_no_internals(response.text, context=path)


def test_unexpected_exception_is_answered_generically() -> None:
    """An exception no handler expects yields the ASGI stack's generic 500.

    ``ValueError`` is not caught by the route (it catches ``RuntimeError``), so
    this exercises the unhandled path rather than the handled one.
    """
    storage = _storage()
    storage.get_node = AsyncMock(side_effect=ValueError(SECRET))
    with _client(storage, raise_server_exceptions=False) as client:
        response = client.get("/v1/enterprise/audit/nodes/" + "c" * 64)
    assert response.status_code == 500, response.status_code
    assert response.text.strip() == "Internal Server Error", response.text
    _assert_no_internals(response.text, context="unhandled")


def test_the_leak_detector_itself_fires() -> None:
    """Negative control: the assertion must reject a body that does leak.

    Without this, a typo in the forbidden-string list would make every test
    above vacuous while staying green.
    """
    try:
        _assert_no_internals(f'{{"detail": "{SECRET}"}}', context="control")
    except AssertionError as exc:
        assert SECRET in str(exc)
    else:  # pragma: no cover - the control is what makes the rest meaningful
        raise AssertionError("the leak detector accepted a leaking body")
