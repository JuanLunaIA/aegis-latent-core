# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The gateway answers an unexpected exception with a generic JSON 500 (REG-D73).

Before the fix an exception no route handled reached Starlette's default and
came back as ``text/plain`` "Internal Server Error". Nothing leaked — the
2026-09-24 gatekeeper probe confirmed that — but every other error the gateway
returns is ``{"detail": ...}`` JSON, so a client had to special-case the one
error it can least predict. `tests/test_error_response_hygiene.py` pins the
enterprise server; this file pins the gateway, on the real ``create_app``.
"""

from __future__ import annotations

from pathlib import Path

from starlette.testclient import TestClient

from aegis.config import AegisSettings
from aegis.proxy.app import create_app

SECRET = "SECRET-INTERNAL-7c1e"


def _settings(tmp_path: Path) -> AegisSettings:
    return AegisSettings(
        backend_api_key="sk-test",
        backend_url="http://mock-upstream",
        api_keys="sk-valid",
        wal_path=str(tmp_path / "gateway.wal"),
        log_level="WARNING",
        auth_disabled=False,
        waf_strict_mode=False,
    )


def test_an_unexpected_exception_is_a_generic_json_500(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))

    @app.get("/__raise_for_test")
    async def _raise() -> None:
        raise ValueError(SECRET)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/__raise_for_test")

    assert response.status_code == 500
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"detail": "Internal server error"}
    for forbidden in (SECRET, "Traceback", "ValueError", 'File "'):
        assert forbidden not in response.text


def test_the_exception_still_reaches_the_server_log(tmp_path: Path, caplog) -> None:
    """Generic to the client does not mean silent: the traceback is logged."""
    app = create_app(_settings(tmp_path))

    @app.get("/__raise_for_test")
    async def _raise() -> None:
        raise ValueError(SECRET)

    with (
        caplog.at_level("ERROR", logger="aegis.proxy.app"),
        TestClient(app, raise_server_exceptions=False) as client,
    ):
        client.get("/__raise_for_test")

    records = [r for r in caplog.records if r.name == "aegis.proxy.app"]
    assert any("unhandled error on GET /__raise_for_test" in r.getMessage() for r in records)
    assert any(r.exc_info and SECRET in str(r.exc_info[1]) for r in records)
