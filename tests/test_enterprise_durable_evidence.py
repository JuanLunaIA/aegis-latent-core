# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from starlette.testclient import TestClient

from aegis_server.config import EnterpriseSettings
from aegis_server.main import create_app


def _settings() -> EnterpriseSettings:
    return EnterpriseSettings(
        signer_provider="hmac",
        hmac_signing_key="a" * 32,
        storage_provider="sqlite",
        sqlite_path="/tmp/aegis_market_hardening_enterprise.db",
        auth_disabled=True,
        compliance_export_dir="/tmp/aegis_market_hardening_exports",
    )


def _storage(*, write_error: Exception | None = None) -> MagicMock:
    storage = MagicMock()
    storage.initialize = AsyncMock()
    storage.close = AsyncMock()
    storage.check_integrity = AsyncMock(return_value={"is_valid": True, "node_count": 0})
    storage.list_nodes = AsyncMock(return_value=[])
    storage.get_latest_node = AsyncMock(return_value=None)
    storage.get_node = AsyncMock(return_value=None)
    storage.write_node = AsyncMock(side_effect=write_error)
    return storage


def _signer() -> MagicMock:
    signer = MagicMock()
    signer.scheme = "hmac-sha256"
    signer.sign_payload = AsyncMock(return_value="a" * 64)
    return signer


def _client(storage: MagicMock, signer: MagicMock, upstream_response=None, upstream_error=None):
    settings = _settings()
    stack = ExitStack()
    stack.enter_context(patch("aegis_server.main.get_settings", return_value=settings))
    stack.enter_context(patch("aegis_server.main.get_provider", return_value=storage))
    stack.enter_context(patch("aegis_server.main.get_signer", return_value=signer))
    if upstream_error is not None:
        upstream = AsyncMock(side_effect=upstream_error)
    else:
        upstream = AsyncMock(return_value=upstream_response)
    http_client = AsyncMock()
    http_client.__aenter__ = AsyncMock(return_value=http_client)
    http_client.__aexit__ = AsyncMock(return_value=False)
    http_client.post = upstream
    stack.enter_context(patch("httpx.AsyncClient", return_value=http_client))
    app = create_app(settings=settings)
    return stack, TestClient(app), storage


def test_success_response_is_returned_only_after_durable_evidence():
    body = json.dumps({"id": "chatcmpl-1", "choices": []}).encode()
    response = MagicMock(status_code=200, headers={"content-type": "application/json"})
    response.aread = AsyncMock(return_value=body)
    stack, client, storage = _client(_storage(), _signer(), upstream_response=response)
    with stack, client:
        result = client.post(
            "/v1/enterprise/proxy/chat/completions", json={"model": "gpt-4", "messages": []}
        )
    assert result.status_code == 200
    assert result.headers["X-Aegis-Evidence-Status"] == "durable"
    storage.write_node.assert_awaited_once()
    assert storage.write_node.call_args.kwargs["node_data"]["upstream_status"] == 200


def test_upstream_non_2xx_is_durably_evidenced_before_return():
    body = json.dumps({"error": {"message": "rate limited"}}).encode()
    response = MagicMock(status_code=429, headers={"content-type": "application/json"})
    response.aread = AsyncMock(return_value=body)
    stack, client, storage = _client(_storage(), _signer(), upstream_response=response)
    with stack, client:
        result = client.post(
            "/v1/enterprise/proxy/chat/completions", json={"model": "gpt-4", "messages": []}
        )
    assert result.status_code == 429
    assert result.headers["X-Aegis-Evidence-Status"] == "durable"
    storage.write_node.assert_awaited_once()
    assert storage.write_node.call_args.kwargs["node_data"]["upstream_status"] == 429


def test_upstream_network_error_uses_durable_error_evidence():
    stack, client, storage = _client(
        _storage(), _signer(), upstream_error=httpx.ConnectError("refused")
    )
    with stack, client:
        result = client.post(
            "/v1/enterprise/proxy/chat/completions", json={"model": "gpt-4", "messages": []}
        )
    assert result.status_code == 502
    assert result.headers["X-Aegis-Evidence-Status"] == "durable"
    storage.write_node.assert_awaited_once()
    assert storage.write_node.call_args.kwargs["node_data"]["upstream_status"] == 502


def test_storage_failure_fails_closed_and_does_not_claim_durable():
    stack, client, storage = _client(
        _storage(write_error=RuntimeError("disk full")),
        _signer(),
        upstream_error=httpx.ConnectError("refused"),
    )
    with stack, client:
        result = client.post(
            "/v1/enterprise/proxy/chat/completions", json={"model": "gpt-4", "messages": []}
        )
    assert result.status_code == 503
    assert result.headers["X-Aegis-Evidence-Status"] == "unavailable"
