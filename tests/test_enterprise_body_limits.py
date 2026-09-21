# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""AUD-09 (REG-D13): the enterprise surface enforces body limits on both sides.

Before this fix `aegis_server` buffered `await request.body()` and
`await resp.aread()` with no limit and installed no body-limit middleware, so
the surface that fronts the gateway was the weaker of the two. It now installs
the gateway's `RequestBodyLimitMiddleware`, streams the upstream response
instead of buffering it, and stops echoing raw exception text to clients
(AF-066).
"""

from __future__ import annotations

import json
from contextlib import ExitStack
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from aegis.proxy.body_limits import RequestBodyLimitMiddleware
from aegis_server.config import EnterpriseSettings
from aegis_server.main import create_app

BIG = 4_096
SMALL = 1_024  # EnterpriseSettings floors the limits at 1_024


def _settings(**kw) -> EnterpriseSettings:
    defaults: dict[str, Any] = dict(
        signer_provider="hmac",
        hmac_signing_key="a" * 32,
        storage_provider="sqlite",
        sqlite_path="/tmp/aegis_aud09.db",
        auth_disabled=True,
        compliance_export_dir="/tmp/aegis_aud09_exports",
    )
    defaults.update(kw)
    return EnterpriseSettings(**defaults)


def _storage(**overrides) -> MagicMock:
    storage = MagicMock()
    storage.initialize = AsyncMock()
    storage.close = AsyncMock()
    storage.check_integrity = AsyncMock(return_value={"is_valid": True, "node_count": 0})
    storage.list_nodes = AsyncMock(return_value=[])
    storage.get_latest_node = AsyncMock(return_value=None)
    storage.get_node = AsyncMock(return_value=None)
    storage.write_node = AsyncMock(return_value=None)
    storage.write_node_atomic = AsyncMock(return_value=None)
    for name, value in overrides.items():
        setattr(storage, name, value)
    return storage


def _signer() -> MagicMock:
    signer = MagicMock()
    signer.scheme = "hmac-sha256"
    signer.sign_payload = AsyncMock(return_value="a" * 64)
    return signer


def _aiter(parts: list[bytes]):
    async def _gen():
        for part in parts:
            yield part

    return _gen()


class _StreamContext:
    """`client.stream(...)` returns a context manager, not a response."""

    def __init__(self, response: MagicMock) -> None:
        self._response = response

    async def __aenter__(self) -> MagicMock:
        return self._response

    async def __aexit__(self, *exc) -> bool:
        return False


def _upstream(*chunks: bytes, status_code: int = 200, headers: dict[str, str] | None = None):
    """A streaming upstream double whose body is the given chunks."""
    response = MagicMock()
    response.status_code = status_code
    response.headers = headers if headers is not None else {"content-type": "application/json"}
    response.aiter_bytes = MagicMock(return_value=_aiter(list(chunks)))
    return response


def _client(settings: EnterpriseSettings, storage: MagicMock, upstream):
    """App + TestClient with the upstream client patched (streaming shape)."""
    stack = ExitStack()
    stack.enter_context(patch("aegis_server.main.get_settings", return_value=settings))
    stack.enter_context(patch("aegis_server.main.get_provider", return_value=storage))
    stack.enter_context(patch("aegis_server.main.get_signer", return_value=_signer()))
    http_client = AsyncMock()
    http_client.__aenter__ = AsyncMock(return_value=http_client)
    http_client.__aexit__ = AsyncMock(return_value=False)
    if isinstance(upstream, Exception):
        http_client.stream = MagicMock(side_effect=upstream)
    else:
        http_client.stream = MagicMock(return_value=_StreamContext(upstream))
    stack.enter_context(patch("httpx.AsyncClient", return_value=http_client))
    return stack, TestClient(create_app(settings=settings))


PROXY = "/v1/enterprise/proxy/chat/completions"


# ── request side ────────────────────────────────────────────────────────────


def test_declared_request_body_over_the_limit_is_refused() -> None:
    """The gateway's middleware is installed here too, so this is now a 413."""
    settings = _settings(max_request_body_bytes=SMALL)
    storage = _storage()
    stack, client = _client(settings, storage, _upstream(b"{}"))
    with stack, client:
        response = client.post(PROXY, json={"model": "gpt-4", "messages": [], "padding": "x" * BIG})
    assert response.status_code == 413
    assert response.json()["detail"] == "Request body too large"
    # The body was refused before the route ran, so nothing was evidenced.
    storage.write_node_atomic.assert_not_awaited()


def test_chunked_request_body_over_the_limit_is_refused() -> None:
    """A body with no Content-Length is still counted, chunk by chunk."""
    settings = _settings(max_request_body_bytes=SMALL)
    storage = _storage()
    stack, client = _client(settings, storage, _upstream(b"{}"))
    with stack, client:
        response = client.post(PROXY, content=iter([b"y" * BIG]))
    assert response.status_code == 413
    storage.write_node_atomic.assert_not_awaited()


def test_request_body_within_the_limit_still_reaches_the_route() -> None:
    settings = _settings(max_request_body_bytes=SMALL)
    storage = _storage()
    body = json.dumps({"id": "chatcmpl-1", "choices": []}).encode()
    stack, client = _client(settings, storage, _upstream(body))
    with stack, client:
        response = client.post(PROXY, json={"model": "gpt-4", "messages": []})
    assert response.status_code == 200
    assert response.content == body


# ── response side ───────────────────────────────────────────────────────────


def test_undeclared_oversized_upstream_response_is_refused_and_evidenced() -> None:
    """The bytes actually read are counted, so a lying upstream is bounded too."""
    settings = _settings(max_response_body_bytes=SMALL)
    storage = _storage()
    huge = b"z" * BIG  # no content-length header: the streaming path must catch it
    stack, client = _client(settings, storage, _upstream(huge))
    with stack, client:
        response = client.post(PROXY, json={"model": "gpt-4", "messages": []})
    assert response.status_code == 502
    assert response.json()["error"] == "upstream LLM response exceeded the configured limit"
    # The refusal is durable evidence, and the oversized body was not relayed.
    storage.write_node_atomic.assert_awaited_once()
    assert storage.write_node_atomic.call_args.kwargs["node_data"]["upstream_status"] == 502
    assert huge not in response.content


def test_declared_oversized_upstream_response_is_refused_before_being_read() -> None:
    settings = _settings(max_response_body_bytes=SMALL)
    storage = _storage()
    upstream = _upstream(
        b"whatever", headers={"content-type": "application/json", "content-length": str(BIG)}
    )
    stack, client = _client(settings, storage, upstream)
    with stack, client:
        response = client.post(PROXY, json={"model": "gpt-4", "messages": []})
    assert response.status_code == 502
    upstream.aiter_bytes.assert_not_called()


def test_upstream_response_within_the_limit_is_still_relayed() -> None:
    settings = _settings(max_response_body_bytes=SMALL)
    storage = _storage()
    body = json.dumps({"id": "chatcmpl-2", "choices": []}).encode()
    stack, client = _client(settings, storage, _upstream(body))
    with stack, client:
        response = client.post(PROXY, json={"model": "gpt-4", "messages": []})
    assert response.status_code == 200
    assert response.content == body
    assert response.headers["X-Aegis-Evidence-Status"] == "durable"


# ── AF-066: raw exception text is not echoed to clients ─────────────────────


@pytest.mark.parametrize(
    ("path", "storage_field", "status", "detail"),
    [
        ("/v1/enterprise/audit/nodes", "list_nodes", 400, "invalid node listing parameters"),
        ("/v1/enterprise/audit/integrity", "check_integrity", 500, "audit integrity check failed"),
        (
            "/v1/enterprise/audit/nodes/" + "a" * 64,
            "get_node",
            500,
            "audit node lookup failed",
        ),
    ],
)
def test_storage_failures_do_not_echo_exception_text(
    path: str, storage_field: str, status: int, detail: str
) -> None:
    leak = "sqlite3: /var/lib/aegis/ledger.db is locked by pid 4242"
    settings = _settings()
    storage = _storage(**{storage_field: AsyncMock(side_effect=RuntimeError(leak))})
    stack, client = _client(settings, storage, _upstream(b"{}"))
    with stack, client:
        response = client.get(path)
    assert response.status_code == status
    assert response.json()["detail"] == detail
    assert leak not in response.text


# ── the shared middleware, on its own (both surfaces install it) ────────────


async def _asgi_app(scope, receive, send) -> None:
    """Reads the whole body, so the receive path is actually exercised."""
    body = b""
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": body})


async def _call(app, scope, messages):
    """Drive an ASGI app with a scripted receive channel, capturing the status."""
    sent: list[dict] = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent[0]["status"] if sent else None


@pytest.mark.anyio
async def test_middleware_refuses_a_declared_oversized_body() -> None:
    middleware = RequestBodyLimitMiddleware(_asgi_app, max_body_bytes=SMALL)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"content-length", str(BIG).encode())],
    }
    status = await _call(middleware, scope, [])
    assert status == 413


@pytest.mark.anyio
async def test_middleware_refuses_a_chunked_oversized_body() -> None:
    """The refusal arrives wrapped in an anyio group; it must still be a 413.

    Before this was handled, the chunked path produced an unhandled server
    error instead of a 413 — on the gateway as well, since it installs the same
    middleware and only ever tested the declared-length path.
    """
    middleware = RequestBodyLimitMiddleware(_asgi_app, max_body_bytes=SMALL)
    scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    messages = [
        {"type": "http.request", "body": b"y" * BIG, "more_body": True},
        {"type": "http.request", "body": b"", "more_body": False},
    ]
    status = await _call(middleware, scope, messages)
    assert status == 413


@pytest.mark.anyio
async def test_middleware_lets_an_unrelated_exception_group_through() -> None:
    """The unwrapping is precise: only this middleware's own refusal is caught."""

    async def _boom(scope, receive, send) -> None:
        raise BaseExceptionGroup("boom", [ValueError("unrelated")])

    middleware = RequestBodyLimitMiddleware(_boom, max_body_bytes=SMALL)
    scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    with pytest.raises(BaseExceptionGroup):
        await _call(middleware, scope, [])
