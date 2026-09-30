# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""REG-D98: a request body the gateway cannot use is a 400, never a 500.

Each of the three model endpoints parsed its body with
``canonical_normalize(json.loads(raw_body))`` and caught ``JSONDecodeError``
alone. Five inputs escaped that catch and were answered 500:

* invalid UTF-8, which ``json.loads`` reports as ``UnicodeDecodeError``;
* an integer longer than Python's 4300-digit limit (``ValueError``);
* nesting past the interpreter's recursion limit (``RecursionError``);
* *valid* JSON nested a few hundred levels, which parsed and then exhausted
  the stack inside ``canonical_normalize``;
* a body that is valid JSON but not an object, which the chat and completions
  endpoints accepted and then failed on the first ``body.get``.

A 500 on hostile input tells the attacker where the parser gives way, and it
is counted as a server fault rather than a client error. The fix is one helper,
``_parse_request_json``, shared by all three endpoints; the tests pin its answer
at every endpoint and confirm that nothing reaches the provider.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis.config import AegisSettings
from aegis.proxy.app import _json_nesting_exceeds, _parse_request_json, create_app

ENDPOINTS = ("/v1/chat/completions", "/v1/completions", "/v1/messages")


def _upstream() -> MagicMock:
    data = {"id": "x", "object": "chat.completion", "choices": [], "usage": {}}
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.content = json.dumps(data).encode()
    resp.json.return_value = data
    resp.headers = {"content-type": "application/json"}
    return resp


def _forwarder(provider: str) -> MagicMock:
    inst = MagicMock()
    inst.start = AsyncMock()
    inst.stop = AsyncMock()
    inst.provider = MagicMock()
    inst.provider.name = provider
    inst.provider.supports_logprobs = True
    inst.forward_json = AsyncMock(return_value=_upstream())
    inst.forward_native_anthropic = AsyncMock(return_value=_upstream())
    inst.stream_sse = AsyncMock(return_value=iter([]))
    return inst


@pytest.fixture(params=ENDPOINTS)
def endpoint_client(request, tmp_path) -> Iterator[tuple[str, TestClient, MagicMock]]:
    path = request.param
    provider = "anthropic" if path == "/v1/messages" else "openai"
    fwd = _forwarder(provider)
    cfg = AegisSettings(
        backend_api_key="sk-backend",
        backend_url="http://mock-upstream",
        api_keys="sk-valid",
        wal_path=str(tmp_path / "test.wal"),
        log_level="WARNING",
        auth_disabled=False,
        analysis_sample_rate=0.0,
        provider=provider,
    )
    with patch("aegis.proxy.app.LLMForwarder", return_value=fwd):
        app = create_app(cfg)
        with TestClient(app, raise_server_exceptions=False) as client:
            yield path, client, fwd
    try:
        app.state.aegis.ledger.close()
    except Exception:
        pass


def _nested(depth: int) -> bytes:
    return (
        b'{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}],"x":'
        + b"[" * depth
        + b"]" * depth
        + b"}"
    )


BAD_BODIES = [
    pytest.param(
        b'{"model":"m","messages":[{"role":"user","content":"\xff\xfe"}]}', id="invalid-utf8"
    ),
    pytest.param(b'{"model":"m","n":' + b"9" * 5000 + b"}", id="5000-digit-integer"),
    pytest.param(_nested(5000), id="nesting-5000"),
    pytest.param(_nested(900), id="nesting-900"),
    pytest.param(_nested(40), id="nesting-40"),
    pytest.param(b"[1, 2, 3]", id="list-body"),
    pytest.param(b'"hello"', id="string-body"),
    pytest.param(b"null", id="null-body"),
    pytest.param(b"not json at all {{{", id="not-json"),
]


@pytest.mark.parametrize("raw", BAD_BODIES)
def test_unusable_body_is_400_at_every_endpoint(endpoint_client, raw: bytes) -> None:
    path, client, fwd = endpoint_client
    resp = client.post(
        path,
        headers={"Authorization": "Bearer sk-valid", "content-type": "application/json"},
        content=raw,
    )
    assert resp.status_code == 400, (path, resp.status_code, resp.text[:200])
    assert fwd.forward_json.await_count == 0
    assert fwd.forward_native_anthropic.await_count == 0


@pytest.mark.parametrize("depth", [40, 900])
def test_a_body_refused_for_depth_is_recorded(endpoint_client, depth: int) -> None:
    """Depth 33+ used to reach the WAF and leave a rejection node; it still does.

    The parse bound answers first now, so it commits the node itself. Without
    that, the REG-D98 fix would have removed evidence the WAF path wrote.
    """
    path, client, _ = endpoint_client
    resp = client.post(
        path,
        headers={"Authorization": "Bearer sk-valid", "content-type": "application/json"},
        content=_nested(depth),
    )
    assert resp.status_code == 400
    assert resp.headers.get("x-aegis-rejection-id"), resp.headers
    assert resp.headers.get("x-aegis-evidence-status") == "durable-rejection"


@pytest.mark.parametrize("raw", [b"not json at all {{{", b"[1, 2, 3]"])
def test_an_unparseable_body_is_not_recorded(endpoint_client, raw: bytes) -> None:
    """Unchanged: these were a 400 with no node before REG-D98, and still are."""
    path, client, _ = endpoint_client
    resp = client.post(
        path,
        headers={"Authorization": "Bearer sk-valid", "content-type": "application/json"},
        content=raw,
    )
    assert resp.status_code == 400
    assert not resp.headers.get("x-aegis-rejection-id")


def test_nesting_within_the_bound_still_reaches_the_waf(endpoint_client) -> None:
    """Depth 11 to 32 is the WAF's to refuse, with a durable rejection node."""
    path, client, _ = endpoint_client
    resp = client.post(
        path,
        headers={"Authorization": "Bearer sk-valid", "content-type": "application/json"},
        content=_nested(20),
    )
    assert resp.status_code == 403, (path, resp.text[:200])
    assert resp.headers.get("x-aegis-rejection-id")


def test_nesting_check_is_iterative_and_exact() -> None:
    value: object = "leaf"
    for _ in range(100_000):
        value = [value]
    assert _json_nesting_exceeds(value, 32)
    assert not _json_nesting_exceeds({"a": [[{"b": 1}]]}, 3)
    assert _json_nesting_exceeds({"a": [[{"b": {}}]]}, 3)


def test_the_helper_canonicalises_what_it_accepts() -> None:
    assert _parse_request_json(b'{"a": "x \\u00a0  y"}') == {"a": "x y"}
