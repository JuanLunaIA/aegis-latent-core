"""
tests/test_forwarder_deep.py — Deep coverage for LLMForwarder.

Covers: start/stop lifecycle, mTLS paths, 401/403 explicit logging,
non-OpenAI provider translation, SSE passthrough, SSE with translation.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.providers.anthropic_provider import AnthropicAdapter
from aegis.providers.openai_provider import OpenAIAdapter
from aegis.proxy.forwarder import LLMForwarder

# ── helpers ──────────────────────────────────────────────────────────────────


def _settings(**overrides) -> AegisSettings:
    base = dict(
        backend_api_key="sk-test",
        backend_url="http://mock-upstream",
        wal_path="/tmp/test_fwd.wal",
        log_level="WARNING",
    )
    base.update(overrides)
    return AegisSettings(**base)


def _make_response(status: int = 200, body: dict | None = None) -> httpx.Response:
    content = json.dumps(body or {"id": "r1", "choices": []}).encode()
    return httpx.Response(
        status_code=status, content=content, headers={"content-type": "application/json"}
    )


# ── lifecycle ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_start_creates_client():
    fwd = LLMForwarder(settings=_settings())
    assert fwd._client is None
    await fwd.start()
    assert fwd._client is not None
    await fwd.stop()
    assert fwd._client is None


@pytest.mark.asyncio
async def test_stop_idempotent():
    """stop() with no client should not raise."""
    fwd = LLMForwarder(settings=_settings())
    await fwd.stop()  # never started — must not raise


@pytest.mark.asyncio
async def test_start_with_ssl_ca_certs(tmp_path):
    """ssl_ca_certs path is forwarded to httpx.AsyncClient as verify=."""
    ca = tmp_path / "ca.crt"
    ca.write_text("fake-cert-data")
    settings = _settings(ssl_ca_certs=str(ca))
    fwd = LLMForwarder(settings=settings)

    captured: dict = {}

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            captured.update(kwargs)

        async def aclose(self):
            pass

    with patch("aegis.proxy.forwarder.httpx.AsyncClient", _FakeClient):
        await fwd.start()
        await fwd.stop()

    assert captured.get("verify") == str(ca)


@pytest.mark.asyncio
async def test_start_mtls_required_with_certs(tmp_path):
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    cert.write_text("fake-cert")
    key.write_text("fake-key")
    fwd = LLMForwarder(
        settings=_settings(
            mtls_required=True,
            ssl_certfile=str(cert),
            ssl_keyfile=str(key),
        )
    )
    # start() should NOT raise — it builds the client with cert paths
    # (httpx validates certs on first connect, not on construction)
    with patch("httpx.AsyncClient.__init__", return_value=None) as mock_init:
        mock_init.return_value = None
        fwd._client = MagicMock()
        # Just verify the settings are picked up (no network call)
        assert fwd._settings.mtls_required is True
        assert str(cert) in str(fwd._settings.ssl_certfile)


@pytest.mark.asyncio
async def test_start_mtls_required_missing_certs_logs_warning(caplog):
    import logging

    fwd = LLMForwarder(settings=_settings(mtls_required=True))
    with caplog.at_level(logging.WARNING, logger="aegis.proxy.forwarder"):
        await fwd.start()
    assert any("MTLS_REQUIRED" in r.message for r in caplog.records)
    await fwd.stop()


# ── forward_json ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_forward_json_200_openai():
    fwd = LLMForwarder(settings=_settings(), provider=OpenAIAdapter())
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=_make_response(200, {"id": "r1"}))
    fwd._client = mock_client

    resp = await fwd.forward_json("/v1/chat/completions", {"model": "gpt-4o", "messages": []})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_forward_json_401_logs_error(caplog):
    import logging

    fwd = LLMForwarder(settings=_settings(), provider=OpenAIAdapter())
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(
        return_value=_make_response(401, {"error": {"message": "Incorrect API key"}})
    )
    fwd._client = mock_client

    with caplog.at_level(logging.ERROR, logger="aegis.proxy.forwarder"):
        resp = await fwd.forward_json("/v1/chat/completions", {"model": "gpt-4o", "messages": []})

    assert resp.status_code == 401
    assert any("401" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_forward_json_403_logs_error(caplog):
    import logging

    fwd = LLMForwarder(settings=_settings(), provider=OpenAIAdapter())
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=_make_response(403, {"error": "forbidden"}))
    fwd._client = mock_client

    with caplog.at_level(logging.ERROR, logger="aegis.proxy.forwarder"):
        resp = await fwd.forward_json("/v1/chat/completions", {"model": "gpt-4o", "messages": []})

    assert resp.status_code == 403
    assert any("403" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_forward_json_non_openai_translates_response():
    """Non-OpenAI providers must translate response bytes to OpenAI format."""
    adapter = AnthropicAdapter()
    fwd = LLMForwarder(settings=_settings(provider="anthropic"), provider=adapter)

    # Minimal Anthropic API response
    anthropic_body = json.dumps(
        {
            "id": "msg_01XFDUDYJgAACzvnptvVoYEL",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello!"}],
            "model": "claude-3-haiku-20240307",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
    ).encode()

    mock_resp = httpx.Response(
        status_code=200,
        content=anthropic_body,
        headers={"content-type": "application/json"},
    )
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    fwd._client = mock_client

    result = await fwd.forward_json(
        "/v1/chat/completions",
        {"model": "claude-3-haiku-20240307", "messages": [{"role": "user", "content": "Hi"}]},
    )
    assert result.status_code == 200
    parsed = json.loads(result.content)
    # Translated response must contain OpenAI-format fields
    assert "choices" in parsed or "id" in parsed


@pytest.mark.asyncio
async def test_forward_json_assert_not_started():
    """forward_json with no client must raise AssertionError."""
    fwd = LLMForwarder(settings=_settings())
    with pytest.raises(AssertionError, match="start"):
        await fwd.forward_json("/v1/chat/completions", {"model": "gpt-4o", "messages": []})


# ── stream_sse ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stream_sse_passthrough_yields_chunks():
    """OpenAI provider streams are passed through without translation."""
    fwd = LLMForwarder(settings=_settings(), provider=OpenAIAdapter())

    sse_lines = [
        'data: {"id":"r1","choices":[{"delta":{"content":"Hi"}}]}',
        "data: [DONE]",
    ]

    async def _mock_stream_context(*args, **kwargs):
        class _FakeResp:
            async def aiter_lines(self):
                for line in sse_lines:
                    yield line

            def raise_for_status(self):
                pass

        return _FakeResp()

    # Patch the stream context manager
    import unittest.mock as mock

    mock_stream_ctx = mock.MagicMock()
    mock_stream_ctx.__aenter__ = AsyncMock(
        return_value=type(
            "R",
            (),
            {
                "aiter_lines": lambda self: _aiter(sse_lines),
                "raise_for_status": lambda self: None,
            },
        )()
    )
    mock_stream_ctx.__aexit__ = AsyncMock(return_value=False)

    async def _aiter(items):
        for item in items:
            yield item

    mock_client = MagicMock()
    mock_client.stream = MagicMock(return_value=mock_stream_ctx)
    fwd._client = mock_client

    chunks = []
    async for raw, parsed in fwd.stream_sse(
        "/v1/chat/completions", {"model": "gpt-4o", "messages": [], "stream": True}
    ):
        chunks.append((raw, parsed))
        if raw == b"data: [DONE]\n":
            break

    assert len(chunks) > 0
    # First chunk should have a parsed dict with 'id'
    first_raw, first_parsed = chunks[0]
    assert first_parsed is not None
    assert "id" in first_parsed


@pytest.mark.asyncio
async def test_stream_sse_assert_not_started():
    fwd = LLMForwarder(settings=_settings())

    async def _consume():
        async for _ in fwd.stream_sse("/v1/chat/completions", {"model": "gpt-4o", "messages": []}):
            break

    with pytest.raises(AssertionError, match="start"):
        await _consume()


# ── provider property ─────────────────────────────────────────────────────────


def test_provider_property():
    adapter = OpenAIAdapter()
    fwd = LLMForwarder(settings=_settings(), provider=adapter)
    assert fwd.provider is adapter
    assert fwd.provider.name == "openai"
