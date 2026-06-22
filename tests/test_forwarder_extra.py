# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Additional forwarder tests — Rust paths and stream translation."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.proxy.forwarder import LLMForwarder


def _settings(**kwargs) -> AegisSettings:
    defaults = {
        "backend_api_key": "sk-test",
        "api_keys": "k",
        "provider": "openai",
        "backend_url_str": "https://api.openai.com/v1",
    }
    defaults.update(kwargs)
    return AegisSettings(**defaults)


def _make_forwarder(**kw) -> LLMForwarder:
    return LLMForwarder(settings=_settings(**kw))


# ── start() — Rust forwarder exception path (lines 153-155) ──────────────────


@pytest.mark.asyncio
async def test_start_rust_forwarder_exception_falls_back_to_none():
    """RustForwarder.new raises → logs warning, _rust_forwarder is None (153-155)."""
    aegis_rust = pytest.importorskip("aegis_rust", reason="Rust extension not installed")

    fwd = _make_forwarder()

    with (
        patch("aegis.proxy.forwarder.httpx.AsyncClient") as mock_cls,
        patch.object(aegis_rust.RustForwarder, "new", side_effect=RuntimeError("init fail")),
    ):
        mock_cls.return_value = AsyncMock()
        await fwd.start()

    assert fwd._rust_forwarder is None


# ── forward_json — Rust executor path (lines 188-200) ────────────────────────


@pytest.mark.asyncio
async def test_forward_json_rust_path_success():
    """HAS_RUST=True and _rust_forwarder set → uses executor, records success (188-200)."""
    from aegis.proxy import forwarder as fwd_mod

    fwd = _make_forwarder()
    mock_response = httpx.Response(200, content=b'{"id":"r"}')
    mock_rust = MagicMock()
    mock_rust.forward_json_sync.return_value = mock_response
    fwd._rust_forwarder = mock_rust

    with (
        patch.object(fwd_mod, "HAS_RUST", True),
        patch.object(fwd._circuit_breaker, "check"),
        patch.object(fwd._circuit_breaker, "record_success") as mock_succ,
    ):
        resp = await fwd.forward_json("/v1/chat/completions", {"messages": []})

    mock_succ.assert_called_once()
    assert resp is mock_response


@pytest.mark.asyncio
async def test_forward_json_rust_path_exception_records_failure():
    """Rust executor raises → record_failure and re-raise (lines 198-200)."""
    from aegis.proxy import forwarder as fwd_mod

    fwd = _make_forwarder()
    mock_rust = MagicMock()
    mock_rust.forward_json_sync.side_effect = RuntimeError("rust died")
    fwd._rust_forwarder = mock_rust

    with (
        patch.object(fwd_mod, "HAS_RUST", True),
        patch.object(fwd._circuit_breaker, "check"),
        patch.object(fwd._circuit_breaker, "record_failure") as mock_fail,
    ):
        with pytest.raises(RuntimeError, match="rust died"):
            await fwd.forward_json("/v1/chat/completions", {})

    mock_fail.assert_called_once()


# ── stream_sse — stream translation path (lines 278-281) ─────────────────────


@pytest.mark.asyncio
async def test_stream_sse_translation_provider():
    """Provider.requires_stream_translation=True → _stream_with_translation called (278-281)."""
    from aegis.providers.anthropic_provider import AnthropicAdapter

    settings = _settings(provider="anthropic")
    mock_provider = MagicMock(spec=AnthropicAdapter)
    mock_provider.name = "anthropic"
    mock_provider.base_url_override = None
    mock_provider.requires_stream_translation = True
    mock_provider.build_headers.return_value = {}
    mock_provider.translate_request.return_value = ("/v1/messages", {"messages": []})

    async def _mock_translate_stream(line_iter, **kwargs):
        yield b'data: {"id":"c","choices":[]}\n'
        yield b"data: [DONE]\n"

    mock_provider.translate_stream = _mock_translate_stream

    fwd = LLMForwarder(settings=settings, provider=mock_provider)

    class _StreamCtxMgr:
        async def __aenter__(self_):
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()

            async def _aiter_lines():
                yield 'data: {"id":"c"}'
                yield "data: [DONE]"

            mock_response.aiter_lines = _aiter_lines
            return mock_response

        async def __aexit__(self_, *a):
            pass

    mock_client = MagicMock()
    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    with (
        patch.object(fwd._circuit_breaker, "check"),
        patch.object(fwd._circuit_breaker, "record_success"),
    ):
        items = []
        async for item in fwd.stream_sse("/v1/chat/completions", {"stream": True}):
            items.append(item)

    assert len(items) >= 1


# ── _stream_with_translation — full path (lines 334-366) ─────────────────────


@pytest.mark.asyncio
async def test_stream_with_translation_yields_chunks():
    """_stream_with_translation correctly yields translated SSE chunks.

    The translate_stream mock MUST iterate line_iter to cover lines 339-344
    (_raw_line_iter's async with / raise_for_status / aiter_lines body).
    """
    from aegis.providers.anthropic_provider import AnthropicAdapter

    settings = _settings(provider="anthropic")
    mock_provider = MagicMock(spec=AnthropicAdapter)
    mock_provider.name = "anthropic"
    mock_provider.base_url_override = None
    mock_provider.requires_stream_translation = True
    mock_provider.build_headers.return_value = {}
    mock_provider.translate_request.return_value = ("/v1/messages", {"messages": []})

    async def _mock_translate_stream(line_iter, **kwargs):
        # Drain line_iter so _raw_line_iter() body (lines 339-344) is exercised
        async for _line in line_iter:
            pass
        yield b'data: {"id":"c","choices":[{"delta":{"content":"hi"}}]}\n'
        yield b"data: [DONE]\n"

    mock_provider.translate_stream = _mock_translate_stream

    fwd = LLMForwarder(settings=settings, provider=mock_provider)

    class _StreamCtxMgr:
        async def __aenter__(self_):
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()

            async def _aiter_lines():
                yield 'data: {"type":"content_block_delta"}'

            mock_response.aiter_lines = _aiter_lines
            return mock_response

        async def __aexit__(self_, *a):
            pass

    mock_client = MagicMock()
    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    items = []
    async for item in fwd._stream_with_translation("/v1/messages", {}, {}, None):
        items.append(item)

    # Should have at least one chunk before [DONE]
    assert len(items) >= 1
    raw_bytes, parsed = items[0]
    assert isinstance(raw_bytes, bytes)


@pytest.mark.asyncio
async def test_stream_with_translation_non_data_line():
    """Lines in _stream_with_translation that don't start with 'data: ' → (bytes, None)."""
    from aegis.providers.anthropic_provider import AnthropicAdapter

    settings = _settings(provider="anthropic")
    mock_provider = MagicMock(spec=AnthropicAdapter)
    mock_provider.name = "anthropic"
    mock_provider.requires_stream_translation = True
    mock_provider.build_headers.return_value = {}
    mock_provider.translate_request.return_value = ("/v1/messages", {})

    async def _mock_translate_stream(line_iter, **kwargs):
        yield b"event: ping\n"  # not data:
        yield b"data: [DONE]\n"

    mock_provider.translate_stream = _mock_translate_stream

    fwd = LLMForwarder(settings=settings, provider=mock_provider)

    class _StreamCtxMgr:
        async def __aenter__(self_):
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()

            async def _aiter_lines():
                yield "event: ping"

            mock_response.aiter_lines = _aiter_lines
            return mock_response

        async def __aexit__(self_, *a):
            pass

    mock_client = MagicMock()
    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    items = []
    async for item in fwd._stream_with_translation("/v1/messages", {}, {}, None):
        items.append(item)

    # First item: non-data line → (bytes, None)
    assert items[0][1] is None


@pytest.mark.asyncio
async def test_stream_with_translation_invalid_json():
    """data: prefix but invalid JSON → (bytes, None)."""
    from aegis.providers.anthropic_provider import AnthropicAdapter

    settings = _settings(provider="anthropic")
    mock_provider = MagicMock(spec=AnthropicAdapter)
    mock_provider.name = "anthropic"
    mock_provider.requires_stream_translation = True
    mock_provider.build_headers.return_value = {}
    mock_provider.translate_request.return_value = ("/v1/messages", {})

    async def _mock_translate_stream(line_iter, **kwargs):
        yield b"data: {bad json here}\n"
        yield b"data: [DONE]\n"

    mock_provider.translate_stream = _mock_translate_stream

    fwd = LLMForwarder(settings=settings, provider=mock_provider)

    class _StreamCtxMgr:
        async def __aenter__(self_):
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()

            async def _aiter_lines():
                yield "event: test"

            mock_response.aiter_lines = _aiter_lines
            return mock_response

        async def __aexit__(self_, *a):
            pass

    mock_client = MagicMock()
    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    items = []
    async for item in fwd._stream_with_translation("/v1/messages", {}, {}, None):
        items.append(item)

    # First item: invalid JSON → (bytes, None)
    assert items[0][1] is None
