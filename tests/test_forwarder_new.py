# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.proxy.forwarder — LLMForwarder HTTP forwarding paths."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.proxy.forwarder import LLMForwarder


# ── helpers ───────────────────────────────────────────────────────────────────


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


def _make_response(status_code: int = 200, content: bytes = b'{"id":"c"}') -> httpx.Response:
    return httpx.Response(status_code, content=content)


# ── start() — mTLS cert loading (lines 117-121) ──────────────────────────────


@pytest.mark.asyncio
async def test_start_mtls_with_certfile_and_keyfile(tmp_path):
    cert_file = tmp_path / "client.crt"
    key_file = tmp_path / "client.key"
    cert_file.write_text("CERT")
    key_file.write_text("KEY")

    settings = _settings(
        mtls_required=True,
        ssl_certfile=cert_file,
        ssl_keyfile=key_file,
    )
    fwd = LLMForwarder(settings=settings)

    with patch("aegis.proxy.forwarder.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = AsyncMock()
        await fwd.start()

    call_kwargs = mock_cls.call_args[1]
    assert call_kwargs.get("cert") is not None
    assert call_kwargs["cert"] == (str(cert_file), str(key_file))


@pytest.mark.asyncio
async def test_start_mtls_required_but_no_cert_files():
    """When mtls_required=True but cert files not set, warns and proceeds without cert."""
    settings = _settings(mtls_required=True)
    fwd = LLMForwarder(settings=settings)

    with patch("aegis.proxy.forwarder.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = AsyncMock()
        await fwd.start()

    call_kwargs = mock_cls.call_args[1]
    assert call_kwargs.get("cert") is None


@pytest.mark.asyncio
async def test_start_with_custom_ca_bundle():
    settings = _settings(ssl_ca_certs="/etc/ssl/custom-ca.pem")
    fwd = LLMForwarder(settings=settings)

    with patch("aegis.proxy.forwarder.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value = AsyncMock()
        await fwd.start()

    call_kwargs = mock_cls.call_args[1]
    assert call_kwargs["verify"] == "/etc/ssl/custom-ca.pem"


# ── stop() ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stop_closes_client():
    fwd = _make_forwarder()
    mock_client = AsyncMock()
    fwd._client = mock_client

    await fwd.stop()

    mock_client.aclose.assert_called_once()
    assert fwd._client is None


@pytest.mark.asyncio
async def test_stop_no_client_is_noop():
    fwd = _make_forwarder()
    fwd._client = None
    await fwd.stop()  # must not raise


# ── forward_json — httpx error → circuit breaker failure (lines 209-211) ─────


@pytest.mark.asyncio
async def test_forward_json_connect_error_records_failure():
    fwd = _make_forwarder()
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "check"), \
         patch.object(fwd._circuit_breaker, "record_failure") as mock_fail:
        with pytest.raises(httpx.ConnectError):
            await fwd.forward_json("/v1/chat/completions", {"messages": []})

    mock_fail.assert_called_once()


@pytest.mark.asyncio
async def test_forward_json_timeout_records_failure():
    fwd = _make_forwarder()
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "check"), \
         patch.object(fwd._circuit_breaker, "record_failure") as mock_fail:
        with pytest.raises(httpx.TimeoutException):
            await fwd.forward_json("/v1/chat/completions", {})

    mock_fail.assert_called_once()


# ── forward_json — 5xx response records failure (line 232) ───────────────────


@pytest.mark.asyncio
async def test_forward_json_5xx_records_failure():
    fwd = _make_forwarder()
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=_make_response(500, b"error"))
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "check"), \
         patch.object(fwd._circuit_breaker, "record_failure") as mock_fail, \
         patch.object(fwd._circuit_breaker, "record_success"):
        await fwd.forward_json("/v1/chat/completions", {})

    mock_fail.assert_called_once()


# ── forward_json — 2xx records success ───────────────────────────────────────


@pytest.mark.asyncio
async def test_forward_json_200_records_success():
    fwd = _make_forwarder()
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=_make_response(200, b'{"id":"c"}'))
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "check"), \
         patch.object(fwd._circuit_breaker, "record_success") as mock_succ:
        await fwd.forward_json("/v1/chat/completions", {})

    mock_succ.assert_called_once()


# ── forward_json — 401 response logs error ────────────────────────────────────


@pytest.mark.asyncio
async def test_forward_json_401_logs_error():
    fwd = _make_forwarder()
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=_make_response(401, b"unauthorized"))
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "check"), \
         patch.object(fwd._circuit_breaker, "record_success"), \
         patch("aegis.proxy.forwarder.logger") as mock_log:
        await fwd.forward_json("/v1/chat/completions", {})

    assert mock_log.error.called


# ── forward_json — 403 response logs error ────────────────────────────────────


@pytest.mark.asyncio
async def test_forward_json_403_logs_error():
    fwd = _make_forwarder()
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=_make_response(403, b"forbidden"))
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "check"), \
         patch.object(fwd._circuit_breaker, "record_success"), \
         patch("aegis.proxy.forwarder.logger") as mock_log:
        await fwd.forward_json("/v1/chat/completions", {})

    assert mock_log.error.called


# ── forward_json — non-openai provider translates response (lines 242-250) ───


@pytest.mark.asyncio
async def test_forward_json_non_openai_translates_response():
    from aegis.providers.anthropic_provider import AnthropicAdapter

    settings = _settings(provider="anthropic")
    mock_provider = MagicMock(spec=AnthropicAdapter)
    mock_provider.name = "anthropic"
    mock_provider.base_url_override = None
    mock_provider.requires_stream_translation = False
    mock_provider.build_headers.return_value = {}
    mock_provider.translate_request.return_value = ("/v1/messages", {"messages": []})
    mock_provider.translate_response.return_value = b'{"choices":[{"message":{"content":"hi"}}]}'

    fwd = LLMForwarder(settings=settings, provider=mock_provider)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(
        return_value=httpx.Response(200, content=b'{"content":[{"text":"hi"}]}')
    )
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "check"), \
         patch.object(fwd._circuit_breaker, "record_success"):
        resp = await fwd.forward_json("/chat/completions", {"model": "claude-3"})

    assert resp.content == b'{"choices":[{"message":{"content":"hi"}}]}'


# ── _stream_passthrough — various line types (lines 297-324) ─────────────────


@pytest.mark.asyncio
async def test_stream_passthrough_data_done():
    fwd = _make_forwarder()

    async def _aiter_lines():
        yield "data: [DONE]"

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.aiter_lines = _aiter_lines

    async def _stream_ctx(*args, **kwargs):
        return mock_response

    mock_client = MagicMock()
    mock_client.stream = MagicMock()

    class _StreamCtxMgr:
        async def __aenter__(self_):
            return mock_response
        async def __aexit__(self_, *a):
            pass

    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "record_success"):
        items = []
        async for item in fwd._stream_passthrough("/v1/chat", {}, None):
            items.append(item)

    assert len(items) == 1
    raw_bytes, parsed = items[0]
    assert b"[DONE]" in raw_bytes
    assert parsed is None


@pytest.mark.asyncio
async def test_stream_passthrough_data_json_line():
    fwd = _make_forwarder()

    chunk = '{"id":"c","choices":[]}'

    async def _aiter_lines():
        yield f"data: {chunk}"
        yield "data: [DONE]"

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.aiter_lines = _aiter_lines

    class _StreamCtxMgr:
        async def __aenter__(self_):
            return mock_response
        async def __aexit__(self_, *a):
            pass

    mock_client = MagicMock()
    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "record_success"):
        items = []
        async for item in fwd._stream_passthrough("/v1/chat", {}, None):
            items.append(item)

    # First item is the JSON chunk, second is [DONE]
    assert len(items) == 2
    raw_bytes, parsed = items[0]
    assert parsed == {"id": "c", "choices": []}


@pytest.mark.asyncio
async def test_stream_passthrough_empty_line():
    fwd = _make_forwarder()

    async def _aiter_lines():
        yield ""  # empty line
        yield "data: [DONE]"

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.aiter_lines = _aiter_lines

    class _StreamCtxMgr:
        async def __aenter__(self_):
            return mock_response
        async def __aexit__(self_, *a):
            pass

    mock_client = MagicMock()
    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "record_success"):
        items = []
        async for item in fwd._stream_passthrough("/v1/chat", {}, None):
            items.append(item)

    # First is empty line (\n, None), second is [DONE]
    assert items[0] == (b"\n", None)


@pytest.mark.asyncio
async def test_stream_passthrough_non_data_line():
    fwd = _make_forwarder()

    async def _aiter_lines():
        yield "event: ping"
        yield "data: [DONE]"

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.aiter_lines = _aiter_lines

    class _StreamCtxMgr:
        async def __aenter__(self_):
            return mock_response
        async def __aexit__(self_, *a):
            pass

    mock_client = MagicMock()
    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "record_success"):
        items = []
        async for item in fwd._stream_passthrough("/v1/chat", {}, None):
            items.append(item)

    # First: "event: ping" → (bytes, None) via the else branch
    assert items[0][1] is None


@pytest.mark.asyncio
async def test_stream_passthrough_invalid_json_line():
    fwd = _make_forwarder()

    async def _aiter_lines():
        yield "data: {not-valid-json}"
        yield "data: [DONE]"

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.aiter_lines = _aiter_lines

    class _StreamCtxMgr:
        async def __aenter__(self_):
            return mock_response
        async def __aexit__(self_, *a):
            pass

    mock_client = MagicMock()
    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "record_success"):
        items = []
        async for item in fwd._stream_passthrough("/v1/chat", {}, None):
            items.append(item)

    # Invalid JSON → (bytes, None)
    assert items[0][1] is None


@pytest.mark.asyncio
async def test_stream_passthrough_5xx_records_failure():
    fwd = _make_forwarder()

    mock_response = AsyncMock()
    mock_response.status_code = 503
    mock_response.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError("error", request=MagicMock(), response=MagicMock())
    )

    class _StreamCtxMgr:
        async def __aenter__(self_):
            return mock_response
        async def __aexit__(self_, *a):
            pass

    mock_client = MagicMock()
    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "record_failure") as mock_fail:
        items = []
        with pytest.raises(httpx.HTTPStatusError):
            async for item in fwd._stream_passthrough("/v1/chat", {}, None):
                items.append(item)

    mock_fail.assert_called_once()


@pytest.mark.asyncio
async def test_stream_passthrough_connect_error_records_failure():
    fwd = _make_forwarder()

    mock_client = MagicMock()
    mock_client.stream.side_effect = httpx.ConnectError("refused")
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "record_failure") as mock_fail:
        with pytest.raises(httpx.ConnectError):
            async for _ in fwd._stream_passthrough("/v1/chat", {}, None):
                pass

    mock_fail.assert_called_once()


# ── stream_sse — passthrough path (lines 282-284) ────────────────────────────


@pytest.mark.asyncio
async def test_stream_sse_passthrough_provider():
    fwd = _make_forwarder()

    async def _aiter_lines():
        yield "data: [DONE]"

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.aiter_lines = _aiter_lines

    class _StreamCtxMgr:
        async def __aenter__(self_):
            return mock_response
        async def __aexit__(self_, *a):
            pass

    mock_client = MagicMock()
    mock_client.stream.return_value = _StreamCtxMgr()
    fwd._client = mock_client

    with patch.object(fwd._circuit_breaker, "check"), \
         patch.object(fwd._circuit_breaker, "record_success"):
        items = []
        async for item in fwd.stream_sse("/v1/chat/completions", {"stream": True}):
            items.append(item)

    assert len(items) == 1
