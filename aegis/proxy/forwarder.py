# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.proxy.forwarder — Provider-aware async HTTP forwarding.

Wraps the upstream LLM call with a ``ProviderAdapter`` so the rest of the
pipeline always works with OpenAI-format requests and responses, regardless
of the configured backend (OpenAI, Anthropic Claude, Google Gemini,
OpenRouter, or any OpenAI-compatible endpoint).

Adapter selection
-----------------
The adapter is injected at construction time by the proxy app's lifespan.
Use ``aegis.providers.build_provider(cfg.provider, ...)`` to create it.

Streaming
---------
Providers that require active SSE translation (currently Anthropic) set
``adapter.requires_stream_translation = True``.  In that case
``stream_sse`` pipes raw upstream lines through ``adapter.translate_stream``
before yielding, so callers always receive OpenAI-format SSE tuples.

Providers that already stream in OpenAI format (OpenAI, OpenRouter, Gemini)
pass through unchanged.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx

from aegis.config import AegisSettings
from aegis.providers.base import ProviderAdapter
from aegis.providers.openai_provider import OpenAIAdapter

logger = logging.getLogger(__name__)

_proxy_dir = os.path.dirname(os.path.abspath(__file__))
if _proxy_dir not in sys.path:
    sys.path.append(_proxy_dir)

try:
    import aegis_rust

    HAS_RUST = True
except ImportError:
    HAS_RUST = False
    logger.debug("aegis_rust extension not installed; using httpx forwarder")


class LLMForwarder:
    """
    Provider-aware async HTTP client for upstream LLM backends.

    Args:
        settings:  Aegis configuration.
        provider:  Optional provider adapter.  Defaults to ``OpenAIAdapter``
                   (passthrough) when not supplied.
    """

    def __init__(
        self,
        settings: AegisSettings,
        provider: ProviderAdapter | None = None,
    ) -> None:
        self._settings = settings
        self._provider: ProviderAdapter = provider or OpenAIAdapter()
        self._rust_forwarder: Any = None
        self._client: httpx.AsyncClient | None = None

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        base_url = (
            self._provider.base_url_override
            or self._settings.backend_url_str
        )
        headers = self._provider.build_headers(self._settings.backend_api_key)
        timeout = httpx.Timeout(
            self._settings.backend_timeout_seconds,
            connect=self._settings.backend_connect_timeout_seconds,
        )
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout,
            headers=headers,
        )
        logger.info(
            "LLMForwarder started: provider=%s base_url=%s",
            self._provider.name,
            base_url,
        )

        if HAS_RUST and self._provider.name == "openai":
            try:
                self._rust_forwarder = aegis_rust.RustForwarder.new(
                    base_url,
                    self._settings.backend_api_key,
                )
                logger.info("LLMForwarder: Rust acceleration enabled")
            except Exception as exc:
                logger.warning("Rust forwarder unavailable (%s); using httpx only", exc)
                self._rust_forwarder = None

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── forwarding ────────────────────────────────────────────────────────

    async def forward_json(
        self,
        path: str,
        body: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """
        Forward a non-streaming request and return an httpx.Response whose
        ``.content`` is always in OpenAI format.

        The adapter translates path + body before sending, and translates
        the raw provider response bytes back before returning.
        """
        provider_path, provider_body = self._provider.translate_request(
            path, body,
            model_override=self._settings.provider_model or None,
        )

        if HAS_RUST and self._rust_forwarder and self._provider.name == "openai":
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None,
                self._rust_forwarder.forward_json_sync,
                provider_path,
                provider_body,
            )

        assert self._client is not None, "LLMForwarder.start() was not called"
        raw_resp = await self._client.post(
            provider_path,
            json=provider_body,
            headers=extra_headers,
        )

        if self._provider.name == "openai":
            return raw_resp

        # Translate provider response → OpenAI format.
        # Re-wrap into an httpx.Response with translated content so the
        # caller sees a consistent interface.
        translated = self._provider.translate_response(
            raw_resp.content,
            original_model=body.get("model", ""),
        )
        return httpx.Response(
            status_code=raw_resp.status_code,
            headers=dict(raw_resp.headers),
            content=translated,
        )

    async def stream_sse(
        self,
        path: str,
        body: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> AsyncIterator[tuple[bytes, Any]]:
        """
        Stream an SSE response, always yielding OpenAI-format tuples.

        Yields:
            ``(raw_bytes, parsed_json | None)`` tuples in OpenAI SSE format.
            For providers that require translation (Anthropic), the raw_bytes
            are the *translated* OpenAI SSE bytes, not the raw provider bytes.
        """
        assert self._client is not None, "LLMForwarder.start() was not called"

        provider_path, provider_body = self._provider.translate_request(
            path, body,
            model_override=self._settings.provider_model or None,
        )

        if self._provider.requires_stream_translation:
            async for item in self._stream_with_translation(
                provider_path, provider_body, body, extra_headers
            ):
                yield item
        else:
            async for item in self._stream_passthrough(
                provider_path, provider_body, extra_headers
            ):
                yield item

    # ── internal stream helpers ───────────────────────────────────────────

    async def _stream_passthrough(
        self,
        path: str,
        body: dict[str, Any],
        extra_headers: dict[str, str] | None,
    ) -> AsyncIterator[tuple[bytes, Any]]:
        """Passthrough for providers that already stream in OpenAI SSE format."""
        async with self._client.stream("POST", path, json=body, headers=extra_headers) as resp:
            resp.raise_for_status()
            async for raw_line in resp.aiter_lines():
                line = raw_line.strip()
                if not line:
                    yield (b"\n", None)
                    continue
                raw_bytes = (line + "\n").encode()
                if line.startswith("data: "):
                    data_str = line[6:]
                    if data_str == "[DONE]":
                        yield (raw_bytes, None)
                        return
                    try:
                        yield (raw_bytes, json.loads(data_str))
                    except json.JSONDecodeError:
                        yield (raw_bytes, None)
                else:
                    yield (raw_bytes, None)

    async def _stream_with_translation(
        self,
        provider_path: str,
        provider_body: dict[str, Any],
        original_body: dict[str, Any],
        extra_headers: dict[str, str] | None,
    ) -> AsyncIterator[tuple[bytes, Any]]:
        """Translate provider SSE → OpenAI SSE for non-passthrough providers."""
        request_id = str(uuid.uuid4()).replace("-", "")
        created = int(time.time())
        original_model = original_body.get("model", "")

        async def _raw_line_iter() -> AsyncIterator[str]:
            async with self._client.stream(
                "POST", provider_path, json=provider_body, headers=extra_headers
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    yield line

        translated = self._provider.translate_stream(
            _raw_line_iter(),
            original_model=original_model,
            request_id=request_id,
            created=created,
        )

        async for chunk_bytes in translated:
            if chunk_bytes.strip() == b"data: [DONE]":
                yield (b"data: [DONE]\n", None)
                return
            data_str = chunk_bytes.decode(errors="replace")
            if data_str.startswith("data: "):
                payload = data_str[6:].strip()
                try:
                    parsed: Any = json.loads(payload)
                except json.JSONDecodeError:
                    parsed = None
                yield (chunk_bytes, parsed)
            else:
                yield (chunk_bytes, None)
