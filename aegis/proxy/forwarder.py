# Copyright (c) 2026 Juan Luna. All rights reserved.
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
from aegis.core.circuit_breaker import CircuitBreaker
from aegis.providers.base import ProviderAdapter
from aegis.providers.openai_provider import OpenAIAdapter
from aegis.proxy.streaming import StreamEventLimitError

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


async def _iter_bounded_lines(
    response: httpx.Response, *, max_line_bytes: int
) -> AsyncIterator[bytes]:
    """Yield HTTP body lines without permitting an unbounded unterminated line."""
    if max_line_bytes < 1:
        raise ValueError("max_line_bytes must be positive")
    instance_attrs = vars(response)
    aiter_bytes = getattr(response, "aiter_bytes", None)
    if aiter_bytes is None or (
        "aiter_lines" in instance_attrs and "aiter_bytes" not in instance_attrs
    ):
        aiter_lines = getattr(response, "aiter_lines", None)
        if aiter_lines is None:
            raise TypeError("streaming response exposes neither aiter_bytes nor aiter_lines")
        async for line in aiter_lines():
            encoded = line.encode("utf-8") if isinstance(line, str) else bytes(line)
            if len(encoded) > max_line_bytes:
                raise StreamEventLimitError("upstream SSE line exceeds configured limit")
            yield encoded
        return
    pending = bytearray()
    chunk_size = min(max_line_bytes, 16_384)
    async for chunk in aiter_bytes(chunk_size=chunk_size):
        pending.extend(chunk)
        while True:
            newline = pending.find(b"\n")
            if newline < 0:
                break
            if newline > max_line_bytes:
                raise StreamEventLimitError("upstream SSE line exceeds configured limit")
            line = bytes(pending[:newline])
            del pending[: newline + 1]
            if line.endswith(b"\r"):
                line = line[:-1]
            yield line
        if len(pending) > max_line_bytes:
            raise StreamEventLimitError("unterminated upstream SSE line exceeds configured limit")
    if pending:
        if len(pending) > max_line_bytes:
            raise StreamEventLimitError("terminal upstream SSE line exceeds configured limit")
        yield bytes(pending)


def _native_sse_event(lines: list[bytes]) -> tuple[bytes, Any]:
    raw = b"\n".join(lines) + b"\n\n"
    parsed: Any = None
    for line in lines:
        if not line.startswith(b"data:"):
            continue
        payload = line[5:].strip()
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            parsed = None
        break
    return raw, parsed


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
        egress_guard: Any = None,
    ) -> None:
        self._settings = settings
        self._provider: ProviderAdapter = provider or OpenAIAdapter()
        self._rust_forwarder: Any = None
        self._client: httpx.AsyncClient | None = None
        self._circuit_breaker = CircuitBreaker(
            name=settings.provider,
            failure_threshold=settings.circuit_breaker_failure_threshold,
            recovery_timeout=settings.circuit_breaker_recovery_timeout,
            success_threshold=settings.circuit_breaker_success_threshold,
        )
        self._egress_guard = egress_guard

    @property
    def provider(self) -> ProviderAdapter:
        return self._provider

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        base_url = self._provider.base_url_override or self._settings.backend_url_str
        headers = self._provider.build_headers(self._settings.backend_api_key)
        timeout = httpx.Timeout(
            self._settings.backend_timeout_seconds,
            connect=self._settings.backend_connect_timeout_seconds,
        )

        # SSL/mTLS configuration for upstream connections.
        # ssl_ca_certs: custom CA bundle for verifying the upstream TLS certificate.
        # ssl_certfile + ssl_keyfile: client certificate for mTLS to the upstream.
        # When mtls_required=True and the cert files are not set, start() logs a
        # WARNING rather than crashing — the operator must supply the cert paths.
        ssl_context: bool | str | None = True  # default: system CA bundle
        if self._settings.ssl_ca_certs is not None:
            ssl_context = str(self._settings.ssl_ca_certs)
            logger.info(
                "LLMForwarder: using custom CA bundle for upstream TLS: %s",
                self._settings.ssl_ca_certs,
            )

        client_cert: tuple[str, str] | None = None
        if self._settings.mtls_required:
            if self._settings.ssl_certfile and self._settings.ssl_keyfile:
                client_cert = (
                    str(self._settings.ssl_certfile),
                    str(self._settings.ssl_keyfile),
                )
                logger.info(
                    "LLMForwarder: mTLS client certificate loaded (%s)",
                    self._settings.ssl_certfile,
                )
            else:
                logger.warning(
                    "MTLS_REQUIRED=true but SSL_CERTFILE/SSL_KEYFILE are not set. "
                    "Upstream connections will proceed without a client certificate. "
                    "Set AEGIS_SSL_CERTFILE and AEGIS_SSL_KEYFILE to enable mTLS."
                )

        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout,
            headers=headers,
            verify=ssl_context,
            cert=client_cert,
        )
        logger.info(
            "LLMForwarder started: provider=%s base_url=%s mtls=%s",
            self._provider.name,
            base_url,
            client_cert is not None,
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
        # Airgap egress guard: block if upstream host is not in allowlist.
        if self._egress_guard is not None:
            self._egress_guard.check(self._settings.backend_url_str)

        # Circuit breaker: fail-fast when upstream is known to be down.
        # CircuitOpenError propagates to the caller (app.py) which returns 503.
        self._circuit_breaker.check()

        provider_path, provider_body = self._provider.translate_request(
            path,
            body,
            model_override=self._settings.provider_model or None,
        )

        if HAS_RUST and self._rust_forwarder and self._provider.name == "openai":
            loop = asyncio.get_running_loop()
            try:
                result = await loop.run_in_executor(
                    None,
                    self._rust_forwarder.forward_json_sync,
                    provider_path,
                    provider_body,
                )
                self._circuit_breaker.record_success()
                return result  # type: ignore[no-any-return]
            except Exception:
                self._circuit_breaker.record_failure()
                raise

        assert self._client is not None, "LLMForwarder.start() was not called"
        try:
            raw_resp = await self._client.post(
                provider_path,
                json=provider_body,
                headers=extra_headers,
            )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
            self._circuit_breaker.record_failure()
            raise

        # FIX-MAJOR: surface 401/403 upstream errors explicitly.
        # Previously these were silently forwarded, making it impossible to
        # distinguish an Aegis auth failure from an upstream key/cert rejection.
        if raw_resp.status_code == 401:
            logger.error(
                "Upstream returned 401 Unauthorized on path=%s. "
                "Verify AEGIS_BACKEND_API_KEY, mTLS certificates, and provider auth headers.",
                provider_path,
            )
        elif raw_resp.status_code == 403:
            logger.error(
                "Upstream returned 403 Forbidden on path=%s. "
                "Check API key permissions and IP allowlist for provider=%s.",
                provider_path,
                self._provider.name,
            )

        # 5xx responses from upstream count as failures for circuit-breaker purposes.
        if raw_resp.status_code >= 500:
            self._circuit_breaker.record_failure()
        else:
            self._circuit_breaker.record_success()

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

    async def forward_native_anthropic(
        self,
        body: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Forward an Anthropic Messages body without public-shape translation."""
        if self._provider.name != "anthropic":
            raise ValueError("native Anthropic ingress requires AEGIS_PROVIDER=anthropic")
        assert self._client is not None, "LLMForwarder.start() was not called"
        if self._egress_guard is not None:
            self._egress_guard.check(self._settings.backend_url_str)
        self._circuit_breaker.check()
        try:
            response = await self._client.post("/v1/messages", json=body, headers=extra_headers)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
            self._circuit_breaker.record_failure()
            raise
        if response.status_code >= 500:
            self._circuit_breaker.record_failure()
        else:
            self._circuit_breaker.record_success()
        return response

    async def stream_native_anthropic(
        self,
        body: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> AsyncIterator[tuple[bytes, Any]]:
        """Yield complete native Anthropic SSE events under an event-byte cap."""
        if self._provider.name != "anthropic":
            raise ValueError("native Anthropic ingress requires AEGIS_PROVIDER=anthropic")
        assert self._client is not None, "LLMForwarder.start() was not called"
        self._circuit_breaker.check()
        async with self._client.stream(
            "POST", "/v1/messages", json=body, headers=extra_headers
        ) as response:
            response.raise_for_status()
            self._circuit_breaker.record_success()
            event_lines: list[bytes] = []
            event_size = 0
            async for line in _iter_bounded_lines(
                response, max_line_bytes=self._settings.max_stream_event_bytes
            ):
                if line:
                    event_size += len(line) + 1
                    if event_size > self._settings.max_stream_event_bytes:
                        raise StreamEventLimitError(
                            "native Anthropic SSE event exceeds configured limit"
                        )
                    event_lines.append(line)
                    continue
                if event_lines:
                    yield _native_sse_event(event_lines)
                    event_lines = []
                    event_size = 0
            if event_lines:
                yield _native_sse_event(event_lines)

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

        # Airgap egress guard: block if upstream host is not in allowlist.
        if self._egress_guard is not None:
            self._egress_guard.check(self._settings.backend_url_str)

        # Circuit breaker check before initiating the stream.
        self._circuit_breaker.check()

        provider_path, provider_body = self._provider.translate_request(
            path,
            body,
            model_override=self._settings.provider_model or None,
        )

        if self._provider.requires_stream_translation:
            async for item in self._stream_with_translation(
                provider_path, provider_body, body, extra_headers
            ):
                yield item
        else:
            async for item in self._stream_passthrough(provider_path, provider_body, extra_headers):
                yield item

    # ── internal stream helpers ───────────────────────────────────────────

    async def _stream_passthrough(
        self,
        path: str,
        body: dict[str, Any],
        extra_headers: dict[str, str] | None,
    ) -> AsyncIterator[tuple[bytes, Any]]:
        """Passthrough for providers that already stream in OpenAI SSE format."""
        try:
            stream_ctx = self._client.stream("POST", path, json=body, headers=extra_headers)
        except (httpx.ConnectError, httpx.TimeoutException):
            self._circuit_breaker.record_failure()
            raise
        async with stream_ctx as resp:
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError:
                if resp.status_code >= 500:
                    self._circuit_breaker.record_failure()
                raise
            self._circuit_breaker.record_success()
            async for raw_line in _iter_bounded_lines(
                resp, max_line_bytes=self._settings.max_stream_event_bytes
            ):
                line = raw_line.decode("utf-8", errors="replace").strip()
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
                async for line in _iter_bounded_lines(
                    resp, max_line_bytes=self._settings.max_stream_event_bytes
                ):
                    yield line.decode("utf-8", errors="replace")

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
