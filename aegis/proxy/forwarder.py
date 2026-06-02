"""
aegis.proxy.forwarder — Async HTTP forwarding to upstream LLM backends.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from collections.abc import AsyncIterator
from typing import Any

import httpx

from aegis.config import AegisSettings

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
    def __init__(self, settings: AegisSettings) -> None:
        self._settings = settings
        self._rust_forwarder: Any = None
        self._client: httpx.AsyncClient | None = None

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._settings.backend_api_key:
            headers["Authorization"] = f"Bearer {self._settings.backend_api_key}"
        return headers

    async def start(self) -> None:
        timeout = httpx.Timeout(
            self._settings.backend_timeout_seconds,
            connect=self._settings.backend_connect_timeout_seconds,
        )
        self._client = httpx.AsyncClient(
            base_url=self._settings.backend_url_str,
            timeout=timeout,
            headers=self._build_headers(),
        )

        if HAS_RUST:
            try:
                self._rust_forwarder = aegis_rust.RustForwarder.new(
                    self._settings.backend_url_str,
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

    async def forward_json(
        self, path: str, body: dict, extra_headers: dict[str, str] | None = None
    ) -> httpx.Response:
        if HAS_RUST and self._rust_forwarder:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None,
                self._rust_forwarder.forward_json_sync,
                path,
                body,
            )

        assert self._client is not None, "LLMForwarder.start() was not called"
        return await self._client.post(path, json=body, headers=extra_headers)

    async def stream_sse(
        self, path: str, body: dict, extra_headers: dict[str, str] | None = None
    ) -> AsyncIterator[tuple[bytes, Any]]:
        assert self._client is not None, "LLMForwarder.start() was not called"
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
