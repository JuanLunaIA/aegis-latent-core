"""
aegis.proxy.forwarder — High-performance Rust-backed forwarding.
"""
from __future__ import annotations
import logging
import asyncio
import sys
import os
from typing import AsyncIterator, Any

from aegis.config import AegisSettings

logger = logging.getLogger(__name__)

# Ensure the directory containing the .so is in the path
_proxy_dir = os.path.dirname(os.path.abspath(__file__))
if _proxy_dir not in sys.path:
    sys.path.append(_proxy_dir)

try:
    import aegis_rust
    HAS_RUST = True
except ImportError as e:
    HAS_RUST = False
    logger.error("Rust extension 'aegis_rust' not found: %s", e)

class LLMForwarder:
    def __init__(self, settings: AegisSettings) -> None:
        self._settings = settings
        self._rust_forwarder = None

    async def start(self) -> None:
        if HAS_RUST:
            try:
                self._rust_forwarder = aegis_rust.RustForwarder.new(
                    self._settings.backend_url_str,
                    self._settings.backend_api_key
                )
                logger.info("LLMForwarder initialized with Rust acceleration.")
            except Exception as e:
                logger.error("Failed to initialize Rust forwarder: %s. Falling back to Python.", e)
                # global HAS_RUST = False # Fixed: removed illegal local assignment
        
        if not HAS_RUST:
            import httpx
            self._client = httpx.AsyncClient(base_url=self._settings.backend_url_str)

    async def stop(self) -> None:
        if hasattr(self, '_client'):
            await self._client.aclose()

    async def forward_json(self, path: str, body: dict, extra_headers: dict | None = None) -> Any:
        if HAS_RUST and self._rust_forwarder:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, 
                self._rust_forwarder.forward_json_sync, 
                path, 
                body
            )
        
        import httpx
        resp = await self._client.post(path, json=body, headers=extra_headers)
        return resp

    async def stream_sse(self, path: str, body: dict, extra_headers: dict | None = None) -> AsyncIterator[tuple[bytes, Any]]:
        import httpx
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
                        import json
                        yield (raw_bytes, json.loads(data_str))
                    except Exception:
                        yield (raw_bytes, None)
                else:
                    yield (raw_bytes, None)
