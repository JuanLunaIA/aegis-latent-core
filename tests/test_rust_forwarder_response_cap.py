# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""AUD-12 (REG-D16): the Rust forwarder reads upstream bodies under a cap.

`resp.bytes().await` collected an unbounded body and `HttpResponse.content`
copied it a second time, so a hostile or misconfigured upstream could drive the
gateway's RSS to twice the response size with no in-crate limit to breach. The
cap is enforced on the declared Content-Length and on the bytes actually read
(the mid-stream case is pinned in-crate, in `forwarder.rs`).

These tests need a freshly built extension: the cap arrives as a constructor
argument, so an `aegis_rust` older than this change answers with a TypeError and
the module skips rather than reporting a false pass.
"""

from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator
from typing import Any

import pytest

aegis_rust = pytest.importorskip("aegis_rust")

CAP = 4_096
BIG = 32_768


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serves a body of the size named in the path, and logs nothing."""

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's API
        size = int(self.path.strip("/").split("/")[-1] or "0")
        body = b"x" * size
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(size))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


@pytest.fixture
def upstream() -> Iterator[str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _new_forwarder(base_url: str, **kwargs: Any) -> Any:
    """Build a forwarder, or skip when the loaded extension predates the cap."""
    try:
        return aegis_rust.RustForwarder.new(base_url, "test-key", timeout_seconds=10, **kwargs)
    except TypeError as exc:
        pytest.skip(f"loaded aegis_rust does not accept max_response_bytes ({exc})")


def test_an_oversized_response_raises_instead_of_being_returned(upstream: str) -> None:
    forwarder = _new_forwarder(upstream, max_response_bytes=CAP)
    with pytest.raises(RuntimeError) as excinfo:
        forwarder.forward_json_sync(f"/{BIG}", {"model": "gpt-4"})
    assert str(CAP) in str(excinfo.value)
    assert "exceeds the configured limit" in str(excinfo.value)


def test_a_response_within_the_cap_is_returned_intact(upstream: str) -> None:
    forwarder = _new_forwarder(upstream, max_response_bytes=CAP)
    response = forwarder.forward_json_sync("/2048", {"model": "gpt-4"})
    assert response.status_code == 200
    assert response.content == b"x" * 2048


def test_the_default_cap_admits_a_body_beyond_the_test_cap(upstream: str) -> None:
    """No argument means the 16 MiB default, not the small cap these tests use."""
    forwarder = _new_forwarder(upstream)
    response = forwarder.forward_json_sync(f"/{BIG}", {"model": "gpt-4"})
    assert response.status_code == 200
    assert len(response.content) == BIG


def test_a_zero_cap_is_refused_at_construction(upstream: str) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        _new_forwarder(upstream, max_response_bytes=0)


@pytest.mark.asyncio
async def test_the_gateway_passes_its_configured_bound() -> None:
    """The wire from configuration to the constructor is asserted, not implied."""
    from unittest.mock import AsyncMock, patch

    from aegis.config import AegisSettings
    from aegis.proxy.forwarder import LLMForwarder

    settings = AegisSettings(
        backend_api_key="sk-test",
        api_keys="k",
        provider="openai",
        backend_url_str="https://api.openai.com/v1",
        max_stream_response_bytes=8_388_608,
    )
    forwarder = LLMForwarder(settings=settings)
    with (
        patch("aegis.proxy.forwarder.httpx.AsyncClient") as client_cls,
        patch.object(aegis_rust.RustForwarder, "new", return_value=object()) as fake_new,
    ):
        client_cls.return_value = AsyncMock()
        await forwarder.start()
    assert fake_new.call_args.kwargs["max_response_bytes"] == 8_388_608
