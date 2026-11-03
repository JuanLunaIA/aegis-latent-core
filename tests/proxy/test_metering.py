# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Usage reporting to the Aegis Cloud control plane (aegis.proxy.metering)."""

from __future__ import annotations

import json
import pathlib
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from aegis.proxy import metering

URL = "https://cloud.example.test"
KEY = "ak_test_only_not_a_secret"


@pytest.fixture(autouse=True)
def _fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(metering, "_RETRY_DELAYS", (0.0, 0.0))
    monkeypatch.setattr(metering, "_EGRESS_GUARD", None)
    monkeypatch.delenv("AEGIS_CLOUD_URL", raising=False)
    monkeypatch.delenv("AEGIS_CLOUD_API_KEY", raising=False)


def _configure(monkeypatch: pytest.MonkeyPatch, url: str = URL) -> None:
    monkeypatch.setenv("AEGIS_CLOUD_URL", url)
    monkeypatch.setenv("AEGIS_CLOUD_API_KEY", KEY)


def _recorder(statuses: list[int | Exception]) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        outcome = statuses[min(len(seen), len(statuses)) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return httpx.Response(outcome, json={})

    return httpx.MockTransport(handler), seen


def test_disabled_without_configuration() -> None:
    assert metering.cloud_config() is None
    assert metering.report_usage("r1", model="m", provider="openai", usage=(1, 1, 0)) is False


@pytest.mark.parametrize("url", ["http://cloud.example.test", "ftp://x", "not a url"])
def test_refuses_to_send_the_key_over_cleartext(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    _configure(monkeypatch, url)
    assert metering.cloud_config() is None


@pytest.mark.parametrize("url", ["http://127.0.0.1:8000", "http://localhost:8000/"])
def test_allows_cleartext_loopback(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    _configure(monkeypatch, url)
    cfg = metering.cloud_config()
    assert cfg is not None
    assert not cfg[0].endswith("/")


def test_openai_usage_and_tool_calls() -> None:
    resp = {
        "usage": {"prompt_tokens": 1200, "completion_tokens": 30},
        "choices": [{"message": {"tool_calls": [{"id": "a"}, {"id": "b"}]}}],
    }
    assert metering.usage_from_response("openai", resp, b"{}") == (1200, 30, 2)


def test_anthropic_usage_and_tool_use_blocks() -> None:
    resp = {
        "usage": {"input_tokens": 50, "output_tokens": 7},
        "content": [{"type": "text"}, {"type": "tool_use"}],
    }
    assert metering.usage_from_response("anthropic", resp, b"{}") == (50, 7, 1)


def test_missing_usage_estimates_input_from_the_request() -> None:
    body = b"x" * 4000
    assert metering.usage_from_response("openai", None, body) == (1000, 0, 0)
    assert metering.usage_from_response("openai", {"usage": {"prompt_tokens": -1}}, body) == (
        1000,
        0,
        0,
    )


def test_values_are_clamped_to_the_server_contract() -> None:
    resp = {"usage": {"prompt_tokens": 10**12, "completion_tokens": True}}
    inp, out, _ = metering.usage_from_response("openai", resp, b"")
    assert inp == metering.MAX_TOKENS
    assert out == 0


async def test_posts_once_with_key_header_and_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    transport, seen = _recorder([202])
    ok = await metering.send_usage(
        "req-1", model="gpt-x", provider="openai", usage=(10, 2, 1), transport=transport
    )
    assert ok is True
    assert len(seen) == 1
    req = seen[0]
    assert str(req.url) == f"{URL}/v1/usage"
    assert req.headers["x-aegis-key"] == KEY
    assert json.loads(req.content) == {
        "request_id": "req-1",
        "model": "gpt-x",
        "provider": "openai",
        "input_tokens": 10,
        "output_tokens": 2,
        "tool_calls": 1,
    }


async def test_retries_server_errors_and_network_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    transport, seen = _recorder([503, httpx.ConnectError("down"), 202])
    assert await metering.send_usage(
        "req-2", model="m", provider="openai", usage=(1, 1, 0), transport=transport
    )
    assert len(seen) == 3


@pytest.mark.parametrize("code", [401, 402, 422])
async def test_client_errors_are_not_retried(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    _configure(monkeypatch)
    transport, seen = _recorder([code])
    assert not await metering.send_usage(
        "req-3", model="m", provider="openai", usage=(1, 1, 0), transport=transport
    )
    assert len(seen) == 1


async def test_gives_up_after_bounded_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch)
    transport, seen = _recorder([500])
    assert not await metering.send_usage(
        "req-4", model="m", provider="openai", usage=(1, 1, 0), transport=transport
    )
    assert len(seen) == len(metering._RETRY_DELAYS) + 1


async def test_airgap_egress_guard_blocks_unlisted_cloud_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegis.proxy.egress_guard import build_egress_guard

    _configure(monkeypatch)
    transport, seen = _recorder([202])
    monkeypatch.setattr(
        metering, "_EGRESS_GUARD", build_egress_guard(True, "", "https://llm.internal.example")
    )
    assert not await metering.send_usage(
        "req-6", model="m", provider="openai", usage=(1, 1, 0), transport=transport
    )
    assert seen == []

    monkeypatch.setattr(
        metering, "_EGRESS_GUARD", build_egress_guard(True, "cloud.example.test", "")
    )
    assert await metering.send_usage(
        "req-7", model="m", provider="openai", usage=(1, 1, 0), transport=transport
    )
    assert len(seen) == 1


async def test_report_schedules_in_background_and_drain_waits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    transport, seen = _recorder([202])
    monkeypatch.setattr(metering, "_TRANSPORT", transport)
    assert metering.report_usage("req-5", model="m", provider="openai", usage=(1, 1, 0))
    await metering.drain(timeout=5)
    assert len(seen) == 1
    assert not metering._PENDING


async def test_unexpected_report_failure_is_logged_not_lost(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _configure(monkeypatch)

    async def boom(*_a: object, **_k: object) -> bool:
        raise RuntimeError("bug")

    monkeypatch.setattr(metering, "send_usage", boom)
    assert metering.report_usage("req-8", model="m", provider="openai", usage=(1, 1, 0))
    await metering.drain(timeout=5)
    assert not metering._PENDING
    assert "usage report crashed: RuntimeError" in caplog.text


async def test_gateway_reports_a_committed_chat_completion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    from aegis.config import AegisSettings
    from aegis.proxy.app import create_app

    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        metering, "report_usage", lambda request_id, **kw: calls.append((request_id, kw)) or True
    )
    app = create_app(
        AegisSettings(
            backend_api_key="test-backend-key",
            api_keys="test-proxy-key",
            wal_path=str(tmp_path / "meter.wal"),
            waf_strict_mode=False,
        )
    )
    resp_data = {
        "choices": [{"message": {"content": "hi", "tool_calls": [{"id": "t1"}]}}],
        "usage": {"prompt_tokens": 42, "completion_tokens": 3},
    }
    upstream = MagicMock(status_code=200, content=json.dumps(resp_data).encode())
    upstream.json.return_value = resp_data
    forwarder = AsyncMock()
    forwarder.forward_json.return_value = upstream
    app.state.aegis.forwarder = forwarder
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": "Bearer test-proxy-key"},
            )
    finally:
        app.state.aegis.ledger.close()
    assert response.status_code == 200
    assert response.headers["X-Aegis-Evidence-Status"] == "durable"
    assert calls == [
        (
            response.headers["X-Aegis-Request-ID"],
            {"model": "gpt-x", "provider": "openai", "usage": (42, 3, 1)},
        )
    ]
