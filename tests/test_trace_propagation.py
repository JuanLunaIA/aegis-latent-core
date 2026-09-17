"""
tests/test_trace_propagation.py — REG-013: a caller's traceparent reaches
the upstream provider.

Before this fix, `aegis/telemetry/otel.py` had a complete, independently
tested W3C `traceparent`/`tracestate` parser and injector
(`parse_trace_context`, `inject_trace_context`, `TraceContext`) with exactly
zero callers outside its own test file — `aegis/proxy/app.py` never called
any of it, so an inbound `traceparent` header was accepted and silently
discarded. The upstream provider call carried no trace context at all,
which meant a distributed trace could never be stitched across Aegis's hop
even when both the caller and the provider otherwise supported it.

`_outbound_trace_headers` (`aegis/proxy/app.py`) closes that gap: parse the
inbound header if present and valid, mint a fresh `span_id` for this hop
(per the W3C spec — a forwarding hop is not the same span as its caller,
even when it does not export one of its own), and inject the result into
the outbound call via the forwarder's existing `extra_headers` parameter,
which every call site already accepted and none used.

What these tests pin:

* a valid inbound `traceparent` is propagated onward with the **same**
  `trace_id` and a **different** `span_id` — reusing the caller's span_id
  would make Aegis indistinguishable from its caller to anything
  reconstructing the trace;
* `tracestate` passes through unchanged, because Aegis has no vendor-specific
  entry of its own to add;
* a missing inbound header still produces a valid outbound `traceparent`,
  rather than the request going out with no trace context at all;
* a malformed inbound header is treated as absent (synthesizes fresh),
  never raises into the request path and never forwards garbage;
* the header actually reaches the forwarder call, not just the helper
  function in isolation.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastapi import Request
from fastapi.testclient import TestClient

from aegis.config import AegisSettings
from aegis.proxy.app import _outbound_trace_headers, create_app

_AUTH = {"Authorization": "Bearer sk-valid"}
_PAYLOAD = {"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]}
_VALID_INBOUND = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def _request(headers: dict[str, str]) -> Request:
    scope = {
        "type": "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope)


def test_a_valid_inbound_traceparent_keeps_the_trace_id_and_changes_the_span_id() -> None:
    request = _request({"traceparent": _VALID_INBOUND})
    outbound = _outbound_trace_headers(request)

    parts = outbound["traceparent"].split("-")
    assert parts[0] == "00"
    assert parts[1] == "4bf92f3577b34da6a3ce929d0e0e4736", "trace_id must be preserved"
    assert parts[2] != "00f067aa0ba902b7", "span_id must be this hop's own, not the caller's"
    assert parts[3] == "01"


def test_tracestate_passes_through_unchanged() -> None:
    request = _request({"traceparent": _VALID_INBOUND, "tracestate": "vendor1=value1"})
    outbound = _outbound_trace_headers(request)
    assert outbound["tracestate"] == "vendor1=value1"


def test_a_missing_inbound_header_still_produces_a_valid_outbound_traceparent() -> None:
    request = _request({})
    outbound = _outbound_trace_headers(request)
    parts = outbound["traceparent"].split("-")
    assert len(parts) == 4
    assert parts[0] == "00"
    assert len(parts[1]) == 32
    assert len(parts[2]) == 16
    assert int(parts[1], 16) != 0
    assert int(parts[2], 16) != 0


def test_a_malformed_inbound_header_is_treated_as_absent_not_raised() -> None:
    """A caller sending garbage must not take down its own request."""
    request = _request({"traceparent": "not-a-real-traceparent"})
    outbound = _outbound_trace_headers(request)  # must not raise
    parts = outbound["traceparent"].split("-")
    assert len(parts) == 4
    assert parts[0] == "00"


def test_two_calls_for_the_same_inbound_header_mint_different_span_ids() -> None:
    """Each hop-local propagation is its own event, not a cached identity."""
    request = _request({"traceparent": _VALID_INBOUND})
    first = _outbound_trace_headers(request)
    second = _outbound_trace_headers(request)
    assert first["traceparent"].split("-")[2] != second["traceparent"].split("-")[2]


def _settings(tmp_path: Any, **overrides: Any) -> AegisSettings:
    defaults = dict(
        backend_api_key="sk-backend",
        backend_url="http://mock-upstream",
        api_keys="sk-valid",
        wal_path=str(tmp_path / "test.wal"),
        log_level="WARNING",
        auth_disabled=False,
        waf_strict_mode=False,
        analysis_sample_rate=0.0,
    )
    defaults.update(overrides)
    return AegisSettings(**defaults)


def _forwarder() -> MagicMock:
    data = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
                "logprobs": None,
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.content = json.dumps(data).encode()
    resp.json.return_value = data
    resp.headers = {"content-type": "application/json"}
    inst = MagicMock()
    inst.start = AsyncMock()
    inst.stop = AsyncMock()
    inst.provider = MagicMock()
    inst.provider.name = "mock"
    inst.provider.supports_logprobs = True
    inst.forward_json = AsyncMock(return_value=resp)
    inst.stream_sse = AsyncMock(return_value=iter([]))
    return inst


def test_the_forwarder_call_actually_receives_the_propagated_header(tmp_path: Any) -> None:
    """The wiring reaches the real call site, not only the helper in isolation."""
    forwarder = _forwarder()
    with patch("aegis.proxy.app.LLMForwarder", return_value=forwarder):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            response = client.post(
                "/v1/chat/completions",
                headers={**_AUTH, "traceparent": _VALID_INBOUND},
                json=_PAYLOAD,
            )

    assert response.status_code == 200
    forwarder.forward_json.assert_awaited_once()
    _, kwargs = forwarder.forward_json.await_args
    sent_headers = kwargs["extra_headers"]
    parts = sent_headers["traceparent"].split("-")
    assert parts[1] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert parts[2] != "00f067aa0ba902b7"


def test_a_request_with_no_inbound_traceparent_still_forwards_one(tmp_path: Any) -> None:
    forwarder = _forwarder()
    with patch("aegis.proxy.app.LLMForwarder", return_value=forwarder):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            response = client.post("/v1/chat/completions", headers=_AUTH, json=_PAYLOAD)

    assert response.status_code == 200
    _, kwargs = forwarder.forward_json.await_args
    assert "traceparent" in kwargs["extra_headers"]
