"""
tests/test_app_wal_corrupt.py — governed traffic is refused once the chain is broken.

WAL replay sets ``_fault_state`` to ``wal_corrupt`` when it stops at a line it
cannot parse. Before ``_require_intact_ledger`` existed, that fault reached
``/health`` but not the request path: the proxy kept forwarding governed
requests and committing nodes on top of a prefix it had already failed to read
back. Each commit succeeded individually, so the divergence was silent — every
node written in that window links to a chain that cannot be replayed.

These tests pin both directions. A faulted ledger must refuse every governed
endpoint with 503 and must not forward upstream; a healthy one must be
unaffected; and the operator's view of the fault must survive, because an
observability surface that fails closed alongside the data path leaves nobody
able to see why traffic stopped.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis.config import AegisSettings
from aegis.proxy.app import create_app

_AUTH = {"Authorization": "Bearer sk-valid"}

_GOVERNED_REQUESTS: list[tuple[str, dict[str, Any]]] = [
    (
        "/v1/chat/completions",
        {"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
    ),
    (
        "/v1/messages",
        {
            "model": "claude-3",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16,
        },
    ),
    ("/v1/completions", {"model": "gpt-4", "prompt": "hi"}),
]


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


def _upstream_response(status_code: int = 200) -> MagicMock:
    """An httpx-shaped upstream reply, matching what the proxy actually reads."""
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
    resp.status_code = status_code
    resp.content = json.dumps(data).encode()
    resp.json.return_value = data
    resp.headers = {"content-type": "application/json"}
    return resp


def _forwarder() -> MagicMock:
    inst = MagicMock()
    inst.start = AsyncMock()
    inst.stop = AsyncMock()
    inst.provider = MagicMock()
    inst.provider.name = "mock"
    inst.provider.supports_logprobs = True
    inst.forward_json = AsyncMock(return_value=_upstream_response())
    inst.stream_sse = AsyncMock(return_value=iter([]))
    return inst


@pytest.mark.parametrize(("path", "payload"), _GOVERNED_REQUESTS)
def test_governed_request_is_refused_when_the_wal_is_corrupt(
    tmp_path: Any, path: str, payload: dict[str, Any]
) -> None:
    """Every governed endpoint must answer 503 while the chain is broken."""
    forwarder = _forwarder()
    with patch("aegis.proxy.app.LLMForwarder", return_value=forwarder):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            app.state.aegis.ledger._fault_state = "wal_corrupt"
            response = client.post(path, headers=_AUTH, json=payload)

    assert response.status_code == 503
    assert "not intact" in response.json()["detail"]


@pytest.mark.parametrize(("path", "payload"), _GOVERNED_REQUESTS)
def test_a_refused_request_never_reaches_the_upstream(
    tmp_path: Any, path: str, payload: dict[str, Any]
) -> None:
    """Rejection must happen before forwarding, not after.

    A 503 returned *after* the provider was called would still have sent the
    caller's payload upstream and incurred its cost, with no admissible evidence
    record to show for it. The guard is only worth having if it runs first.
    """
    forwarder = _forwarder()
    with patch("aegis.proxy.app.LLMForwarder", return_value=forwarder):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            app.state.aegis.ledger._fault_state = "wal_corrupt"
            client.post(path, headers=_AUTH, json=payload)

    forwarder.forward_json.assert_not_awaited()
    forwarder.stream_sse.assert_not_awaited()


def test_a_refused_request_commits_no_new_node(tmp_path: Any) -> None:
    """The chain must not grow while it is known to be unreplayable.

    This is the property the guard exists for: appending to a broken prefix
    produces nodes that verify individually and replay as nothing.
    """
    forwarder = _forwarder()
    with patch("aegis.proxy.app.LLMForwarder", return_value=forwarder):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            ledger = app.state.aegis.ledger
            ledger._fault_state = "wal_corrupt"
            depth_before = len(ledger.chain)
            leaves_before = ledger._mmr.get_leaf_count()

            response = client.post(
                "/v1/chat/completions",
                headers=_AUTH,
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
            )

            assert response.status_code == 503
            assert len(ledger.chain) == depth_before
            assert ledger._mmr.get_leaf_count() == leaves_before


def test_health_still_reports_the_fault_while_traffic_is_refused(tmp_path: Any) -> None:
    """Fail closed on the data path, stay observable on the control path.

    `/health` must keep answering and must name the fault. If it failed closed
    too, an operator would see traffic stop with no way to learn why from the
    process itself.
    """
    forwarder = _forwarder()
    with patch("aegis.proxy.app.LLMForwarder", return_value=forwarder):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            app.state.aegis.ledger._fault_state = "wal_corrupt"
            health = client.get("/health")

    assert health.status_code == 503
    body = health.json()
    assert body["ledger"]["fault_state"] == "wal_corrupt"
    assert body["ledger"]["healthy"] is False


def test_a_healthy_ledger_is_unaffected_by_the_guard(tmp_path: Any) -> None:
    """The guard must not reject anything while the chain is intact.

    Without this, every test above would also pass against a guard that
    rejected unconditionally.
    """
    forwarder = _forwarder()
    with patch("aegis.proxy.app.LLMForwarder", return_value=forwarder):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            assert app.state.aegis.ledger._fault_state == "healthy"
            response = client.post(
                "/v1/chat/completions",
                headers=_AUTH,
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
            )

    assert response.status_code == 200
    forwarder.forward_json.assert_awaited()
