"""
tests/test_proxy.py — Integration tests for the Aegis FastAPI proxy.

Uses httpx.AsyncClient + ASGITransport to test the full request/response
cycle without binding a real port.  A mock upstream server intercepts
backend calls to avoid external network dependencies.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis.config import AegisSettings
from aegis.proxy.app import create_app

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_settings(**overrides) -> AegisSettings:
    defaults = {
        "backend_url": "http://mock-backend",
        "backend_api_key": "",
        "api_keys": "sk-test-key",
        "audit_api_keys": "sk-audit-key",
        "auth_disabled": False,
        "wal_path": "/tmp/aegis_test_wal.jsonl",
        "force_logprobs": True,
        "top_logprobs": 5,
        "log_level": "WARNING",
        "workers": 1,
    }
    defaults.update(overrides)
    return AegisSettings(**defaults)


_CHAT_RESPONSE = {
    "id": "chatcmpl-test",
    "object": "chat.completion",
    "created": int(time.time()),
    "model": "gpt-4o-mini",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "Hello world!"},
            "finish_reason": "stop",
            "logprobs": {
                "content": [
                    {
                        "token": "Hello",
                        "logprob": -0.1,
                        "top_logprobs": [
                            {"token": "Hello", "logprob": -0.1},
                            {"token": "Hi", "logprob": -1.2},
                            {"token": "Hey", "logprob": -2.3},
                        ],
                    },
                    {
                        "token": " world",
                        "logprob": -0.2,
                        "top_logprobs": [
                            {"token": " world", "logprob": -0.2},
                            {"token": " there", "logprob": -1.5},
                        ],
                    },
                    {
                        "token": "!",
                        "logprob": -0.05,
                        "top_logprobs": [
                            {"token": "!", "logprob": -0.05},
                            {"token": ".", "logprob": -0.8},
                        ],
                    },
                ]
            },
        }
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13},
}


@pytest.fixture
def settings(tmp_path):
    return _make_settings(wal_path=str(tmp_path / "test.wal.jsonl"))


@pytest.fixture
def mock_upstream_response():
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.content = json.dumps(_CHAT_RESPONSE).encode()
    resp.json.return_value = _CHAT_RESPONSE
    resp.headers = {"content-type": "application/json"}
    return resp


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestHealthEndpoints:
    def test_health(self, settings):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            mock_fwd_cls.return_value.start = AsyncMock()
            mock_fwd_cls.return_value.stop = AsyncMock()
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "healthy"

    def test_ready(self, settings):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            mock_fwd_cls.return_value.start = AsyncMock()
            mock_fwd_cls.return_value.stop = AsyncMock()
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.get("/ready")
            assert resp.status_code == 200
            assert resp.json()["status"] == "ready"


class TestAuthentication:
    def test_missing_auth_returns_401(self, settings):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            mock_fwd_cls.return_value.start = AsyncMock()
            mock_fwd_cls.return_value.stop = AsyncMock()
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.post(
                    "/v1/chat/completions",
                    json={"model": "gpt-4o-mini", "messages": []},
                )
        assert resp.status_code == 401

    def test_wrong_key_returns_401(self, settings):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            mock_fwd_cls.return_value.start = AsyncMock()
            mock_fwd_cls.return_value.stop = AsyncMock()
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": "Bearer sk-wrong-key"},
                    json={"model": "gpt-4o-mini", "messages": []},
                )
        assert resp.status_code == 401

    def test_valid_key_passes(self, settings, mock_upstream_response):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            instance = mock_fwd_cls.return_value
            instance.start = AsyncMock()
            instance.stop = AsyncMock()
            # IMPORTANT: forward_json MUST be an AsyncMock because it is awaited in app.py
            instance.forward_json = AsyncMock(return_value=mock_upstream_response)
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": "Bearer sk-test-key"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "hello"}],
                    },
                )
        assert resp.status_code == 200


class TestChatCompletions:
    def test_response_contains_aegis_headers(self, settings, mock_upstream_response):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            instance = mock_fwd_cls.return_value
            instance.start = AsyncMock()
            instance.stop = AsyncMock()
            instance.forward_json = AsyncMock(return_value=mock_upstream_response)
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": "Bearer sk-test-key"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "hello"}],
                    },
                )
        assert resp.status_code == 200
        assert "x-aegis-request-id" in resp.headers
        assert "x-aegis-session-id" in resp.headers
        assert "x-aegis-alert-count" in resp.headers

    def test_logprobs_injected_into_upstream_call(self, settings, mock_upstream_response):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            instance = mock_fwd_cls.return_value
            instance.start = AsyncMock()
            instance.stop = AsyncMock()
            instance.forward_json = AsyncMock(return_value=mock_upstream_response)
            app = create_app(settings)
            with TestClient(app) as client:
                client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": "Bearer sk-test-key"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "hello"}],
                    },
                )
            call_args = instance.forward_json.call_args
            forwarded_body = call_args[0][1]
        assert forwarded_body.get("logprobs") is True
        assert forwarded_body.get("top_logprobs") == settings.top_logprobs

    def test_session_id_from_header(self, settings, mock_upstream_response):
        session_id = "my-custom-session-123"
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            instance = mock_fwd_cls.return_value
            instance.start = AsyncMock()
            instance.stop = AsyncMock()
            instance.forward_json = AsyncMock(return_value=mock_upstream_response)
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.post(
                    "/v1/chat/completions",
                    headers={
                        "Authorization": "Bearer sk-test-key",
                        "X-Session-ID": session_id,
                    },
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": "hello"}],
                    },
                )
        assert resp.headers["x-aegis-session-id"] == session_id

    def test_invalid_json_returns_400(self, settings):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            instance = mock_fwd_cls.return_value
            instance.start = AsyncMock()
            instance.stop = AsyncMock()
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.post(
                    "/v1/chat/completions",
                    content=b"not-json{{{",
                    headers={
                        "Authorization": "Bearer sk-test-key",
                        "content-type": "application/json",
                    },
                )
        assert resp.status_code in (400, 422)


class TestAuditEndpoints:
    def test_audit_health_requires_key(self, settings):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            instance = mock_fwd_cls.return_value
            instance.start = AsyncMock()
            instance.stop = AsyncMock()
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.get("/v1/audit/health")
        assert resp.status_code == 401

    def test_audit_health_with_key(self, settings):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            instance = mock_fwd_cls.return_value
            instance.start = AsyncMock()
            instance.stop = AsyncMock()
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.get(
                    "/v1/audit/health",
                    headers={"Authorization": "Bearer sk-audit-key"},
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "node_count" in data

    def test_integrity_endpoint(self, settings):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            instance = mock_fwd_cls.return_value
            instance.start = AsyncMock()
            instance.stop = AsyncMock()
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.get(
                    "/v1/audit/integrity",
                    headers={"Authorization": "Bearer sk-audit-key"},
                )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True

    def test_nodes_pagination(self, settings, mock_upstream_response):
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            instance = mock_fwd_cls.return_value
            instance.start = AsyncMock()
            instance.stop = AsyncMock()
            instance.forward_json = AsyncMock(return_value=mock_upstream_response)
            app = create_app(settings)
            with TestClient(app) as client:
                # Make 3 requests to populate audit nodes
                for _ in range(3):
                    client.post(
                        "/v1/chat/completions",
                        headers={"Authorization": "Bearer sk-test-key"},
                        json={
                            "model": "gpt-4o-mini",
                            "messages": [{"role": "user", "content": "hello"}],
                        },
                    )
                resp = client.get(
                    "/v1/audit/nodes?limit=2",
                    headers={"Authorization": "Bearer sk-audit-key"},
                )
        assert resp.status_code == 200
        nodes = resp.json()
        assert len(nodes) <= 2


class TestAuthDisabled:
    def test_no_key_needed_when_disabled(self, tmp_path):
        settings = _make_settings(
            auth_disabled=True,
            debug_mode=True,  # auth_disabled is only honoured in debug mode
            wal_path=str(tmp_path / "test.wal.jsonl"),
        )
        with patch("aegis.proxy.app.LLMForwarder") as mock_fwd_cls:
            instance = mock_fwd_cls.return_value
            instance.start = AsyncMock()
            instance.stop = AsyncMock()
            app = create_app(settings)
            with TestClient(app) as client:
                resp = client.get("/health")
        assert resp.status_code == 200
