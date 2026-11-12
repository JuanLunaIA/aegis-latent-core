# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Minimal gateway integration: reversible vault, tenancy and edge secret."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis.config import AegisSettings
from aegis.proxy.app import create_app

DNI = "30123456"


def _settings(tmp_path, **overrides) -> AegisSettings:
    defaults = dict(
        backend_api_key="sk-backend",
        backend_url="http://mock-upstream",
        api_keys="sk-valid",
        wal_path=str(tmp_path / "test.wal"),
        log_level="ERROR",
        auth_disabled=False,
        waf_strict_mode=False,
        analysis_sample_rate=0.0,
    )
    defaults.update(overrides)
    return AegisSettings(**defaults)


def _response(data: dict) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.content = json.dumps(data).encode()
    resp.json.return_value = data
    resp.headers = {"content-type": "application/json"}
    return resp


def _forwarder(reply) -> MagicMock:
    inst = MagicMock()
    inst.start = AsyncMock()
    inst.stop = AsyncMock()
    inst.provider = MagicMock()
    inst.provider.name = "mock"
    inst.provider.supports_logprobs = False
    inst.forward_json = AsyncMock(side_effect=reply)
    return inst


def test_provider_never_sees_the_dni(tmp_path):
    sent: list[dict] = []

    async def reply(path, body, extra_headers=None):
        sent.append(body)
        token = body["messages"][0]["content"].split("DNI: ")[1]
        return _response(
            {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": f"Su DNI es {token}."},
                        "finish_reason": "stop",
                        "logprobs": None,
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
            }
        )

    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(_settings(tmp_path, pii_vault_enabled=True))
        with TestClient(app) as client:
            resp = client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer sk-valid"},
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": f"DNI: {DNI}"}],
                },
            )

    assert resp.status_code == 200
    assert sent, "the forwarder was never called"
    provider_content = sent[0]["messages"][0]["content"]
    assert DNI not in provider_content
    assert "[[AEGIS:DNI:" in provider_content
    assert DNI in resp.json()["choices"][0]["message"]["content"]
    node = app.state.aegis.ledger.chain[-1]
    assert node.sampling_params["pii_restored"] is True
    assert node.sampling_params["response_upstream_sha256"] != node.response_hash
    # The evidence commits to the tokenised body, not the original.
    assert node.request_hash == hashlib.sha256(json.dumps(sent[0]).encode()).hexdigest()


def test_vault_off_leaves_the_body_intact(tmp_path):
    sent: list[dict] = []

    async def reply(path, body, extra_headers=None):
        sent.append(body)
        return _response(
            {
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
                "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
            }
        )

    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(_settings(tmp_path, pii_vault_enabled=False))
        with TestClient(app) as client:
            resp = client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer sk-valid"},
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": f"DNI: {DNI}"}],
                },
            )

    assert resp.status_code == 200
    assert DNI in sent[0]["messages"][0]["content"]
    node = app.state.aegis.ledger.chain[-1]
    assert "pii_restored" not in node.sampling_params
    assert node.sampling_params["response_upstream_sha256"] == node.response_hash


async def _unreached(*_args, **_kwargs):
    raise AssertionError("the forwarder must not be called")


def test_cross_tenant_request_is_rejected(tmp_path):
    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(_unreached)):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            resp = client.post(
                "/v1/chat/completions",
                headers={
                    "Authorization": "Bearer sk-valid",
                    "X-Aegis-Host": "globex.api.aegislatent.com",
                },
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "hola"}],
                },
            )

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Tenant mismatch"


def test_edge_secret_registered_only_when_configured(tmp_path):
    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(AsyncMock())):
        app = create_app(_settings(tmp_path, edge_secret="topsecret"))
        with TestClient(app) as client:
            assert client.get("/health").status_code == 200
            blocked = client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer sk-valid"},
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "x"}]},
            )
            # With a valid secret the edge no longer stops the request.
            allowed = client.get(
                "/v1/audit/proofs/does-not-exist", headers={"x-aegis-edge": "topsecret"}
            )
            metrics = client.get("/metrics")

    assert blocked.status_code == 403
    assert allowed.status_code != 403  # the missing header is no longer what fails
    assert metrics.status_code == 404


def test_no_edge_secret_means_no_middleware(tmp_path):
    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(AsyncMock())):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            # Without a configured secret the request reaches the handler (401/422/200),
            # never the edge middleware's 403.
            resp = client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer sk-valid"},
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "x"}]},
            )
    assert resp.status_code != 403


@pytest.mark.parametrize("unknown", ["PASSPORT", "EMAIL,PASSPORT"])
def test_unknown_vault_type_is_a_startup_error(unknown: str):
    with pytest.raises(ValueError):
        AegisSettings(pii_vault_types=unknown)


# ── streaming ───────────────────────────────────────────────────────────────


def _sse(content: str) -> tuple[bytes, dict]:
    parsed = {"choices": [{"index": 0, "delta": {"content": content}}]}
    return b"data: " + json.dumps(parsed).encode() + b"\n\n", parsed


def _deltas(body: bytes) -> str:
    out: list[str] = []
    for line in body.decode().splitlines():
        if not line.startswith("data: ") or line.strip() == "data: [DONE]":
            continue
        payload = json.loads(line[6:])
        for choice in payload.get("choices", []):
            out.append(choice.get("delta", {}).get("content", ""))
    return "".join(out)


def test_stream_restores_a_token_split_across_events(tmp_path):
    """The token is split across two events; the client receives the value, not the token."""
    sent: list[dict] = []

    async def reply(path, body, extra_headers=None):
        return _response({})

    def stream(_path, body, extra_headers=None):
        sent.append(body)
        token = body["messages"][0]["content"].split("DNI: ")[1]

        async def source():
            yield _sse(f"Su DNI es {token[:7]}")
            yield _sse(f"{token[7:]}.")
            yield b"data: [DONE]\n\n", None

        return source()

    fwd = _forwarder(reply)
    fwd.stream_sse = MagicMock(side_effect=stream)
    with patch("aegis.proxy.app.LLMForwarder", return_value=fwd):
        app = create_app(
            _settings(tmp_path, pii_vault_enabled=True, max_stream_duration_seconds=10)
        )
        with TestClient(app) as client:
            with client.stream(
                "POST",
                "/v1/chat/completions",
                headers={"Authorization": "Bearer sk-valid"},
                json={
                    "model": "gpt-4",
                    "stream": True,
                    "messages": [{"role": "user", "content": f"DNI: {DNI}"}],
                },
            ) as response:
                body = b"".join(response.iter_bytes())

    assert response.status_code == 200
    assert "[[AEGIS:DNI:" in sent[0]["messages"][0]["content"]
    assert _deltas(body) == f"Su DNI es {DNI}."
    node = app.state.aegis.ledger.chain[-1]
    assert node.sampling_params["pii_restored"] is True
    assert node.sampling_params["response_upstream_sha256"] != node.response_hash
    assert node.sampling_params["response_client_sha256"] == node.response_hash
    assert node.request_hash == hashlib.sha256(json.dumps(sent[0]).encode()).hexdigest()
