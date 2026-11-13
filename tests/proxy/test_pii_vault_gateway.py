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
from aegis.core.pii_vault import VAULT_INSTRUCTION
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
        token = body["messages"][-1]["content"].split("DNI: ")[1]
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
    provider_content = sent[0]["messages"][-1]["content"]
    assert DNI not in provider_content
    assert "[[AEGIS:DNI:" in provider_content
    # The model is told to keep the opaque references verbatim.
    assert sent[0]["messages"][0] == {"role": "system", "content": VAULT_INSTRUCTION}
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
            # With a valid secret the edge lets the request reach its handler.
            allowed = client.get(
                "/v1/audit/proofs/does-not-exist",
                headers={"x-aegis-edge": "topsecret", "Authorization": "Bearer sk-valid"},
            )
            metrics = client.get("/metrics")

    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "edge authentication required"
    assert allowed.status_code == 404
    assert allowed.json()["detail"] == "No audit record exists for this state identifier."
    assert metrics.status_code == 404


def test_no_edge_secret_means_no_middleware(tmp_path):
    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(AsyncMock())):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            # Without a configured secret a request with no edge header reaches
            # its handler: the audit lookup answers, not the edge middleware.
            resp = client.get(
                "/v1/audit/proofs/does-not-exist", headers={"Authorization": "Bearer sk-valid"}
            )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "No audit record exists for this state identifier."


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
        token = body["messages"][-1]["content"].split("DNI: ")[1]

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
    assert "[[AEGIS:DNI:" in sent[0]["messages"][-1]["content"]
    assert _deltas(body) == f"Su DNI es {DNI}."
    node = app.state.aegis.ledger.chain[-1]
    assert node.sampling_params["pii_restored"] is True
    assert node.sampling_params["response_upstream_sha256"] != node.response_hash
    assert node.sampling_params["response_client_sha256"] == node.response_hash
    assert node.request_hash == hashlib.sha256(json.dumps(sent[0]).encode()).hexdigest()


# ── PR #276 review findings ─────────────────────────────────────────────────


def _completion(content: str) -> MagicMock:
    return _response(
        {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                    "logprobs": None,
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
        }
    )


def _token_in(body: dict) -> str:
    return body["messages"][-1]["content"].split("DNI: ")[1].split()[0]


def _chat(client: TestClient, content: str, **extra) -> httpx.Response:
    return client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer sk-valid", **extra.pop("headers", {})},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": content}], **extra},
    )


def test_vault_does_not_switch_off_the_pci_scrubber(tmp_path):
    """Data the vault does not cover (here a card, with CARD left out of the
    policy) is still masked before the provider sees it."""
    sent: list[dict] = []

    async def reply(path, body, extra_headers=None):
        sent.append(body)
        return _completion("ok")

    card = "4111 1111 1111 1111"
    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(
            _settings(tmp_path, pii_vault_enabled=True, pii_vault_types="DNI", pci_scrub=True)
        )
        with TestClient(app) as client:
            resp = _chat(client, f"DNI: {DNI} tarjeta {card}")

    assert resp.status_code == 200
    provider_content = sent[0]["messages"][-1]["content"]
    assert "[[AEGIS:DNI:" in provider_content
    assert card not in provider_content
    node = app.state.aegis.ledger.chain[-1]
    assert node.scrub_method == "pii_vault+pci_pan_mask"


def test_vault_still_scrubs_identifiers_the_model_generates(tmp_path):
    """The response is scrubbed while still tokenised, then restored: the value
    the vault holds comes back, the one the model invented does not."""

    async def reply(path, body, extra_headers=None):
        return _completion(f"Su DNI es {_token_in(body)}. SSN 123-45-6789.")

    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(_settings(tmp_path, pii_vault_enabled=True, phi_deidentify=True))
        with TestClient(app) as client:
            resp = _chat(client, f"DNI: {DNI}")

    content = resp.json()["choices"][0]["message"]["content"]
    assert DNI in content
    assert "123-45-6789" not in content


def test_no_restoration_claim_when_nothing_was_restored(tmp_path):
    async def reply(path, body, extra_headers=None):
        return _completion("Sin referencias.")

    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(_settings(tmp_path, pii_vault_enabled=True))
        with TestClient(app) as client:
            assert _chat(client, f"DNI: {DNI}").status_code == 200

    node = app.state.aegis.ledger.chain[-1]
    assert "pii_restored" not in node.sampling_params


def test_upstream_digest_is_the_provider_bytes(tmp_path):
    upstream: list[bytes] = []

    async def reply(path, body, extra_headers=None):
        resp = _completion(f"Su DNI es {_token_in(body)}.")
        upstream.append(resp.content)
        return resp

    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(_settings(tmp_path, pii_vault_enabled=True))
        with TestClient(app) as client:
            resp = _chat(client, f"DNI: {DNI}")

    node = app.state.aegis.ledger.chain[-1]
    assert node.sampling_params["response_upstream_sha256"] == hashlib.sha256(
        upstream[0]
    ).hexdigest()
    assert node.response_hash == hashlib.sha256(resp.content).hexdigest()
    assert node.sampling_params["response_client_sha256"] == node.response_hash


def test_provider_error_that_echoes_a_token_is_restored_for_the_client(tmp_path):
    provider: list[bytes] = []

    async def reply(path, body, extra_headers=None):
        error = MagicMock(spec=httpx.Response)
        error.status_code = 400
        error.content = json.dumps(
            {"error": {"message": f"invalid field DNI: {_token_in(body)}"}}
        ).encode()
        error.headers = {"content-type": "application/json"}
        provider.append(error.content)
        return error

    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(_settings(tmp_path, pii_vault_enabled=True))
        with TestClient(app) as client:
            resp = _chat(client, f"DNI: {DNI}")

    assert resp.status_code == 400
    assert DNI in resp.json()["error"]["message"]
    assert DNI.encode() not in provider[0]
    # As on success: the signed hash is over what the caller received and the
    # provider's tokenised bytes are the upstream digest.
    node = app.state.aegis.ledger.chain[-1]
    assert node.response_hash == hashlib.sha256(resp.content).hexdigest()
    assert node.sampling_params["response_upstream_sha256"] == hashlib.sha256(
        provider[0]
    ).hexdigest()
    assert node.sampling_params["pii_restored"] is True


def test_tool_fields_are_tokenised_and_the_session_keeps_the_callers_id(tmp_path):
    sent: list[dict] = []

    async def reply(path, body, extra_headers=None):
        sent.append(body)
        return _completion("ok")

    email = "ana@example.com"
    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(_settings(tmp_path, pii_vault_enabled=True))
        with TestClient(app) as client:
            resp = client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer sk-valid"},
                json={
                    "model": "gpt-4",
                    "user": "caller-7",
                    "stop": [email],
                    "messages": [
                        {"role": "user", "content": "hola"},
                        {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": json.dumps({"email": email}),
                                    },
                                }
                            ],
                        },
                    ],
                },
            )

    assert resp.status_code == 200
    forwarded = sent[0]
    assert email not in forwarded["messages"][-1]["tool_calls"][0]["function"]["arguments"]
    assert forwarded["stop"] == [email]
    assert resp.headers["X-Aegis-Session-ID"] == "caller-7"


def test_analysis_never_receives_restored_values(tmp_path):
    jobs: list = []

    async def reply(path, body, extra_headers=None):
        return _completion(f"Su DNI es {_token_in(body)}.")

    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(_settings(tmp_path, pii_vault_enabled=True, analysis_sample_rate=1.0))
        with TestClient(app) as client:
            app.state.aegis.analysis_queue.put_nowait = jobs.append
            resp = _chat(client, f"DNI: {DNI}")

    assert DNI in resp.json()["choices"][0]["message"]["content"]
    assert jobs, "the analysis job was not queued"
    assert DNI.encode() not in jobs[0].raw_body
    assert DNI.encode() not in jobs[0].response_bytes


def test_waf_session_state_is_keyed_by_tenant(tmp_path):
    async def reply(path, body, extra_headers=None):
        return _completion("ok")

    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(_settings(tmp_path))
        with TestClient(app) as client:
            tracker = app.state.aegis.waf_session_tracker
            with patch.object(tracker, "record_and_check", wraps=tracker.record_and_check) as spy:
                _chat(client, "hola", headers={"x-aegis-session-id": "shared-session"})

    keyed = spy.call_args.kwargs["session_id"]
    tenant, _, session = keyed.rpartition(":")
    assert session == "shared-session"
    assert tenant


def test_stream_with_the_vault_persists_no_restored_preview(tmp_path):
    async def reply(path, body, extra_headers=None):
        return _response({})

    def stream(_path, body, extra_headers=None):
        token = _token_in(body)

        async def source():
            yield _sse(f"Su DNI es {token}.")
            yield b"data: [DONE]\n\n", None

        return source()

    fwd = _forwarder(reply)
    fwd.stream_sse = MagicMock(side_effect=stream)
    with patch("aegis.proxy.app.LLMForwarder", return_value=fwd):
        app = create_app(
            _settings(tmp_path, pii_vault_enabled=True, max_stream_duration_seconds=10)
        )
        with TestClient(app) as client:
            ledger = app.state.aegis.ledger
            with patch.object(
                ledger, "commit_forensic_summary", wraps=ledger.commit_forensic_summary
            ) as spy:
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

    assert _deltas(body) == f"Su DNI es {DNI}."
    assert spy.call_args.kwargs["response_preview"] == b""


def test_empty_vault_types_are_a_startup_error():
    with pytest.raises(ValueError):
        AegisSettings(pii_vault_types="")


@pytest.mark.parametrize(
    ("content", "vault_on"),
    [
        (b"\xff\xfe [[AEGIS:", True),  # not UTF-8: the client gets the provider's bytes
        (b'{"error": "no tokens"}', True),  # nothing to restore
        (b'{"error": "[[AEGIS:DNI:abcdef1234]]"}', False),  # vault off
        (b'{"error": "[[AEGIS:DNI:abcdef1234]]"}', True),  # unknown token: nothing restored
    ],
)
def test_error_body_restore_falls_back_to_the_provider_bytes(content: bytes, vault_on: bool):
    from aegis.core.pii_vault import PIIMap
    from aegis.proxy.app import _restored_error_body

    assert _restored_error_body(content, PIIMap() if vault_on else None) is None


def test_provider_failure_with_the_vault_on_fails_closed(tmp_path):
    """The provider call raises: the client gets the fixed 503 body and the
    evidence commits to the tokenised request, never the original value."""

    async def reply(path, body, extra_headers=None):
        raise httpx.ConnectError("upstream down")

    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(_settings(tmp_path, pii_vault_enabled=True))
        with TestClient(app) as client:
            resp = _chat(client, f"DNI: {DNI}")

    assert resp.status_code == 503
    assert DNI not in resp.text
    node = app.state.aegis.ledger.chain[-1]
    assert node.request_hash != hashlib.sha256(
        json.dumps({"model": "gpt-4", "messages": [{"role": "user", "content": f"DNI: {DNI}"}]}).encode()
    ).hexdigest()
