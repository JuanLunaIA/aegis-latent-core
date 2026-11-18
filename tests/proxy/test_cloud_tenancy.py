# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Hosted multi-tenant mode (``auth_mode=aegis_cloud``).

The hosted gateway serves many tenants from one process, so a mistake here bills
or answers one organisation with another's credentials. These tests pin the
fail-closed contract: an unknown key is 401, an inactive endpoint is 403, a
control plane that is down or answers nonsense is 503 (never a pass), and a
tenant's sealed provider key is used only for that tenant's upstream.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import functools
import hashlib
import hmac
import os
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi.testclient import TestClient

from aegis.auth.scopes import SCOPE_PROXY_COMPLETIONS
from aegis.proxy.app import create_app
from aegis.proxy.cloud_tenancy import CloudTenancy, TenancyError, open_envelope, parse_private_key
from tests.proxy.test_pii_vault_gateway import _completion, _forwarder, _settings

SECRET = "s" * 40
CLOUD = "https://cloud.example"
ORG_ID = "11111111-1111-1111-1111-111111111111"
GATEWAY_KEY = X25519PrivateKey.generate()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _seal(
    secret: str, *, org_id: str = ORG_ID, provider_id: str = "p1", key_id: str = "k1"
) -> dict:
    """Same construction as aegis-cloud ``seal_for_gateway``."""
    recipient = GATEWAY_KEY.public_key()
    ephemeral = X25519PrivateKey.generate()
    epk = ephemeral.public_key().public_bytes_raw()
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=epk + recipient.public_bytes_raw(),
        info=b"aegis-provider-envelope-v1",
    ).derive(ephemeral.exchange(recipient))
    nonce = os.urandom(12)
    aad = f"aegis:provider-envelope:v1:{org_id}:{provider_id}:{key_id}".encode()
    return {
        "v": 1,
        "alg": "X25519-HKDF-SHA256-AESGCM",
        "key_id": key_id,
        "provider_id": provider_id,
        "epk": _b64(epk),
        "nonce": _b64(nonce),
        "context": _b64(aad),
        "ciphertext": _b64(AESGCM(key).encrypt(nonce, secret.encode(), aad)),
    }


def _verified(**overrides: Any) -> dict:
    body = {
        "org_id": ORG_ID,
        "org_slug": "acme",
        "key_id": "key-1",
        "scopes": ["chat"],
        "plan": "pro",
        "tenant_id": "acme",
    }
    body.update(overrides)
    return body


def _byok(**overrides: Any) -> dict:
    body = {
        "source": "byok",
        "provider": "deepseek",
        "provider_id": "p1",
        "key_id": "k1",
        "base_url": "https://api.deepseek.example/v1",
        "model": "deepseek-chat",
        "envelope": _seal("sk-tenant-secret"),
    }
    body.update(overrides)
    return body


class _Cloud:
    """A scripted control plane that records what the gateway sent."""

    def __init__(self, verify: Any = None, provider: Any = None) -> None:
        self.verify = verify if verify is not None else (200, _verified())
        self.provider = provider if provider is not None else (200, {"source": "platform"})
        self.seen: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        reply = self.verify if request.url.path.endswith("/keys/verify") else self.provider
        if isinstance(reply, Exception):
            raise reply
        status, body = reply
        if isinstance(body, bytes):
            return httpx.Response(status, content=body)
        return httpx.Response(status, json=body)

    def paths(self) -> list[str]:
        return [r.url.path for r in self.seen]


def _error(code: str) -> dict:
    return {"error": {"code": code, "message": code}}


class _Factory:
    def __init__(self) -> None:
        self.built: list[Any] = []

    def __call__(self, settings: Any, *, provider: Any, egress_guard: Any) -> Any:
        forwarder = _forwarder(None)
        forwarder.settings = settings
        forwarder.provider_obj = provider
        self.built.append(forwarder)
        return forwarder


def _tenancy(tmp_path, cloud: _Cloud, **kwargs: Any) -> CloudTenancy:
    kwargs.setdefault("private_key", GATEWAY_KEY)
    return CloudTenancy(
        _settings(tmp_path),
        cloud_url=CLOUD,
        secret=SECRET,
        transport=httpx.MockTransport(cloud),
        **kwargs,
    )


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ── keys ──────────────────────────────────────────────────────────────────


def test_valid_key_becomes_a_tenant_principal_without_admin(tmp_path) -> None:
    cloud = _Cloud()
    tenancy = _tenancy(tmp_path, cloud)

    async def go() -> Any:
        first = await tenancy.principal_for_key("aeg_live_abc")
        second = await tenancy.principal_for_key("aeg_live_abc")
        await tenancy.stop()
        return first, second

    first, second = _run(go())
    assert first is second, "a verified key is cached"
    assert cloud.paths() == ["/v1/internal/keys/verify"]
    assert first.tenant_id == "acme"
    assert first.auth_method == "aegis_cloud"
    assert SCOPE_PROXY_COMPLETIONS in first.scopes
    assert {r.value for r in first.roles} == {"proxy_user"}
    assert first.attributes["org_id"] == ORG_ID
    assert cloud.seen[0].headers["x-aegis-key"] == "aeg_live_abc"


def test_verify_request_is_signed_the_way_the_control_plane_checks(tmp_path) -> None:
    cloud = _Cloud()
    tenancy = _tenancy(tmp_path, cloud)
    _run(tenancy.principal_for_key("aeg_live_abc"))
    (request,) = cloud.seen
    message = (
        f"{request.headers['x-aegis-timestamp']}\n{request.headers['x-aegis-nonce']}\n"
        f"POST\n/v1/internal/keys/verify\n{hashlib.sha256(b'').hexdigest()}"
    ).encode()
    expected = hmac.new(SECRET.encode(), message, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(request.headers["x-aegis-signature"], expected)
    assert len(request.headers["x-aegis-nonce"]) == 32


def test_admin_scope_maps_to_auditor_and_anchor_grants_nothing(tmp_path) -> None:
    cloud = _Cloud(verify=(200, _verified(scopes=["admin", "anchor", "bogus", 7])))
    principal = _run(_tenancy(tmp_path, cloud).principal_for_key("aeg_live_abc"))
    assert {r.value for r in principal.roles} == {"auditor"}
    assert SCOPE_PROXY_COMPLETIONS not in principal.scopes


@pytest.mark.parametrize(
    ("status", "code", "expected"),
    [(401, "invalid_api_key", 401), (403, "endpoint_not_active", 403)],
)
def test_refusals_are_passed_through_and_cached_briefly(tmp_path, status, code, expected) -> None:
    cloud = _Cloud(verify=(status, _error(code)))
    tenancy = _tenancy(tmp_path, cloud)

    async def go() -> list[int]:
        codes = []
        for _ in range(2):
            with pytest.raises(TenancyError) as exc:
                await tenancy.principal_for_key("aeg_live_bad")
            codes.append(exc.value.status_code)
        return codes

    assert _run(go()) == [expected, expected]
    assert len(cloud.seen) == 1, "a refusal is negatively cached"


@pytest.mark.parametrize(
    "reply",
    [
        (401, _error("internal_auth_failed")),
        (409, _error("nonce_replayed")),
        (500, _error("internal")),
        (503, _error("internal_auth_not_configured")),
        (403, _error("forbidden")),
        (200, b"not json"),
        (200, {"org_id": ORG_ID}),
        (200, _verified(org_slug="Acme/../other")),
        (200, _verified(scopes="chat")),
        httpx.ConnectTimeout("down"),
    ],
)
def test_control_plane_trouble_is_503_and_not_cached(tmp_path, reply) -> None:
    cloud = _Cloud(verify=reply)
    tenancy = _tenancy(tmp_path, cloud)

    async def go() -> list[int]:
        codes = []
        for _ in range(2):
            with pytest.raises(TenancyError) as exc:
                await tenancy.principal_for_key("aeg_live_abc")
            codes.append(exc.value.status_code)
        return codes

    assert _run(go()) == [503, 503]
    assert len(cloud.seen) == 2, "an outage must not be remembered as a verdict"


def test_empty_or_oversized_key_is_refused_without_a_call(tmp_path) -> None:
    cloud = _Cloud()
    tenancy = _tenancy(tmp_path, cloud)
    for key in ("", "x" * 513):
        with pytest.raises(TenancyError) as exc:
            _run(tenancy.principal_for_key(key))
        assert exc.value.status_code == 401
    assert cloud.seen == []


def test_blocked_control_plane_url_fails_closed(tmp_path) -> None:
    class Deny:
        def is_allowed(self, url: str) -> bool:
            return False

    cloud = _Cloud()
    tenancy = _tenancy(tmp_path, cloud, egress_guard=Deny())
    with pytest.raises(TenancyError) as exc:
        _run(tenancy.principal_for_key("aeg_live_abc"))
    assert exc.value.status_code == 503
    assert cloud.seen == []


# ── upstreams ─────────────────────────────────────────────────────────────


def test_platform_source_uses_the_gateway_forwarder(tmp_path) -> None:
    cloud = _Cloud()
    tenancy = _tenancy(tmp_path, cloud)
    default = object()

    async def go() -> Any:
        principal = await tenancy.principal_for_key("aeg_live_abc")
        return await tenancy.forwarder_for(principal, default)

    assert _run(go()) is default
    assert cloud.paths()[-1] == "/v1/internal/orgs/acme/provider"


def test_byok_opens_the_envelope_and_builds_a_tenant_forwarder(tmp_path) -> None:
    cloud = _Cloud(provider=(200, _byok()))
    factory = _Factory()
    tenancy = _tenancy(tmp_path, cloud, forwarder_factory=factory)

    async def go() -> tuple[Any, Any]:
        principal = await tenancy.principal_for_key("aeg_live_abc")
        first = await tenancy.forwarder_for(principal, object())
        second = await tenancy.forwarder_for(principal, object())
        await tenancy.stop()
        return first, second

    first, second = _run(go())
    assert first is second, "the tenant forwarder is reused"
    (built,) = factory.built
    assert built.settings.backend_api_key == "sk-tenant-secret"
    assert str(built.settings.backend_url).rstrip("/") == "https://api.deepseek.example/v1"
    assert built.settings.provider == "openai"
    assert built.settings.provider_model == "deepseek-chat"
    built.start.assert_awaited_once()
    built.stop.assert_awaited_once()
    assert cloud.paths().count("/v1/internal/orgs/acme/provider") == 1


def test_rotated_tenant_key_builds_a_new_forwarder(tmp_path) -> None:
    cloud = _Cloud(provider=(200, _byok()))
    factory = _Factory()
    tenancy = _tenancy(tmp_path, cloud, forwarder_factory=factory)

    async def go() -> None:
        principal = await tenancy.principal_for_key("aeg_live_abc")
        await tenancy.forwarder_for(principal, object())
        cloud.provider = (200, _byok(envelope=_seal("sk-rotated")))
        tenancy._upstreams.clear()
        await tenancy.forwarder_for(principal, object())
        await tenancy.stop()

    _run(go())
    assert [f.settings.backend_api_key for f in factory.built] == [
        "sk-tenant-secret",
        "sk-rotated",
    ]
    assert all(f.stop.await_count == 1 for f in factory.built)


@pytest.mark.parametrize(
    ("provider_reply", "private_key"),
    [
        ((200, _byok(envelope=_seal("x", org_id="22222222-2222-2222-2222-222222222222"))), "set"),
        ((200, _byok(envelope=_seal("x", key_id="other"))), "set"),
        ((200, _byok(base_url="http://api.deepseek.example/v1")), "set"),
        ((200, _byok(base_url="https://user:pw@api.deepseek.example/v1")), "set"),
        ((200, _byok()), None),
        ((200, {"source": "mystery"}), "set"),
        ((404, _error("not_found")), "set"),
        (httpx.ReadTimeout("slow"), "set"),
    ],
)
def test_unusable_upstream_is_503_never_the_platform(tmp_path, provider_reply, private_key) -> None:
    cloud = _Cloud(provider=provider_reply)
    factory = _Factory()
    tenancy = _tenancy(
        tmp_path,
        cloud,
        forwarder_factory=factory,
        private_key=GATEWAY_KEY if private_key else None,
    )
    default = object()

    async def go() -> None:
        principal = await tenancy.principal_for_key("aeg_live_abc")
        await tenancy.forwarder_for(principal, default)

    with pytest.raises(TenancyError) as exc:
        _run(go())
    assert exc.value.status_code == 503
    assert factory.built == []


def test_tampered_ciphertext_does_not_open() -> None:
    envelope = _seal("sk-tenant-secret")
    raw = bytearray(base64.urlsafe_b64decode(envelope["ciphertext"] + "=="))
    raw[0] ^= 1
    envelope["ciphertext"] = _b64(bytes(raw))
    with pytest.raises(ValueError):
        open_envelope(envelope, GATEWAY_KEY, org_id=ORG_ID, provider_id="p1", key_id="k1")


def test_private_key_must_be_32_bytes_of_hex() -> None:
    assert parse_private_key(GATEWAY_KEY.private_bytes_raw().hex()) is not None
    for bad in ("", "zz" * 32, "ab" * 31):
        with pytest.raises(ValueError):
            parse_private_key(bad)


# ── through the HTTP surface ─────────────────────────────────────────────


@contextlib.contextmanager
def _app(tmp_path, monkeypatch, cloud: _Cloud, factory: Any, platform: Any) -> Iterator[TestClient]:
    monkeypatch.setenv("AEGIS_CLOUD_URL", CLOUD)
    monkeypatch.setenv("AEGIS_CLOUD_INTERNAL_HMAC", SECRET)
    settings = _settings(
        tmp_path,
        auth_mode="aegis_cloud",
        cloud_gateway_private_key=GATEWAY_KEY.private_bytes_raw().hex(),
    )
    tenancy = functools.partial(
        CloudTenancy, transport=httpx.MockTransport(cloud), forwarder_factory=factory
    )
    calls = iter([(CLOUD, SECRET)])
    with (
        patch("aegis.proxy.app.LLMForwarder", return_value=platform),
        patch("aegis.proxy.app.CloudTenancy", tenancy),
        # Metering is out of scope here: only the tenancy setup sees the cloud config.
        patch("aegis.proxy.app.cloud_config", side_effect=lambda: next(calls, None)),
        TestClient(create_app(settings)) as client,
    ):
        yield client


def _post(client: TestClient, key: str) -> httpx.Response:
    return client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {key}"},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
    )


def test_http_unknown_key_is_401_and_upstream_is_not_called(tmp_path, monkeypatch) -> None:
    platform = _forwarder(lambda *a, **k: _completion("platform"))
    cloud = _Cloud(verify=(401, _error("invalid_api_key")))
    with _app(tmp_path, monkeypatch, cloud, _Factory(), platform) as client:
        response = _post(client, "aeg_live_bad")
    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"
    platform.forward_json.assert_not_called()


def test_http_control_plane_down_is_503(tmp_path, monkeypatch) -> None:
    platform = _forwarder(lambda *a, **k: _completion("platform"))
    cloud = _Cloud(verify=httpx.ConnectError("down"))
    with _app(tmp_path, monkeypatch, cloud, _Factory(), platform) as client:
        response = _post(client, "aeg_live_abc")
    assert response.status_code == 503
    platform.forward_json.assert_not_called()


def test_http_byok_tenant_is_served_by_its_own_forwarder(tmp_path, monkeypatch) -> None:
    platform = _forwarder(lambda *a, **k: _completion("platform"))
    factory = _Factory()
    cloud = _Cloud(provider=(200, _byok()))

    original = factory.__call__

    def build(settings: Any, *, provider: Any, egress_guard: Any) -> Any:
        forwarder = original(settings, provider=provider, egress_guard=egress_guard)
        forwarder.forward_json.side_effect = lambda *a, **k: _completion("tenant")
        return forwarder

    with _app(tmp_path, monkeypatch, cloud, build, platform) as client:
        response = _post(client, "aeg_live_abc")
    assert response.status_code == 200, response.text
    assert response.json()["choices"][0]["message"]["content"] == "tenant"
    platform.forward_json.assert_not_called()
    (tenant,) = factory.built
    tenant.forward_json.assert_called_once()


def test_http_platform_tenant_uses_the_aegis_model(tmp_path, monkeypatch) -> None:
    platform = _forwarder(lambda *a, **k: _completion("platform"))
    factory = _Factory()
    with _app(tmp_path, monkeypatch, _Cloud(), factory, platform) as client:
        response = _post(client, "aeg_live_abc")
    assert response.status_code == 200, response.text
    assert response.json()["choices"][0]["message"]["content"] == "platform"
    assert factory.built == []
