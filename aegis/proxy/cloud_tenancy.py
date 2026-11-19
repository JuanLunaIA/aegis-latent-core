# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Hosted multi-tenant mode: tenant API keys and upstreams from Aegis Cloud.

With ``AEGIS_AUTH_MODE=aegis_cloud`` the gateway serves many tenants from one
process. For each request it:

1. resolves the bearer key with ``POST /v1/internal/keys/verify`` on the control
   plane (internal HMAC channel, see :func:`aegis.proxy.metering.sign`), and
2. resolves the tenant's upstream with ``GET /v1/internal/orgs/{slug}/provider``.
   ``source=platform`` uses the gateway's own configured upstream (the Aegis
   model). ``source=byok`` carries the tenant's provider key sealed to this
   gateway's X25519 key (``AEGIS_CLOUD_GATEWAY_PRIVATE_KEY``); it is opened here
   and used only in the upstream ``Authorization`` header.

Every failure is closed: an unknown key is 401, an inactive endpoint is 403, and
an unreachable control plane, a malformed answer or an envelope that does not
open is 503. Nothing falls back to another tenant's or the platform upstream.

Results are cached briefly (positive and negative) so the control plane is not
called on every request. A revoked key keeps working for at most
``KEY_TTL_SECONDS``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import AnyHttpUrl

from aegis.auth.principal import Principal, Role, permissions_for_roles
from aegis.proxy.metering import sign

logger = logging.getLogger(__name__)

KEY_TTL_SECONDS = 30.0
NEGATIVE_TTL_SECONDS = 10.0
PROVIDER_TTL_SECONDS = 60.0
MAX_CACHE_ENTRIES = 10_000
_TIMEOUT = httpx.Timeout(5.0)
_VERIFY_PATH = "/v1/internal/keys/verify"
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
_MAX_KEY_BYTES = 512

# Cloud key scopes -> gateway roles. "anchor" has no gateway counterpart and
# grants nothing; no Cloud scope maps to the cross-tenant admin role.
_SCOPE_ROLES: dict[str, Role] = {
    "chat": Role.PROXY_USER,
    "audit": Role.AUDIT_READER,
    "admin": Role.AUDITOR,
}

# Cloud provider ids -> gateway adapters. Everything not listed speaks the
# OpenAI wire format (deepseek, mistral, groq, together, fireworks, modal, ...).
_ADAPTERS = {"anthropic": "anthropic", "openrouter": "openrouter"}

# Must match aegis-cloud app/provider_envelope.py.
_ENVELOPE_VERSION = 1
_ENVELOPE_ALG = "X25519-HKDF-SHA256-AESGCM"
_HKDF_INFO = b"aegis-provider-envelope-v1"
_AAD_PREFIX = "aegis:provider-envelope:v1"


class TenancyError(Exception):
    """A refusal with the HTTP status the gateway should answer."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _unavailable() -> TenancyError:
    return TenancyError(503, "Tenant control plane is unavailable")


def parse_private_key(value: str) -> X25519PrivateKey:
    raw = value.strip().lower()
    if len(raw) != 64:
        raise ValueError("AEGIS_CLOUD_GATEWAY_PRIVATE_KEY must be 32 bytes of hex")
    try:
        return X25519PrivateKey.from_private_bytes(bytes.fromhex(raw))
    except ValueError as exc:
        raise ValueError("AEGIS_CLOUD_GATEWAY_PRIVATE_KEY must be 32 bytes of hex") from exc


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("envelope field must be a string")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def open_envelope(
    envelope: object, private_key: X25519PrivateKey, *, org_id: str, provider_id: str, key_id: str
) -> str:
    """Open a provider envelope; raises ``ValueError`` on any mismatch."""
    if not isinstance(envelope, dict):
        raise ValueError("envelope must be an object")
    if envelope.get("v") != _ENVELOPE_VERSION or envelope.get("alg") != _ENVELOPE_ALG:
        raise ValueError("unsupported envelope")
    if envelope.get("key_id") != key_id or envelope.get("provider_id") != provider_id:
        raise ValueError("envelope is bound to another key or provider")
    aad = f"{_AAD_PREFIX}:{org_id}:{provider_id}:{key_id}".encode()
    if not hmac.compare_digest(_unb64(envelope.get("context")), aad):
        raise ValueError("envelope context does not match")
    epk = _unb64(envelope.get("epk"))
    nonce = _unb64(envelope.get("nonce"))
    if len(epk) != 32 or len(nonce) != 12:
        raise ValueError("envelope is malformed")
    shared = private_key.exchange(X25519PublicKey.from_public_bytes(epk))
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=epk + private_key.public_key().public_bytes_raw(),
        info=_HKDF_INFO,
    ).derive(shared)
    try:
        plaintext = AESGCM(key).decrypt(nonce, _unb64(envelope.get("ciphertext")), aad)
    except InvalidTag as exc:
        raise ValueError("envelope failed authentication") from exc
    return plaintext.decode("utf-8")


@dataclass(frozen=True)
class _Upstream:
    source: str  # "platform" or "byok"
    provider: str
    base_url: str
    model: str
    api_key: str
    provider_id: str


class CloudTenancy:
    """Key verification and per-tenant forwarders backed by Aegis Cloud."""

    def __init__(
        self,
        settings: Any,
        *,
        cloud_url: str,
        secret: str,
        private_key: X25519PrivateKey | None,
        egress_guard: Any = None,
        transport: httpx.AsyncBaseTransport | None = None,
        forwarder_factory: Any = None,
    ) -> None:
        self._settings = settings
        self._cloud_url = cloud_url.rstrip("/")
        self._secret = secret
        self._private_key = private_key
        self._egress_guard = egress_guard
        self._client = httpx.AsyncClient(timeout=_TIMEOUT, transport=transport)
        self._keys: OrderedDict[str, tuple[float, Principal | TenancyError]] = OrderedDict()
        self._upstreams: OrderedDict[str, tuple[float, _Upstream]] = OrderedDict()
        self._forwarders: dict[str, tuple[str, Any]] = {}
        self._retired: list[Any] = []
        self._forwarder_factory = forwarder_factory

    async def stop(self) -> None:
        for _, forwarder in self._forwarders.values():
            await forwarder.stop()
        for forwarder in self._retired:
            await forwarder.stop()
        self._forwarders.clear()
        self._retired.clear()
        await self._client.aclose()

    # ── control-plane calls ───────────────────────────────────────────────

    def _headers(self, method: str, path: str, body: bytes) -> dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        return {
            "x-aegis-timestamp": timestamp,
            "x-aegis-nonce": nonce,
            "x-aegis-signature": sign(
                self._secret, timestamp=timestamp, nonce=nonce, method=method, path=path, body=body
            ),
        }

    async def _call(self, method: str, path: str, extra: dict[str, str]) -> httpx.Response:
        url = f"{self._cloud_url}{path}"
        if self._egress_guard is not None and not self._egress_guard.is_allowed(url):
            logger.error("aegis_cloud: control plane URL is blocked by the egress guard")
            raise _unavailable()
        try:
            return await self._client.request(
                method, url, content=b"", headers={**self._headers(method, path, b""), **extra}
            )
        except httpx.HTTPError as exc:
            logger.warning("aegis_cloud: control plane request failed: %s", type(exc).__name__)
            raise _unavailable() from None

    @staticmethod
    def _error_code(response: httpx.Response) -> str:
        try:
            error = response.json().get("error", {})
            return str(error.get("code", "")) if isinstance(error, dict) else ""
        except (ValueError, AttributeError):
            return ""

    @staticmethod
    def _cache_put(cache: OrderedDict[str, Any], key: str, value: Any) -> None:
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > MAX_CACHE_ENTRIES:
            cache.popitem(last=False)

    # ── keys ──────────────────────────────────────────────────────────────

    async def principal_for_key(self, raw_key: str) -> Principal:
        if not raw_key or len(raw_key.encode("utf-8")) > _MAX_KEY_BYTES:
            raise TenancyError(401, "Invalid API key")
        cache_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        cached = self._keys.get(cache_key)
        if cached is not None and cached[0] > time.monotonic():
            result = cached[1]
            if isinstance(result, TenancyError):
                raise result
            return result
        try:
            principal = await self._verify(raw_key)
        except TenancyError as exc:
            if exc.status_code in {401, 403}:
                expiry = time.monotonic() + NEGATIVE_TTL_SECONDS
                self._cache_put(self._keys, cache_key, (expiry, exc))
            raise
        self._cache_put(self._keys, cache_key, (time.monotonic() + KEY_TTL_SECONDS, principal))
        return principal

    async def _verify(self, raw_key: str) -> Principal:
        response = await self._call("POST", _VERIFY_PATH, {"x-aegis-key": raw_key})
        code = self._error_code(response) if response.status_code >= 400 else ""
        if response.status_code == 401 and code == "invalid_api_key":
            raise TenancyError(401, "Invalid API key")
        if response.status_code == 403 and code == "endpoint_not_active":
            raise TenancyError(403, "Tenant endpoint is not active")
        if response.status_code != 200:
            # internal_auth_failed, nonce replay, 5xx: our problem, not the caller's key.
            logger.error("aegis_cloud: key verification answered %s %s", response.status_code, code)
            raise _unavailable()
        try:
            body = response.json()
            org_slug = str(body["org_slug"])
            org_id = str(body["org_id"])
            key_id = str(body["key_id"])
            scopes = body["scopes"]
            if not _SLUG_RE.fullmatch(org_slug) or not org_id or not key_id:
                raise ValueError("invalid identifiers")
            if not isinstance(scopes, list):
                raise ValueError("scopes must be a list")
        except (ValueError, KeyError, TypeError):
            logger.error("aegis_cloud: key verification answer is malformed")
            raise _unavailable() from None
        roles = frozenset(
            _SCOPE_ROLES[s] for s in scopes if isinstance(s, str) and s in _SCOPE_ROLES
        )
        return Principal(
            subject=f"aegis-cloud:{key_id}",
            # The org slug is what the provider and usage routes key on.
            tenant_id=org_slug,
            roles=roles,
            scopes=permissions_for_roles(roles),
            auth_method="aegis_cloud",
            credential_id=f"aegis-cloud:{key_id}",
            attributes={
                "org_id": org_id,
                "key_id": key_id,
                "plan": str(body.get("plan", "")),
                "endpoint": str(body.get("tenant_id") or ""),
            },
        )

    # ── upstreams ─────────────────────────────────────────────────────────

    async def _upstream(self, principal: Principal) -> _Upstream:
        slug = principal.tenant_id
        cached = self._upstreams.get(slug)
        if cached is not None and cached[0] > time.monotonic():
            return cached[1]
        response = await self._call("GET", f"/v1/internal/orgs/{quote(slug, safe='')}/provider", {})
        if response.status_code != 200:
            logger.error(
                "aegis_cloud: provider lookup answered %s %s",
                response.status_code,
                self._error_code(response),
            )
            raise _unavailable()
        try:
            body = response.json()
            source = body["source"]
            if source == "platform":
                upstream = _Upstream("platform", "", "", "", "", "")
            elif source == "byok":
                upstream = self._open_byok(body, principal)
            else:
                raise ValueError("unknown source")
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            logger.error("aegis_cloud: provider answer for a tenant could not be used")
            raise _unavailable() from None
        self._cache_put(self._upstreams, slug, (time.monotonic() + PROVIDER_TTL_SECONDS, upstream))
        return upstream

    def _open_byok(self, body: dict[str, Any], principal: Principal) -> _Upstream:
        if self._private_key is None:
            raise ValueError("no gateway private key is configured")
        base_url = str(body["base_url"]).rstrip("/")
        parts = urlsplit(base_url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            raise ValueError("tenant upstream must be an https URL")
        provider_id = str(body["provider_id"])
        api_key = open_envelope(
            body["envelope"],
            self._private_key,
            org_id=str(principal.attributes.get("org_id", "")),
            provider_id=provider_id,
            key_id=str(body["key_id"]),
        )
        return _Upstream(
            source="byok",
            provider=_ADAPTERS.get(str(body.get("provider") or ""), "openai"),
            base_url=base_url,
            model=str(body.get("model") or ""),
            api_key=api_key,
            provider_id=provider_id,
        )

    async def forwarder_for(self, principal: Principal, default: Any) -> Any:
        """The forwarder for *principal*: the platform one or the tenant's own."""
        upstream = await self._upstream(principal)
        if upstream.source == "platform":
            return default
        if self._egress_guard is not None and not self._egress_guard.is_allowed(upstream.base_url):
            logger.error("aegis_cloud: a tenant upstream is blocked by the egress guard")
            raise _unavailable()
        fingerprint = hashlib.sha256(
            "\0".join(
                (upstream.provider, upstream.base_url, upstream.model, upstream.api_key)
            ).encode()
        ).hexdigest()
        current = self._forwarders.get(principal.tenant_id)
        if current is not None and current[0] == fingerprint:
            return current[1]
        forwarder = await self._build(upstream)
        if current is not None:
            # shortcut: a replaced forwarder may still serve in-flight requests,
            # so it is closed at shutdown, not now; fine while key rotations are rare.
            self._retired.append(current[1])
        self._forwarders[principal.tenant_id] = (fingerprint, forwarder)
        return forwarder

    async def _build(self, upstream: _Upstream) -> Any:
        from aegis.providers import build_provider
        from aegis.proxy.forwarder import LLMForwarder

        cfg = self._settings
        settings = cfg.model_copy(
            update={
                "backend_url": AnyHttpUrl(upstream.base_url),
                "backend_api_key": upstream.api_key,
                "provider": upstream.provider,
                "provider_model": upstream.model,
            }
        )
        provider = build_provider(
            upstream.provider,
            openrouter_site_url=cfg.openrouter_site_url,
            openrouter_site_name=cfg.openrouter_site_name,
            openrouter_base_url=upstream.base_url if upstream.provider == "openrouter" else "",
            anthropic_api_version=cfg.anthropic_api_version,
            anthropic_base_url=upstream.base_url if upstream.provider == "anthropic" else "",
        )
        factory = self._forwarder_factory or LLMForwarder
        forwarder = factory(settings, provider=provider, egress_guard=self._egress_guard)
        await forwarder.start()
        return forwarder


__all__ = ["CloudTenancy", "TenancyError", "open_envelope", "parse_private_key"]
