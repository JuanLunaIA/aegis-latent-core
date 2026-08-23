"""Deterministic tests for immutable principals and strict OIDC validation."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import builtins
from dataclasses import FrozenInstanceError
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from aegis.auth.oidc import (
    InMemoryJWKSCache,
    OIDCAuthenticationError,
    OIDCConfig,
    OIDCDependencyError,
    OIDCManager,
    _load_pyjwt,
)
from aegis.auth.principal import ALL_ROLES, Principal, Role
from aegis.proxy.dependencies import _combine

NOW = 2_000_000_000
ISSUER = "https://id.example.test"
AUDIENCE = "aegis-api"


class Transport:
    def __init__(self, documents: list[dict[str, object]]) -> None:
        self.documents = documents
        self.calls: list[str] = []

    async def fetch_jwks(self, issuer: str) -> dict[str, object]:
        self.calls.append(issuer)
        return self.documents[min(len(self.calls) - 1, len(self.documents) - 1)]


def key_material(kid: str) -> tuple[Any, dict[str, object]]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = dict(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return private, jwk


def token(private: Any, kid: str, **overrides: object) -> str:
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "alice",
        "tenant_id": "tenant-a",
        "roles": ["auditor", "audit_reader"],
        "iat": NOW - 10,
        "nbf": NOW - 10,
        "exp": NOW + 60,
    }
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": kid})


def test_dual_factor_empty_grants_never_inherit_other_factor() -> None:
    bearer = Principal(
        subject="alice",
        tenant_id="tenant-a",
        roles=frozenset(),
        scopes=frozenset(),
        auth_method="oidc",
        credential_id="oidc-key",
    )
    certificate = Principal(
        subject="certificate",
        tenant_id="tenant-a",
        roles=frozenset({Role.PROXY_USER}),
        scopes=frozenset({"proxy:completions"}),
        auth_method="mtls",
        credential_id="mtls-key",
    )
    combined = _combine(bearer, certificate, "x" * 32)
    assert combined.roles == frozenset()
    assert combined.scopes == frozenset()


@pytest.mark.asyncio
async def test_authenticates_exact_claims_and_maps_only_four_roles() -> None:
    private, jwk = key_material("key-1")
    transport = Transport([{"keys": [jwk]}])
    manager = OIDCManager(OIDCConfig(ISSUER, AUDIENCE), transport, clock=lambda: NOW)

    principal = await manager.authenticate(token(private, "key-1"))

    assert principal == Principal(
        subject="alice",
        tenant_id="tenant-a",
        roles=frozenset({Role.AUDITOR, Role.AUDIT_READER}),
        credential_id="oidc:key-1:alice",
    )
    assert len(ALL_ROLES) == 4
    assert transport.calls == [ISSUER]
    with pytest.raises(FrozenInstanceError):
        principal.subject = "mallory"  # type: ignore[misc]
    with pytest.raises(TypeError):
        principal.attributes["issuer"] = "changed"  # type: ignore[index]


@pytest.mark.asyncio
async def test_unknown_kid_forces_exactly_one_refresh() -> None:
    private, jwk = key_material("rotated")
    cache = InMemoryJWKSCache()
    await cache.set(ISSUER, {"keys": []})
    transport = Transport([{"keys": [jwk]}])
    manager = OIDCManager(OIDCConfig(ISSUER, AUDIENCE), transport, cache, clock=lambda: NOW)

    assert (await manager.verify(token(private, "rotated"))).subject == "alice"
    assert transport.calls == [ISSUER]


@pytest.mark.asyncio
async def test_unknown_kid_refreshes_only_once_then_fails_without_token_disclosure() -> None:
    private, _ = key_material("missing")
    encoded = token(private, "missing")
    transport = Transport([{"keys": []}])
    manager = OIDCManager(OIDCConfig(ISSUER, AUDIENCE), transport, clock=lambda: NOW)

    with pytest.raises(OIDCAuthenticationError) as raised:
        await manager.authenticate(encoded)
    assert transport.calls == [ISSUER]
    assert encoded not in str(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", f"{ISSUER}/"),
        ("aud", f"{AUDIENCE}-other"),
        ("sub", ""),
        ("exp", NOW),
        ("iat", NOW + 1),
        ("nbf", NOW + 1),
    ],
)
async def test_rejects_non_exact_and_invalid_time_claims(claim: str, value: object) -> None:
    private, jwk = key_material("key-1")
    manager = OIDCManager(
        OIDCConfig(ISSUER, AUDIENCE), Transport([{"keys": [jwk]}]), clock=lambda: NOW
    )
    with pytest.raises(OIDCAuthenticationError):
        await manager.authenticate(token(private, "key-1", **{claim: value}))


@pytest.mark.asyncio
async def test_rejects_missing_kid_unapproved_alg_and_unknown_role() -> None:
    private, jwk = key_material("key-1")
    manager = OIDCManager(
        OIDCConfig(ISSUER, AUDIENCE), Transport([{"keys": [jwk]}]), clock=lambda: NOW
    )
    no_kid = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "alice", "iat": NOW, "exp": NOW + 1},
        private,
        algorithm="RS256",
    )
    with pytest.raises(OIDCAuthenticationError, match="kid"):
        await manager.authenticate(no_kid)
    hs_token = jwt.encode({"sub": "alice"}, "x" * 32, algorithm="HS256", headers={"kid": "key-1"})
    with pytest.raises(OIDCAuthenticationError, match="unapproved algorithm"):
        await manager.authenticate(hs_token)
    with pytest.raises(OIDCAuthenticationError, match="unsupported role"):
        await manager.authenticate(token(private, "key-1", roles=["superuser"]))


def test_pyjwt_is_lazy_and_dependency_error_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    original = builtins.__import__

    def reject_jwt(name: str, *args: object, **kwargs: object) -> Any:
        if name == "jwt":
            raise ImportError("missing")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_jwt)
    with pytest.raises(OIDCDependencyError, match=r"pip install.*PyJWT"):
        _load_pyjwt()
