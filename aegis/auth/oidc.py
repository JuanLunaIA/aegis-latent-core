"""OIDC access-token verification without network or global-cache side effects."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

import httpx

from aegis.auth.principal import Principal, Role

JsonObject = Mapping[str, object]


class OIDCError(ValueError):
    """Base class for safe, token-free OIDC authentication failures."""


class OIDCConfigurationError(OIDCError):
    """Raised for unsafe or incomplete verifier configuration."""


class OIDCDependencyError(RuntimeError):
    """Raised when the optional JWT implementation is not installed."""


class OIDCAuthenticationError(OIDCError):
    """Raised when an OIDC token cannot be authenticated."""


@runtime_checkable
class AsyncJWKSTransport(Protocol):
    """Injected network boundary for retrieving an issuer JWKS document."""

    async def fetch_jwks(self, issuer: str) -> JsonObject:
        """Fetch and return the issuer's JSON Web Key Set."""


@runtime_checkable
class AsyncJWKSCache(Protocol):
    """Injected asynchronous cache boundary for issuer JWKS documents."""

    async def get(self, issuer: str) -> JsonObject | None:
        """Return a cached JWKS, or ``None`` on cache miss."""

    async def set(self, issuer: str, jwks: JsonObject) -> None:
        """Store a JWKS for an issuer."""


class InMemoryJWKSCache:
    """Small lock-protected cache suitable for a single process."""

    def __init__(
        self, *, ttl_seconds: float = 300.0, clock: Callable[[], float] = time.monotonic
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("JWKS cache TTL must be positive")
        self._values: dict[str, tuple[float, JsonObject]] = {}
        self._lock = asyncio.Lock()
        self._ttl_seconds = ttl_seconds
        self._clock = clock

    async def get(self, issuer: str) -> JsonObject | None:
        async with self._lock:
            entry = self._values.get(issuer)
            if entry is None:
                return None
            expires_at, value = entry
            if self._clock() >= expires_at:
                del self._values[issuer]
                return None
            return cast(JsonObject, json.loads(json.dumps(value)))

    async def set(self, issuer: str, jwks: JsonObject) -> None:
        async with self._lock:
            copied = json.loads(json.dumps(jwks))
            self._values[issuer] = (self._clock() + self._ttl_seconds, copied)


@dataclass(frozen=True, slots=True)
class OIDCConfig:
    """Strict validation and claim-mapping configuration."""

    issuer: str
    audience: str
    algorithms: tuple[str, ...] = ("RS256",)
    tenant_claim: str = "tenant_id"
    roles_claim: str = "roles"
    leeway_seconds: int = 0
    require_iat: bool = True

    def __post_init__(self) -> None:
        if not self.issuer or self.issuer != self.issuer.strip():
            raise OIDCConfigurationError("OIDC issuer must be a non-empty exact value")
        if not self.audience or self.audience != self.audience.strip():
            raise OIDCConfigurationError("OIDC audience must be a non-empty exact value")
        if not self.algorithms or any(not value for value in self.algorithms):
            raise OIDCConfigurationError("at least one explicit OIDC algorithm is required")
        if "none" in {value.lower() for value in self.algorithms}:
            raise OIDCConfigurationError("the unsigned JWT algorithm is forbidden")
        if self.leeway_seconds < 0:
            raise OIDCConfigurationError("OIDC leeway_seconds cannot be negative")
        parsed = urlsplit(self.issuer)
        if parsed.scheme != "https" or not parsed.hostname:
            raise OIDCConfigurationError("OIDC issuer must be an absolute HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise OIDCConfigurationError("OIDC issuer must not contain credentials")
        if parsed.query or parsed.fragment:
            raise OIDCConfigurationError("OIDC issuer must not contain query or fragment")


class HTTPXJWKSTransport:
    """Fetch one configured JWKS endpoint with strict HTTPS and response bounds."""

    def __init__(self, jwks_url: str, *, timeout: float = 5.0, max_bytes: int = 1_048_576) -> None:
        parsed = urlsplit(jwks_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise OIDCConfigurationError("OIDC JWKS URL must be an absolute HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise OIDCConfigurationError("OIDC JWKS URL must not contain credentials")
        if parsed.fragment:
            raise OIDCConfigurationError("OIDC JWKS URL must not contain a fragment")
        if timeout <= 0 or max_bytes < 1:
            raise OIDCConfigurationError("OIDC JWKS transport bounds must be positive")
        self._url = jwks_url
        self._timeout = timeout
        self._max_bytes = max_bytes

    async def fetch_jwks(self, issuer: str) -> JsonObject:
        del issuer
        async with httpx.AsyncClient(follow_redirects=False, timeout=self._timeout) as client:
            response = await client.get(self._url, headers={"Accept": "application/json"})
        if response.status_code != 200:
            raise OIDCAuthenticationError("OIDC JWKS endpoint did not return HTTP 200")
        if len(response.content) > self._max_bytes:
            raise OIDCAuthenticationError("OIDC JWKS response exceeds configured size bound")
        media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type not in {"application/json", "application/jwk-set+json"}:
            raise OIDCAuthenticationError("OIDC JWKS response has an invalid content type")
        try:
            result = json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OIDCAuthenticationError("OIDC JWKS response is not valid JSON") from exc
        _validate_jwks(result)
        return dict(result)


class OIDCManager:
    """Verify OIDC JWTs using injected async JWKS I/O.

    A cache hit performs no transport operation. An unknown ``kid`` triggers exactly one
    forced JWKS refresh, which supports normal identity-provider key rotation without an
    unbounded retry path.
    """

    def __init__(
        self,
        config: OIDCConfig,
        transport: AsyncJWKSTransport | Callable[[str], Awaitable[JsonObject]],
        cache: AsyncJWKSCache | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self._transport = transport
        self._cache = cache or InMemoryJWKSCache()
        self._clock = clock
        self._refresh_lock = asyncio.Lock()
        self._refresh_clock = time.monotonic
        self._last_refresh = float("-inf")

    async def authenticate(self, token: str) -> Principal:
        """Authenticate *token* and return an immutable tenant principal."""

        if not isinstance(token, str) or not token:
            raise OIDCAuthenticationError("OIDC token is required")
        jwt = _load_pyjwt()
        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise OIDCAuthenticationError("OIDC token has an invalid JOSE header") from exc
        kid = header.get("kid")
        algorithm = header.get("alg")
        if not isinstance(kid, str) or not kid:
            raise OIDCAuthenticationError("OIDC token header must contain a non-empty kid")
        if not isinstance(algorithm, str) or algorithm not in self.config.algorithms:
            raise OIDCAuthenticationError("OIDC token uses an unapproved algorithm")

        jwks = await self._cache.get(self.config.issuer)
        if jwks is None:
            jwks = await self._refresh(force=False)
        jwk = _find_jwk(jwks, kid)
        if jwk is None:
            jwks = await self._refresh(force=True)
            jwk = _find_jwk(jwks, kid)
        if jwk is None:
            raise OIDCAuthenticationError("OIDC signing key is unknown after JWKS refresh")
        key_algorithm = jwk.get("alg")
        if key_algorithm is not None and key_algorithm != algorithm:
            raise OIDCAuthenticationError("OIDC signing key algorithm does not match token")
        if jwk.get("use") not in (None, "sig"):
            raise OIDCAuthenticationError("OIDC key is not authorized for signatures")

        required = ["iss", "aud", "sub", "exp"]
        if self.config.require_iat:
            required.append("iat")
        try:
            claims = self._decode(jwt, token, jwk, algorithm, required)
        except Exception as first_error:
            refreshed = await self._refresh(force=True, allow_immediate=True)
            refreshed_jwk = _find_jwk(refreshed, kid)
            if refreshed_jwk is None:
                raise OIDCAuthenticationError(
                    "OIDC signing key is unknown after JWKS refresh"
                ) from first_error
            try:
                claims = self._decode(jwt, token, refreshed_jwk, algorithm, required)
            except Exception as exc:
                raise OIDCAuthenticationError("OIDC token signature or claims are invalid") from exc
        self._validate_exact_claims(claims)
        return self._principal_from_claims(claims, kid)

    async def verify(self, token: str) -> Principal:
        """Alias for :meth:`authenticate`."""

        return await self.authenticate(token)

    async def verify_token(self, token: str) -> Principal:
        """Alias for :meth:`authenticate`."""

        return await self.authenticate(token)

    def _decode(
        self,
        jwt: Any,
        token: str,
        jwk: Mapping[str, object],
        algorithm: str,
        required: list[str],
    ) -> dict[str, Any]:
        key = jwt.PyJWK.from_dict(dict(jwk), algorithm=algorithm).key
        return cast(
            dict[str, Any],
            jwt.decode(
                token,
                key=key,
                algorithms=[algorithm],
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.leeway_seconds,
                options={
                    "require": required,
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            ),
        )

    async def _refresh(self, *, force: bool, allow_immediate: bool = False) -> JsonObject:
        async with self._refresh_lock:
            cached = await self._cache.get(self.config.issuer)
            if not force and cached is not None:
                return cached
            now = self._refresh_clock()
            if (
                force
                and not allow_immediate
                and cached is not None
                and now - self._last_refresh < 1.0
            ):
                return cached
            try:
                transport = self._transport
                if isinstance(transport, AsyncJWKSTransport):
                    result = await transport.fetch_jwks(self.config.issuer)
                else:
                    result = await transport(self.config.issuer)
            except Exception as exc:
                raise OIDCAuthenticationError("OIDC JWKS retrieval failed") from exc
            _validate_jwks(result)
            copied: JsonObject = dict(result)
            await self._cache.set(self.config.issuer, copied)
            self._last_refresh = now
            return copied

    def _validate_exact_claims(self, claims: Mapping[str, object]) -> None:
        if claims.get("iss") != self.config.issuer:
            raise OIDCAuthenticationError("OIDC issuer claim does not exactly match")
        audience = claims.get("aud")
        if isinstance(audience, str):
            audience_matches = audience == self.config.audience
        elif isinstance(audience, Sequence):
            audience_matches = self.config.audience in audience and all(
                isinstance(item, str) for item in audience
            )
        else:
            audience_matches = False
        if not audience_matches:
            raise OIDCAuthenticationError("OIDC audience claim does not exactly match")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise OIDCAuthenticationError("OIDC subject claim must be a non-empty string")
        now = self._clock()
        for name in ("exp", "iat", "nbf"):
            value = claims.get(name)
            if value is None and name == "nbf":
                continue
            if value is None and name == "iat" and not self.config.require_iat:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise OIDCAuthenticationError(f"OIDC {name} claim must be a NumericDate")
        expiration = claims.get("exp")
        issued_at = claims.get("iat")
        not_before = claims.get("nbf")
        if not isinstance(expiration, (int, float)) or isinstance(expiration, bool):
            raise OIDCAuthenticationError("OIDC exp claim must be a NumericDate")
        if expiration <= now - self.config.leeway_seconds:
            raise OIDCAuthenticationError("OIDC token has expired")
        if (
            isinstance(issued_at, (int, float))
            and not isinstance(issued_at, bool)
            and issued_at > now + self.config.leeway_seconds
        ):
            raise OIDCAuthenticationError("OIDC token was issued in the future")
        if (
            isinstance(not_before, (int, float))
            and not isinstance(not_before, bool)
            and not_before > now + self.config.leeway_seconds
        ):
            raise OIDCAuthenticationError("OIDC token is not yet valid")

    def _principal_from_claims(self, claims: Mapping[str, object], kid: str) -> Principal:
        tenant = claims.get(self.config.tenant_claim)
        if not isinstance(tenant, str) or not tenant.strip():
            raise OIDCAuthenticationError("OIDC tenant claim must be a non-empty string")
        raw_roles = claims.get(self.config.roles_claim, ())
        if isinstance(raw_roles, str):
            role_values: Sequence[object] = raw_roles.split()
        elif isinstance(raw_roles, Sequence):
            role_values = raw_roles
        else:
            raise OIDCAuthenticationError("OIDC roles claim must be a string or array")
        try:
            roles = frozenset(Role(value) for value in role_values if isinstance(value, str))
        except ValueError as exc:
            raise OIDCAuthenticationError("OIDC roles claim contains an unsupported role") from exc
        if len(roles) != len(role_values):
            raise OIDCAuthenticationError("OIDC roles claim contains a non-string role")
        return Principal(
            subject=str(claims["sub"]),
            tenant_id=tenant,
            roles=roles,
            auth_method="oidc",
            credential_id=f"oidc:{kid}:{claims['sub']}",
            attributes={"issuer": self.config.issuer},
        )


def _load_pyjwt() -> Any:
    try:
        import jwt
    except ImportError as exc:
        raise OIDCDependencyError(
            "OIDC JWT verification requires PyJWT with cryptographic support; "
            "install it with `pip install 'PyJWT[crypto]>=2.8'`."
        ) from exc
    return jwt


def _validate_jwks(jwks: object) -> None:
    if not isinstance(jwks, Mapping):
        raise OIDCAuthenticationError("OIDC JWKS response must be an object")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not all(isinstance(key, Mapping) for key in keys):
        raise OIDCAuthenticationError("OIDC JWKS response must contain a keys array")
    kids = [key.get("kid") for key in keys]
    if any(not isinstance(kid, str) or not kid for kid in kids):
        raise OIDCAuthenticationError("every OIDC JWK must contain a non-empty kid")
    if len(set(kids)) != len(kids):
        raise OIDCAuthenticationError("OIDC JWKS contains duplicate kid values")


def _find_jwk(jwks: JsonObject, kid: str) -> Mapping[str, object] | None:
    _validate_jwks(jwks)
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        return None
    for key in keys:
        if isinstance(key, Mapping) and key.get("kid") == kid:
            return {str(name): value for name, value in key.items()}
    return None


__all__ = [
    "AsyncJWKSCache",
    "AsyncJWKSTransport",
    "HTTPXJWKSTransport",
    "InMemoryJWKSCache",
    "OIDCAuthenticationError",
    "OIDCConfig",
    "OIDCConfigurationError",
    "OIDCDependencyError",
    "OIDCError",
    "OIDCManager",
]
