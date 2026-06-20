"""
aegis.auth.apikey — Constant-time API key authentication for FastAPI.

Security properties:
  - hmac.compare_digest used for all key comparisons (timing-safe).
  - Missing Authorization header returns 401, not 403, to avoid enumeration.
  - Key set is a frozenset built at startup; hot-reload not supported by design.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from aegis.config import AegisSettings, get_settings

# Single shared bearer instance for the whole app
_bearer = HTTPBearer(auto_error=False)


def constant_time_key_in(key: str, valid_keys: frozenset[str]) -> bool:
    """Public wrapper for timing-safe key membership checks."""
    return _constant_time_in(key, valid_keys)


def _constant_time_in(key: str, valid_keys: frozenset[str]) -> bool:
    """Return True iff *key* is in *valid_keys* using constant-time comparisons.

    Iterates all keys to prevent early-exit timing attacks.  The overhead is
    O(N) where N = number of valid keys; acceptable for N < 10_000.
    """
    result = False
    for valid in valid_keys:
        match = hmac.compare_digest(key.encode(), valid.encode())
        result = result or match
    return result


class ProxyKeyAuth:
    """FastAPI dependency that validates proxy API keys."""

    def __init__(self, settings: AegisSettings) -> None:
        self._keys = settings.get_api_keys()
        self._disabled = settings.auth_disabled

    async def validate_request(self, request: Request) -> str:
        """Validate request using the shared _bearer security scheme."""
        # Manually resolve the bearer credentials from the request
        # This avoids the 422 issues often seen with nested Security() calls in closures
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            credentials = None
        elif auth_header.startswith("Bearer "):
            credentials = HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials=auth_header[7:],
            )
        else:
            credentials = None

        return self.__call__(credentials)

    def __call__(
        self,
        credentials: HTTPAuthorizationCredentials | None,
    ) -> str:
        if self._disabled:
            return "auth-disabled"
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not self._keys:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="No API keys configured on server; authentication impossible.",
            )
        if not _constant_time_in(credentials.credentials, self._keys):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return credentials.credentials


class AuditKeyAuth:
    """FastAPI dependency that validates audit-read API keys."""

    def __init__(self, settings: AegisSettings) -> None:
        self._keys = settings.get_audit_api_keys()
        self._disabled = settings.auth_disabled

    async def validate_request(self, request: Request) -> str:
        """Validate request using the shared _bearer security scheme."""
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            credentials = None
        elif auth_header.startswith("Bearer "):
            credentials = HTTPAuthorizationCredentials(
                scheme="Bearer",
                credentials=auth_header[7:],
            )
        else:
            credentials = None

        return self.__call__(credentials)

    def __call__(
        self,
        credentials: HTTPAuthorizationCredentials | None,
    ) -> str:
        if self._disabled:
            return "auth-disabled"
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not _constant_time_in(credentials.credentials, self._keys):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid audit API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return credentials.credentials


def build_proxy_auth(settings: AegisSettings | None = None) -> ProxyKeyAuth:
    s = settings or get_settings()
    return ProxyKeyAuth(s)


def build_audit_auth(settings: AegisSettings | None = None) -> AuditKeyAuth:
    s = settings or get_settings()
    return AuditKeyAuth(s)
