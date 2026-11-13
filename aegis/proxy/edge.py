"""Reject traffic that does not come from CloudFront.

The gateway's second barrier: the security group only admits the
``com.amazonaws.global.cloudfront.origin-facing`` prefix, and this middleware
requires the shared secret CloudFront adds as a custom header.

``/health`` and ``/ready`` are exempt (the load balancer and the edge itself use
them). ``/metrics`` is not exempt: it is served to loopback only, and any other
origin gets 404, not 403, so the endpoint's existence is not revealed.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
from __future__ import annotations

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

EXEMPT_PATHS = frozenset({"/health", "/ready"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
METRICS_PATH = "/metrics"


class EdgeSecretMiddleware(BaseHTTPMiddleware):
    """Require ``x-aegis-edge: <secret>`` on everything except health probes."""

    def __init__(self, app: ASGIApp, secret: str, header: str = "x-aegis-edge") -> None:
        super().__init__(app)
        self._secret = secret.encode("utf-8")
        self._header = header.lower()

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        path = request.url.path
        if path in EXEMPT_PATHS:
            return await call_next(request)
        if path == METRICS_PATH:
            client = request.client.host if request.client else ""
            if client in LOOPBACK_HOSTS:
                return await call_next(request)
            return JSONResponse({"detail": "not found"}, status_code=404)
        supplied = request.headers.get(self._header, "").encode("utf-8")
        # Constant-time comparison. An empty secret never authenticates: the
        # middleware is not registered without a secret, but if it were built by
        # hand with "" it fails closed instead of accepting a missing header.
        if not self._secret or not hmac.compare_digest(supplied, self._secret):
            return JSONResponse({"detail": "edge authentication required"}, status_code=403)
        return await call_next(request)


def install_edge_middleware(app: ASGIApp, secret: str) -> bool:
    """Register the middleware only when a secret is set. Return whether it is active."""
    if not secret:
        return False
    app.add_middleware(EdgeSecretMiddleware, secret=secret)  # type: ignore[attr-defined]
    return True


__all__ = [
    "EXEMPT_PATHS",
    "LOOPBACK_HOSTS",
    "METRICS_PATH",
    "EdgeSecretMiddleware",
    "install_edge_middleware",
]
