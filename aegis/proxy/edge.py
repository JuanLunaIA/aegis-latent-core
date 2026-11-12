"""Rechaza tráfico que no venga de CloudFront.

Segunda barrera del gateway: el security group sólo admite el prefijo
``com.amazonaws.global.cloudfront.origin-facing`` y este middleware exige el
secreto compartido que CloudFront añade como cabecera personalizada.

``/health`` y ``/ready`` quedan exentos (los consume el balanceador y el propio
borde). ``/metrics`` no se exime: sólo se sirve a loopback, y a cualquier otro
origen se le responde 404 — no 403 — para no revelar que el endpoint existe.
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
    """Exige ``x-aegis-edge: <secreto>`` en todo lo que no sea sonda de salud."""

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
        # Comparación en tiempo constante. Un secreto vacío nunca autentica: el
        # middleware no se registra sin secreto, pero si se construyera a mano
        # con "" fallaría cerrado en vez de aceptar cualquier cabecera ausente.
        if not self._secret or not hmac.compare_digest(supplied, self._secret):
            return JSONResponse({"detail": "edge authentication required"}, status_code=403)
        return await call_next(request)


def install_edge_middleware(app: ASGIApp, secret: str) -> bool:
    """Registra el middleware sólo si hay secreto. Devuelve si quedó activo."""
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
