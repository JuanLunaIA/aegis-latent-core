# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.proxy.dmz_middleware — DMZ-mode source-IP allowlist middleware.

When ``AEGIS_DMZ_ALLOWED_SOURCE_IPS`` is non-empty, every inbound request whose
client IP is **not** in the allowlist is rejected with ``403 Forbidden`` before
any authentication is attempted.  This implements the OT-sector DMZ requirement
(IEC 62443-3-3): the proxy only accepts traffic from explicitly enumerated source
networks.

Allowlist entries are parsed once at startup and may be:
- Exact IPv4 or IPv6 addresses: ``10.0.0.5``, ``::1``
- CIDR networks: ``10.0.0.0/24``, ``192.168.1.0/24``, ``fd00::/8``

Client IP resolution:
- Default: ``request.client.host`` (TCP connection peer address).
- When ``dmz_trust_proxy_headers=True``: reads the leftmost (originating) IP
  from ``X-Forwarded-For``, falling back to ``X-Real-IP``, then the TCP peer.
  Only enable this behind a trusted reverse proxy — in internet-facing scenarios
  it allows client IP spoofing.

The middleware emits a ``WARNING`` log on every rejected request and returns a
deliberately terse body to avoid leaking network topology to unauthenticated
callers.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


def _resolve_client_ip(request: Request, trust_proxy: bool) -> str:
    """Extract the effective client IP from *request*.

    Parameters
    ----------
    request:
        The incoming HTTP request.
    trust_proxy:
        When True, read ``X-Forwarded-For`` / ``X-Real-IP`` before the TCP peer.

    Returns
    -------
    str
        An IP address string, or ``"unknown"`` when unavailable.
    """
    if trust_proxy:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            # Leftmost entry is the originating client IP
            candidate = xff.split(",")[0].strip()
            if candidate:
                return candidate
        xri = request.headers.get("x-real-ip", "").strip()
        if xri:
            return xri

    if request.client:
        return request.client.host
    return "unknown"


def _ip_in_networks(ip_str: str, networks: list[Any]) -> bool:
    """Return True if *ip_str* is contained in any network in *networks*."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in networks)


class DMZSourceIPMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces a source-IP allowlist in DMZ mode.

    Parameters
    ----------
    app:
        The wrapped ASGI application.
    allowed_networks:
        Pre-parsed list of :class:`ipaddress.IPv4Network` or
        :class:`ipaddress.IPv6Network` objects.  If empty, all IPs are allowed
        (DMZ mode disabled).
    trust_proxy_headers:
        Honour ``X-Forwarded-For`` / ``X-Real-IP`` for client IP resolution.
    """

    def __init__(
        self,
        app: ASGIApp,
        allowed_networks: list[Any],
        trust_proxy_headers: bool = False,
    ) -> None:
        super().__init__(app)
        self._networks = allowed_networks
        self._trust_proxy = trust_proxy_headers

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        if not self._networks:
            return await call_next(request)

        client_ip = _resolve_client_ip(request, self._trust_proxy)

        if not _ip_in_networks(client_ip, self._networks):
            logger.warning(
                "DMZ: rejected request from %s — not in allowed source IP list",
                client_ip,
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Forbidden: source IP not in allowlist"},
            )

        return await call_next(request)
