# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Read-only status queries against a running gateway's ``/v1/audit`` API.

Stdlib-only. The answer is the gateway's own report about itself: it says what
that gateway claims about its retained window, not that the claim is true. To
check evidence independently, export a bundle and use
:func:`aegis_sdk.bundle.verify_bundle`.

Three refusals are deliberate:

* **No credential over plain HTTP to another host.** The audit key is a bearer
  token; sending it unencrypted anywhere but loopback hands it to the network.
* **No redirects.** ``urllib`` re-sends ``Authorization`` to wherever a
  redirect points, so following one would let the first host choose who
  receives the key.
* **No unbounded or non-JSON response.** The body is capped and must be a JSON
  object, so a misbehaving endpoint cannot make the caller buffer without end.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from aegis_sdk._config import normalize_gateway_url

DEFAULT_API_KEY_ENV = "AEGIS_AUDIT_API_KEY"
MAX_RESPONSE_BYTES = 1024 * 1024


class GatewayAuditError(RuntimeError):
    """The gateway could not be queried, refused the query, or answered badly."""


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        raise GatewayAuditError(
            f"gateway answered HTTP {code} redirect to {newurl!r}; redirects are not followed "
            "so the audit key is never re-sent to another location"
        )


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def audit_url(gateway_url: str, endpoint: str) -> str:
    """``https://gw`` or ``https://gw/v1`` → ``https://gw/v1/audit/<endpoint>``."""
    base = normalize_gateway_url(gateway_url, openai=False)
    if not base.rstrip("/").endswith("/v1"):
        base += "v1/"
    return f"{base}audit/{endpoint}"


def _get_json(
    opener: urllib.request.OpenerDirector, url: str, api_key: str | None, timeout: float
) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if api_key is not None:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 - scheme checked by the caller
    try:
        with opener.open(request, timeout=timeout) as response:
            content_type = response.headers.get_content_type()
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise GatewayAuditError(f"{url}: HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise GatewayAuditError(f"{url}: {exc}") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise GatewayAuditError(f"{url}: response exceeds {MAX_RESPONSE_BYTES} bytes")
    if content_type != "application/json":
        raise GatewayAuditError(f"{url}: expected application/json, got {content_type!r}")
    try:
        value = json.loads(body)
    except ValueError as exc:
        raise GatewayAuditError(f"{url}: response is not JSON") from exc
    if not isinstance(value, dict):
        raise GatewayAuditError(f"{url}: response is not a JSON object")
    return value


def fetch_audit_status(
    gateway_url: str,
    *,
    api_key: str | None,
    include_integrity: bool = False,
    timeout: float = 10.0,
    opener: urllib.request.OpenerDirector | None = None,
) -> dict[str, Any]:
    """Return ``{"gateway", "health", "integrity"}`` from the gateway's audit API.

    ``integrity`` is ``None`` unless requested; the gateway documents
    ``/audit/integrity`` as O(N) over its retained window.
    """
    parsed = urlsplit(gateway_url.strip())
    if parsed.scheme == "http" and api_key is not None and not _is_loopback(parsed.hostname or ""):
        raise GatewayAuditError(
            "refusing to send the audit key over plain HTTP to a non-loopback host; use https://"
        )
    if timeout <= 0:
        raise GatewayAuditError("timeout must be positive")
    active = opener or urllib.request.build_opener(_RefuseRedirects())
    health_url = audit_url(gateway_url, "health")
    report: dict[str, Any] = {
        "gateway": health_url[: -len("audit/health")],
        "health": _get_json(active, health_url, api_key, timeout),
        "integrity": None,
    }
    if include_integrity:
        report["integrity"] = _get_json(
            active, audit_url(gateway_url, "integrity"), api_key, timeout
        )
    return report


def is_healthy(report: dict[str, Any]) -> bool:
    """``True`` when the gateway reports ``status == "ok"`` and, if asked, ``valid``."""
    health = report.get("health")
    if not isinstance(health, dict) or health.get("status") != "ok":
        return False
    integrity = report.get("integrity")
    return integrity is None or (isinstance(integrity, dict) and integrity.get("valid") is True)
