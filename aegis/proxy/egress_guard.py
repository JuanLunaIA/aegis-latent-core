# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.proxy.egress_guard — Application-layer egress enforcement for air-gapped zones.

When AEGIS_AIRGAP_MODE=true, this module intercepts all outbound HTTP requests
made by the proxy and blocks any that are not destined for an explicitly allowed
host.  This provides an application-layer network zone enforcement mechanism
that complements (but does not replace) kernel-level network namespaces or
iptables rules.

The guard patches httpx's transport layer so every HTTPX request is validated
before the TCP connection is established.  Requests to non-allowed hosts raise
EgressBlockedError, which the proxy translates to a 502 Bad Gateway response
(the upstream is not reachable from this zone).

Configuration
-------------
AEGIS_AIRGAP_MODE             true | false (default: false)
AEGIS_AIRGAP_ALLOWED_HOSTS    Comma-separated list of allowed hostnames/IPs.
                               Ports may be included (host:port).  An empty
                               value allows nothing when airgap mode is active.

The upstream host from AegisSettings.upstream_url is always automatically
included in the allowlist when airgap mode is active.

Example
-------
AEGIS_AIRGAP_MODE=true
AEGIS_AIRGAP_ALLOWED_HOSTS=internal-llm.corp.example.com,10.0.0.5:8080

Network security note
---------------------
This is an application-level control only.  For defense-in-depth in OT/ICS
environments, pair with:
  - Linux network namespaces (ip netns) isolating the proxy process
  - nftables/iptables OUTPUT chain rules on the host
  - Container network policies (Kubernetes NetworkPolicy)
"""

from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class EgressBlockedError(Exception):
    """Raised when an outbound connection is blocked by the egress guard."""


class EgressGuard:
    """Application-layer egress filter for air-gapped network zones.

    Parameters
    ----------
    allowed_hosts:
        Set of allowed destination host strings (``host`` or ``host:port``).
        Pass an empty set to block all outbound connections.
    enabled:
        When False, the guard is a no-op passthrough.
    """

    def __init__(self, allowed_hosts: set[str], *, enabled: bool = True) -> None:
        self._allowed = {self._canonical_allow_entry(h) for h in allowed_hosts if h.strip()}
        self._enabled = enabled

    @staticmethod
    def _canonical_allow_entry(entry: str) -> str:
        value = entry.strip().lower()
        if not value or "://" in value or any(ch in value for ch in "\r\n@/?#"):
            raise ValueError(f"invalid egress allowlist entry: {entry!r}")
        if value.startswith("["):
            end = value.find("]")
            if end < 0:
                raise ValueError(f"invalid IPv6 allowlist entry: {entry!r}")
            host = value[1:end]
            suffix = value[end + 1 :]
            if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
                raise ValueError(f"invalid IPv6 port entry: {entry!r}")
            ipaddress.ip_address(host)
            if suffix and not 1 <= int(suffix[1:]) <= 65535:
                raise ValueError(f"invalid port in allowlist entry: {entry!r}")
            return value
        if value.count(":") > 1:
            ipaddress.ip_address(value)
            return value
        if ":" in value:
            host, port = value.rsplit(":", 1)
            if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError(f"invalid port in allowlist entry: {entry!r}")
        return value

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset(self._allowed)

    def check(self, url: str) -> None:
        """Raise EgressBlockedError if *url* is not in the allowlist.

        Parameters
        ----------
        url:
            Absolute URL of the outbound request.
        """
        if not self._enabled:
            return

        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise EgressBlockedError("only http/https egress is permitted")
        if parsed.username is not None or parsed.password is not None:
            raise EgressBlockedError("userinfo in outbound URLs is forbidden")
        host = (parsed.hostname or "").lower()
        if not host:
            raise EgressBlockedError("outbound URL must include a hostname")
        try:
            port = parsed.port
        except ValueError as exc:
            raise EgressBlockedError("outbound URL contains an invalid port") from exc

        candidates = {host}
        if port:
            candidates.add(f"{host}:{port}")

        if candidates & self._allowed:
            return

        logger.warning(
            "EGRESS BLOCKED: airgap mode denied connection to %s (allowed: %s)",
            host,
            ", ".join(sorted(self._allowed)) or "<none>",
        )
        raise EgressBlockedError(
            f"Airgap mode: outbound connection to {host!r} is not in the "
            f"allowed-hosts list.  Add it to AEGIS_AIRGAP_ALLOWED_HOSTS."
        )

    def is_allowed(self, url: str) -> bool:
        """Return True if *url* passes the egress check, False if it would be blocked."""
        try:
            self.check(url)
            return True
        except EgressBlockedError:
            return False


# ── Factory ───────────────────────────────────────────────────────────────────


def build_egress_guard(
    airgap_mode: bool,
    allowed_hosts_csv: str,
    upstream_url: str = "",
) -> EgressGuard:
    """Build an EgressGuard from configuration values.

    Parameters
    ----------
    airgap_mode:
        When False, returns a disabled (passthrough) guard.
    allowed_hosts_csv:
        Comma-separated list of allowed host strings from config.
    upstream_url:
        The proxy's configured upstream URL.  Its hostname is automatically
        added to the allowlist so the proxy can always reach its upstream.
    """
    if not airgap_mode:
        return EgressGuard(set(), enabled=False)

    allowed: set[str] = set()
    for entry in allowed_hosts_csv.split(","):
        entry = entry.strip()
        if entry:
            allowed.add(EgressGuard._canonical_allow_entry(entry))

    # Always allow the configured upstream
    if upstream_url:
        parsed = urlparse(upstream_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("backend_url must be an absolute http/https URL with a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("backend_url must not contain URL userinfo")
        allowed.add(EgressGuard._canonical_allow_entry(parsed.hostname))
        if parsed.port:
            allowed.add(EgressGuard._canonical_allow_entry(f"{parsed.hostname}:{parsed.port}"))

    guard = EgressGuard(allowed, enabled=True)
    logger.info(
        "Airgap egress guard ACTIVE — allowed hosts: %s",
        ", ".join(sorted(guard.allowed_hosts)) or "<none>",
    )
    return guard
