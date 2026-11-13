"""Resolve the organisation from the Host, without trusting the client.

``Host`` is the default source. Behind CloudFront, the edge function copies the
visitor's host into ``X-Aegis-Host``, and the gateway accepts it only when the
edge secret is valid (``EdgeSecretMiddleware``); that is why resolution prefers
``X-Aegis-Host`` over the origin ``Host``.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
from __future__ import annotations

import re

# Same vocabulary as the organisation slug (T1.8): lowercase, digits and inner
# hyphens. A dot, an underscore or a trailing hyphen is not a tenant.
_SLUG = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

TENANT_HOST = re.compile(rf"^(?P<slug>{_SLUG})\.api\.aegislatent\.com$")
# No path form: the gateway has no ``/o/<slug>/...`` routes, so a path-based
# tenant would only ever resolve for a request that then answers 404. The path
# argument is kept so callers do not change; it no longer selects a tenant.

# A trailing port is dropped before comparing; an IPv6 literal is not a tenant
# and must not be mistaken for "host:port".
_PORT_SUFFIX = re.compile(r":\d{1,5}$")


class TenantMismatch(ValueError):  # noqa: N818 - name fixed by the 5.1.0 API
    """The host and the authenticated key do not identify the same organisation."""


def normalize_host(host: str) -> str:
    """Lowercase, no surrounding spaces, no trailing port."""
    value = (host or "").strip().lower()
    if value.startswith("["):  # IPv6 literal: not a tenant host
        return value
    return _PORT_SUFFIX.sub("", value)


def tenant_from_request(host: str, path: str, principal_tenant: str | None) -> str:
    """Return the slug of the organisation the request belongs to.

    - ``acme.api.aegislatent.com`` → ``acme``
    - No tenant host → the key's tenant, if it has one. ``path`` is ignored.

    Raises:
        TenantMismatch: there is no tenant host and the key has no tenant, or
            the host contradicts the authenticated key's tenant.
    """
    del path  # see the note on TENANT_HOST: no path form in 5.1.0
    match = TENANT_HOST.match(normalize_host(host))
    if match is None:
        if principal_tenant:
            return principal_tenant
        raise TenantMismatch("no tenant in host and key has no tenant")
    slug = match.group("slug")
    if principal_tenant and principal_tenant != slug:
        raise TenantMismatch("key tenant does not match request host")
    return slug


def tenant_from_headers(
    host_header: str,
    x_aegis_host: str,
    path: str,
    principal_tenant: str | None,
) -> str:
    """Resolve the tenant, preferring ``X-Aegis-Host`` (written by the edge).

    ``X-Aegis-Host`` is acceptable only because the edge middleware rejects any
    request without the shared secret; without it, a client could pick its own
    tenant with a header.
    """
    host = (x_aegis_host or "").strip() or host_header
    return tenant_from_request(host, path, principal_tenant)


__all__ = [
    "TENANT_HOST",
    "TenantMismatch",
    "normalize_host",
    "tenant_from_headers",
    "tenant_from_request",
]
