"""Resuelve la organización desde el Host o el path, sin confiar en el cliente.

``Host`` es la fuente por defecto. Cuando el gateway está detrás de CloudFront,
la función de borde copia el host del visitante a ``X-Aegis-Host`` y el gateway
sólo lo acepta si el secreto de borde es válido (``EdgeSecretMiddleware``); por
eso la resolución prefiere ``X-Aegis-Host`` sobre el ``Host`` del origen.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
from __future__ import annotations

import re

# Mismo vocabulario que el slug de organización (T1.8): minúsculas, dígitos y
# guiones interiores. Un punto, un guion bajo o un guion final no son tenants.
_SLUG = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"

TENANT_HOST = re.compile(rf"^(?P<slug>{_SLUG})\.api\.aegislatent\.com$")
TENANT_PATH = re.compile(rf"^/o/(?P<slug>{_SLUG})(?:/|$)")

# Un puerto al final se descarta antes de comparar; un IPv6 literal no es un
# tenant y no debe confundirse con "host:puerto".
_PORT_SUFFIX = re.compile(r":\d{1,5}$")


class TenantMismatch(ValueError):  # noqa: N818 - name fixed by the 5.1.0 API
    """El host/path y la clave autenticada no identifican la misma organización."""


def normalize_host(host: str) -> str:
    """Minúsculas, sin espacios y sin puerto final."""
    value = (host or "").strip().lower()
    if value.startswith("["):  # IPv6 literal: no es un host de tenant
        return value
    return _PORT_SUFFIX.sub("", value)


def tenant_from_request(host: str, path: str, principal_tenant: str | None) -> str:
    """Devuelve el slug de la organización que corresponde a la petición.

    - ``acme.api.aegislatent.com`` → ``acme``
    - ``/o/acme/v1/...`` → ``acme``
    - Sin host ni path de tenant → el tenant de la clave, si existe.

    Raises:
        TenantMismatch: no hay tenant en host/path y la clave tampoco lo aporta,
            o el host/path contradicen el tenant de la clave autenticada.
    """
    host = normalize_host(host)
    match = TENANT_HOST.match(host)
    if match is None:
        match = TENANT_PATH.match(path or "")
    if match is None:
        if principal_tenant:
            return principal_tenant
        raise TenantMismatch("no tenant in host or path and key has no tenant")
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
    """Resuelve el tenant prefiriendo ``X-Aegis-Host`` (escrito por el borde).

    ``X-Aegis-Host`` es aceptable únicamente porque el middleware de borde
    rechaza cualquier petición que no traiga el secreto compartido; sin él, un
    cliente podría elegir su propio tenant con una cabecera.
    """
    host = (x_aegis_host or "").strip() or host_header
    return tenant_from_request(host, path, principal_tenant)


__all__ = [
    "TENANT_HOST",
    "TENANT_PATH",
    "TenantMismatch",
    "normalize_host",
    "tenant_from_headers",
    "tenant_from_request",
]
