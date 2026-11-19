# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""An Aegis Cloud key's subdomain label may differ from its organisation slug.

Before this, a hosted organisation whose API subdomain was not its slug got a
403 "Tenant mismatch" on every request through its own subdomain.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from aegis.auth.principal import Principal
from aegis.proxy.app import _request_tenant


def _request(host: str, x_aegis_host: str = "") -> Request:
    headers = [(b"host", host.encode())]
    if x_aegis_host:
        headers.append((b"x-aegis-host", x_aegis_host.encode()))
    return Request(
        {"type": "http", "method": "POST", "path": "/v1/chat/completions", "headers": headers}
    )


def _cloud(org_slug: str, endpoint: str) -> Principal:
    return Principal(
        subject="aegis-cloud:k1",
        tenant_id=org_slug,
        auth_method="aegis_cloud",
        attributes={"endpoint": endpoint},
    )


def test_subdomain_label_differs_from_slug_resolves_to_the_org_slug():
    req = _request("acme-prod.api.aegislatent.com")
    assert _request_tenant(req, _cloud("acme", "acme-prod")) == "acme"


def test_another_orgs_subdomain_is_still_rejected():
    req = _request("globex.api.aegislatent.com")
    with pytest.raises(HTTPException) as exc:
        _request_tenant(req, _cloud("acme", "acme-prod"))
    assert exc.value.status_code == 403


def test_the_org_slug_is_not_accepted_when_the_label_differs():
    req = _request("acme.api.aegislatent.com")
    with pytest.raises(HTTPException):
        _request_tenant(req, _cloud("acme", "acme-prod"))


def test_edge_header_is_checked_against_the_label():
    req = _request("origin.internal", x_aegis_host="acme-prod.api.aegislatent.com")
    assert _request_tenant(req, _cloud("acme", "acme-prod")) == "acme"


def test_no_tenant_host_falls_back_to_the_org_slug():
    req = _request("gateway.internal")
    assert _request_tenant(req, _cloud("acme", "acme-prod")) == "acme"


def test_without_an_endpoint_the_slug_is_compared_as_before():
    principal = Principal(subject="k", tenant_id="acme", auth_method="api_key")
    assert _request_tenant(_request("acme.api.aegislatent.com"), principal) == "acme"
    with pytest.raises(HTTPException):
        _request_tenant(_request("globex.api.aegislatent.com"), principal)
