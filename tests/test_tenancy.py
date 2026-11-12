# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Tenant resolution by Host or path, and refusal of cross-organisation requests."""

from __future__ import annotations

import pytest

from aegis.core.tenancy import (
    TenantMismatch,
    normalize_host,
    tenant_from_headers,
    tenant_from_request,
)


@pytest.mark.parametrize(
    ("host", "path", "principal", "expected"),
    [
        ("acme.api.aegislatent.com", "/v1/chat/completions", "acme", "acme"),
        ("acme.api.aegislatent.com", "/v1/chat/completions", None, "acme"),
        ("api.aegislatent.com", "/o/acme/v1/chat/completions", "acme", "acme"),
        ("api.aegislatent.com", "/v1/chat/completions", "legacy", "legacy"),
        # The Host port is not part of the slug.
        ("acme.api.aegislatent.com:443", "/v1/chat/completions", None, "acme"),
        # Some clients send the Host in uppercase.
        ("ACME.API.AEGISLATENT.COM", "/v1/chat/completions", None, "acme"),
        # The tenant path also works without a principal.
        ("api.aegislatent.com", "/o/acme/", None, "acme"),
        ("api.aegislatent.com", "/o/acme", None, "acme"),
        # A double slash does not change the resolved slug.
        ("api.aegislatent.com", "/o/acme//v1/x", None, "acme"),
    ],
)
def test_resolves(host: str, path: str, principal: str | None, expected: str) -> None:
    assert tenant_from_request(host, path, principal) == expected


def test_rejects_cross_tenant() -> None:
    with pytest.raises(TenantMismatch):
        tenant_from_request("acme.api.aegislatent.com", "/v1/x", "globex")


def test_rejects_cross_tenant_via_path() -> None:
    with pytest.raises(TenantMismatch):
        tenant_from_request("api.aegislatent.com", "/o/acme/v1/x", "globex")


def test_no_tenant_anywhere_is_an_error() -> None:
    with pytest.raises(TenantMismatch):
        tenant_from_request("api.aegislatent.com", "/v1/x", None)


def test_x_aegis_host_wins_over_origin_host() -> None:
    """CloudFront writes the visitor's host; the origin Host is the IP."""
    assert (
        tenant_from_headers(
            "54-211-93-10.sslip.io",
            "acme.api.aegislatent.com",
            "/v1/chat/completions",
            "acme",
        )
        == "acme"
    )


def test_x_aegis_host_absent_falls_back_to_host_header() -> None:
    assert tenant_from_headers("acme.api.aegislatent.com", "", "/v1/x", None) == "acme"


def test_x_aegis_host_still_rejects_cross_tenant() -> None:
    with pytest.raises(TenantMismatch):
        tenant_from_headers(
            "origin.api.aegislatent.com",
            "acme.api.aegislatent.com",
            "/v1/x",
            "globex",
        )


@pytest.mark.parametrize(
    "host",
    [
        "api.aegislatent.com",  # no slug
        "acme.api.aegislatent.com.evil.example",  # sufijo extra
        "-acme.api.aegislatent.com",  # guion inicial
        "acme-.api.aegislatent.com",  # guion final
        "ac. me.api.aegislatent.com",  # espacio
        "acme.api.aegislatent.com:notaport",  # non-numeric port
    ],
)
def test_non_tenant_hosts_do_not_match(host: str) -> None:
    assert tenant_from_request(host, "/v1/x", "principal-tenant") == "principal-tenant"


def test_punycode_is_out_of_scope_for_resolution() -> None:
    """The resolver applies the slug grammar; rejecting punycode belongs to
    organisation sign-up (T1.8), not to the gateway."""
    assert tenant_from_request("xn--acme-9ja.api.aegislatent.com", "/v1/x", None) == "xn--acme-9ja"


@pytest.mark.parametrize(
    "path",
    [
        "/o/ACME/v1/x",  # uppercase
        "/o/-acme/v1/x",
        "/o/acme-/v1/x",
        "/o/acme.evil/v1/x",
        "/o/",
        "/o",  # no slug: not a tenant path
    ],
)
def test_non_tenant_paths_do_not_match(path: str) -> None:
    assert tenant_from_request("api.aegislatent.com", path, "principal-tenant") == (
        "principal-tenant"
    )


def test_slug_max_length_boundary() -> None:
    slug_63 = "a" * 63
    assert tenant_from_request(f"{slug_63}.api.aegislatent.com", "/v1/x", None) == slug_63
    slug_64 = "a" * 64
    with pytest.raises(TenantMismatch):
        tenant_from_request(f"{slug_64}.api.aegislatent.com", "/v1/x", None)


def test_normalize_host_strips_port_but_not_ipv6() -> None:
    assert normalize_host(" Acme.API.aegislatent.com:8443 ") == "acme.api.aegislatent.com"
    assert normalize_host("[::1]:8443") == "[::1]:8443"
    assert normalize_host("") == ""
