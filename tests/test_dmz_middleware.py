# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.proxy.dmz_middleware — DMZ-mode source-IP allowlist."""

from __future__ import annotations

import ipaddress

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegis.proxy.dmz_middleware import DMZSourceIPMiddleware, _ip_in_networks

# ── Helper ────────────────────────────────────────────────────────────────────


def _parse(entries: list[str]) -> list:
    return [ipaddress.ip_network(e, strict=False) for e in entries]


def _app_with_dmz(allowed: list[str], trust_proxy: bool = False) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        DMZSourceIPMiddleware,
        allowed_networks=_parse(allowed),
        trust_proxy_headers=trust_proxy,
    )

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    return app


# ── _ip_in_networks unit tests ────────────────────────────────────────────────


class TestIpInNetworks:
    def test_exact_match(self):
        nets = _parse(["10.0.0.1"])
        assert _ip_in_networks("10.0.0.1", nets) is True

    def test_no_match(self):
        nets = _parse(["10.0.0.1"])
        assert _ip_in_networks("10.0.0.2", nets) is False

    def test_cidr_match(self):
        nets = _parse(["10.0.0.0/24"])
        assert _ip_in_networks("10.0.0.200", nets) is True

    def test_cidr_no_match(self):
        nets = _parse(["10.0.0.0/24"])
        assert _ip_in_networks("10.0.1.1", nets) is False

    def test_ipv6_loopback(self):
        nets = _parse(["::1"])
        assert _ip_in_networks("::1", nets) is True

    def test_ipv6_cidr(self):
        nets = _parse(["fd00::/8"])
        assert _ip_in_networks("fd12:3456:789a::1", nets) is True

    def test_multiple_networks_first_matches(self):
        nets = _parse(["192.168.1.0/24", "10.0.0.0/8"])
        assert _ip_in_networks("10.5.6.7", nets) is True

    def test_invalid_ip_returns_false(self):
        nets = _parse(["10.0.0.0/24"])
        assert _ip_in_networks("not-an-ip", nets) is False

    def test_empty_networks_always_false(self):
        assert _ip_in_networks("1.2.3.4", []) is False

    def test_loopback_127_in_subnet(self):
        nets = _parse(["127.0.0.0/8"])
        assert _ip_in_networks("127.0.0.1", nets) is True


# ── DMZ disabled (empty allowlist) ───────────────────────────────────────────


class TestDMZDisabled:
    def test_no_allowlist_allows_all(self):
        app = FastAPI()
        app.add_middleware(
            DMZSourceIPMiddleware,
            allowed_networks=[],
        )

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        client = TestClient(app)
        resp = client.get("/ping")
        assert resp.status_code == 200

    def test_empty_allowlist_allows_arbitrary_ip(self):
        app = FastAPI()
        app.add_middleware(DMZSourceIPMiddleware, allowed_networks=[])

        @app.get("/ping")
        async def ping():
            return {"ok": True}

        client = TestClient(app, headers={"X-Real-IP": "1.2.3.4"})
        resp = client.get("/ping")
        assert resp.status_code == 200


# ── DMZ enabled — via trust-proxy header (standard test-client path) ──────────


class TestDMZEnabled:
    def test_allowed_ip_via_xff_returns_200(self):
        # Inject client IP via X-Forwarded-For (trust_proxy=True)
        app = _app_with_dmz(["10.0.0.0/24"], trust_proxy=True)
        client = TestClient(app)
        resp = client.get("/ping", headers={"X-Forwarded-For": "10.0.0.5"})
        assert resp.status_code == 200

    def test_disallowed_ip_via_xff_gets_403(self):
        app = _app_with_dmz(["10.0.0.0/24"], trust_proxy=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/ping", headers={"X-Forwarded-For": "9.9.9.9"})
        assert resp.status_code == 403

    def test_disallowed_tcp_peer_gets_403(self):
        # TestClient peer address is "testclient" which is not a valid IP → rejected
        app = _app_with_dmz(["10.0.0.0/24"])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/ping")
        assert resp.status_code == 403

    def test_403_response_has_detail_field(self):
        app = _app_with_dmz(["10.0.0.0/24"])
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/ping")
        assert "detail" in resp.json()

    def test_403_body_does_not_reveal_allowlist_entry(self):
        app = _app_with_dmz(["10.0.0.1"], trust_proxy=True)
        client = TestClient(app, raise_server_exceptions=False)
        body = client.get("/ping", headers={"X-Forwarded-For": "9.9.9.9"}).text
        assert "10.0.0.1" not in body

    def test_multiple_endpoints_all_filtered(self):
        app = FastAPI()
        app.add_middleware(DMZSourceIPMiddleware, allowed_networks=_parse(["10.0.0.0/8"]))

        @app.get("/a")
        async def a():
            return {}

        @app.get("/b")
        async def b():
            return {}

        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/a").status_code == 403
        assert client.get("/b").status_code == 403


# ── Trust-proxy-header mode ───────────────────────────────────────────────────


class TestTrustProxyHeaders:
    def test_xff_allowed(self):
        app = _app_with_dmz(["10.1.2.0/24"], trust_proxy=True)
        client = TestClient(app)
        resp = client.get("/ping", headers={"X-Forwarded-For": "10.1.2.5"})
        assert resp.status_code == 200

    def test_xff_disallowed(self):
        app = _app_with_dmz(["10.1.2.0/24"], trust_proxy=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/ping", headers={"X-Forwarded-For": "1.2.3.4"})
        assert resp.status_code == 403

    def test_xff_uses_leftmost_ip(self):
        # "real client, trusted proxy1, trusted proxy2" — leftmost is the real IP
        app = _app_with_dmz(["10.0.0.0/24"], trust_proxy=True)
        client = TestClient(app)
        resp = client.get("/ping", headers={"X-Forwarded-For": "10.0.0.5, 172.16.0.1"})
        assert resp.status_code == 200

    def test_x_real_ip_fallback(self):
        app = _app_with_dmz(["10.0.0.0/24"], trust_proxy=True)
        client = TestClient(app)
        resp = client.get("/ping", headers={"X-Real-IP": "10.0.0.9"})
        assert resp.status_code == 200

    def test_x_real_ip_disallowed(self):
        app = _app_with_dmz(["10.0.0.0/24"], trust_proxy=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/ping", headers={"X-Real-IP": "5.6.7.8"})
        assert resp.status_code == 403

    def test_xff_takes_precedence_over_x_real_ip(self):
        # XFF is checked first; 10.5.6.7 is not in 10.0.0.0/24 → 403
        app = _app_with_dmz(["10.0.0.0/24"], trust_proxy=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(
            "/ping",
            headers={"X-Forwarded-For": "10.5.6.7", "X-Real-IP": "10.0.0.1"},
        )
        assert resp.status_code == 403

    def test_no_proxy_headers_falls_back_to_peer_which_fails(self):
        # trust_proxy=True but no headers → falls back to TCP peer ("testclient"
        # in httpx TestClient — not a valid IP → rejected)
        app = _app_with_dmz(["127.0.0.0/8", "::1"], trust_proxy=True)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/ping")
        assert resp.status_code == 403


# ── Config integration ────────────────────────────────────────────────────────


class TestConfigIntegration:
    def test_get_dmz_networks_empty_string(self):
        from aegis.config import AegisSettings

        s = AegisSettings(dmz_allowed_source_ips="")
        assert s.get_dmz_networks() == []

    def test_get_dmz_networks_single_ip(self):
        from aegis.config import AegisSettings

        s = AegisSettings(dmz_allowed_source_ips="10.0.0.1")
        nets = s.get_dmz_networks()
        assert len(nets) == 1
        assert ipaddress.ip_address("10.0.0.1") in nets[0]

    def test_get_dmz_networks_cidr(self):
        from aegis.config import AegisSettings

        s = AegisSettings(dmz_allowed_source_ips="10.0.0.0/24")
        nets = s.get_dmz_networks()
        assert len(nets) == 1
        assert ipaddress.ip_address("10.0.0.99") in nets[0]

    def test_get_dmz_networks_multiple(self):
        from aegis.config import AegisSettings

        s = AegisSettings(dmz_allowed_source_ips="10.0.0.0/24, 192.168.1.0/24")
        nets = s.get_dmz_networks()
        assert len(nets) == 2

    def test_get_dmz_networks_invalid_raises(self):
        from aegis.config import AegisSettings

        s = AegisSettings(dmz_allowed_source_ips="not-an-ip")
        with pytest.raises(ValueError, match="invalid address or network"):
            s.get_dmz_networks()

    def test_trust_proxy_headers_default_false(self):
        from aegis.config import AegisSettings

        s = AegisSettings()
        assert s.dmz_trust_proxy_headers is False

    def test_dmz_disabled_by_default(self):
        from aegis.config import AegisSettings

        s = AegisSettings()
        assert s.dmz_allowed_source_ips == ""
        assert s.get_dmz_networks() == []


# ── Logging ───────────────────────────────────────────────────────────────────


class TestLogging:
    def test_rejected_request_logs_warning(self, caplog):
        import logging

        app = _app_with_dmz(["10.0.0.0/24"])
        client = TestClient(app, raise_server_exceptions=False)
        with caplog.at_level(logging.WARNING, logger="aegis.proxy.dmz_middleware"):
            client.get("/ping")
        assert any("rejected" in r.message for r in caplog.records)

    def test_allowed_request_no_warning(self, caplog):
        import logging

        app = _app_with_dmz(["10.0.0.0/24"], trust_proxy=True)
        client = TestClient(app)
        with caplog.at_level(logging.WARNING, logger="aegis.proxy.dmz_middleware"):
            client.get("/ping", headers={"X-Forwarded-For": "10.0.0.5"})
        assert not any("rejected" in r.message for r in caplog.records)
