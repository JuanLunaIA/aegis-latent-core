# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.proxy.egress_guard — air-gapped network zone enforcement."""

from __future__ import annotations

import pytest

from aegis.proxy.egress_guard import (
    EgressBlockedError,
    EgressGuard,
    build_egress_guard,
)

# ── EgressGuard.check() ───────────────────────────────────────────────────────


class TestEgressGuardCheck:
    def test_disabled_allows_anything(self):
        guard = EgressGuard(set(), enabled=False)
        guard.check("https://evil.example.com/v1/chat")  # must not raise

    def test_empty_allowlist_blocks_all(self):
        guard = EgressGuard(set(), enabled=True)
        with pytest.raises(EgressBlockedError):
            guard.check("https://any-host.example.com/path")

    def test_exact_hostname_allowed(self):
        guard = EgressGuard({"internal-llm.corp.example.com"})
        guard.check("https://internal-llm.corp.example.com/v1/chat")  # must not raise

    def test_exact_hostname_blocked(self):
        guard = EgressGuard({"allowed.example.com"})
        with pytest.raises(EgressBlockedError):
            guard.check("https://blocked.example.com/v1/chat")

    def test_host_with_port_allowed(self):
        guard = EgressGuard({"10.0.0.5:8080"})
        guard.check("https://10.0.0.5:8080/v1/chat")

    def test_host_without_port_not_matched_by_host_port_entry(self):
        guard = EgressGuard({"10.0.0.5:8080"})
        with pytest.raises(EgressBlockedError):
            guard.check("https://10.0.0.5/v1/chat")  # port 443 implicit, not 8080

    def test_hostname_only_entry_matches_any_port(self):
        guard = EgressGuard({"myhost.internal"})
        guard.check("http://myhost.internal:9000/api")  # must not raise

    def test_ip_address_allowed(self):
        guard = EgressGuard({"192.168.1.100"})
        guard.check("http://192.168.1.100/api")  # must not raise

    def test_ip_address_blocked(self):
        guard = EgressGuard({"192.168.1.100"})
        with pytest.raises(EgressBlockedError):
            guard.check("http://192.168.1.200/api")

    def test_case_insensitive_host_matching(self):
        guard = EgressGuard({"MyHost.Internal"})
        guard.check("https://myhost.internal/v1/completions")  # lowercase must match

    def test_multiple_allowed_hosts(self):
        guard = EgressGuard({"llm.corp.example.com", "vault.corp.example.com"})
        guard.check("https://llm.corp.example.com/v1/chat")
        guard.check("https://vault.corp.example.com/v1/sys/health")

    def test_error_message_contains_blocked_host(self):
        guard = EgressGuard({"allowed.example.com"})
        with pytest.raises(EgressBlockedError, match="evil.example.com"):
            guard.check("https://evil.example.com/path")


# ── EgressGuard.is_allowed() ─────────────────────────────────────────────────


class TestIsAllowed:
    def test_returns_true_for_allowed(self):
        guard = EgressGuard({"allowed.example.com"})
        assert guard.is_allowed("https://allowed.example.com/path") is True

    def test_returns_false_for_blocked(self):
        guard = EgressGuard({"allowed.example.com"})
        assert guard.is_allowed("https://evil.example.com/path") is False

    def test_returns_true_when_disabled(self):
        guard = EgressGuard(set(), enabled=False)
        assert guard.is_allowed("https://anything.example.com") is True


# ── EgressGuard properties ────────────────────────────────────────────────────


class TestEgressGuardProperties:
    def test_enabled_property(self):
        assert EgressGuard(set(), enabled=True).enabled is True
        assert EgressGuard(set(), enabled=False).enabled is False

    def test_allowed_hosts_is_frozenset(self):
        guard = EgressGuard({"a.example.com", "b.example.com"})
        hosts = guard.allowed_hosts
        assert isinstance(hosts, frozenset)
        assert "a.example.com" in hosts

    def test_whitespace_stripped_from_hosts(self):
        guard = EgressGuard({"  myhost.corp  ", "other.corp"})
        assert "myhost.corp" in guard.allowed_hosts

    def test_empty_strings_excluded(self):
        guard = EgressGuard({"", "  ", "valid.corp"})
        assert "" not in guard.allowed_hosts
        assert "valid.corp" in guard.allowed_hosts


# ── build_egress_guard() ─────────────────────────────────────────────────────


class TestBuildEgressGuard:
    def test_disabled_when_airgap_mode_false(self):
        guard = build_egress_guard(airgap_mode=False, allowed_hosts_csv="any.example.com")
        assert guard.enabled is False

    def test_enabled_when_airgap_mode_true(self):
        guard = build_egress_guard(airgap_mode=True, allowed_hosts_csv="llm.corp.example.com")
        assert guard.enabled is True

    def test_upstream_auto_added(self):
        guard = build_egress_guard(
            airgap_mode=True,
            allowed_hosts_csv="",
            upstream_url="https://internal-llm.corp.example.com:8443",
        )
        assert guard.is_allowed("https://internal-llm.corp.example.com:8443/v1/chat")

    def test_upstream_host_added_without_port(self):
        guard = build_egress_guard(
            airgap_mode=True,
            allowed_hosts_csv="",
            upstream_url="https://internal-llm.corp.example.com/v1",
        )
        assert guard.is_allowed("https://internal-llm.corp.example.com/v1/chat")

    def test_csv_hosts_parsed(self):
        guard = build_egress_guard(
            airgap_mode=True,
            allowed_hosts_csv="host1.corp.example.com,host2.corp.example.com",
            upstream_url="https://llm.corp.example.com",
        )
        assert guard.is_allowed("https://host1.corp.example.com/api")
        assert guard.is_allowed("https://host2.corp.example.com/api")

    def test_csv_with_whitespace(self):
        guard = build_egress_guard(
            airgap_mode=True,
            allowed_hosts_csv=" host1.corp.example.com , host2.corp.example.com ",
            upstream_url="",
        )
        assert guard.is_allowed("https://host1.corp.example.com/api")

    def test_empty_csv_only_upstream_allowed(self):
        guard = build_egress_guard(
            airgap_mode=True,
            allowed_hosts_csv="",
            upstream_url="https://llm.corp.example.com",
        )
        assert guard.is_allowed("https://llm.corp.example.com/v1/completions")
        assert not guard.is_allowed("https://vault.example.com/v1/secret")

    def test_disabled_allows_everything(self):
        guard = build_egress_guard(
            airgap_mode=False,
            allowed_hosts_csv="",
            upstream_url="",
        )
        assert guard.is_allowed("https://evil.example.com/path")


# ── Config integration ────────────────────────────────────────────────────────


class TestConfigIntegration:
    def test_config_get_egress_guard_disabled(self, monkeypatch):
        monkeypatch.setenv("AEGIS_AIRGAP_MODE", "false")
        monkeypatch.setenv("AEGIS_SIGNING_KEY", "test-key-32bytes-xyzzy12345678901")
        from aegis.config import AegisSettings

        cfg = AegisSettings()
        guard = cfg.get_egress_guard()
        assert guard.enabled is False

    def test_config_get_egress_guard_enabled(self, monkeypatch):
        monkeypatch.setenv("AEGIS_AIRGAP_MODE", "true")
        monkeypatch.setenv("AEGIS_AIRGAP_ALLOWED_HOSTS", "llm.corp.example.com")
        monkeypatch.setenv("AEGIS_SIGNING_KEY", "test-key-32bytes-xyzzy12345678901")
        from aegis.config import AegisSettings

        cfg = AegisSettings()
        guard = cfg.get_egress_guard()
        assert guard.enabled is True
        assert guard.is_allowed("https://llm.corp.example.com/v1/chat")

    def test_upstream_url_auto_included(self, monkeypatch):
        monkeypatch.setenv("AEGIS_AIRGAP_MODE", "true")
        monkeypatch.setenv("AEGIS_AIRGAP_ALLOWED_HOSTS", "")
        monkeypatch.setenv("AEGIS_BACKEND_URL", "http://internal-llm.corp.example.com:8080")
        monkeypatch.setenv("AEGIS_SIGNING_KEY", "test-key-32bytes-xyzzy12345678901")
        from aegis.config import AegisSettings

        cfg = AegisSettings()
        guard = cfg.get_egress_guard()
        assert guard.is_allowed("http://internal-llm.corp.example.com:8080/v1/chat")


# ── LLMForwarder integration ──────────────────────────────────────────────────


class TestForwarderEgressIntegration:
    def test_forwarder_accepts_egress_guard_kwarg(self):
        from aegis.config import AegisSettings
        from aegis.proxy.egress_guard import EgressGuard
        from aegis.proxy.forwarder import LLMForwarder

        settings = AegisSettings()
        guard = EgressGuard({"localhost"}, enabled=True)
        fwd = LLMForwarder(settings, egress_guard=guard)
        assert fwd._egress_guard is guard

    def test_forwarder_defaults_to_no_guard(self):
        from aegis.config import AegisSettings
        from aegis.proxy.forwarder import LLMForwarder

        settings = AegisSettings()
        fwd = LLMForwarder(settings)
        assert fwd._egress_guard is None

    async def test_forward_json_raises_on_blocked_host(self, monkeypatch):

        from aegis.config import AegisSettings
        from aegis.proxy.egress_guard import EgressBlockedError, EgressGuard
        from aegis.proxy.forwarder import LLMForwarder

        settings = AegisSettings()
        guard = EgressGuard(set(), enabled=True)  # block everything
        fwd = LLMForwarder(settings, egress_guard=guard)
        fwd._client = object()  # mock: ensure check fires before client is accessed

        with pytest.raises(EgressBlockedError):
            await fwd.forward_json("/v1/chat/completions", {"model": "test"})
