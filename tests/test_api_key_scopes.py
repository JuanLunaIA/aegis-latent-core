# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for HIPAA minimum-necessary API key scope enforcement (aegis.auth.scopes)."""

from __future__ import annotations

import pytest

from aegis.auth.scopes import (
    ALL_SCOPES,
    SCOPE_AUDIT_ANALYTICS,
    SCOPE_AUDIT_EXPORT,
    SCOPE_AUDIT_READ,
    SCOPE_PROXY_COMPLETIONS,
    ScopedKeyRegistry,
    ScopeViolationError,
    parse_scope_config,
)


class TestScopeConstants:
    def test_all_scopes_is_frozenset(self):
        assert isinstance(ALL_SCOPES, frozenset)

    def test_all_scopes_contains_four_entries(self):
        assert len(ALL_SCOPES) == 4

    def test_all_scope_values_present(self):
        assert SCOPE_PROXY_COMPLETIONS in ALL_SCOPES
        assert SCOPE_AUDIT_READ in ALL_SCOPES
        assert SCOPE_AUDIT_EXPORT in ALL_SCOPES
        assert SCOPE_AUDIT_ANALYTICS in ALL_SCOPES

    def test_scope_string_values(self):
        assert SCOPE_PROXY_COMPLETIONS == "proxy:completions"
        assert SCOPE_AUDIT_READ == "audit:read"
        assert SCOPE_AUDIT_EXPORT == "audit:export"
        assert SCOPE_AUDIT_ANALYTICS == "audit:analytics"


class TestScopeViolationError:
    def test_is_permission_error(self):
        err = ScopeViolationError("audit:export", frozenset({"audit:read"}))
        assert isinstance(err, PermissionError)

    def test_attributes_set(self):
        scopes = frozenset({"audit:read"})
        err = ScopeViolationError("audit:export", scopes)
        assert err.required_scope == "audit:export"
        assert err.key_scopes == scopes

    def test_message_contains_required_scope(self):
        err = ScopeViolationError("audit:export", frozenset({"audit:read"}))
        assert "audit:export" in str(err)

    def test_message_contains_key_scopes(self):
        err = ScopeViolationError("audit:export", frozenset({"audit:read"}))
        assert "audit:read" in str(err)


class TestParseScopeConfig:
    def test_empty_string_returns_empty_dict(self):
        assert parse_scope_config("") == {}

    def test_whitespace_only_returns_empty_dict(self):
        assert parse_scope_config("   ") == {}

    def test_single_key_single_scope(self):
        result = parse_scope_config("mykey:audit:read")
        assert result == {"mykey": frozenset({"audit:read"})}

    def test_single_key_multiple_scopes(self):
        result = parse_scope_config("mykey:audit:read,audit:export")
        assert result == {"mykey": frozenset({"audit:read", "audit:export"})}

    def test_multiple_keys(self):
        result = parse_scope_config("key1:audit:read;key2:proxy:completions")
        assert result == {
            "key1": frozenset({"audit:read"}),
            "key2": frozenset({"proxy:completions"}),
        }

    def test_multiple_keys_multiple_scopes(self):
        result = parse_scope_config(
            "k1:audit:read,audit:export;k2:proxy:completions,audit:analytics"
        )
        assert result["k1"] == frozenset({"audit:read", "audit:export"})
        assert result["k2"] == frozenset({"proxy:completions", "audit:analytics"})

    def test_trailing_semicolon_ignored(self):
        result = parse_scope_config("key1:audit:read;")
        assert len(result) == 1
        assert "key1" in result

    def test_leading_and_trailing_whitespace_stripped(self):
        result = parse_scope_config("  key1 : audit:read , audit:export  ")
        assert "key1" in result
        assert "audit:read" in result["key1"]
        assert "audit:export" in result["key1"]

    def test_empty_segment_skipped(self):
        result = parse_scope_config("key1:audit:read;;key2:audit:export")
        assert len(result) == 2

    def test_entry_without_colon_skipped(self):
        result = parse_scope_config("invalid_no_colon;key1:audit:read")
        assert "invalid_no_colon" not in result
        assert "key1" in result

    def test_entry_with_empty_key_skipped(self):
        # ":audit:read" has an empty key
        result = parse_scope_config(":audit:read;key1:audit:read")
        assert "" not in result
        assert "key1" in result

    def test_unknown_scope_strings_accepted(self):
        result = parse_scope_config("key1:future:scope,audit:read")
        assert "future:scope" in result["key1"]
        assert "audit:read" in result["key1"]

    def test_scopes_returned_as_frozenset(self):
        result = parse_scope_config("key1:audit:read")
        assert isinstance(result["key1"], frozenset)

    def test_empty_scope_strings_stripped(self):
        result = parse_scope_config("key1:audit:read,,audit:export")
        assert "" not in result["key1"]


class TestScopedKeyRegistry:
    _KEYS = frozenset({"alpha-key", "beta-key", "gamma-key"})

    def _registry_no_scope_map(self) -> ScopedKeyRegistry:
        return ScopedKeyRegistry(valid_keys=self._KEYS)

    def _registry_with_scope_map(self) -> ScopedKeyRegistry:
        scope_map = {
            "alpha-key": frozenset({SCOPE_AUDIT_READ}),
            "beta-key": frozenset({SCOPE_AUDIT_READ, SCOPE_AUDIT_EXPORT}),
        }
        return ScopedKeyRegistry(valid_keys=self._KEYS, scope_map=scope_map)

    # ── validate() ──────────────────────────────────────────────────────
    def test_valid_key_returns_scopes(self):
        reg = self._registry_no_scope_map()
        scopes = reg.validate("alpha-key")
        assert isinstance(scopes, frozenset)
        assert SCOPE_AUDIT_READ in scopes

    def test_invalid_key_raises_key_error(self):
        reg = self._registry_no_scope_map()
        with pytest.raises(KeyError):
            reg.validate("nonexistent-key")

    def test_key_not_in_scope_map_gets_all_scopes(self):
        reg = self._registry_with_scope_map()
        # gamma-key is valid but not in scope_map
        scopes = reg.validate("gamma-key")
        assert scopes == ALL_SCOPES

    def test_key_in_scope_map_gets_restricted_scopes(self):
        reg = self._registry_with_scope_map()
        scopes = reg.validate("alpha-key")
        assert scopes == frozenset({SCOPE_AUDIT_READ})
        assert SCOPE_PROXY_COMPLETIONS not in scopes

    def test_no_scope_map_gives_all_scopes(self):
        reg = self._registry_no_scope_map()
        assert reg.validate("alpha-key") == ALL_SCOPES

    # ── require_scope() ─────────────────────────────────────────────────
    def test_require_scope_valid_key_has_scope(self):
        reg = self._registry_with_scope_map()
        scopes = reg.require_scope("alpha-key", SCOPE_AUDIT_READ)
        assert SCOPE_AUDIT_READ in scopes

    def test_require_scope_valid_key_missing_scope_raises(self):
        reg = self._registry_with_scope_map()
        with pytest.raises(ScopeViolationError) as exc_info:
            reg.require_scope("alpha-key", SCOPE_PROXY_COMPLETIONS)
        assert exc_info.value.required_scope == SCOPE_PROXY_COMPLETIONS

    def test_require_scope_invalid_key_raises_key_error(self):
        reg = self._registry_no_scope_map()
        with pytest.raises(KeyError):
            reg.require_scope("bad-key", SCOPE_AUDIT_READ)

    def test_require_scope_returns_full_scope_set(self):
        reg = self._registry_with_scope_map()
        scopes = reg.require_scope("beta-key", SCOPE_AUDIT_EXPORT)
        assert scopes == frozenset({SCOPE_AUDIT_READ, SCOPE_AUDIT_EXPORT})

    def test_require_scope_violation_error_has_key_scopes(self):
        reg = self._registry_with_scope_map()
        with pytest.raises(ScopeViolationError) as exc_info:
            reg.require_scope("alpha-key", SCOPE_AUDIT_EXPORT)
        assert exc_info.value.key_scopes == frozenset({SCOPE_AUDIT_READ})

    # ── constant-time membership check ──────────────────────────────────
    def test_constant_time_in_returns_true_for_valid_key(self):
        reg = self._registry_no_scope_map()
        assert reg._constant_time_in("alpha-key") is True

    def test_constant_time_in_returns_false_for_invalid_key(self):
        reg = self._registry_no_scope_map()
        assert reg._constant_time_in("not-a-key") is False

    def test_constant_time_in_empty_keys(self):
        reg = ScopedKeyRegistry(valid_keys=frozenset())
        assert reg._constant_time_in("anything") is False

    def test_constant_time_in_does_not_short_circuit(self):
        # All keys must be compared regardless of early match to prevent timing attacks.
        # We exercise this by putting the target key first vs last in the set and
        # verifying the result is always correct (we can't directly measure timing here).
        keys = frozenset({f"key-{i}" for i in range(50)} | {"target-key"})
        reg = ScopedKeyRegistry(valid_keys=keys)
        assert reg._constant_time_in("target-key") is True
        assert reg._constant_time_in("missing-key") is False

    # ── from_config() classmethod ────────────────────────────────────────
    def test_from_config_empty_scope_config(self):
        reg = ScopedKeyRegistry.from_config(self._KEYS, "")
        assert reg.validate("alpha-key") == ALL_SCOPES

    def test_from_config_with_scope_restriction(self):
        config = "alpha-key:audit:read"
        reg = ScopedKeyRegistry.from_config(self._KEYS, config)
        scopes = reg.validate("alpha-key")
        assert scopes == frozenset({"audit:read"})

    def test_from_config_multiple_keys(self):
        config = "alpha-key:audit:read;beta-key:proxy:completions,audit:analytics"
        reg = ScopedKeyRegistry.from_config(self._KEYS, config)
        assert reg.validate("alpha-key") == frozenset({"audit:read"})
        assert reg.validate("beta-key") == frozenset({"proxy:completions", "audit:analytics"})

    def test_from_config_unconfigured_key_gets_all_scopes(self):
        config = "alpha-key:audit:read"
        reg = ScopedKeyRegistry.from_config(self._KEYS, config)
        # gamma-key is valid but not in config → ALL_SCOPES
        assert reg.validate("gamma-key") == ALL_SCOPES


class TestScopedKeyRegistryIntegration:
    """End-to-end scenarios mimicking real deployment configurations."""

    def test_read_only_key_cannot_use_proxy(self):
        keys = frozenset({"ro-key", "full-key"})
        reg = ScopedKeyRegistry.from_config(keys, "ro-key:audit:read")
        with pytest.raises(ScopeViolationError):
            reg.require_scope("ro-key", SCOPE_PROXY_COMPLETIONS)

    def test_proxy_key_cannot_export(self):
        keys = frozenset({"proxy-key"})
        reg = ScopedKeyRegistry.from_config(keys, "proxy-key:proxy:completions")
        with pytest.raises(ScopeViolationError):
            reg.require_scope("proxy-key", SCOPE_AUDIT_EXPORT)

    def test_full_key_has_all_scopes(self):
        keys = frozenset({"full-key"})
        reg = ScopedKeyRegistry.from_config(keys, "")
        for scope in ALL_SCOPES:
            # Must not raise
            reg.require_scope("full-key", scope)

    def test_export_key_can_read_and_export(self):
        keys = frozenset({"export-key"})
        config = "export-key:audit:read,audit:export"
        reg = ScopedKeyRegistry.from_config(keys, config)
        reg.require_scope("export-key", SCOPE_AUDIT_READ)
        reg.require_scope("export-key", SCOPE_AUDIT_EXPORT)
        with pytest.raises(ScopeViolationError):
            reg.require_scope("export-key", SCOPE_PROXY_COMPLETIONS)

    def test_analytics_key_scope(self):
        keys = frozenset({"dp-key"})
        config = "dp-key:audit:analytics"
        reg = ScopedKeyRegistry.from_config(keys, config)
        reg.require_scope("dp-key", SCOPE_AUDIT_ANALYTICS)
        with pytest.raises(ScopeViolationError):
            reg.require_scope("dp-key", SCOPE_AUDIT_EXPORT)
