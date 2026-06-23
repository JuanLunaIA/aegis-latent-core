# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.lsm_guard — LSM confinement detection."""

from __future__ import annotations

import logging
import sys
from unittest.mock import patch

from aegis.core.lsm_guard import LSMGuard, LSMStatus, LSMType

# ── detect() ──────────────────────────────────────────────────────────────────


class TestDetect:
    def test_returns_lsm_status(self):
        status = LSMGuard.detect()
        assert isinstance(status, LSMStatus)

    def test_lsm_type_is_valid_enum(self):
        status = LSMGuard.detect()
        assert status.lsm_type in list(LSMType)

    def test_active_is_bool(self):
        status = LSMGuard.detect()
        assert isinstance(status.active, bool)

    def test_mode_is_non_empty_string(self):
        status = LSMGuard.detect()
        assert isinstance(status.mode, str)
        assert len(status.mode) > 0

    def test_mode_in_valid_values(self):
        status = LSMGuard.detect()
        assert status.mode in ("enforcing", "permissive", "disabled", "unknown")

    def test_profile_is_none_or_str(self):
        status = LSMGuard.detect()
        assert status.profile is None or isinstance(status.profile, str)

    def test_context_is_none_or_str(self):
        status = LSMGuard.detect()
        assert status.context is None or isinstance(status.context, str)

    def test_non_linux_returns_none_type(self):
        with patch.object(sys, "platform", "darwin"):
            status = LSMGuard.detect()
        assert status.lsm_type == LSMType.NONE
        assert status.active is False
        assert status.mode == "disabled"

    def test_apparmor_detected_when_profiles_present(self, tmp_path):
        profiles = tmp_path / "profiles"
        profiles.write_text("aegis-latent-core (enforce)\n")
        with (
            patch("aegis.core.lsm_guard._APPARMOR_PROFILES", str(profiles)),
            patch("os.path.exists", side_effect=lambda p: p == str(profiles)),
            patch.object(sys, "platform", "linux"),
        ):
            status = LSMGuard.detect()
        assert status.lsm_type == LSMType.APPARMOR
        assert status.active is True

    def test_selinux_enforcing_detected(self, tmp_path):
        enforce = tmp_path / "enforce"
        enforce.write_text("1")
        with (
            patch("aegis.core.lsm_guard._APPARMOR_PROFILES", "/nonexistent/apparmor/profiles"),
            patch("aegis.core.lsm_guard._SELINUX_ENFORCE", str(enforce)),
            patch.object(sys, "platform", "linux"),
        ):
            status = LSMGuard.detect()
        assert status.lsm_type == LSMType.SELINUX
        assert status.active is True
        assert status.mode == "enforcing"

    def test_selinux_permissive_detected(self, tmp_path):
        enforce = tmp_path / "enforce"
        enforce.write_text("0")
        with (
            patch("aegis.core.lsm_guard._APPARMOR_PROFILES", "/nonexistent/apparmor/profiles"),
            patch("aegis.core.lsm_guard._SELINUX_ENFORCE", str(enforce)),
            patch.object(sys, "platform", "linux"),
        ):
            status = LSMGuard.detect()
        assert status.lsm_type == LSMType.SELINUX
        assert status.mode == "permissive"

    def test_none_when_no_lsm(self):
        with (
            patch("aegis.core.lsm_guard._APPARMOR_PROFILES", "/nonexistent/apparmor/profiles"),
            patch("aegis.core.lsm_guard._SELINUX_ENFORCE", "/nonexistent/selinux/enforce"),
            patch.object(sys, "platform", "linux"),
        ):
            status = LSMGuard.detect()
        assert status.lsm_type == LSMType.NONE
        assert status.active is False


# ── is_apparmor_active() ──────────────────────────────────────────────────────


class TestIsAppArmorActive:
    def test_returns_bool(self):
        result = LSMGuard.is_apparmor_active()
        assert isinstance(result, bool)

    def test_false_on_non_linux(self):
        with patch.object(sys, "platform", "win32"):
            assert LSMGuard.is_apparmor_active() is False

    def test_true_when_profiles_file_exists(self, tmp_path):
        profiles = tmp_path / "profiles"
        profiles.write_text("")
        with (
            patch("aegis.core.lsm_guard._APPARMOR_PROFILES", str(profiles)),
            patch.object(sys, "platform", "linux"),
        ):
            assert LSMGuard.is_apparmor_active() is True

    def test_false_when_profiles_absent(self):
        with (
            patch("aegis.core.lsm_guard._APPARMOR_PROFILES", "/nonexistent/apparmor/profiles"),
            patch.object(sys, "platform", "linux"),
        ):
            assert LSMGuard.is_apparmor_active() is False


# ── is_selinux_enforcing() ────────────────────────────────────────────────────


class TestIsSELinuxEnforcing:
    def test_returns_bool(self):
        result = LSMGuard.is_selinux_enforcing()
        assert isinstance(result, bool)

    def test_does_not_raise(self):
        LSMGuard.is_selinux_enforcing()

    def test_false_on_non_linux(self):
        with patch.object(sys, "platform", "darwin"):
            assert LSMGuard.is_selinux_enforcing() is False

    def test_true_when_enforce_is_one(self, tmp_path):
        enforce = tmp_path / "enforce"
        enforce.write_text("1")
        with (
            patch("aegis.core.lsm_guard._SELINUX_ENFORCE", str(enforce)),
            patch.object(sys, "platform", "linux"),
        ):
            assert LSMGuard.is_selinux_enforcing() is True

    def test_false_when_enforce_is_zero(self, tmp_path):
        enforce = tmp_path / "enforce"
        enforce.write_text("0")
        with (
            patch("aegis.core.lsm_guard._SELINUX_ENFORCE", str(enforce)),
            patch.object(sys, "platform", "linux"),
        ):
            assert LSMGuard.is_selinux_enforcing() is False


# ── get_apparmor_profile_name() ───────────────────────────────────────────────


class TestGetAppArmorProfileName:
    def test_does_not_raise_on_non_apparmor_system(self):
        with patch("aegis.core.lsm_guard._PROC_SELF_ATTR", "/nonexistent/attr"):
            result = LSMGuard.get_apparmor_profile_name()
        assert result is None

    def test_returns_none_for_unconfined(self, tmp_path):
        attr = tmp_path / "current"
        attr.write_bytes(b"unconfined\n")
        with patch("aegis.core.lsm_guard._PROC_SELF_ATTR", str(attr)):
            assert LSMGuard.get_apparmor_profile_name() is None

    def test_returns_label_when_confined(self, tmp_path):
        attr = tmp_path / "current"
        attr.write_bytes(b"aegis-latent-core (enforce)\n")
        with patch("aegis.core.lsm_guard._PROC_SELF_ATTR", str(attr)):
            result = LSMGuard.get_apparmor_profile_name()
        assert result == "aegis-latent-core (enforce)"


# ── get_selinux_context() ─────────────────────────────────────────────────────


class TestGetSELinuxContext:
    def test_does_not_raise_on_non_selinux_system(self):
        with patch("aegis.core.lsm_guard._PROC_SELF_ATTR", "/nonexistent/attr"):
            result = LSMGuard.get_selinux_context()
        assert result is None

    def test_returns_label_when_file_exists(self, tmp_path):
        attr = tmp_path / "current"
        attr.write_bytes(b"system_u:system_r:init_t:s0\n")
        with patch("aegis.core.lsm_guard._PROC_SELF_ATTR", str(attr)):
            result = LSMGuard.get_selinux_context()
        assert result == "system_u:system_r:init_t:s0"


# ── LSMStatus.to_dict() ───────────────────────────────────────────────────────


class TestLSMStatusToDict:
    def test_has_required_keys(self):
        status = LSMGuard.detect()
        d = status.to_dict()
        for key in ("lsm_type", "active", "mode", "profile", "context"):
            assert key in d

    def test_lsm_type_is_string_in_dict(self):
        status = LSMStatus(
            lsm_type=LSMType.APPARMOR,
            active=True,
            mode="enforcing",
            profile="aegis",
            context=None,
        )
        d = status.to_dict()
        assert d["lsm_type"] == "apparmor"

    def test_serialisable_values(self):
        import json

        status = LSMGuard.detect()
        json.dumps(status.to_dict())


# ── assert_enforcing_or_warn() ────────────────────────────────────────────────


class TestAssertEnforcingOrWarn:
    def test_does_not_raise(self):
        LSMGuard.assert_enforcing_or_warn()

    def test_emits_warning_when_no_lsm(self, caplog):
        with (
            patch("aegis.core.lsm_guard._APPARMOR_PROFILES", "/nonexistent/apparmor/profiles"),
            patch("aegis.core.lsm_guard._SELINUX_ENFORCE", "/nonexistent/selinux/enforce"),
            patch.object(sys, "platform", "linux"),
            caplog.at_level(logging.WARNING, logger="aegis.core.lsm_guard"),
        ):
            LSMGuard.assert_enforcing_or_warn()
        assert any("not enforcing" in r.message or "DAC-only" in r.message for r in caplog.records)
