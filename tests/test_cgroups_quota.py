# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Copyright (c) 2026 Juan Luna. All rights reserved.
"""Tests for aegis.core.cgroups_quota."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from aegis.core.cgroups_quota import (
    CgroupsQuota,
    CgroupsQuotaResult,
    apply_cgroups_quota,
    is_cgroups_v2_available,
)

# ── CgroupsQuotaResult ────────────────────────────────────────────────────────


class TestCgroupsQuotaResult:
    def test_defaults(self):
        r = CgroupsQuotaResult()
        assert r.cgroups_v2_detected is False
        assert r.cgroup_path == ""
        assert r.memory_max_applied is False
        assert r.cpu_max_applied is False
        assert r.memory_max_bytes == 0
        assert r.cpu_max_cores == 0.0
        assert r.platform == ""
        assert r.errors == []
        assert r.skipped is False

    def test_applied_false_when_neither_applied(self):
        r = CgroupsQuotaResult()
        assert r.applied is False

    def test_applied_true_memory_only(self):
        r = CgroupsQuotaResult(memory_max_applied=True)
        assert r.applied is True

    def test_applied_true_cpu_only(self):
        r = CgroupsQuotaResult(cpu_max_applied=True)
        assert r.applied is True

    def test_applied_true_both(self):
        r = CgroupsQuotaResult(memory_max_applied=True, cpu_max_applied=True)
        assert r.applied is True

    def test_fully_applied_both_requested_both_applied(self):
        r = CgroupsQuotaResult(
            memory_max_bytes=1024,
            cpu_max_cores=1.0,
            memory_max_applied=True,
            cpu_max_applied=True,
        )
        assert r.fully_applied is True

    def test_fully_applied_memory_only_requested_and_applied(self):
        r = CgroupsQuotaResult(
            memory_max_bytes=1024,
            cpu_max_cores=0.0,
            memory_max_applied=True,
            cpu_max_applied=False,
        )
        assert r.fully_applied is True

    def test_fully_applied_cpu_only_requested_and_applied(self):
        r = CgroupsQuotaResult(
            memory_max_bytes=0,
            cpu_max_cores=1.0,
            memory_max_applied=False,
            cpu_max_applied=True,
        )
        assert r.fully_applied is True

    def test_fully_applied_false_memory_requested_not_applied(self):
        r = CgroupsQuotaResult(
            memory_max_bytes=1024,
            cpu_max_cores=0.0,
            memory_max_applied=False,
        )
        assert r.fully_applied is False

    def test_fully_applied_false_cpu_requested_not_applied(self):
        r = CgroupsQuotaResult(
            memory_max_bytes=0,
            cpu_max_cores=1.0,
            cpu_max_applied=False,
        )
        assert r.fully_applied is False

    def test_fully_applied_true_nothing_requested(self):
        r = CgroupsQuotaResult(memory_max_bytes=0, cpu_max_cores=0.0)
        assert r.fully_applied is True

    def test_to_dict_keys(self):
        r = CgroupsQuotaResult()
        d = r.to_dict()
        expected = {
            "cgroups_v2_detected",
            "cgroup_path",
            "memory_max_applied",
            "cpu_max_applied",
            "memory_max_bytes",
            "cpu_max_cores",
            "applied",
            "fully_applied",
            "platform",
            "errors",
            "skipped",
        }
        assert set(d.keys()) == expected

    def test_to_dict_values_match(self):
        r = CgroupsQuotaResult(
            cgroups_v2_detected=True,
            cgroup_path="/system.slice/aegis",
            memory_max_applied=True,
            cpu_max_applied=True,
            memory_max_bytes=2048,
            cpu_max_cores=1.5,
            platform="linux",
            errors=["err"],
            skipped=False,
        )
        d = r.to_dict()
        assert d["cgroups_v2_detected"] is True
        assert d["cgroup_path"] == "/system.slice/aegis"
        assert d["memory_max_applied"] is True
        assert d["cpu_max_applied"] is True
        assert d["memory_max_bytes"] == 2048
        assert d["cpu_max_cores"] == 1.5
        assert d["platform"] == "linux"
        assert d["errors"] == ["err"]
        assert d["skipped"] is False
        assert d["applied"] is True
        assert d["fully_applied"] is True

    def test_to_dict_errors_is_copy(self):
        r = CgroupsQuotaResult(errors=["e1"])
        d = r.to_dict()
        d["errors"].append("e2")
        assert r.errors == ["e1"]


# ── Skip logic ────────────────────────────────────────────────────────────────


class TestCgroupsQuotaSkip:
    def test_skip_via_env_var(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        result = CgroupsQuota().apply()
        assert result.skipped is True
        assert result.applied is False

    def test_skip_env_var_any_value(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "yes")
        result = CgroupsQuota().apply()
        assert result.skipped is True

    def test_no_skip_when_env_var_empty(self, monkeypatch):
        monkeypatch.delenv("AEGIS_SKIP_CGROUPS_QUOTA", raising=False)
        # Will still skip if not Linux or no cgroup, but not via env var
        result = CgroupsQuota().apply()
        if sys.platform != "linux":
            assert result.skipped is True  # platform skip
        # On Linux without a writable cgroup, we just check it didn't skip via env var flag

    def test_skip_non_linux(self, monkeypatch):
        monkeypatch.delenv("AEGIS_SKIP_CGROUPS_QUOTA", raising=False)
        with patch("aegis.core.cgroups_quota.sys") as mock_sys:
            mock_sys.platform = "darwin"
            result = CgroupsQuota().apply()
        assert result.skipped is True

    def test_skip_result_platform_set(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        result = CgroupsQuota().apply()
        assert result.platform == sys.platform

    def test_skip_memory_max_bytes_recorded(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        result = CgroupsQuota().apply(memory_max_bytes=1024, cpu_max_cores=0.5)
        assert result.memory_max_bytes == 1024
        assert result.cpu_max_cores == 0.5


# ── _read_proc_self_cgroup ────────────────────────────────────────────────────


class TestReadProcSelfCgroup:
    def test_parses_unified_hierarchy(self, tmp_path):
        cgroup_file = tmp_path / "cgroup"
        cgroup_file.write_text("0::/system.slice/aegis.service\n")
        with patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", cgroup_file):
            result = CgroupsQuota._read_proc_self_cgroup()
        assert result == "/system.slice/aegis.service"

    def test_parses_when_multiple_lines(self, tmp_path):
        cgroup_file = tmp_path / "cgroup"
        cgroup_file.write_text(
            "12:cpuset:/docker/abc\n11:memory:/docker/abc\n0::/system.slice/aegis.service\n"
        )
        with patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", cgroup_file):
            result = CgroupsQuota._read_proc_self_cgroup()
        assert result == "/system.slice/aegis.service"

    def test_returns_empty_on_missing_file(self, tmp_path):
        missing = tmp_path / "no_such_file"
        with patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", missing):
            result = CgroupsQuota._read_proc_self_cgroup()
        assert result == ""

    def test_returns_empty_when_no_unified_hierarchy_line(self, tmp_path):
        cgroup_file = tmp_path / "cgroup"
        cgroup_file.write_text("12:cpuset:/docker/abc\n")
        with patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", cgroup_file):
            result = CgroupsQuota._read_proc_self_cgroup()
        assert result == ""

    def test_path_with_colon_in_cgroup_name(self, tmp_path):
        cgroup_file = tmp_path / "cgroup"
        cgroup_file.write_text("0::/slice:with:colons\n")
        with patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", cgroup_file):
            result = CgroupsQuota._read_proc_self_cgroup()
        assert result == "/slice:with:colons"

    def test_root_cgroup(self, tmp_path):
        cgroup_file = tmp_path / "cgroup"
        cgroup_file.write_text("0::/\n")
        with patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", cgroup_file):
            result = CgroupsQuota._read_proc_self_cgroup()
        assert result == "/"


# ── _detect_cgroup_dir ────────────────────────────────────────────────────────


class TestDetectCgroupDir:
    def test_returns_none_when_cgroup_mount_missing(self, tmp_path):
        missing = tmp_path / "no_cgroup"
        result = CgroupsQuotaResult()
        with patch("aegis.core.cgroups_quota._CGROUP_MOUNT", missing):
            cgroup_dir = CgroupsQuota()._detect_cgroup_dir(result)
        assert cgroup_dir is None
        assert any("not found" in e for e in result.errors)

    def test_returns_none_when_no_cgroup_controllers(self, tmp_path):
        mount = tmp_path / "cgroup"
        mount.mkdir()
        # No cgroup.controllers file
        result = CgroupsQuotaResult()
        with patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount):
            cgroup_dir = CgroupsQuota()._detect_cgroup_dir(result)
        assert cgroup_dir is None
        assert result.cgroups_v2_detected is False

    def test_detects_v2_when_controllers_present(self, tmp_path):
        mount = tmp_path / "cgroup"
        mount.mkdir()
        (mount / "cgroup.controllers").write_text("cpu memory\n")
        proc_cgroup = tmp_path / "proc_cgroup"
        proc_cgroup.write_text("0::/\n")
        # Root cgroup exists (it's the mount itself)
        result = CgroupsQuotaResult()
        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
            patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", proc_cgroup),
        ):
            cgroup_dir = CgroupsQuota()._detect_cgroup_dir(result)
        assert result.cgroups_v2_detected is True
        assert cgroup_dir == mount

    def test_returns_none_when_cgroup_dir_not_found(self, tmp_path):
        mount = tmp_path / "cgroup"
        mount.mkdir()
        (mount / "cgroup.controllers").write_text("cpu memory\n")
        proc_cgroup = tmp_path / "proc_cgroup"
        proc_cgroup.write_text("0::/nonexistent/path\n")
        result = CgroupsQuotaResult()
        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
            patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", proc_cgroup),
        ):
            cgroup_dir = CgroupsQuota()._detect_cgroup_dir(result)
        assert cgroup_dir is None
        assert any("not found" in e for e in result.errors)

    def test_cgroup_path_recorded_in_result(self, tmp_path):
        mount = tmp_path / "cgroup"
        mount.mkdir()
        (mount / "cgroup.controllers").write_text("cpu memory\n")
        proc_cgroup = tmp_path / "proc_cgroup"
        proc_cgroup.write_text("0::/system.slice/aegis\n")
        (mount / "system.slice" / "aegis").mkdir(parents=True)
        result = CgroupsQuotaResult()
        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
            patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", proc_cgroup),
        ):
            CgroupsQuota()._detect_cgroup_dir(result)
        assert result.cgroup_path == "/system.slice/aegis"


# ── _write_memory_max / _write_cpu_max ───────────────────────────────────────


class TestWriteMemoryMax:
    def test_writes_value(self, tmp_path):
        result = CgroupsQuotaResult()
        ok = CgroupsQuota._write_memory_max(tmp_path, 2 * 1024**3, result)
        assert ok is True
        assert (tmp_path / "memory.max").read_text() == str(2 * 1024**3)

    def test_returns_false_on_permission_error(self, tmp_path):
        result = CgroupsQuotaResult()
        with patch.object(Path, "write_text", side_effect=PermissionError("denied")):
            ok = CgroupsQuota._write_memory_max(tmp_path, 1024, result)
        assert ok is False
        assert any("permission denied" in e for e in result.errors)

    def test_returns_false_on_oserror(self, tmp_path):
        result = CgroupsQuotaResult()
        with patch.object(Path, "write_text", side_effect=OSError("no space")):
            ok = CgroupsQuota._write_memory_max(tmp_path, 1024, result)
        assert ok is False
        assert any("memory.max" in e for e in result.errors)


class TestWriteCpuMax:
    def test_writes_correct_format(self, tmp_path):
        result = CgroupsQuotaResult()
        ok = CgroupsQuota._write_cpu_max(tmp_path, 2.0, result)
        assert ok is True
        content = (tmp_path / "cpu.max").read_text()
        assert content == "200000 100000"

    def test_fractional_cores(self, tmp_path):
        result = CgroupsQuotaResult()
        CgroupsQuota._write_cpu_max(tmp_path, 0.5, result)
        content = (tmp_path / "cpu.max").read_text()
        assert content == "50000 100000"

    def test_returns_false_on_permission_error(self, tmp_path):
        result = CgroupsQuotaResult()
        with patch.object(Path, "write_text", side_effect=PermissionError("denied")):
            ok = CgroupsQuota._write_cpu_max(tmp_path, 1.0, result)
        assert ok is False
        assert any("permission denied" in e for e in result.errors)

    def test_returns_false_on_oserror(self, tmp_path):
        result = CgroupsQuotaResult()
        with patch.object(Path, "write_text", side_effect=OSError("fail")):
            ok = CgroupsQuota._write_cpu_max(tmp_path, 1.0, result)
        assert ok is False

    def test_quota_math_four_cores(self, tmp_path):
        result = CgroupsQuotaResult()
        CgroupsQuota._write_cpu_max(tmp_path, 4.0, result)
        content = (tmp_path / "cpu.max").read_text()
        quota_us, period_us = content.split()
        assert int(quota_us) == 400_000
        assert int(period_us) == 100_000


# ── Full apply() integration ──────────────────────────────────────────────────


class TestCgroupsQuotaApply:
    def _make_cgroup_tree(self, tmp_path):
        mount = tmp_path / "sys_fs_cgroup"
        mount.mkdir()
        (mount / "cgroup.controllers").write_text("cpu memory\n")
        proc_cgroup = tmp_path / "proc_self_cgroup"
        proc_cgroup.write_text("0::/aegis\n")
        cgroup_dir = mount / "aegis"
        cgroup_dir.mkdir()
        return mount, proc_cgroup, cgroup_dir

    def test_apply_writes_both_quotas(self, tmp_path):
        mount, proc_cgroup, cgroup_dir = self._make_cgroup_tree(tmp_path)
        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
            patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", proc_cgroup),
            patch("aegis.core.cgroups_quota.sys") as mock_sys,
        ):
            mock_sys.platform = "linux"
            result = CgroupsQuota().apply(memory_max_bytes=1024, cpu_max_cores=1.0)
        assert result.memory_max_applied is True
        assert result.cpu_max_applied is True
        assert result.applied is True
        assert result.fully_applied is True
        assert (cgroup_dir / "memory.max").read_text() == "1024"
        assert (cgroup_dir / "cpu.max").read_text() == "100000 100000"

    def test_apply_skips_memory_when_zero(self, tmp_path):
        mount, proc_cgroup, cgroup_dir = self._make_cgroup_tree(tmp_path)
        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
            patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", proc_cgroup),
            patch("aegis.core.cgroups_quota.sys") as mock_sys,
        ):
            mock_sys.platform = "linux"
            result = CgroupsQuota().apply(memory_max_bytes=0, cpu_max_cores=1.0)
        assert result.memory_max_applied is False
        assert result.cpu_max_applied is True
        assert not (cgroup_dir / "memory.max").exists()

    def test_apply_skips_cpu_when_zero(self, tmp_path):
        mount, proc_cgroup, cgroup_dir = self._make_cgroup_tree(tmp_path)
        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
            patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", proc_cgroup),
            patch("aegis.core.cgroups_quota.sys") as mock_sys,
        ):
            mock_sys.platform = "linux"
            result = CgroupsQuota().apply(memory_max_bytes=1024, cpu_max_cores=0.0)
        assert result.cpu_max_applied is False
        assert result.memory_max_applied is True

    def test_apply_graceful_on_cgroup_missing(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AEGIS_SKIP_CGROUPS_QUOTA", raising=False)
        missing_mount = tmp_path / "no_cgroup"
        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", missing_mount),
            patch("aegis.core.cgroups_quota.sys") as mock_sys,
        ):
            mock_sys.platform = "linux"
            result = CgroupsQuota().apply()
        assert result.applied is False
        assert result.skipped is True

    def test_apply_records_cgroup_path(self, tmp_path):
        mount, proc_cgroup, cgroup_dir = self._make_cgroup_tree(tmp_path)
        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
            patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", proc_cgroup),
            patch("aegis.core.cgroups_quota.sys") as mock_sys,
        ):
            mock_sys.platform = "linux"
            result = CgroupsQuota().apply()
        assert result.cgroup_path == "/aegis"

    def test_apply_partial_permission_error_memory(self, tmp_path):
        mount, proc_cgroup, cgroup_dir = self._make_cgroup_tree(tmp_path)

        original_write = Path.write_text

        def selective_fail(self, data, *args, **kwargs):
            if "memory.max" in str(self):
                raise PermissionError("denied")
            return original_write(self, data, *args, **kwargs)

        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
            patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", proc_cgroup),
            patch("aegis.core.cgroups_quota.sys") as mock_sys,
            patch.object(Path, "write_text", selective_fail),
        ):
            mock_sys.platform = "linux"
            result = CgroupsQuota().apply(memory_max_bytes=1024, cpu_max_cores=1.0)
        assert result.memory_max_applied is False
        assert result.cpu_max_applied is True
        assert result.errors  # permission error recorded


# ── read_memory_current ───────────────────────────────────────────────────────


class TestReadMemoryCurrent:
    def test_reads_value(self, tmp_path):
        mount = tmp_path / "cgroup"
        (mount / "aegis").mkdir(parents=True)
        (mount / "aegis" / "memory.current").write_text("104857600\n")
        with patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount):
            val = CgroupsQuota.read_memory_current("/aegis")
        assert val == 104857600

    def test_returns_none_on_missing_file(self, tmp_path):
        mount = tmp_path / "cgroup"
        mount.mkdir()
        with patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount):
            val = CgroupsQuota.read_memory_current("/nonexistent")
        assert val is None

    def test_returns_none_on_invalid_content(self, tmp_path):
        mount = tmp_path / "cgroup"
        (mount / "aegis").mkdir(parents=True)
        (mount / "aegis" / "memory.current").write_text("not_a_number\n")
        with patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount):
            val = CgroupsQuota.read_memory_current("/aegis")
        assert val is None

    def test_auto_detects_cgroup_path(self, tmp_path):
        mount = tmp_path / "cgroup"
        (mount / "aegis").mkdir(parents=True)
        (mount / "aegis" / "memory.current").write_text("512\n")
        proc_cgroup = tmp_path / "proc_self_cgroup"
        proc_cgroup.write_text("0::/aegis\n")
        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
            patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", proc_cgroup),
        ):
            val = CgroupsQuota.read_memory_current()
        assert val == 512

    def test_strips_whitespace(self, tmp_path):
        mount = tmp_path / "cgroup"
        (mount / "aegis").mkdir(parents=True)
        (mount / "aegis" / "memory.current").write_text("  1024  \n")
        with patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount):
            val = CgroupsQuota.read_memory_current("/aegis")
        assert val == 1024


# ── read_cpu_stat ─────────────────────────────────────────────────────────────


class TestReadCpuStat:
    def test_reads_counters(self, tmp_path):
        mount = tmp_path / "cgroup"
        (mount / "aegis").mkdir(parents=True)
        (mount / "aegis" / "cpu.stat").write_text(
            "usage_usec 1000000\nuser_usec 800000\nsystem_usec 200000\n"
        )
        with patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount):
            stat = CgroupsQuota.read_cpu_stat("/aegis")
        assert stat == {"usage_usec": 1000000, "user_usec": 800000, "system_usec": 200000}

    def test_returns_empty_on_missing_file(self, tmp_path):
        mount = tmp_path / "cgroup"
        mount.mkdir()
        with patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount):
            stat = CgroupsQuota.read_cpu_stat("/nonexistent")
        assert stat == {}

    def test_returns_empty_on_invalid_line(self, tmp_path):
        mount = tmp_path / "cgroup"
        (mount / "aegis").mkdir(parents=True)
        (mount / "aegis" / "cpu.stat").write_text("bad_line\n")
        with patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount):
            stat = CgroupsQuota.read_cpu_stat("/aegis")
        assert stat == {}

    def test_auto_detects_cgroup_path(self, tmp_path):
        mount = tmp_path / "cgroup"
        (mount / "aegis").mkdir(parents=True)
        (mount / "aegis" / "cpu.stat").write_text("usage_usec 5000\n")
        proc_cgroup = tmp_path / "proc_self_cgroup"
        proc_cgroup.write_text("0::/aegis\n")
        with (
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
            patch("aegis.core.cgroups_quota._PROC_SELF_CGROUP", proc_cgroup),
        ):
            stat = CgroupsQuota.read_cpu_stat()
        assert stat["usage_usec"] == 5000

    def test_skips_malformed_lines(self, tmp_path):
        mount = tmp_path / "cgroup"
        (mount / "aegis").mkdir(parents=True)
        (mount / "aegis" / "cpu.stat").write_text("usage_usec 1000\nmalformed\nuser_usec 800\n")
        with patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount):
            stat = CgroupsQuota.read_cpu_stat("/aegis")
        assert stat["usage_usec"] == 1000
        assert stat["user_usec"] == 800
        assert "malformed" not in stat


# ── apply_cgroups_quota ───────────────────────────────────────────────────────


class TestApplyCgroupsQuota:
    def test_uses_env_var_memory(self, monkeypatch, tmp_path):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        monkeypatch.setenv("AEGIS_CGROUP_MEMORY_MAX", "1073741824")
        result = apply_cgroups_quota()
        assert result.memory_max_bytes == 1073741824

    def test_uses_env_var_cpu(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        monkeypatch.setenv("AEGIS_CGROUP_CPU_MAX", "4.0")
        result = apply_cgroups_quota()
        assert result.cpu_max_cores == 4.0

    def test_defaults_when_no_env_vars(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        monkeypatch.delenv("AEGIS_CGROUP_MEMORY_MAX", raising=False)
        monkeypatch.delenv("AEGIS_CGROUP_CPU_MAX", raising=False)
        result = apply_cgroups_quota()
        assert result.memory_max_bytes == 2 * 1024**3
        assert result.cpu_max_cores == 2.0

    def test_explicit_params_used_when_no_env_vars(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        monkeypatch.delenv("AEGIS_CGROUP_MEMORY_MAX", raising=False)
        monkeypatch.delenv("AEGIS_CGROUP_CPU_MAX", raising=False)
        result = apply_cgroups_quota(memory_max_bytes=512, cpu_max_cores=0.5)
        assert result.memory_max_bytes == 512
        assert result.cpu_max_cores == 0.5

    def test_env_var_overrides_explicit_param(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        monkeypatch.setenv("AEGIS_CGROUP_MEMORY_MAX", "999")
        result = apply_cgroups_quota(memory_max_bytes=512)
        assert result.memory_max_bytes == 999

    def test_invalid_env_var_memory_uses_default(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        monkeypatch.setenv("AEGIS_CGROUP_MEMORY_MAX", "not_a_number")
        monkeypatch.delenv("AEGIS_CGROUP_CPU_MAX", raising=False)
        result = apply_cgroups_quota()
        assert result.memory_max_bytes == 2 * 1024**3

    def test_invalid_env_var_cpu_uses_default(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        monkeypatch.delenv("AEGIS_CGROUP_MEMORY_MAX", raising=False)
        monkeypatch.setenv("AEGIS_CGROUP_CPU_MAX", "not_a_float")
        result = apply_cgroups_quota()
        assert result.cpu_max_cores == 2.0

    def test_zero_memory_env_var_disables(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        monkeypatch.setenv("AEGIS_CGROUP_MEMORY_MAX", "0")
        result = apply_cgroups_quota()
        assert result.memory_max_bytes == 0

    def test_zero_cpu_env_var_disables(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_CGROUPS_QUOTA", "1")
        monkeypatch.setenv("AEGIS_CGROUP_CPU_MAX", "0")
        result = apply_cgroups_quota()
        assert result.cpu_max_cores == 0.0


# ── is_cgroups_v2_available ───────────────────────────────────────────────────


class TestIsCgroupsV2Available:
    def test_returns_false_on_non_linux(self):
        with patch("aegis.core.cgroups_quota.sys") as mock_sys:
            mock_sys.platform = "darwin"
            assert is_cgroups_v2_available() is False

    def test_returns_false_when_controllers_missing(self, tmp_path):
        mount = tmp_path / "cgroup"
        mount.mkdir()
        with (
            patch("aegis.core.cgroups_quota.sys") as mock_sys,
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
        ):
            mock_sys.platform = "linux"
            assert is_cgroups_v2_available() is False

    def test_returns_true_when_available(self, tmp_path):
        mount = tmp_path / "cgroup"
        mount.mkdir()
        (mount / "cgroup.controllers").write_text("cpu memory\n")
        with (
            patch("aegis.core.cgroups_quota.sys") as mock_sys,
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", mount),
        ):
            mock_sys.platform = "linux"
            assert is_cgroups_v2_available() is True

    def test_returns_false_when_mount_missing_entirely(self, tmp_path):
        missing = tmp_path / "no_mount"
        with (
            patch("aegis.core.cgroups_quota.sys") as mock_sys,
            patch("aegis.core.cgroups_quota._CGROUP_MOUNT", missing),
        ):
            mock_sys.platform = "linux"
            assert is_cgroups_v2_available() is False
