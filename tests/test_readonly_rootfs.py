# Copyright (c) 2026 Juan Luna. All rights reserved.
"""Tests for aegis.core.readonly_rootfs."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from aegis.core.readonly_rootfs import (
    PathResolutionResult,
    ReadOnlyRootfsGuard,
    ReadOnlyRootfsResult,
)

# ── PathResolutionResult ──────────────────────────────────────────────────────


class TestPathResolutionResult:
    def test_defaults(self):
        r = PathResolutionResult(
            label="wal",
            preferred_path="/var/lib/aegis/wal",
            path=Path("/var/lib/aegis/wal"),
            redirected=False,
        )
        assert r.label == "wal"
        assert r.redirected is False
        assert r.fallback_base is None

    def test_to_dict_keys(self):
        r = PathResolutionResult(
            label="wal",
            preferred_path="/var/lib/aegis/wal",
            path=Path("/tmp/aegis/var/lib/aegis/wal"),
            redirected=True,
            fallback_base="/tmp/aegis",
        )
        d = r.to_dict()
        assert set(d.keys()) == {"label", "preferred_path", "path", "redirected", "fallback_base"}
        assert d["redirected"] is True
        assert d["fallback_base"] == "/tmp/aegis"
        assert d["path"] == "/tmp/aegis/var/lib/aegis/wal"

    def test_to_dict_path_as_string(self):
        r = PathResolutionResult(
            label="logs",
            preferred_path="/var/log/aegis",
            path=Path("/var/log/aegis"),
            redirected=False,
        )
        assert isinstance(r.to_dict()["path"], str)


# ── ReadOnlyRootfsResult ──────────────────────────────────────────────────────


class TestReadOnlyRootfsResult:
    def test_defaults(self):
        r = ReadOnlyRootfsResult()
        assert r.rootfs_readonly is False
        assert r.proc_mounts_readonly is False
        assert r.write_probe_failed is False
        assert r.resolutions == []
        assert r.skip_check is False
        assert r.any_redirected is False

    def test_any_redirected_true(self):
        r = ReadOnlyRootfsResult()
        r.resolutions.append(
            PathResolutionResult(
                "wal", "/var/lib/aegis/wal", Path("/tmp/aegis/wal"), redirected=True
            )
        )
        assert r.any_redirected is True

    def test_any_redirected_false_when_none(self):
        r = ReadOnlyRootfsResult()
        r.resolutions.append(
            PathResolutionResult(
                "wal", "/var/lib/aegis/wal", Path("/var/lib/aegis/wal"), redirected=False
            )
        )
        assert r.any_redirected is False

    def test_to_dict_keys(self):
        r = ReadOnlyRootfsResult()
        d = r.to_dict()
        assert set(d.keys()) == {
            "rootfs_readonly",
            "proc_mounts_readonly",
            "write_probe_failed",
            "any_redirected",
            "tmpfs_base",
            "skip_check",
            "resolutions",
        }

    def test_to_dict_resolutions_serialized(self):
        r = ReadOnlyRootfsResult()
        r.resolutions.append(
            PathResolutionResult(
                "wal", "/var/lib/aegis/wal", Path("/var/lib/aegis/wal"), redirected=False
            )
        )
        d = r.to_dict()
        assert len(d["resolutions"]) == 1
        assert d["resolutions"][0]["label"] == "wal"


# ── ReadOnlyRootfsGuard construction ─────────────────────────────────────────


class TestGuardConstruction:
    def test_default_tmpfs_base(self, monkeypatch):
        monkeypatch.delenv("AEGIS_TMPFS_BASE", raising=False)
        monkeypatch.delenv("AEGIS_NFS_MOUNT", raising=False)
        g = ReadOnlyRootfsGuard()
        assert g.tmpfs_base == "/tmp/aegis"

    def test_custom_tmpfs_base_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_TMPFS_BASE", "/mnt/tmpfs/aegis")
        g = ReadOnlyRootfsGuard()
        assert g.tmpfs_base == "/mnt/tmpfs/aegis"

    def test_custom_tmpfs_base_param(self):
        g = ReadOnlyRootfsGuard(tmpfs_base="/custom/base")
        assert g.tmpfs_base == "/custom/base"

    def test_nfs_mount_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_NFS_MOUNT", "/nfs/aegis")
        g = ReadOnlyRootfsGuard()
        assert g.nfs_mount == "/nfs/aegis"

    def test_nfs_mount_param(self):
        g = ReadOnlyRootfsGuard(nfs_mount="/nfs/aegis")
        assert g.nfs_mount == "/nfs/aegis"

    def test_nfs_mount_empty_env_treated_as_none(self, monkeypatch):
        monkeypatch.setenv("AEGIS_NFS_MOUNT", "")
        g = ReadOnlyRootfsGuard()
        assert g.nfs_mount is None

    def test_skip_check_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SKIP_READONLY_CHECK", "1")
        g = ReadOnlyRootfsGuard()
        assert g.skip_check is True

    def test_skip_check_param(self):
        g = ReadOnlyRootfsGuard(skip_check=True)
        assert g.skip_check is True

    def test_not_skip_check_by_default(self, monkeypatch):
        monkeypatch.delenv("AEGIS_SKIP_READONLY_CHECK", raising=False)
        g = ReadOnlyRootfsGuard()
        assert g.skip_check is False


# ── _probe_proc_mounts ────────────────────────────────────────────────────────


class TestProbeProcMounts:
    def _make_mounts(self, content: str):
        return mock_open(read_data=content)

    def test_root_ro(self):
        content = "sysfs /sys sysfs rw,nosuid 0 0\n/dev/sda1 / ext4 ro,relatime 0 0\n"
        with patch("builtins.open", mock_open(read_data=content)):
            assert ReadOnlyRootfsGuard._probe_proc_mounts("/proc/mounts") is True

    def test_root_rw(self):
        content = "/dev/sda1 / ext4 rw,relatime 0 0\n"
        with patch("builtins.open", mock_open(read_data=content)):
            assert ReadOnlyRootfsGuard._probe_proc_mounts("/proc/mounts") is False

    def test_no_root_entry(self):
        content = "tmpfs /tmp tmpfs rw 0 0\n"
        with patch("builtins.open", mock_open(read_data=content)):
            assert ReadOnlyRootfsGuard._probe_proc_mounts("/proc/mounts") is False

    def test_file_not_found_returns_false(self):
        assert ReadOnlyRootfsGuard._probe_proc_mounts("/nonexistent/mounts") is False

    def test_root_ro_first_match_wins(self):
        content = "/dev/sda1 / ext4 ro,relatime 0 0\n/dev/sda2 / ext4 rw 0 0\n"
        with patch("builtins.open", mock_open(read_data=content)):
            # First match at "/" is ro
            assert ReadOnlyRootfsGuard._probe_proc_mounts("/proc/mounts") is True

    def test_comma_separated_options_contain_ro(self):
        content = "/dev/sda1 / xfs ro,noatime,inode64 0 0\n"
        with patch("builtins.open", mock_open(read_data=content)):
            assert ReadOnlyRootfsGuard._probe_proc_mounts("/proc/mounts") is True

    def test_overlayfs_readonly(self):
        content = "overlay / overlay ro,lowerdir=/lower 0 0\n"
        with patch("builtins.open", mock_open(read_data=content)):
            assert ReadOnlyRootfsGuard._probe_proc_mounts("/proc/mounts") is True


# ── _probe_write ──────────────────────────────────────────────────────────────


class TestProbeWrite:
    def test_writable_directory(self, tmp_path):
        assert ReadOnlyRootfsGuard._probe_write(str(tmp_path)) is True

    def test_writable_via_parent(self, tmp_path):
        subdir = tmp_path / "subdir" / "deep"
        assert ReadOnlyRootfsGuard._probe_write(str(subdir)) is True

    def test_nonexistent_path_uses_ancestor(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c"
        assert ReadOnlyRootfsGuard._probe_write(str(deep)) is True

    @pytest.mark.skipif(os.getuid() == 0, reason="root bypasses chmod restrictions")
    def test_readonly_directory_returns_false(self, tmp_path):
        ro_dir = tmp_path / "readonly"
        ro_dir.mkdir()
        os.chmod(ro_dir, stat.S_IRUSR | stat.S_IXUSR)
        try:
            result = ReadOnlyRootfsGuard._probe_write(str(ro_dir))
            assert result is False
        finally:
            os.chmod(ro_dir, stat.S_IRWXU)

    def test_completely_nonexistent_path(self):
        result = ReadOnlyRootfsGuard._probe_write("/nonexistent/path/that/cannot/exist")
        # Either False (can't write) or True (parent writable) depending on whether / is writable
        assert isinstance(result, bool)


# ── inspect() ─────────────────────────────────────────────────────────────────


class TestInspect:
    def test_skip_check_returns_clean_result(self):
        g = ReadOnlyRootfsGuard(skip_check=True)
        result = g.inspect()
        assert result.skip_check is True
        assert result.rootfs_readonly is False
        assert result.proc_mounts_readonly is False
        assert result.write_probe_failed is False

    def test_nfs_mount_used_as_base_in_result(self):
        g = ReadOnlyRootfsGuard(skip_check=True, nfs_mount="/nfs/aegis")
        result = g.inspect()
        assert result.tmpfs_base == "/nfs/aegis"

    def test_tmpfs_base_used_when_no_nfs(self):
        g = ReadOnlyRootfsGuard(skip_check=True, tmpfs_base="/custom/tmp")
        result = g.inspect()
        assert result.tmpfs_base == "/custom/tmp"

    def test_proc_mounts_ro_sets_rootfs_readonly(self, tmp_path):
        g = ReadOnlyRootfsGuard(tmpfs_base=str(tmp_path), skip_check=False)
        with patch.object(ReadOnlyRootfsGuard, "_probe_proc_mounts", return_value=True):
            with patch.object(ReadOnlyRootfsGuard, "_probe_write", return_value=True):
                result = g.inspect()
        assert result.proc_mounts_readonly is True
        assert result.rootfs_readonly is True

    def test_write_probe_failure_sets_rootfs_readonly(self, tmp_path):
        g = ReadOnlyRootfsGuard(tmpfs_base=str(tmp_path), skip_check=False)
        with patch.object(ReadOnlyRootfsGuard, "_probe_proc_mounts", return_value=False):
            with patch.object(ReadOnlyRootfsGuard, "_probe_write", return_value=False):
                result = g.inspect()
        assert result.write_probe_failed is True
        assert result.rootfs_readonly is True

    def test_both_probes_ok_not_readonly(self, tmp_path):
        g = ReadOnlyRootfsGuard(tmpfs_base=str(tmp_path), skip_check=False)
        with patch.object(ReadOnlyRootfsGuard, "_probe_proc_mounts", return_value=False):
            with patch.object(ReadOnlyRootfsGuard, "_probe_write", return_value=True):
                result = g.inspect()
        assert result.rootfs_readonly is False
        assert result.write_probe_failed is False

    def test_to_dict_round_trip(self):
        g = ReadOnlyRootfsGuard(skip_check=True)
        d = g.inspect().to_dict()
        assert d["skip_check"] is True
        assert d["rootfs_readonly"] is False


# ── resolve() ────────────────────────────────────────────────────────────────


class TestResolve:
    def test_writable_preferred_path_returned_unchanged(self, tmp_path):
        preferred = str(tmp_path / "wal")
        (tmp_path / "wal").mkdir()
        g = ReadOnlyRootfsGuard(tmpfs_base=str(tmp_path / "fallback"), skip_check=False)
        result = g.resolve(preferred, label="wal")
        assert result.redirected is False
        assert result.path == Path(preferred)
        assert result.label == "wal"

    def test_unwritable_path_redirected_to_tmpfs(self, tmp_path):
        fallback = tmp_path / "fallback"
        fallback.mkdir()
        g = ReadOnlyRootfsGuard(tmpfs_base=str(fallback), skip_check=False)
        with patch.object(ReadOnlyRootfsGuard, "_probe_write", return_value=False):
            result = g.resolve("/var/lib/aegis/wal", label="wal")
        assert result.redirected is True
        assert result.fallback_base == str(fallback)
        # Path should be under fallback base
        assert str(result.path).startswith(str(fallback))

    def test_unwritable_path_creates_directories(self, tmp_path):
        fallback = tmp_path / "fallback"
        fallback.mkdir()
        g = ReadOnlyRootfsGuard(tmpfs_base=str(fallback), skip_check=False)
        with patch.object(ReadOnlyRootfsGuard, "_probe_write", return_value=False):
            result = g.resolve("/var/lib/aegis/wal", label="wal")
        assert result.path.is_dir()

    def test_nfs_mount_takes_precedence_over_tmpfs(self, tmp_path):
        nfs = tmp_path / "nfs"
        nfs.mkdir()
        fallback = tmp_path / "fallback"
        fallback.mkdir()
        g = ReadOnlyRootfsGuard(tmpfs_base=str(fallback), nfs_mount=str(nfs), skip_check=False)
        with patch.object(ReadOnlyRootfsGuard, "_probe_write", return_value=False):
            result = g.resolve("/var/lib/aegis/wal", label="wal")
        assert str(result.path).startswith(str(nfs))
        assert result.fallback_base == str(nfs)

    def test_skip_check_always_returns_preferred(self, tmp_path):
        g = ReadOnlyRootfsGuard(tmpfs_base=str(tmp_path), skip_check=True)
        preferred = "/var/lib/aegis/wal"
        result = g.resolve(preferred, label="wal")
        assert result.redirected is False
        assert result.path == Path(preferred)

    def test_resolve_default_label(self, tmp_path):
        g = ReadOnlyRootfsGuard(tmpfs_base=str(tmp_path), skip_check=True)
        result = g.resolve(str(tmp_path))
        assert result.label == "path"

    def test_resolve_relative_path_under_fallback(self, tmp_path):
        fallback = tmp_path / "fallback"
        fallback.mkdir()
        g = ReadOnlyRootfsGuard(tmpfs_base=str(fallback), skip_check=False)
        with patch.object(ReadOnlyRootfsGuard, "_probe_write", return_value=False):
            result = g.resolve("/var/lib/aegis/wal", label="wal")
        # The redirected path should include the original path components
        assert "var" in str(result.path) or str(result.path).startswith(str(fallback))


# ── is_readonly() ─────────────────────────────────────────────────────────────


class TestIsReadonly:
    def test_is_readonly_false_when_skip(self):
        g = ReadOnlyRootfsGuard(skip_check=True)
        assert g.is_readonly() is False

    def test_is_readonly_true_when_proc_mounts_ro(self, tmp_path):
        g = ReadOnlyRootfsGuard(tmpfs_base=str(tmp_path), skip_check=False)
        with patch.object(ReadOnlyRootfsGuard, "_probe_proc_mounts", return_value=True):
            with patch.object(ReadOnlyRootfsGuard, "_probe_write", return_value=True):
                assert g.is_readonly() is True

    def test_is_readonly_false_when_both_probes_ok(self, tmp_path):
        g = ReadOnlyRootfsGuard(tmpfs_base=str(tmp_path), skip_check=False)
        with patch.object(ReadOnlyRootfsGuard, "_probe_proc_mounts", return_value=False):
            with patch.object(ReadOnlyRootfsGuard, "_probe_write", return_value=True):
                assert g.is_readonly() is False


# ── Integration: multiple paths resolved ──────────────────────────────────────


class TestMultiplePathResolution:
    def test_resolve_wal_and_logs(self, tmp_path):
        g = ReadOnlyRootfsGuard(tmpfs_base=str(tmp_path), skip_check=True)
        wal_result = g.resolve(str(tmp_path / "wal"), label="wal")
        log_result = g.resolve(str(tmp_path / "logs"), label="logs")
        assert wal_result.label == "wal"
        assert log_result.label == "logs"
        assert not wal_result.redirected
        assert not log_result.redirected

    def test_all_paths_redirected_when_unwritable(self, tmp_path):
        fallback = tmp_path / "fallback"
        fallback.mkdir()
        g = ReadOnlyRootfsGuard(tmpfs_base=str(fallback), skip_check=False)
        results = []
        with patch.object(ReadOnlyRootfsGuard, "_probe_write", return_value=False):
            for label, path in [("wal", "/var/lib/aegis/wal"), ("logs", "/var/log/aegis")]:
                results.append(g.resolve(path, label=label))
        assert all(r.redirected for r in results)
        assert all(str(r.path).startswith(str(fallback)) for r in results)
