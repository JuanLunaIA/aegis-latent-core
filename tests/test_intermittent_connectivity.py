# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.intermittent_connectivity."""

from __future__ import annotations

import json
import os

from aegis.core.intermittent_connectivity import (
    _DEFAULT_BYTES_THRESHOLD,
    _DEFAULT_ENTRY_THRESHOLD,
    BackpressureStatus,
    WALBackpressureMonitor,
)

# ── BackpressureStatus ────────────────────────────────────────────────────────


class TestBackpressureStatus:
    def test_defaults_inactive(self):
        s = BackpressureStatus(
            active=False,
            entry_count=0,
            entry_threshold=1000,
            size_bytes=0,
            size_threshold_bytes=100 * 1024 * 1024,
        )
        assert s.active is False
        assert s.signal_reasons == []
        assert s.wal_path == ""

    def test_to_dict_keys(self):
        s = BackpressureStatus(
            active=True,
            entry_count=1500,
            entry_threshold=1000,
            size_bytes=200,
            size_threshold_bytes=100,
            signal_reasons=["entry_count=1500 >= threshold=1000"],
            wal_path="/tmp/test.wal",
        )
        d = s.to_dict()
        assert d["active"] is True
        assert d["entry_count"] == 1500
        assert d["entry_threshold"] == 1000
        assert d["size_bytes"] == 200
        assert d["size_threshold_bytes"] == 100
        assert d["signal_reasons"] == ["entry_count=1500 >= threshold=1000"]
        assert d["wal_path"] == "/tmp/test.wal"

    def test_to_dict_all_keys_present(self):
        s = BackpressureStatus(
            active=False, entry_count=0, entry_threshold=1, size_bytes=0, size_threshold_bytes=1
        )
        keys = set(s.to_dict().keys())
        assert keys == {
            "active",
            "entry_count",
            "entry_threshold",
            "size_bytes",
            "size_threshold_bytes",
            "signal_reasons",
            "wal_path",
        }


# ── WALBackpressureMonitor construction ──────────────────────────────────────


class TestMonitorConstruction:
    def test_defaults(self, tmp_path):
        m = WALBackpressureMonitor(wal_path=str(tmp_path / "audit.wal"))
        assert m.entry_threshold == _DEFAULT_ENTRY_THRESHOLD
        assert m.bytes_threshold == _DEFAULT_BYTES_THRESHOLD

    def test_explicit_thresholds(self, tmp_path):
        m = WALBackpressureMonitor(
            wal_path=str(tmp_path / "audit.wal"),
            entry_threshold=500,
            bytes_threshold=50 * 1024,
        )
        assert m.entry_threshold == 500
        assert m.bytes_threshold == 50 * 1024

    def test_entry_threshold_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGIS_WAL_BACKPRESSURE_THRESHOLD", "250")
        m = WALBackpressureMonitor(wal_path=str(tmp_path / "audit.wal"))
        assert m.entry_threshold == 250

    def test_bytes_threshold_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGIS_WAL_BACKPRESSURE_BYTES", "1048576")
        m = WALBackpressureMonitor(wal_path=str(tmp_path / "audit.wal"))
        assert m.bytes_threshold == 1048576

    def test_invalid_entry_threshold_env_uses_default(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGIS_WAL_BACKPRESSURE_THRESHOLD", "notanumber")
        m = WALBackpressureMonitor(wal_path=str(tmp_path / "audit.wal"))
        assert m.entry_threshold == _DEFAULT_ENTRY_THRESHOLD

    def test_invalid_bytes_threshold_env_uses_default(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGIS_WAL_BACKPRESSURE_BYTES", "bad")
        m = WALBackpressureMonitor(wal_path=str(tmp_path / "audit.wal"))
        assert m.bytes_threshold == _DEFAULT_BYTES_THRESHOLD

    def test_explicit_overrides_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGIS_WAL_BACKPRESSURE_THRESHOLD", "999")
        m = WALBackpressureMonitor(wal_path=str(tmp_path / "audit.wal"), entry_threshold=42)
        assert m.entry_threshold == 42

    def test_threshold_clamped_to_minimum_1(self, tmp_path):
        m = WALBackpressureMonitor(
            wal_path=str(tmp_path / "audit.wal"),
            entry_threshold=0,
            bytes_threshold=0,
        )
        assert m.entry_threshold == 1
        assert m.bytes_threshold == 1

    def test_wal_path_stored(self, tmp_path):
        p = str(tmp_path / "audit.wal")
        m = WALBackpressureMonitor(wal_path=p)
        assert m.wal_path == p


# ── check() — no WAL ─────────────────────────────────────────────────────────


class TestCheckNoWAL:
    def test_no_wal_file_no_backpressure(self, tmp_path):
        m = WALBackpressureMonitor(
            wal_path=str(tmp_path / "missing.wal"),
            entry_threshold=10,
            bytes_threshold=1024,
        )
        status = m.check()
        assert status.active is False
        assert status.entry_count == 0
        assert status.size_bytes == 0

    def test_no_wal_status_wal_path(self, tmp_path):
        p = str(tmp_path / "missing.wal")
        m = WALBackpressureMonitor(wal_path=p, entry_threshold=10, bytes_threshold=1024)
        status = m.check()
        assert status.wal_path == p

    def test_no_wal_thresholds_preserved(self, tmp_path):
        m = WALBackpressureMonitor(
            wal_path=str(tmp_path / "missing.wal"),
            entry_threshold=42,
            bytes_threshold=999,
        )
        status = m.check()
        assert status.entry_threshold == 42
        assert status.size_threshold_bytes == 999


# ── check() — below thresholds ────────────────────────────────────────────────


class TestCheckBelowThreshold:
    def _write_wal(self, path, n_entries):
        with open(path, "w") as f:
            for i in range(n_entries):
                f.write(json.dumps({"index": i}) + "\n")

    def test_below_both_thresholds(self, tmp_path):
        p = tmp_path / "audit.wal"
        self._write_wal(str(p), 5)
        m = WALBackpressureMonitor(str(p), entry_threshold=100, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.active is False
        assert status.entry_count == 5
        assert status.signal_reasons == []

    def test_exactly_at_threshold_is_active(self, tmp_path):
        p = tmp_path / "audit.wal"
        self._write_wal(str(p), 10)
        m = WALBackpressureMonitor(str(p), entry_threshold=10, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.active is True

    def test_one_below_threshold_inactive(self, tmp_path):
        p = tmp_path / "audit.wal"
        self._write_wal(str(p), 9)
        m = WALBackpressureMonitor(str(p), entry_threshold=10, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.active is False

    def test_empty_wal_no_backpressure(self, tmp_path):
        p = tmp_path / "audit.wal"
        p.write_text("")
        m = WALBackpressureMonitor(str(p), entry_threshold=1, bytes_threshold=1024)
        status = m.check()
        assert status.active is False
        assert status.entry_count == 0

    def test_whitespace_lines_not_counted(self, tmp_path):
        p = tmp_path / "audit.wal"
        p.write_text("\n\n\n")
        m = WALBackpressureMonitor(str(p), entry_threshold=1, bytes_threshold=1024)
        status = m.check()
        assert status.entry_count == 0


# ── check() — entry threshold exceeded ───────────────────────────────────────


class TestCheckEntryThreshold:
    def _write_wal(self, path, n_entries):
        with open(path, "w") as f:
            for i in range(n_entries):
                f.write(json.dumps({"index": i}) + "\n")

    def test_entry_threshold_exceeded(self, tmp_path):
        p = tmp_path / "audit.wal"
        self._write_wal(str(p), 20)
        m = WALBackpressureMonitor(str(p), entry_threshold=10, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.active is True
        assert status.entry_count == 20
        assert any("entry_count" in r for r in status.signal_reasons)

    def test_entry_count_accurate(self, tmp_path):
        p = tmp_path / "audit.wal"
        self._write_wal(str(p), 50)
        m = WALBackpressureMonitor(str(p), entry_threshold=1000, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.entry_count == 50

    def test_signal_reasons_mention_threshold(self, tmp_path):
        p = tmp_path / "audit.wal"
        self._write_wal(str(p), 15)
        m = WALBackpressureMonitor(str(p), entry_threshold=10, bytes_threshold=1024 * 1024)
        status = m.check()
        assert any("threshold=10" in r for r in status.signal_reasons)


# ── check() — byte threshold exceeded ────────────────────────────────────────


class TestCheckByteThreshold:
    def test_byte_threshold_exceeded(self, tmp_path):
        p = tmp_path / "audit.wal"
        # Write 200 bytes of content
        p.write_text("x" * 200)
        m = WALBackpressureMonitor(str(p), entry_threshold=10000, bytes_threshold=100)
        status = m.check()
        assert status.active is True
        assert status.size_bytes >= 200
        assert any("size_bytes" in r for r in status.signal_reasons)

    def test_size_bytes_reported(self, tmp_path):
        p = tmp_path / "audit.wal"
        data = "x" * 1024
        p.write_text(data)
        m = WALBackpressureMonitor(str(p), entry_threshold=10000, bytes_threshold=999999)
        status = m.check()
        assert status.size_bytes == len(data.encode())


# ── check() — both thresholds exceeded ────────────────────────────────────────


class TestCheckBothThresholds:
    def test_both_thresholds_two_reasons(self, tmp_path):
        p = tmp_path / "audit.wal"
        content = "\n".join(json.dumps({"i": i}) for i in range(20)) + "\n"
        p.write_text(content)
        m = WALBackpressureMonitor(str(p), entry_threshold=10, bytes_threshold=10)
        status = m.check()
        assert status.active is True
        assert len(status.signal_reasons) == 2


# ── check() — WAL segments ────────────────────────────────────────────────────


class TestCheckSegments:
    def _write_seg(self, path, n_entries):
        with open(str(path), "w") as f:
            for i in range(n_entries):
                f.write(json.dumps({"index": i}) + "\n")

    def test_segments_included_in_count(self, tmp_path):
        wal = tmp_path / "audit.wal"
        seg0 = tmp_path / "audit.wal.000001"
        seg1 = tmp_path / "audit.wal.000002"
        self._write_seg(seg0, 5)
        self._write_seg(seg1, 3)
        self._write_seg(wal, 7)
        m = WALBackpressureMonitor(str(wal), entry_threshold=1000, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.entry_count == 15

    def test_segments_included_in_bytes(self, tmp_path):
        wal = tmp_path / "audit.wal"
        seg = tmp_path / "audit.wal.000001"
        seg.write_text("a" * 100)
        wal.write_text("b" * 200)
        m = WALBackpressureMonitor(str(wal), entry_threshold=1000, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.size_bytes == 300

    def test_non_segment_files_excluded(self, tmp_path):
        wal = tmp_path / "audit.wal"
        other = tmp_path / "audit.wal.bak"  # .bak is not a digit-only suffix
        self._write_seg(wal, 3)
        self._write_seg(other, 50)
        m = WALBackpressureMonitor(str(wal), entry_threshold=1000, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.entry_count == 3

    def test_segment_threshold_trigger(self, tmp_path):
        wal = tmp_path / "audit.wal"
        seg = tmp_path / "audit.wal.000001"
        self._write_seg(seg, 6)
        self._write_seg(wal, 5)
        m = WALBackpressureMonitor(str(wal), entry_threshold=10, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.active is True
        assert status.entry_count == 11


# ── check() — only active WAL, no segments ────────────────────────────────────


class TestCheckActiveOnly:
    def test_only_active_wal_counted(self, tmp_path):
        wal = tmp_path / "audit.wal"
        with open(str(wal), "w") as f:
            for i in range(7):
                f.write(json.dumps({"i": i}) + "\n")
        m = WALBackpressureMonitor(str(wal), entry_threshold=100, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.entry_count == 7


# ── check() — I/O errors gracefully handled ──────────────────────────────────


class TestCheckIOErrors:
    def test_missing_dir_returns_zero(self, tmp_path):
        m = WALBackpressureMonitor(
            wal_path=str(tmp_path / "nonexistent" / "audit.wal"),
            entry_threshold=10,
            bytes_threshold=1024,
        )
        status = m.check()
        assert status.entry_count == 0
        assert status.size_bytes == 0
        assert status.active is False


# ── check() result fields ─────────────────────────────────────────────────────


class TestCheckFields:
    def test_status_has_correct_wal_path(self, tmp_path):
        p = str(tmp_path / "audit.wal")
        m = WALBackpressureMonitor(wal_path=p, entry_threshold=10, bytes_threshold=1024)
        status = m.check()
        assert status.wal_path == p

    def test_inactive_signal_reasons_empty(self, tmp_path):
        p = tmp_path / "audit.wal"
        p.write_text('{"a": 1}\n')
        m = WALBackpressureMonitor(str(p), entry_threshold=1000, bytes_threshold=1024 * 1024)
        status = m.check()
        assert status.signal_reasons == []

    def test_to_dict_active(self, tmp_path):
        p = tmp_path / "audit.wal"
        with open(str(p), "w") as f:
            for i in range(20):
                f.write(json.dumps({"i": i}) + "\n")
        m = WALBackpressureMonitor(str(p), entry_threshold=10, bytes_threshold=1024 * 1024)
        d = m.check().to_dict()
        assert d["active"] is True
        assert isinstance(d["signal_reasons"], list)


# ── _all_segment_paths ────────────────────────────────────────────────────────


class TestAllSegmentPaths:
    def test_returns_sorted_segments_then_active(self, tmp_path):
        wal = tmp_path / "audit.wal"
        seg1 = tmp_path / "audit.wal.000001"
        seg3 = tmp_path / "audit.wal.000003"
        for f in [wal, seg1, seg3]:
            f.write_text("")
        m = WALBackpressureMonitor(str(wal), entry_threshold=10, bytes_threshold=1024)
        paths = m._all_segment_paths()
        assert paths[-1] == str(wal)
        assert str(seg1) in paths
        assert str(seg3) in paths
        assert paths.index(str(seg1)) < paths.index(str(seg3))

    def test_no_active_wal_only_segments(self, tmp_path):
        wal = tmp_path / "audit.wal"
        seg = tmp_path / "audit.wal.000001"
        seg.write_text("")
        # active WAL absent
        m = WALBackpressureMonitor(str(wal), entry_threshold=10, bytes_threshold=1024)
        paths = m._all_segment_paths()
        assert str(seg) in paths
        assert str(wal) not in paths

    def test_no_wal_no_segments(self, tmp_path):
        m = WALBackpressureMonitor(
            str(tmp_path / "missing.wal"), entry_threshold=10, bytes_threshold=1024
        )
        assert m._all_segment_paths() == []


# ── _inspect_file ─────────────────────────────────────────────────────────────


class TestInspectFile:
    def test_counts_non_empty_lines(self, tmp_path):
        p = tmp_path / "seg.wal"
        p.write_text('{"a":1}\n{"b":2}\n\n{"c":3}\n')
        m = WALBackpressureMonitor(str(p), entry_threshold=10, bytes_threshold=1024)
        count, size = m._inspect_file(str(p))
        assert count == 3

    def test_size_bytes_matches_file_size(self, tmp_path):
        p = tmp_path / "seg.wal"
        content = "hello\nworld\n"
        p.write_text(content)
        m = WALBackpressureMonitor(str(p), entry_threshold=10, bytes_threshold=1024)
        _, size = m._inspect_file(str(p))
        assert size == os.path.getsize(str(p))

    def test_missing_file_returns_zero(self, tmp_path):
        m = WALBackpressureMonitor(
            str(tmp_path / "audit.wal"), entry_threshold=10, bytes_threshold=1024
        )
        count, size = m._inspect_file(str(tmp_path / "nonexistent.wal"))
        assert count == 0
        assert size == 0
