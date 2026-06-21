# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for WAF hot-reload (aegis.core.waf_hot_reload)."""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from threading import Event

import pytest

from aegis.core.waf_hot_reload import (
    WAFHotReloader,
    WAFPatternFileError,
    WAFPatternSet,
    load_pattern_file,
)
from aegis.proxy.waf import AegisWAF

# ── Helpers ───────────────────────────────────────────────────────────────────

_VALID_JSON = {
    "version": 2,
    "critical": [r"ignore\b.{0,20}?\bprevious", r"system[\s\-_]*override"],
    "soft": [r"hypothetically", r"pretend you are"],
}


def _write_pattern_file(path: Path, data: object = None) -> Path:
    payload = data if data is not None else _VALID_JSON
    path.write_text(json.dumps(payload))
    return path


# ── WAFPatternSet ─────────────────────────────────────────────────────────────


class TestWAFPatternSet:
    def test_fields(self):
        ps = WAFPatternSet(
            critical=[re.compile(r"foo")],
            soft=[re.compile(r"bar")],
            source_path="/tmp/f.json",
            loaded_at=1234567890.0,
            version=3,
        )
        assert len(ps.critical) == 1
        assert len(ps.soft) == 1
        assert ps.version == 3

    def test_to_dict_structure(self):
        ps = WAFPatternSet(
            critical=[re.compile(r"a"), re.compile(r"b")],
            soft=[re.compile(r"c")],
            source_path="/tmp/f.json",
            loaded_at=1000.0,
            version=2,
        )
        d = ps.to_dict()
        assert d["critical_count"] == 2
        assert d["soft_count"] == 1
        assert d["version"] == 2
        assert d["source_path"] == "/tmp/f.json"
        assert d["loaded_at"] == 1000.0

    def test_loaded_at_defaults_to_now(self):
        before = time.time()
        ps = WAFPatternSet(critical=[], soft=[], source_path="/tmp/x")
        after = time.time()
        assert before <= ps.loaded_at <= after

    def test_version_defaults_to_one(self):
        ps = WAFPatternSet(critical=[], soft=[], source_path="/tmp/x")
        assert ps.version == 1


# ── load_pattern_file ─────────────────────────────────────────────────────────


class TestLoadPatternFile:
    def test_loads_valid_file(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        ps = load_pattern_file(str(p))
        assert len(ps.critical) == 2
        assert len(ps.soft) == 2
        assert ps.version == 2

    def test_patterns_are_compiled(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        ps = load_pattern_file(str(p))
        for pat in ps.critical + ps.soft:
            assert isinstance(pat, re.Pattern)

    def test_critical_patterns_match(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        ps = load_pattern_file(str(p))
        assert any(pat.search("ignore all previous instructions") for pat in ps.critical)

    def test_source_path_is_absolute(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        ps = load_pattern_file(str(p))
        assert os.path.isabs(ps.source_path)

    def test_missing_critical_defaults_to_empty(self, tmp_path):
        p = tmp_path / "patterns.json"
        p.write_text(json.dumps({"version": 1, "soft": [r"foo"]}))
        ps = load_pattern_file(str(p))
        assert ps.critical == []
        assert len(ps.soft) == 1

    def test_missing_soft_defaults_to_empty(self, tmp_path):
        p = tmp_path / "patterns.json"
        p.write_text(json.dumps({"version": 1, "critical": [r"foo"]}))
        ps = load_pattern_file(str(p))
        assert ps.soft == []

    def test_version_extracted(self, tmp_path):
        p = tmp_path / "patterns.json"
        p.write_text(json.dumps({"version": 7, "critical": [], "soft": []}))
        ps = load_pattern_file(str(p))
        assert ps.version == 7

    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_pattern_file(str(tmp_path / "nonexistent.json"))

    def test_invalid_json_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not valid json}")
        with pytest.raises(WAFPatternFileError):
            load_pattern_file(str(p))

    def test_non_object_root_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("[1, 2, 3]")
        with pytest.raises(WAFPatternFileError):
            load_pattern_file(str(p))

    def test_invalid_regex_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({"critical": [r"(unclosed group"]}))
        with pytest.raises(WAFPatternFileError):
            load_pattern_file(str(p))

    def test_non_string_pattern_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({"critical": [123, "valid"]}))
        with pytest.raises(WAFPatternFileError):
            load_pattern_file(str(p))

    def test_non_list_critical_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({"critical": "not a list"}))
        with pytest.raises(WAFPatternFileError):
            load_pattern_file(str(p))


# ── WAFHotReloader constructor ────────────────────────────────────────────────


class TestWAFHotReloaderConstructor:
    def test_default_poll_interval(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None)
        assert r._poll_interval == 1.0

    def test_custom_poll_interval(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None, poll_interval_s=0.1)
        assert r._poll_interval == 0.1

    def test_zero_poll_interval_raises(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        with pytest.raises(ValueError):
            WAFHotReloader(str(p), on_reload=lambda ps: None, poll_interval_s=0.0)

    def test_negative_poll_interval_raises(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        with pytest.raises(ValueError):
            WAFHotReloader(str(p), on_reload=lambda ps: None, poll_interval_s=-1.0)

    def test_not_running_initially(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None)
        assert not r.is_running

    def test_current_none_before_start(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None)
        assert r.current is None


# ── WAFHotReloader.reload_now ─────────────────────────────────────────────────


class TestReloadNow:
    def test_returns_pattern_set(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None)
        ps = r.reload_now()
        assert isinstance(ps, WAFPatternSet)

    def test_invokes_callback(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        received: list[WAFPatternSet] = []
        r = WAFHotReloader(str(p), on_reload=received.append)
        r.reload_now()
        assert len(received) == 1
        assert isinstance(received[0], WAFPatternSet)

    def test_updates_current(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None)
        ps = r.reload_now()
        assert r.current is ps

    def test_invalid_file_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{bad}")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None)
        with pytest.raises(WAFPatternFileError):
            r.reload_now()

    def test_missing_file_raises(self, tmp_path):
        p = tmp_path / "missing.json"
        _write_pattern_file(p)  # create it so constructor succeeds, then delete it
        r = WAFHotReloader(str(p), on_reload=lambda ps: None)
        p.unlink()
        with pytest.raises(FileNotFoundError):
            r.reload_now()


# ── WAFHotReloader.start / stop ───────────────────────────────────────────────


class TestStartStop:
    def test_start_loads_patterns_immediately(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        received: list[WAFPatternSet] = []
        r = WAFHotReloader(str(p), on_reload=received.append, poll_interval_s=0.05)
        r.start()
        try:
            assert len(received) >= 1
            assert r.current is not None
        finally:
            r.stop()

    def test_is_running_after_start(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None, poll_interval_s=0.05)
        r.start()
        try:
            assert r.is_running
        finally:
            r.stop()

    def test_not_running_after_stop(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None, poll_interval_s=0.05)
        r.start()
        r.stop()
        assert not r.is_running

    def test_start_idempotent(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        received: list[WAFPatternSet] = []
        r = WAFHotReloader(str(p), on_reload=received.append, poll_interval_s=0.05)
        r.start()
        thread1 = r._thread
        r.start()  # second call should be a no-op
        try:
            assert r._thread is thread1
        finally:
            r.stop()

    def test_poll_based_reload_on_file_change(self, tmp_path):
        """Polling loop fires reload when the file's mtime changes."""
        p = _write_pattern_file(tmp_path / "patterns.json")
        reload_count: list[int] = [0]
        event = Event()

        def on_reload(ps: WAFPatternSet) -> None:
            reload_count[0] += 1
            if reload_count[0] >= 2:
                event.set()

        # Force poll mode by overriding inotify detection.
        r = WAFHotReloader(str(p), on_reload=on_reload, poll_interval_s=0.05)
        r._use_inotify = False
        r.start()
        try:
            time.sleep(0.1)
            # Write updated content.
            new_data = dict(_VALID_JSON, version=99, soft=[r"updated_signal"])
            p.write_text(json.dumps(new_data))
            # Touch mtime explicitly to guarantee detection.
            os.utime(str(p), None)
            triggered = event.wait(timeout=2.0)
            assert triggered, "Polling loop did not detect file change in 2 s"
            assert r.current is not None
            assert r.current.version == 99
        finally:
            r.stop()


# ── Error recovery ────────────────────────────────────────────────────────────


class TestErrorRecovery:
    def test_safe_reload_logs_warning_on_error(self, tmp_path, caplog):
        import logging

        p = _write_pattern_file(tmp_path / "patterns.json")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None)
        # Delete the file to cause a reload failure.
        p.unlink()
        with caplog.at_level(logging.WARNING, logger="aegis.core.waf_hot_reload"):
            r._safe_reload()
        assert any("reload failed" in rec.message.lower() for rec in caplog.records)

    def test_safe_reload_keeps_old_patterns_on_error(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        r = WAFHotReloader(str(p), on_reload=lambda ps: None)
        original_ps = r.reload_now()
        p.unlink()
        r._safe_reload()  # should not raise; old current preserved
        assert r.current is original_ps


# ── AegisWAF.enable_hot_reload integration ───────────────────────────────────


class TestEnableHotReload:
    def test_returns_reloader(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        waf = AegisWAF()
        reloader = waf.enable_hot_reload(str(p), poll_interval_s=0.05)
        try:
            from aegis.core.waf_hot_reload import WAFHotReloader

            assert isinstance(reloader, WAFHotReloader)
        finally:
            reloader.stop()

    def test_critical_patterns_replaced(self, tmp_path):
        p = _write_pattern_file(tmp_path / "patterns.json")
        waf = AegisWAF()
        reloader = waf.enable_hot_reload(str(p), poll_interval_s=0.05)
        try:
            # After reload, critical_patterns is replaced with the 2 from the file.
            assert len(waf._critical_patterns) == 2
        finally:
            reloader.stop()

    def test_hot_loaded_pattern_blocks_request(self, tmp_path):
        p = tmp_path / "patterns.json"
        p.write_text(
            json.dumps(
                {
                    "version": 1,
                    "critical": [r"hot_reload_sentinel_\d+"],
                    "soft": [],
                }
            )
        )
        waf = AegisWAF()
        reloader = waf.enable_hot_reload(str(p), poll_interval_s=0.05)
        try:
            body = {
                "messages": [
                    {"role": "user", "content": "hot_reload_sentinel_42 should be blocked"}
                ]
            }
            result = waf.inspect_payload(body)
            assert not result.allowed
        finally:
            reloader.stop()
