# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.export_audit_log — tamper-evident compliance export log."""

from __future__ import annotations

import json
import os
import stat

import pytest

from aegis.core.export_audit_log import (
    ExportAuditLog,
    ExportLogEntry,
    _sign_entry,
    _verify_entry_sig,
)

_KEY = "test-signing-key-32bytes-xyzzy1234"


def _log(tmp_path, key: str = _KEY) -> ExportAuditLog:
    return ExportAuditLog(tmp_path / "export_audit.jsonl", signing_key=key)


# ── Construction ──────────────────────────────────────────────────────────────


class TestConstruction:
    def test_creates_file(self, tmp_path):
        log = _log(tmp_path)
        assert log.path.exists()

    def test_file_mode_0o600(self, tmp_path):
        log = _log(tmp_path)
        mode = stat.S_IMODE(os.stat(log.path).st_mode)
        assert mode == 0o600

    def test_enforces_0o600_on_existing_wide_file(self, tmp_path):
        p = tmp_path / "export_audit.jsonl"
        p.touch(mode=0o644)
        ExportAuditLog(p, signing_key=_KEY)
        mode = stat.S_IMODE(os.stat(p).st_mode)
        assert mode == 0o600

    def test_empty_signing_key_raises(self, tmp_path):
        with pytest.raises(ValueError, match="signing_key"):
            ExportAuditLog(tmp_path / "log.jsonl", signing_key="")

    def test_initial_entry_count_zero(self, tmp_path):
        log = _log(tmp_path)
        assert log.entry_count == 0

    def test_creates_parent_dirs(self, tmp_path):
        log = ExportAuditLog(
            tmp_path / "nested" / "deep" / "export_audit.jsonl",
            signing_key=_KEY,
        )
        assert log.path.exists()


# ── record() ─────────────────────────────────────────────────────────────────


class TestRecord:
    def test_record_returns_entry(self, tmp_path):
        log = _log(tmp_path)
        entry = log.record(operator="alice", package_id="pkg-1")
        assert isinstance(entry, ExportLogEntry)

    def test_entry_index_starts_at_zero(self, tmp_path):
        log = _log(tmp_path)
        e = log.record(operator="alice", package_id="pkg-1")
        assert e.index == 0

    def test_subsequent_entries_increment_index(self, tmp_path):
        log = _log(tmp_path)
        e0 = log.record(operator="a", package_id="p0")
        e1 = log.record(operator="b", package_id="p1")
        e2 = log.record(operator="c", package_id="p2")
        assert e0.index == 0
        assert e1.index == 1
        assert e2.index == 2

    def test_entry_count_matches_records(self, tmp_path):
        log = _log(tmp_path)
        for i in range(5):
            log.record(operator="alice", package_id=f"pkg-{i}")
        assert log.entry_count == 5

    def test_entry_sig_non_empty(self, tmp_path):
        log = _log(tmp_path)
        e = log.record(operator="alice", package_id="pkg-1")
        assert e.entry_sig != ""

    def test_operator_stored(self, tmp_path):
        log = _log(tmp_path)
        e = log.record(operator="bob@example.org", package_id="pkg-1")
        assert e.operator == "bob@example.org"

    def test_package_id_stored(self, tmp_path):
        log = _log(tmp_path)
        e = log.record(operator="alice", package_id="my-uuid-123")
        assert e.package_id == "my-uuid-123"

    def test_client_ip_default_unknown(self, tmp_path):
        log = _log(tmp_path)
        e = log.record(operator="alice", package_id="pkg")
        assert e.client_ip == "unknown"

    def test_client_ip_stored(self, tmp_path):
        log = _log(tmp_path)
        e = log.record(operator="alice", package_id="pkg", client_ip="192.168.1.1")
        assert e.client_ip == "192.168.1.1"

    def test_api_key_hash_stored(self, tmp_path):
        log = _log(tmp_path)
        e = log.record(operator="alice", package_id="pkg", api_key_hash="sha256:deadbeef")
        assert e.api_key_hash == "sha256:deadbeef"

    def test_node_count_stored(self, tmp_path):
        log = _log(tmp_path)
        e = log.record(operator="alice", package_id="pkg", node_count=42)
        assert e.node_count == 42

    def test_extra_stored(self, tmp_path):
        log = _log(tmp_path)
        e = log.record(operator="alice", package_id="pkg", extra={"reason": "audit"})
        assert e.extra == {"reason": "audit"}

    def test_custom_timestamp_stored(self, tmp_path):
        log = _log(tmp_path)
        ts = "2026-01-01T00:00:00+00:00"
        e = log.record(operator="alice", package_id="pkg", timestamp_iso=ts)
        assert e.timestamp_iso == ts

    def test_record_persists_to_file(self, tmp_path):
        log = _log(tmp_path)
        log.record(operator="alice", package_id="pkg-1")
        with log.path.open() as fh:
            lines = [ln for ln in fh if ln.strip()]
        assert len(lines) == 1

    def test_record_is_valid_json(self, tmp_path):
        log = _log(tmp_path)
        log.record(operator="alice", package_id="pkg-1")
        with log.path.open() as fh:
            data = json.loads(fh.readline().strip())
        assert "entry_sig" in data


# ── HMAC signing ─────────────────────────────────────────────────────────────


class TestHMACSigning:
    def _entry(self) -> ExportLogEntry:
        return ExportLogEntry(
            index=0,
            timestamp_iso="2026-01-01T00:00:00+00:00",
            operator="alice",
            package_id="pkg-1",
            client_ip="10.0.0.1",
            api_key_hash="sha256:abc",
            node_count=10,
            extra={},
        )

    def test_sign_returns_hex_string(self):
        e = self._entry()
        sig = _sign_entry(e, _KEY.encode())
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA-256 hex

    def test_verify_accepts_correct_sig(self):
        e = self._entry()
        e.entry_sig = _sign_entry(e, _KEY.encode())
        assert _verify_entry_sig(e, _KEY.encode()) is True

    def test_verify_rejects_wrong_key(self):
        e = self._entry()
        e.entry_sig = _sign_entry(e, _KEY.encode())
        assert _verify_entry_sig(e, b"wrong-key") is False

    def test_verify_rejects_tampered_operator(self):
        e = self._entry()
        e.entry_sig = _sign_entry(e, _KEY.encode())
        e.operator = "evil"
        assert _verify_entry_sig(e, _KEY.encode()) is False

    def test_verify_rejects_tampered_index(self):
        e = self._entry()
        e.entry_sig = _sign_entry(e, _KEY.encode())
        e.index = 99
        assert _verify_entry_sig(e, _KEY.encode()) is False

    def test_verify_rejects_tampered_node_count(self):
        e = self._entry()
        e.entry_sig = _sign_entry(e, _KEY.encode())
        e.node_count = 9999
        assert _verify_entry_sig(e, _KEY.encode()) is False

    def test_verify_rejects_tampered_package_id(self):
        e = self._entry()
        e.entry_sig = _sign_entry(e, _KEY.encode())
        e.package_id = "evil-pkg"
        assert _verify_entry_sig(e, _KEY.encode()) is False

    def test_verify_rejects_tampered_timestamp(self):
        e = self._entry()
        e.entry_sig = _sign_entry(e, _KEY.encode())
        e.timestamp_iso = "1970-01-01T00:00:00+00:00"
        assert _verify_entry_sig(e, _KEY.encode()) is False


# ── verify() ─────────────────────────────────────────────────────────────────


class TestVerify:
    def test_empty_log_passes(self, tmp_path):
        log = _log(tmp_path)
        ok, errors = log.verify()
        assert ok is True
        assert errors == []

    def test_single_entry_passes(self, tmp_path):
        log = _log(tmp_path)
        log.record(operator="alice", package_id="pkg-1")
        ok, errors = log.verify()
        assert ok is True

    def test_multiple_entries_pass(self, tmp_path):
        log = _log(tmp_path)
        for i in range(10):
            log.record(operator="alice", package_id=f"pkg-{i}")
        ok, errors = log.verify()
        assert ok is True

    def test_detects_corrupted_entry_sig(self, tmp_path):
        log = _log(tmp_path)
        log.record(operator="alice", package_id="pkg-1")
        # Corrupt the sig in the file
        with log.path.open() as fh:
            data = json.loads(fh.read())
        data["entry_sig"] = "0" * 64
        with log.path.open("w") as fh:
            fh.write(json.dumps(data) + "\n")
        ok, errors = log.verify()
        assert ok is False
        assert any("HMAC" in e for e in errors)

    def test_detects_tampered_operator_field(self, tmp_path):
        log = _log(tmp_path)
        log.record(operator="alice", package_id="pkg-1")
        with log.path.open() as fh:
            data = json.loads(fh.read())
        data["operator"] = "mallory"
        with log.path.open("w") as fh:
            fh.write(json.dumps(data) + "\n")
        ok, errors = log.verify()
        assert ok is False

    def test_detects_index_mismatch(self, tmp_path):
        log = _log(tmp_path)
        log.record(operator="alice", package_id="pkg-1")
        with log.path.open() as fh:
            data = json.loads(fh.read())
        # Overwrite index without re-signing
        data["index"] = 999
        with log.path.open("w") as fh:
            fh.write(json.dumps(data) + "\n")
        ok, errors = log.verify()
        assert ok is False
        assert any("index" in e for e in errors)

    def test_detects_invalid_json_line(self, tmp_path):
        log = _log(tmp_path)
        log.record(operator="alice", package_id="pkg-1")
        with log.path.open("a") as fh:
            fh.write("NOT-JSON\n")
        ok, errors = log.verify()
        assert ok is False
        assert any("JSON" in e for e in errors)

    def test_errors_list_identifies_line_number(self, tmp_path):
        log = _log(tmp_path)
        log.record(operator="alice", package_id="pkg-1")
        with log.path.open() as fh:
            data = json.loads(fh.read())
        data["entry_sig"] = "bad"
        with log.path.open("w") as fh:
            fh.write(json.dumps(data) + "\n")
        ok, errors = log.verify()
        assert not ok
        assert errors[0].startswith("line 1")

    def test_verify_nonexistent_log_passes(self, tmp_path):
        log = _log(tmp_path)
        log.path.unlink()  # remove file
        ok, errors = log.verify()
        assert ok is True
        assert errors == []


# ── read_all() ────────────────────────────────────────────────────────────────


class TestReadAll:
    def test_empty_returns_empty_list(self, tmp_path):
        log = _log(tmp_path)
        assert log.read_all() == []

    def test_returns_all_entries(self, tmp_path):
        log = _log(tmp_path)
        for i in range(5):
            log.record(operator="alice", package_id=f"pkg-{i}")
        entries = log.read_all()
        assert len(entries) == 5

    def test_entries_are_ExportLogEntry(self, tmp_path):
        log = _log(tmp_path)
        log.record(operator="alice", package_id="pkg-1")
        entries = log.read_all()
        assert isinstance(entries[0], ExportLogEntry)

    def test_data_roundtrip(self, tmp_path):
        log = _log(tmp_path)
        log.record(
            operator="alice@example.org",
            package_id="roundtrip-pkg",
            client_ip="10.1.2.3",
            api_key_hash="sha256:beef",
            node_count=77,
        )
        e = log.read_all()[0]
        assert e.operator == "alice@example.org"
        assert e.package_id == "roundtrip-pkg"
        assert e.client_ip == "10.1.2.3"
        assert e.api_key_hash == "sha256:beef"
        assert e.node_count == 77


# ── ExportLogEntry dataclass ──────────────────────────────────────────────────


class TestExportLogEntry:
    def test_to_dict_keys(self):
        e = ExportLogEntry(
            index=0,
            timestamp_iso="2026-01-01T00:00:00+00:00",
            operator="op",
            package_id="pkg",
            client_ip="127.0.0.1",
            api_key_hash="sha256:abc",
            node_count=5,
            extra={"x": 1},
            entry_sig="sig",
        )
        d = e.to_dict()
        assert set(d.keys()) == {
            "version",
            "index",
            "timestamp_iso",
            "operator",
            "package_id",
            "client_ip",
            "api_key_hash",
            "node_count",
            "hash_algorithm",
            "extra",
            "entry_sig",
        }

    def test_from_dict_roundtrip(self):
        e = ExportLogEntry(
            index=3,
            timestamp_iso="2026-06-01T12:00:00+00:00",
            operator="carol",
            package_id="pkg-xyz",
            client_ip="::1",
            api_key_hash="sha256:ff",
            node_count=99,
            extra={"env": "prod"},
            entry_sig="abc123",
        )
        d = e.to_dict()
        e2 = ExportLogEntry.from_dict(d)
        assert e2.index == e.index
        assert e2.operator == e.operator
        assert e2.package_id == e.package_id
        assert e2.entry_sig == e.entry_sig


# ── Cross-instance persistence ────────────────────────────────────────────────


class TestPersistence:
    def test_entries_survive_new_instance(self, tmp_path):
        p = tmp_path / "log.jsonl"
        log1 = ExportAuditLog(p, signing_key=_KEY)
        log1.record(operator="alice", package_id="pkg-1")
        log1.record(operator="bob", package_id="pkg-2")

        log2 = ExportAuditLog(p, signing_key=_KEY)
        assert log2.entry_count == 2

    def test_new_instance_continues_index(self, tmp_path):
        p = tmp_path / "log.jsonl"
        ExportAuditLog(p, signing_key=_KEY).record(operator="a", package_id="p0")
        log2 = ExportAuditLog(p, signing_key=_KEY)
        e = log2.record(operator="b", package_id="p1")
        assert e.index == 1

    def test_verification_across_instances(self, tmp_path):
        p = tmp_path / "log.jsonl"
        for i in range(3):
            ExportAuditLog(p, signing_key=_KEY).record(operator="alice", package_id=f"pkg-{i}")
        ok, errors = ExportAuditLog(p, signing_key=_KEY).verify()
        assert ok is True
        assert errors == []
