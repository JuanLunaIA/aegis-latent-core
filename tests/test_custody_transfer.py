# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.custody_transfer — ISO/IEC 27037 custody transfer protocol."""

from __future__ import annotations

import json
import os
import stat

import pytest

from aegis.core.custody_transfer import (
    CustodyTransferLog,
    CustodyTransferRecord,
    _sign_record,
    _verify_record_sig,
)

_KEY = "test-signing-key-32bytes-xyzzy1234"


def _log(tmp_path, key: str = _KEY) -> CustodyTransferLog:
    return CustodyTransferLog(tmp_path / "custody.jsonl", signing_key=key)


# ── Construction ──────────────────────────────────────────────────────────────


class TestConstruction:
    def test_creates_file(self, tmp_path):
        log = _log(tmp_path)
        assert log.path.exists()

    def test_file_mode_0o600(self, tmp_path):
        log = _log(tmp_path)
        mode = stat.S_IMODE(os.stat(log.path).st_mode)
        assert mode == 0o600

    def test_enforces_0o600_on_wide_file(self, tmp_path):
        p = tmp_path / "custody.jsonl"
        p.touch(mode=0o644)
        CustodyTransferLog(p, signing_key=_KEY)
        mode = stat.S_IMODE(os.stat(p).st_mode)
        assert mode == 0o600

    def test_empty_key_raises(self, tmp_path):
        with pytest.raises(ValueError, match="signing_key"):
            CustodyTransferLog(tmp_path / "c.jsonl", signing_key="")

    def test_initial_entry_count_zero(self, tmp_path):
        assert _log(tmp_path).entry_count == 0

    def test_creates_parent_dirs(self, tmp_path):
        log = CustodyTransferLog(tmp_path / "deep" / "nested" / "custody.jsonl", signing_key=_KEY)
        assert log.path.exists()


# ── record() ─────────────────────────────────────────────────────────────────


class TestRecord:
    def test_returns_record(self, tmp_path):
        log = _log(tmp_path)
        rec = log.record(transferor="alice", transferee="bob", package_id="pkg-1")
        assert isinstance(rec, CustodyTransferRecord)

    def test_first_index_zero(self, tmp_path):
        log = _log(tmp_path)
        rec = log.record(transferor="a", transferee="b", package_id="p")
        assert rec.index == 0

    def test_index_increments(self, tmp_path):
        log = _log(tmp_path)
        r0 = log.record(transferor="a", transferee="b", package_id="p0")
        r1 = log.record(transferor="b", transferee="c", package_id="p1")
        r2 = log.record(transferor="c", transferee="d", package_id="p2")
        assert r0.index == 0
        assert r1.index == 1
        assert r2.index == 2

    def test_entry_count_matches(self, tmp_path):
        log = _log(tmp_path)
        for i in range(4):
            log.record(transferor="a", transferee="b", package_id=f"p{i}")
        assert log.entry_count == 4

    def test_sig_non_empty(self, tmp_path):
        log = _log(tmp_path)
        rec = log.record(transferor="a", transferee="b", package_id="p")
        assert rec.transfer_sig != ""

    def test_transferor_stored(self, tmp_path):
        log = _log(tmp_path)
        rec = log.record(transferor="alice@example.org", transferee="bob", package_id="p")
        assert rec.transferor == "alice@example.org"

    def test_transferee_stored(self, tmp_path):
        log = _log(tmp_path)
        rec = log.record(transferor="a", transferee="carol@lab.gov", package_id="p")
        assert rec.transferee == "carol@lab.gov"

    def test_package_id_stored(self, tmp_path):
        log = _log(tmp_path)
        rec = log.record(transferor="a", transferee="b", package_id="uuid-xyz")
        assert rec.package_id == "uuid-xyz"

    def test_evidence_hash_stored(self, tmp_path):
        log = _log(tmp_path)
        rec = log.record(
            transferor="a",
            transferee="b",
            package_id="p",
            evidence_hash="sha256:deadbeef",
        )
        assert rec.evidence_hash == "sha256:deadbeef"

    def test_reason_stored(self, tmp_path):
        log = _log(tmp_path)
        rec = log.record(
            transferor="a",
            transferee="b",
            package_id="p",
            reason="court order CR-2026-001",
        )
        assert rec.reason == "court order CR-2026-001"

    def test_authorization_stored(self, tmp_path):
        log = _log(tmp_path)
        rec = log.record(
            transferor="a",
            transferee="b",
            package_id="p",
            authorization="CASE-9901",
        )
        assert rec.authorization == "CASE-9901"

    def test_extra_stored(self, tmp_path):
        log = _log(tmp_path)
        rec = log.record(
            transferor="a", transferee="b", package_id="p", extra={"chain": "of-custody"}
        )
        assert rec.extra == {"chain": "of-custody"}

    def test_custom_timestamp_stored(self, tmp_path):
        log = _log(tmp_path)
        ts = "2026-01-15T09:00:00+00:00"
        rec = log.record(transferor="a", transferee="b", package_id="p", timestamp_iso=ts)
        assert rec.timestamp_iso == ts

    def test_persists_to_file(self, tmp_path):
        log = _log(tmp_path)
        log.record(transferor="a", transferee="b", package_id="p")
        with log.path.open() as fh:
            lines = [ln for ln in fh if ln.strip()]
        assert len(lines) == 1

    def test_record_is_valid_json(self, tmp_path):
        log = _log(tmp_path)
        log.record(transferor="a", transferee="b", package_id="p")
        with log.path.open() as fh:
            data = json.loads(fh.readline().strip())
        assert "transfer_sig" in data


# ── HMAC signing ─────────────────────────────────────────────────────────────


class TestHMACSigning:
    def _rec(self) -> CustodyTransferRecord:
        return CustodyTransferRecord(
            index=0,
            timestamp_iso="2026-01-01T00:00:00+00:00",
            transferor="alice",
            transferee="bob",
            package_id="pkg-1",
            evidence_hash="sha256:abc",
            reason="investigation",
            authorization="CASE-001",
            extra={},
        )

    def test_sign_returns_64_char_hex(self):
        rec = self._rec()
        sig = _sign_record(rec, _KEY.encode())
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)

    def test_verify_correct_sig(self):
        rec = self._rec()
        rec.transfer_sig = _sign_record(rec, _KEY.encode())
        assert _verify_record_sig(rec, _KEY.encode()) is True

    def test_verify_wrong_key(self):
        rec = self._rec()
        rec.transfer_sig = _sign_record(rec, _KEY.encode())
        assert _verify_record_sig(rec, b"wrong-key") is False

    def test_verify_tampered_transferor(self):
        rec = self._rec()
        rec.transfer_sig = _sign_record(rec, _KEY.encode())
        rec.transferor = "mallory"
        assert _verify_record_sig(rec, _KEY.encode()) is False

    def test_verify_tampered_transferee(self):
        rec = self._rec()
        rec.transfer_sig = _sign_record(rec, _KEY.encode())
        rec.transferee = "evil"
        assert _verify_record_sig(rec, _KEY.encode()) is False

    def test_verify_tampered_index(self):
        rec = self._rec()
        rec.transfer_sig = _sign_record(rec, _KEY.encode())
        rec.index = 99
        assert _verify_record_sig(rec, _KEY.encode()) is False

    def test_verify_tampered_evidence_hash(self):
        rec = self._rec()
        rec.transfer_sig = _sign_record(rec, _KEY.encode())
        rec.evidence_hash = "sha256:evil"
        assert _verify_record_sig(rec, _KEY.encode()) is False

    def test_verify_tampered_package_id(self):
        rec = self._rec()
        rec.transfer_sig = _sign_record(rec, _KEY.encode())
        rec.package_id = "evil-pkg"
        assert _verify_record_sig(rec, _KEY.encode()) is False


# ── verify() ─────────────────────────────────────────────────────────────────


class TestVerify:
    def test_empty_log_passes(self, tmp_path):
        log = _log(tmp_path)
        ok, errors = log.verify()
        assert ok is True
        assert errors == []

    def test_single_record_passes(self, tmp_path):
        log = _log(tmp_path)
        log.record(transferor="a", transferee="b", package_id="p")
        ok, errors = log.verify()
        assert ok is True

    def test_multiple_records_pass(self, tmp_path):
        log = _log(tmp_path)
        for i in range(8):
            log.record(transferor="a", transferee="b", package_id=f"p{i}")
        ok, errors = log.verify()
        assert ok is True

    def test_detects_tampered_sig(self, tmp_path):
        log = _log(tmp_path)
        log.record(transferor="a", transferee="b", package_id="p")
        with log.path.open() as fh:
            data = json.loads(fh.read())
        data["transfer_sig"] = "0" * 64
        with log.path.open("w") as fh:
            fh.write(json.dumps(data) + "\n")
        ok, errors = log.verify()
        assert ok is False
        assert any("HMAC" in e for e in errors)

    def test_detects_tampered_transferor(self, tmp_path):
        log = _log(tmp_path)
        log.record(transferor="alice", transferee="bob", package_id="p")
        with log.path.open() as fh:
            data = json.loads(fh.read())
        data["transferor"] = "mallory"
        with log.path.open("w") as fh:
            fh.write(json.dumps(data) + "\n")
        ok, _ = log.verify()
        assert ok is False

    def test_detects_index_mismatch(self, tmp_path):
        log = _log(tmp_path)
        log.record(transferor="a", transferee="b", package_id="p")
        with log.path.open() as fh:
            data = json.loads(fh.read())
        data["index"] = 999
        with log.path.open("w") as fh:
            fh.write(json.dumps(data) + "\n")
        ok, errors = log.verify()
        assert ok is False
        assert any("index" in e for e in errors)

    def test_detects_invalid_json(self, tmp_path):
        log = _log(tmp_path)
        log.record(transferor="a", transferee="b", package_id="p")
        with log.path.open("a") as fh:
            fh.write("NOT-JSON\n")
        ok, errors = log.verify()
        assert ok is False
        assert any("JSON" in e for e in errors)

    def test_error_identifies_line_number(self, tmp_path):
        log = _log(tmp_path)
        log.record(transferor="a", transferee="b", package_id="p")
        with log.path.open() as fh:
            data = json.loads(fh.read())
        data["transfer_sig"] = "bad"
        with log.path.open("w") as fh:
            fh.write(json.dumps(data) + "\n")
        ok, errors = log.verify()
        assert not ok
        assert errors[0].startswith("line 1")

    def test_nonexistent_log_passes(self, tmp_path):
        log = _log(tmp_path)
        log.path.unlink()
        ok, errors = log.verify()
        assert ok is True
        assert errors == []


# ── read_all() ────────────────────────────────────────────────────────────────


class TestReadAll:
    def test_empty_returns_empty(self, tmp_path):
        assert _log(tmp_path).read_all() == []

    def test_returns_all_records(self, tmp_path):
        log = _log(tmp_path)
        for i in range(5):
            log.record(transferor="a", transferee="b", package_id=f"p{i}")
        assert len(log.read_all()) == 5

    def test_entries_are_correct_type(self, tmp_path):
        log = _log(tmp_path)
        log.record(transferor="a", transferee="b", package_id="p")
        assert isinstance(log.read_all()[0], CustodyTransferRecord)

    def test_data_roundtrip(self, tmp_path):
        log = _log(tmp_path)
        log.record(
            transferor="alice@example.org",
            transferee="bob@court.gov",
            package_id="rt-pkg",
            evidence_hash="sha256:beef",
            reason="subpoena",
            authorization="CASE-2026-42",
        )
        rec = log.read_all()[0]
        assert rec.transferor == "alice@example.org"
        assert rec.transferee == "bob@court.gov"
        assert rec.package_id == "rt-pkg"
        assert rec.evidence_hash == "sha256:beef"
        assert rec.reason == "subpoena"
        assert rec.authorization == "CASE-2026-42"


# ── CustodyTransferRecord dataclass ──────────────────────────────────────────


class TestCustodyTransferRecord:
    def test_to_dict_keys(self):
        rec = CustodyTransferRecord(
            index=0,
            timestamp_iso="2026-01-01T00:00:00+00:00",
            transferor="alice",
            transferee="bob",
            package_id="p",
            evidence_hash="sha256:abc",
            reason="test",
            authorization="AUTH-1",
            extra={"note": "x"},
            transfer_sig="sig",
        )
        d = rec.to_dict()
        assert set(d.keys()) == {
            "version",
            "index",
            "timestamp_iso",
            "transferor",
            "transferee",
            "package_id",
            "evidence_hash",
            "reason",
            "authorization",
            "extra",
            "transfer_sig",
        }

    def test_from_dict_roundtrip(self):
        rec = CustodyTransferRecord(
            index=7,
            timestamp_iso="2026-06-15T10:00:00+00:00",
            transferor="carol",
            transferee="dave",
            package_id="rt-pkg-xyz",
            evidence_hash="sha256:ff",
            reason="appeal",
            authorization="CASE-999",
            extra={"env": "prod"},
            transfer_sig="abc123",
        )
        d = rec.to_dict()
        rec2 = CustodyTransferRecord.from_dict(d)
        assert rec2.index == rec.index
        assert rec2.transferor == rec.transferor
        assert rec2.transferee == rec.transferee
        assert rec2.transfer_sig == rec.transfer_sig


# ── Cross-instance persistence ────────────────────────────────────────────────


class TestPersistence:
    def test_records_survive_new_instance(self, tmp_path):
        p = tmp_path / "ct.jsonl"
        log1 = CustodyTransferLog(p, signing_key=_KEY)
        log1.record(transferor="a", transferee="b", package_id="p0")
        log1.record(transferor="b", transferee="c", package_id="p1")
        log2 = CustodyTransferLog(p, signing_key=_KEY)
        assert log2.entry_count == 2

    def test_new_instance_continues_index(self, tmp_path):
        p = tmp_path / "ct.jsonl"
        CustodyTransferLog(p, signing_key=_KEY).record(
            transferor="a", transferee="b", package_id="p0"
        )
        log2 = CustodyTransferLog(p, signing_key=_KEY)
        rec = log2.record(transferor="b", transferee="c", package_id="p1")
        assert rec.index == 1

    def test_verify_across_instances(self, tmp_path):
        p = tmp_path / "ct.jsonl"
        for i in range(3):
            CustodyTransferLog(p, signing_key=_KEY).record(
                transferor="a", transferee="b", package_id=f"p{i}"
            )
        ok, errors = CustodyTransferLog(p, signing_key=_KEY).verify()
        assert ok is True
        assert errors == []
