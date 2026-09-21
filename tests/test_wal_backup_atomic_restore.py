# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Restore must not write the live WAL in place (AF-054 / REG-D27).

``restore()`` documented "Copies backup files to the target path atomically" and
then ran ``shutil.copy2(src, dest)`` straight into the live WAL, followed by
``os.chmod``. The probe run for this row replaced ``copy2`` with an interrupted
copy — half the source written, then ``OSError``, which is exactly what a crash,
``ENOSPC`` or ``EIO`` leaves behind — and the live WAL ended up as the first half
of the backup payload, no longer parseable as a ledger, with the failure reported
only by the post-copy verification that runs *after* the live bytes are gone.

These tests pin the replacement: temp file in the same directory, fsync, rename,
directory fsync — and that an interrupted copy leaves the live bytes untouched.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.wal_backup import WALBackupManager


def _make_ledger(path, count: int = 3):
    ledger = CryptographicAuditLedger(persistence_path=str(path))
    for index in range(count):
        ledger.commit_forensic(state_id=f"s{index}", request_bytes=b'{"p": 1}')
    return ledger


def _live_bytes(path) -> bytes:
    return open(path, "rb").read()


@pytest.fixture
def restore_setup(tmp_path):
    live_wal = tmp_path / "live" / "audit.wal.jsonl"
    live_wal.parent.mkdir()
    _make_ledger(live_wal, count=3)

    manager = WALBackupManager(signing_key="k")
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    result = manager.backup(source_path=str(live_wal), backup_dir=str(backup_dir))
    assert result.success, result.error
    # restore() reads manifest.json from the timestamped snapshot directory.
    snapshot = Path(result.backup_path)

    # The live WAL moves on after the backup, so a restore has something to undo.
    ledger = CryptographicAuditLedger(persistence_path=str(live_wal))
    ledger.commit_forensic(state_id="post-backup", request_bytes=b'{"p": 2}')
    return manager, snapshot, live_wal


def test_restore_never_copies_over_the_live_file(restore_setup, monkeypatch) -> None:
    """The pre-fix code called ``shutil.copy2(src, dest)`` with dest = the live
    WAL. Now every write goes to a temp file and is renamed into place."""
    manager, snapshot, live_wal = restore_setup

    copy2_calls: list[str] = []
    real_copy2 = shutil.copy2

    def recording_copy2(src, dst, *args, **kwargs):
        copy2_calls.append(str(dst))
        return real_copy2(src, dst, *args, **kwargs)

    temps: list[str] = []
    real_mkstemp = tempfile.mkstemp

    def recording_mkstemp(*args, **kwargs):
        fd, path = real_mkstemp(*args, **kwargs)
        temps.append(path)
        return fd, path

    replaces: list[tuple[str, str]] = []
    real_replace = os.replace

    def recording_replace(src, dst, *args, **kwargs):
        replaces.append((str(src), str(dst)))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(shutil, "copy2", recording_copy2)
    monkeypatch.setattr(tempfile, "mkstemp", recording_mkstemp)
    monkeypatch.setattr(os, "replace", recording_replace)

    result = manager.restore(backup_path=str(snapshot), target_path=str(live_wal))
    assert result.success, result.error

    assert copy2_calls == [], f"restore copied straight onto a destination: {copy2_calls}"
    assert temps, "restore wrote no temp file"

    # Scope the rename claim to the files the manifest restores: the ledger's own
    # checkpoint writer (`.mmr.state`) renames too, which is not this test's subject.
    manifest = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
    restored = {name for name in manifest["files"] if name != "manifest.json"}
    assert restored, "the snapshot lists no files"
    restore_replaces = [(src, dst) for src, dst in replaces if os.path.basename(dst) in restored]
    assert restore_replaces, "restore never renamed a temp file into place"
    assert all(src in temps for src, _ in restore_replaces), restore_replaces
    assert any(dst == str(live_wal) for _, dst in restore_replaces), restore_replaces


def test_interrupted_restore_leaves_the_live_wal_untouched(restore_setup, monkeypatch) -> None:
    manager, backup_dir, live_wal = restore_setup
    before = _live_bytes(live_wal)

    def interrupted_copyfileobj(src, dst, *args, **kwargs):
        dst.write(b"half the backup")
        raise OSError("simulated crash / disk full mid-copy")

    monkeypatch.setattr(shutil, "copyfileobj", interrupted_copyfileobj)

    result = manager.restore(backup_path=str(backup_dir), target_path=str(live_wal))

    assert result.success is False, "a torn copy reported success"
    assert _live_bytes(live_wal) == before, "the live WAL was written in place"
    # The half-written temp must not be left behind as a decoy live file.
    residue = [name for name in os.listdir(live_wal.parent) if ".tmp-" in name]
    assert residue == [], residue


def test_successful_restore_leaves_no_temp_residue_and_a_valid_ledger(
    restore_setup,
) -> None:
    manager, backup_dir, live_wal = restore_setup
    result = manager.restore(backup_path=str(backup_dir), target_path=str(live_wal))
    assert result.success, result.error

    residue = [name for name in os.listdir(live_wal.parent) if ".tmp-" in name]
    assert residue == [], residue

    ledger = CryptographicAuditLedger(persistence_path=str(live_wal))
    ok, reason = ledger.verify_integrity()
    assert ok, reason
    assert "post-backup" not in open(live_wal, encoding="utf-8").read()

    # Every restored line is still strict JSON and every file is mode 0600.
    for line in open(live_wal, encoding="utf-8"):
        if line.strip():
            json.loads(line, parse_constant=lambda c: pytest.fail(f"bare {c} in WAL"))
    assert (os.stat(live_wal).st_mode & 0o777) == 0o600


def test_backup_also_writes_through_the_atomic_helper(tmp_path, monkeypatch) -> None:
    """Same class, sibling site: the snapshot copy loop must not write in place
    either, so a torn backup cannot be advertised by list_backups."""
    live_wal = tmp_path / "audit.wal.jsonl"
    _make_ledger(live_wal, count=2)
    manager = WALBackupManager(signing_key="k")
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    copy2_calls: list[str] = []
    real_copy2 = shutil.copy2

    def recording_copy2(src, dst, *args, **kwargs):
        copy2_calls.append(str(dst))
        return real_copy2(src, dst, *args, **kwargs)

    monkeypatch.setattr(shutil, "copy2", recording_copy2)
    result = manager.backup(source_path=str(live_wal), backup_dir=str(backup_dir))
    assert result.success, result.error

    assert copy2_calls == [], f"backup copied straight onto a destination: {copy2_calls}"
    snapshot = Path(result.backup_path)
    assert (snapshot / "manifest.json").is_file()
    residue = [name for name in os.listdir(snapshot) if ".tmp-" in name]
    assert residue == [], residue
    listing = manager.list_backups(backup_dir=str(backup_dir))
    assert listing, "the backup was not listed"
