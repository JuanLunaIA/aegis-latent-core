# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""WAL backup and restore with integrity re-verification (ROADMAP Domain 2.2)."""
from __future__ import annotations

import json
import os

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.wal_backup import WALBackupManager, WALBackupResult, WALRestoreResult


def _make_ledger(path: str, signing_key: str = "test-key", n: int = 5) -> CryptographicAuditLedger:
    ledger = CryptographicAuditLedger(path, signing_key=signing_key)
    for i in range(n):
        ledger.commit_state(f"s{i}", float(i), f"payload-{i}".encode())
    ledger.close()
    return ledger


class TestWALBackupResult:
    def test_defaults(self):
        r = WALBackupResult(success=True)
        assert r.backup_path == ""
        assert r.node_count == 0
        assert r.segments_backed_up == []

    def test_failure_defaults(self):
        r = WALBackupResult(success=False, error="disk full")
        assert not r.success
        assert r.error == "disk full"


class TestWALRestoreResult:
    def test_defaults(self):
        r = WALRestoreResult(success=True)
        assert r.nodes_restored == 0
        assert r.integrity_valid is False


class TestWALBackup:
    def test_backup_success(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, n=5)
        mgr = WALBackupManager(signing_key="test-key")
        result = mgr.backup(source_path=wal, backup_dir=str(tmp_path / "backups"))
        assert result.success
        assert result.node_count == 5
        assert len(result.chain_tip_hash) == 64  # SHA-256 hex
        assert os.path.isdir(result.backup_path)
        assert result.timestamp

    def test_backup_creates_manifest(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, n=3)
        mgr = WALBackupManager()
        result = mgr.backup(wal, str(tmp_path / "backups"))
        assert result.success
        manifest_path = os.path.join(result.backup_path, "manifest.json")
        assert os.path.isfile(manifest_path)
        with open(manifest_path) as f:
            manifest = json.load(f)
        assert manifest["node_count"] == 3
        assert manifest["integrity_valid"] is True
        assert "chain_tip_hash" in manifest

    def test_backup_files_have_restricted_permissions(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, n=2)
        mgr = WALBackupManager()
        result = mgr.backup(wal, str(tmp_path / "backups"))
        assert result.success
        backed_wal = os.path.join(result.backup_path, "audit.wal.jsonl")
        mode = oct(os.stat(backed_wal).st_mode)[-3:]
        assert mode == "600"

    def test_backup_nonexistent_wal_fails(self, tmp_path):
        mgr = WALBackupManager()
        result = mgr.backup(
            source_path=str(tmp_path / "missing.wal.jsonl"),
            backup_dir=str(tmp_path / "backups"),
        )
        assert not result.success
        assert "No WAL file" in result.error

    def test_backup_tampered_wal_fails(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, n=3)
        # Corrupt the hash chain by changing a node's prev_hash
        with open(wal) as f:
            lines = f.readlines()
        node = json.loads(lines[1])
        node["prev_hash"] = "a" * 64  # invalid hash breaks chain linkage
        lines[1] = json.dumps(node) + "\n"
        with open(wal, "w") as f:
            f.writelines(lines)
        mgr = WALBackupManager(signing_key="test-key")
        result = mgr.backup(wal, str(tmp_path / "backups"))
        # Backup copy was made but integrity check on the copy detects tamper
        assert not result.success
        assert "integrity" in result.error.lower()

    def test_backup_with_signing_key_verifies_hmac(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, signing_key="secret-key", n=4)
        mgr = WALBackupManager(signing_key="secret-key")
        result = mgr.backup(wal, str(tmp_path / "backups"))
        assert result.success
        assert result.node_count == 4

    def test_backup_includes_archived_segments(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        # Create a small ledger with WAL rotation (max_wal_bytes=1)
        ledger = CryptographicAuditLedger(wal, signing_key="k", max_wal_bytes=1)
        for i in range(3):
            ledger.commit_state(f"s{i}", float(i), b"payload")
        segments = list(ledger.archived_segments)
        ledger.close()

        mgr = WALBackupManager(signing_key="k")
        result = mgr.backup(wal, str(tmp_path / "backups"))
        assert result.success
        # Should have backed up the active WAL + at least one segment
        if segments:
            assert len(result.segments_backed_up) >= 2

    def test_list_backups_empty_dir(self, tmp_path):
        mgr = WALBackupManager()
        assert mgr.list_backups(str(tmp_path / "no_such_dir")) == []

    def test_list_backups_returns_newest_first(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, n=2)
        backup_dir = str(tmp_path / "backups")
        mgr = WALBackupManager()
        r1 = mgr.backup(wal, backup_dir)
        r2 = mgr.backup(wal, backup_dir)
        assert r1.success
        assert r2.success
        backups = mgr.list_backups(backup_dir)
        assert len(backups) == 2
        # Newest first
        assert backups[0]["backup_timestamp"] >= backups[1]["backup_timestamp"]

    def test_list_backups_includes_backup_dir_path(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, n=1)
        backup_dir = str(tmp_path / "backups")
        mgr = WALBackupManager()
        mgr.backup(wal, backup_dir)
        backups = mgr.list_backups(backup_dir)
        assert len(backups) == 1
        assert "backup_dir_path" in backups[0]
        assert os.path.isdir(backups[0]["backup_dir_path"])


class TestWALRestore:
    def test_restore_success(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, n=5)
        backup_dir = str(tmp_path / "backups")
        target = str(tmp_path / "restored" / "audit.wal.jsonl")
        mgr = WALBackupManager(signing_key="test-key")
        br = mgr.backup(wal, backup_dir)
        assert br.success

        rr = mgr.restore(br.backup_path, target)
        assert rr.success
        assert rr.nodes_restored == 5
        assert rr.integrity_valid is True

    def test_restore_produces_valid_ledger(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, n=4)
        backup_dir = str(tmp_path / "backups")
        mgr = WALBackupManager()
        br = mgr.backup(wal, backup_dir)
        assert br.success

        target = str(tmp_path / "restored" / "audit.wal.jsonl")
        rr = mgr.restore(br.backup_path, target)
        assert rr.success

        # Verify the restored ledger is readable and intact
        ledger = CryptographicAuditLedger(target, signing_key="")
        valid, idx = ledger.verify_integrity()
        ledger.close()
        assert valid
        assert idx is None

    def test_restore_missing_manifest_fails(self, tmp_path):
        mgr = WALBackupManager()
        rr = mgr.restore(str(tmp_path / "no_backup"), str(tmp_path / "target.wal.jsonl"))
        assert not rr.success
        assert "manifest.json" in rr.error

    def test_restore_with_pre_restore_backup(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, n=3)
        backup_dir = str(tmp_path / "backups")
        pre_backup_dir = str(tmp_path / "pre_restore_backups")
        mgr = WALBackupManager()
        br = mgr.backup(wal, backup_dir)
        assert br.success

        # Create a "live" WAL to be backed up before restore
        live = str(tmp_path / "live.wal.jsonl")
        _make_ledger(live, n=2)

        rr = mgr.restore(br.backup_path, live, pre_restore_backup_dir=pre_backup_dir)
        assert rr.success
        # Pre-restore backup should exist
        pre_backups = mgr.list_backups(pre_backup_dir)
        assert len(pre_backups) >= 1

    def test_collect_wal_files_active_only(self, tmp_path):
        wal = str(tmp_path / "audit.wal.jsonl")
        _make_ledger(wal, n=2)
        files = WALBackupManager._collect_wal_files(wal)
        assert len(files) == 1
        assert files[0] == wal

    def test_collect_wal_files_missing(self, tmp_path):
        files = WALBackupManager._collect_wal_files(str(tmp_path / "missing.wal.jsonl"))
        assert files == []
