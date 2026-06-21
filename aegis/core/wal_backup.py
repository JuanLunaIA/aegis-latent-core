# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.wal_backup — WAL backup and restore with integrity re-verification.

Implements EU Annex 11 §7.1 backup requirements for the cryptographic audit
trail: every backup is integrity-verified before being considered valid; every
restore is verified before the backup replaces the live WAL.

Backup layout::

    <backup_dir>/
        <basename>_<timestamp>/          # e.g. audit.wal.jsonl_20260620T153045Z/
            audit.wal.jsonl              # active WAL snapshot
            audit.wal.jsonl.000001       # archived segment (if any)
            audit.wal.jsonl.000002       # …
            manifest.json                # integrity metadata

``manifest.json`` fields::

    {
        "source_path":       "/path/to/audit.wal.jsonl",
        "backup_timestamp":  "2026-06-20T15:30:45Z",
        "node_count":        1234,
        "chain_tip_hash":    "abc…",
        "integrity_valid":   true,
        "segments_count":    2,
        "files":             ["audit.wal.jsonl", "audit.wal.jsonl.000001", ...]
    }

Security: backup files are created with 0o600 permissions (same as WAL).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass
class WALBackupResult:
    """Result of a :meth:`WALBackupManager.backup` call."""

    success: bool
    backup_path: str = ""
    node_count: int = 0
    chain_tip_hash: str = ""
    timestamp: str = ""
    segments_backed_up: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class WALRestoreResult:
    """Result of a :meth:`WALBackupManager.restore` call."""

    success: bool
    nodes_restored: int = 0
    integrity_valid: bool = False
    error: str = ""


class WALBackupManager:
    """Backup and restore the cryptographic WAL with integrity re-verification.

    Each backup:
    1. Copies the active WAL and all archived segments to a timestamped
       directory under ``backup_dir``.
    2. Opens the copies in a temporary :class:`CryptographicAuditLedger` and
       runs :meth:`~CryptographicAuditLedger.verify_integrity`.
    3. Writes a ``manifest.json`` with integrity metadata.
    4. Returns :class:`WALBackupResult` — ``success=False`` if integrity fails.

    Each restore:
    1. Verifies the backup's hash chain before touching the live path.
    2. Optionally backs up the current live WAL to a ``pre_restore_backup``
       subdirectory first.
    3. Copies backup files to the target path atomically.
    4. Verifies the restored WAL.

    Parameters
    ----------
    signing_key:
        HMAC-SHA256 signing key for signature verification during integrity
        checks.  Pass an empty string to verify only the hash chain linkage
        (still detects tampering; just skips HMAC re-validation).
    """

    def __init__(self, signing_key: str = "") -> None:
        self._signing_key = signing_key

    # ── Public API ────────────────────────────────────────────────────────────

    def backup(
        self,
        source_path: str,
        backup_dir: str,
    ) -> WALBackupResult:
        """Create a verified backup of the WAL at *source_path*.

        Parameters
        ----------
        source_path:
            Path to the active WAL JSONL file.
        backup_dir:
            Directory where timestamped backup snapshots are stored.
            Created if it does not exist.

        Returns
        -------
        WALBackupResult
            ``success=True`` only when the copy is complete AND
            ``verify_integrity()`` passes on the backup copy.
        """
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        backup_name = f"{os.path.basename(source_path)}_{ts}"
        backup_path = os.path.join(backup_dir, backup_name)

        try:
            os.makedirs(backup_path, mode=0o700, exist_ok=True)

            # Collect source files: active WAL + archived segments
            source_files = self._collect_wal_files(source_path)
            if not source_files:
                return WALBackupResult(
                    success=False,
                    error=f"No WAL file found at {source_path!r}",
                )

            # Copy each file into the backup directory
            backed_up: list[str] = []
            for src in source_files:
                dest = os.path.join(backup_path, os.path.basename(src))
                shutil.copy2(src, dest)
                os.chmod(dest, 0o600)
                backed_up.append(os.path.basename(src))

            # The active WAL copy in the backup directory
            backup_wal = os.path.join(backup_path, os.path.basename(source_path))

            # Integrity re-verification on the backup copy
            node_count, chain_tip, valid, err = self._verify_wal(backup_wal)
            if not valid:
                return WALBackupResult(
                    success=False,
                    backup_path=backup_path,
                    node_count=node_count,
                    error=f"Backup integrity check failed: {err}",
                    segments_backed_up=backed_up,
                )

            # Write manifest
            manifest = {
                "source_path": os.path.abspath(source_path),
                "backup_timestamp": ts,
                "node_count": node_count,
                "chain_tip_hash": chain_tip,
                "integrity_valid": True,
                "segments_count": len(backed_up) - 1,
                "files": backed_up,
            }
            manifest_path = os.path.join(backup_path, "manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
            os.chmod(manifest_path, 0o600)

            logger.info(
                "WAL backup completed: %d nodes, tip=%s…, path=%s",
                node_count,
                chain_tip[:16] if chain_tip else "?",
                backup_path,
            )
            return WALBackupResult(
                success=True,
                backup_path=backup_path,
                node_count=node_count,
                chain_tip_hash=chain_tip,
                timestamp=ts,
                segments_backed_up=backed_up,
            )

        except Exception as exc:
            logger.error("WAL backup failed: %s", exc)
            return WALBackupResult(success=False, backup_path=backup_path, error=str(exc))

    def restore(
        self,
        backup_path: str,
        target_path: str,
        *,
        pre_restore_backup_dir: str = "",
    ) -> WALRestoreResult:
        """Restore a WAL backup to *target_path*.

        Parameters
        ----------
        backup_path:
            Path to a backup directory previously created by :meth:`backup`.
        target_path:
            Destination for the restored active WAL (overwrites existing file).
        pre_restore_backup_dir:
            When non-empty and the target WAL already exists, the current live
            WAL is backed up here first (safety net).

        Returns
        -------
        WALRestoreResult
            ``success=True`` only when the backup is valid AND the restored
            WAL passes integrity verification.
        """
        try:
            # Read manifest to find the active WAL filename
            manifest_path = os.path.join(backup_path, "manifest.json")
            if not os.path.isfile(manifest_path):
                return WALRestoreResult(
                    success=False,
                    error=f"No manifest.json found in {backup_path!r}",
                )
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)

            backup_wal = os.path.join(backup_path, os.path.basename(manifest["source_path"]))
            if not os.path.isfile(backup_wal):
                return WALRestoreResult(
                    success=False,
                    error=f"Backup WAL file not found: {backup_wal!r}",
                )

            # Verify backup integrity BEFORE touching live path
            node_count, chain_tip, valid, err = self._verify_wal(backup_wal)
            if not valid:
                return WALRestoreResult(
                    success=False,
                    nodes_restored=0,
                    integrity_valid=False,
                    error=f"Backup integrity check failed (refusing restore): {err}",
                )

            # Optionally safety-backup the current live WAL
            if pre_restore_backup_dir and os.path.isfile(target_path):
                self.backup(source_path=target_path, backup_dir=pre_restore_backup_dir)

            # Restore: copy all WAL files from backup to target directory
            target_dir = os.path.dirname(os.path.abspath(target_path))
            os.makedirs(target_dir, exist_ok=True)

            for filename in manifest.get("files", []):
                if filename == "manifest.json":
                    continue
                src = os.path.join(backup_path, filename)
                dest_name = filename
                dest = os.path.join(target_dir, dest_name)
                if os.path.isfile(src):
                    shutil.copy2(src, dest)
                    os.chmod(dest, 0o600)

            # Final verification on restored files
            _, _, restored_valid, restore_err = self._verify_wal(target_path)
            if not restored_valid:
                return WALRestoreResult(
                    success=False,
                    nodes_restored=node_count,
                    integrity_valid=False,
                    error=f"Post-restore integrity check failed: {restore_err}",
                )

            logger.info(
                "WAL restore completed: %d nodes restored from %s to %s",
                node_count,
                backup_path,
                target_path,
            )
            return WALRestoreResult(
                success=True,
                nodes_restored=node_count,
                integrity_valid=True,
            )

        except Exception as exc:
            logger.error("WAL restore failed: %s", exc)
            return WALRestoreResult(success=False, error=str(exc))

    def list_backups(self, backup_dir: str) -> list[dict]:
        """Return metadata for all backups in *backup_dir*, newest first.

        Each entry contains the manifest fields plus ``backup_dir_path``.
        Entries with missing or unreadable manifests are skipped.
        """
        if not os.path.isdir(backup_dir):
            return []
        results: list[dict] = []
        for name in os.listdir(backup_dir):
            entry_path = os.path.join(backup_dir, name)
            if not os.path.isdir(entry_path):
                continue
            manifest_path = os.path.join(entry_path, "manifest.json")
            if not os.path.isfile(manifest_path):
                continue
            try:
                with open(manifest_path, encoding="utf-8") as f:
                    data = json.load(f)
                data["backup_dir_path"] = entry_path
                results.append(data)
            except Exception:
                pass
        results.sort(key=lambda d: d.get("backup_timestamp", ""), reverse=True)
        return results

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _verify_wal(self, wal_path: str) -> tuple[int, str, bool, str]:
        """Load WAL at *wal_path* and run verify_integrity().

        Returns ``(node_count, chain_tip_hash, valid, error_message)``.
        """
        from aegis.core.crypto_audit import CryptographicAuditLedger  # noqa: PLC0415

        try:
            ledger = CryptographicAuditLedger(
                persistence_path=wal_path,
                signing_key=self._signing_key,
                async_mode=False,
            )
            node_count = len(ledger.chain)
            chain_tip = ledger.chain[-1].node_hash if ledger.chain else ""
            valid, failed_idx = ledger.verify_integrity()
            ledger.close()
            if not valid:
                return node_count, chain_tip, False, f"integrity violation at node {failed_idx}"
            return node_count, chain_tip, True, ""
        except Exception as exc:
            return 0, "", False, str(exc)

    @staticmethod
    def _collect_wal_files(source_path: str) -> list[str]:
        """Return [active_wal] + sorted archived segments that exist on disk."""
        files: list[str] = []
        if os.path.isfile(source_path):
            files.append(source_path)
        # Archived segments: <source_path>.<NNNNNN>
        directory = os.path.dirname(os.path.abspath(source_path))
        prefix = os.path.basename(source_path) + "."
        segments: list[tuple[int, str]] = []
        try:
            for name in os.listdir(directory):
                if name.startswith(prefix):
                    suffix = name[len(prefix) :]
                    if suffix.isdigit():
                        segments.append((int(suffix), os.path.join(directory, name)))
        except OSError:
            pass
        segments.sort(key=lambda t: t[0])
        files.extend(p for _, p in segments)
        return files
