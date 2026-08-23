# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.storage.segment_manifest import build_segment_manifest


def _rotated_segment(tmp_path: Path) -> Path:
    wal = tmp_path / "audit.wal.jsonl"
    ledger = CryptographicAuditLedger(wal, signing_key="manifest-test-key", max_wal_bytes=1024)
    try:
        for index in range(12):
            ledger.commit_state(f"state-{index}", 1.0, b"x" * 300)
        return Path(ledger.archived_segments[0])
    finally:
        ledger.close()


def test_manifest_binds_exact_segment_and_terminal_checkpoint(tmp_path: Path) -> None:
    segment = _rotated_segment(tmp_path)
    manifest = build_segment_manifest(segment)
    terminal = json.loads(segment.read_bytes().rstrip(b"\n").rsplit(b"\n", 1)[-1])

    assert manifest.format == "aegis-wal-segment-manifest-v1"
    assert manifest.segment_name == segment.name
    assert manifest.size == segment.stat().st_size
    assert manifest.file_sha256 == hashlib.sha256(segment.read_bytes()).hexdigest()
    assert manifest.mmr_root == terminal["merkle_root"]
    assert manifest.mmr_leaf_count == terminal["mmr_leaf_count"]
    assert manifest.chain_tip != manifest.file_sha256
    assert manifest.mmr_root != manifest.file_sha256
    assert json.loads(manifest.canonical_bytes()) == manifest.to_dict()


def test_manifest_rejects_active_or_truncated_bytes(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_bytes(b'{"not":"complete"}')
    with pytest.raises(ValueError, match="newline terminated"):
        build_segment_manifest(path)


def test_manifest_detects_terminal_record_tampering(tmp_path: Path) -> None:
    segment = _rotated_segment(tmp_path)
    lines = segment.read_bytes().splitlines()
    terminal = json.loads(lines[-1])
    terminal.pop("merkle_root")
    lines[-1] = json.dumps(terminal).encode()
    segment.write_bytes(b"\n".join(lines) + b"\n")
    with pytest.raises((TypeError, ValueError), match="terminal record"):
        build_segment_manifest(segment)
