# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from aegis.anchoring.rfc3161 import TimestampVerificationError, VerificationResult
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.storage.s3_worm import ArchiveState
from aegis.storage.segment_manifest import archive_finalized_segment, build_segment_manifest


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


class _VerifiedArchiver:
    def __init__(self) -> None:
        self._records: dict[str, SimpleNamespace] = {}

    async def archive(self, _data: bytes, *, key: str) -> SimpleNamespace:
        record = SimpleNamespace(archive_id=key, state=ArchiveState.VERIFIED)
        self._records[key] = record
        return record

    async def wait(self) -> None:
        return None

    async def get(self, archive_id: str) -> SimpleNamespace:
        return self._records[archive_id]


def _write_receipt(
    receipt_dir: Path, segment: Path, *, overrides: dict[str, object] | None = None
) -> Path:
    manifest = build_segment_manifest(segment)
    digest = hashlib.sha256(manifest.canonical_bytes()).hexdigest()
    request_path = receipt_dir / "anchor-id.tsq"
    response_path = receipt_dir / "anchor-id.tsr"
    request_path.write_bytes(b"request")
    response_path.write_bytes(b"response")
    receipt: dict[str, object] = {
        "anchor_id": "anchor-id",
        "cms_trusted": True,
        "manifest_sha256": digest,
        "message_imprint": digest,
        "nonce": "123",
        "request_path": str(request_path),
        "response_path": str(response_path),
    }
    receipt.update(overrides or {})
    receipt_path = receipt_dir / f"{segment.name}.anchor.json"
    receipt_path.write_text(json.dumps(receipt))
    return receipt_path


def _revalidating_client(segment: Path) -> SimpleNamespace:
    manifest_bytes = build_segment_manifest(segment).canonical_bytes()
    return SimpleNamespace(
        anchor=AsyncMock(),
        verify_existing=MagicMock(
            return_value=VerificationResult(
                pki_status=0,
                message_imprint=hashlib.sha256(manifest_bytes).digest(),
                nonce=123,
                cms_trusted=True,
            )
        ),
    )


@pytest.mark.asyncio
async def test_archive_reuses_only_exact_current_receipt(tmp_path: Path) -> None:
    segment = _rotated_segment(tmp_path)
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    _write_receipt(receipt_dir, segment)
    anchor_client = _revalidating_client(segment)

    manifest, anchor = await archive_finalized_segment(
        segment,
        archiver=_VerifiedArchiver(),  # type: ignore[arg-type]
        prefix="audit",
        receipt_dir=receipt_dir,
        anchor_client=anchor_client,  # type: ignore[arg-type]
    )

    assert manifest == build_segment_manifest(segment)
    assert anchor is None
    anchor_client.anchor.assert_not_awaited()
    anchor_client.verify_existing.assert_called_once()


@pytest.mark.asyncio
async def test_archive_rejects_receipt_without_configured_verifier(tmp_path: Path) -> None:
    segment = _rotated_segment(tmp_path)
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    _write_receipt(receipt_dir, segment)

    with pytest.raises(RuntimeError, match="configured RFC 3161 verifier"):
        await archive_finalized_segment(
            segment,
            archiver=_VerifiedArchiver(),  # type: ignore[arg-type]
            prefix="audit",
            receipt_dir=receipt_dir,
        )


@pytest.mark.asyncio
async def test_archive_rejects_receipt_when_crypto_revalidation_fails(tmp_path: Path) -> None:
    segment = _rotated_segment(tmp_path)
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    _write_receipt(receipt_dir, segment)
    anchor_client = _revalidating_client(segment)
    anchor_client.verify_existing.side_effect = TimestampVerificationError("rejected")

    with pytest.raises(RuntimeError, match="cryptographic verification failed"):
        await archive_finalized_segment(
            segment,
            archiver=_VerifiedArchiver(),  # type: ignore[arg-type]
            prefix="audit",
            receipt_dir=receipt_dir,
            anchor_client=anchor_client,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"manifest_sha256": "0" * 64}, "manifest hash mismatch"),
        ({"message_imprint": "0" * 64}, "message imprint mismatch"),
        ({"cms_trusted": False}, "expected schema"),
        ({"unexpected": "field"}, "expected schema"),
    ],
)
async def test_archive_rejects_receipt_mismatch_closed(
    tmp_path: Path, overrides: dict[str, object], error: str
) -> None:
    segment = _rotated_segment(tmp_path)
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    _write_receipt(receipt_dir, segment, overrides=overrides)

    with pytest.raises(RuntimeError, match=error):
        await archive_finalized_segment(
            segment,
            archiver=_VerifiedArchiver(),  # type: ignore[arg-type]
            prefix="audit",
            receipt_dir=receipt_dir,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("missing_field", "error"),
    [
        ("request_path", "missing timestamp request"),
        ("response_path", "missing timestamp response"),
    ],
)
async def test_archive_rejects_receipt_with_missing_timestamp_evidence(
    tmp_path: Path, missing_field: str, error: str
) -> None:
    segment = _rotated_segment(tmp_path)
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    receipt_path = _write_receipt(receipt_dir, segment)
    receipt = json.loads(receipt_path.read_text())
    Path(receipt[missing_field]).unlink()

    with pytest.raises(RuntimeError, match=error):
        await archive_finalized_segment(
            segment,
            archiver=_VerifiedArchiver(),  # type: ignore[arg-type]
            prefix="audit",
            receipt_dir=receipt_dir,
        )
