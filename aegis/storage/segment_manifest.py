# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Versioned manifests for finalized JSONL WAL segments.

A segment digest, MMR root, chain tip, and RFC 3161 imprint are separate
cryptographic domains. This module records each value explicitly and never treats
one as a substitute for another.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.anchoring.rfc3161 import RFC3161AnchorClient, TimestampAnchor
from aegis.core.crypto_audit import AuditNode
from aegis.storage.s3_worm import ArchiveState, S3WormArchiver


@dataclass(frozen=True, slots=True)
class SegmentManifest:
    format: str
    segment_name: str
    size: int
    file_sha256: str
    chain_tip: str
    mmr_root: str
    mmr_leaf_count: int
    finalized_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "chain_tip": self.chain_tip,
            "file_sha256": self.file_sha256,
            "finalized_at": self.finalized_at,
            "format": self.format,
            "mmr_leaf_count": self.mmr_leaf_count,
            "mmr_root": self.mmr_root,
            "segment_name": self.segment_name,
            "size": self.size,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")


def build_segment_manifest(path: str | Path) -> SegmentManifest:
    segment = Path(path)
    data = segment.read_bytes()
    if not data or not data.endswith(b"\n"):
        raise ValueError("finalized WAL segment must be non-empty and newline terminated")
    last_line = data.rstrip(b"\n").rsplit(b"\n", 1)[-1]
    try:
        node: Any = json.loads(last_line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("finalized WAL segment has an invalid terminal JSON record") from exc
    if not isinstance(node, dict):
        raise ValueError("finalized WAL terminal record must be an object")
    try:
        terminal_node = AuditNode.from_dict(dict(node))
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("finalized WAL terminal record cannot be reconstructed") from exc
    chain_tip = terminal_node.node_hash
    mmr_root = terminal_node.merkle_root
    mmr_leaf_count = terminal_node.mmr_leaf_count
    if (
        not isinstance(chain_tip, str)
        or len(chain_tip) != 64
        or not isinstance(mmr_root, str)
        or len(mmr_root) != 64
        or isinstance(mmr_leaf_count, bool)
        or not isinstance(mmr_leaf_count, int)
        or mmr_leaf_count < 1
    ):
        raise ValueError("finalized WAL terminal record lacks cryptographic checkpoint fields")
    stat = segment.stat()
    return SegmentManifest(
        format="aegis-wal-segment-manifest-v1",
        segment_name=segment.name,
        size=len(data),
        file_sha256=hashlib.sha256(data).hexdigest(),
        chain_tip=chain_tip,
        mmr_root=mmr_root,
        mmr_leaf_count=mmr_leaf_count,
        finalized_at=datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
    )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


async def archive_finalized_segment(
    path: str | Path,
    *,
    archiver: S3WormArchiver,
    prefix: str,
    receipt_dir: Path,
    anchor_client: RFC3161AnchorClient | None = None,
) -> tuple[SegmentManifest, TimestampAnchor | None]:
    """Archive one immutable segment and manifest, then optionally timestamp it."""

    segment = Path(path)
    manifest = build_segment_manifest(segment)
    normalized_prefix = prefix.strip("/")
    segment_key = f"{normalized_prefix}/segments/{manifest.segment_name}"
    manifest_key = f"{normalized_prefix}/manifests/{manifest.segment_name}.json"
    segment_record = await archiver.archive(segment.read_bytes(), key=segment_key)
    manifest_bytes = manifest.canonical_bytes()
    manifest_record = await archiver.archive(manifest_bytes, key=manifest_key)
    await archiver.wait()
    segment_record = await archiver.get(segment_record.archive_id)
    manifest_record = await archiver.get(manifest_record.archive_id)
    if segment_record.state is not ArchiveState.VERIFIED:
        raise RuntimeError("segment archive is not remotely verified")
    if manifest_record.state is not ArchiveState.VERIFIED:
        raise RuntimeError("segment manifest archive is not remotely verified")

    receipt_path = receipt_dir / f"{manifest.segment_name}.anchor.json"
    if receipt_path.exists() or anchor_client is None:
        return manifest, None
    anchor = await anchor_client.anchor(manifest_bytes)
    receipt = {
        "anchor_id": anchor.anchor_id,
        "cms_trusted": anchor.cms_trusted,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "message_imprint": anchor.message_imprint.hex(),
        "nonce": str(anchor.nonce),
        "request_path": str(anchor.request_path),
        "response_path": str(anchor.response_path),
    }
    _atomic_write(
        receipt_path,
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )
    return manifest, anchor


__all__ = ["SegmentManifest", "archive_finalized_segment", "build_segment_manifest"]
