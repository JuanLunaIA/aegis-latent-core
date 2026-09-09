# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Convert a finalized JSONL WAL segment into Parquet for a lakehouse.

Produces a zstd-compressed Parquet file plus the segment's own
``aegis-wal-segment-manifest-v1`` manifest, so a warehouse table and the
cryptographic checkpoint that describes it travel together.

    result = export_segment("/var/lib/aegis/wal.jsonl.1", "/out")
    result.parquet_path, result.manifest_path, result.row_count

The Parquet copy is a projection, not the evidence
--------------------------------------------------

This is the point most likely to be misread in a compliance review, so it is
stated here and in the manifest:

- The schema below is a **projection**. Hashes, roots and signatures are
  carried; request and response *bodies* are not, because the WAL does not hold
  them either.
- **Verification is against the WAL**, never against the table. Parquet
  encoding, column pruning, engine-side type coercion and any later ``OPTIMIZE``
  or compaction can all change bytes without changing SQL semantics — which is
  fine for analytics and fatal for a hash. Recomputing a chain from Parquet
  rows is not a verification.
- The manifest is the join point. It carries the segment's SHA-256, chain tip,
  MMR root and leaf count, so a reviewer can tie a table partition back to the
  bytes it came from and then verify *those*.
- Rows are ordered as the segment was. Lakehouse engines do not promise to
  preserve that on read; sort by ``timestamp`` and ``state_id`` if order
  matters to a query.

``pyarrow`` is an optional dependency. It is imported lazily so the core
package and its lock file stay untouched by a connector most deployments never
enable; install it with the ``lakehouse`` extra.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from aegis.storage.segment_manifest import build_segment_manifest

if TYPE_CHECKING:  # pragma: no cover - typing only
    import pyarrow as pa

#: Emitted alongside the Parquet file, describing the projection applied.
EXPORT_FORMAT: Final[str] = "aegis-wal-parquet-export-v1"

_ZSTD: Final[str] = "zstd"


class PyArrowUnavailableError(RuntimeError):
    """``pyarrow`` is not installed; the lakehouse extra provides it."""


def _require_pyarrow() -> tuple[Any, Any]:
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise PyArrowUnavailableError(
            "the Parquet exporter needs pyarrow; install it with "
            "`pip install 'aegis-latent-core[lakehouse]'`"
        ) from exc
    return pa, pq


def arrow_schema() -> pa.Schema:
    """The exported schema.

    ``binary`` rather than ``string`` for the digest columns: they are 32-byte
    values, and storing them as hex text doubles the column and invites a
    reader to compare them case-sensitively.
    """

    pa, _ = _require_pyarrow()
    return pa.schema(
        [
            pa.field("state_id", pa.string(), nullable=False),
            pa.field("timestamp", pa.timestamp("us", tz="UTC"), nullable=True),
            pa.field("tenant_id", pa.string(), nullable=True),
            pa.field("request_hash", pa.binary(), nullable=True),
            pa.field("response_hash", pa.binary(), nullable=True),
            pa.field("merkle_root", pa.binary(), nullable=True),
            pa.field("signature", pa.binary(), nullable=True),
            pa.field("status", pa.string(), nullable=True),
        ]
    )


@dataclass(frozen=True, slots=True)
class ExportResult:
    """What an export produced, and how to tie it back to the WAL."""

    parquet_path: Path
    manifest_path: Path
    row_count: int
    segment_sha256: str
    chain_tip: str
    mmr_root: str


def _maybe_hex(value: Any) -> bytes | None:
    """Decode a hex digest to bytes, or ``None`` when absent or malformed.

    Malformed is ``None`` rather than an exception: one unparseable field in a
    historical record should not block the export of a whole segment, and the
    manifest still pins the source bytes for anyone who needs to look.
    """

    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _maybe_timestamp(value: Any) -> datetime | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _iter_nodes(segment: Path) -> Iterator[dict[str, Any]]:
    with segment.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                node = json.loads(line)
            except json.JSONDecodeError:
                # A truncated tail is how a segment looks after an abrupt stop.
                # Stopping here mirrors the WAL loader, which also treats the
                # first bad record as the end of the readable prefix.
                break
            if isinstance(node, dict):
                yield node


def _project(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "state_id": str(node.get("state_id", "")),
        "timestamp": _maybe_timestamp(node.get("timestamp")),
        "tenant_id": node.get("tenant_id") if isinstance(node.get("tenant_id"), str) else None,
        "request_hash": _maybe_hex(node.get("request_hash")),
        "response_hash": _maybe_hex(node.get("response_hash")),
        "merkle_root": _maybe_hex(node.get("merkle_root")),
        "signature": _maybe_hex(node.get("signature")),
        "status": node.get("status") if isinstance(node.get("status"), str) else None,
    }


def export_segment(
    segment_path: str | Path,
    output_dir: str | Path,
    *,
    compression: str = _ZSTD,
) -> ExportResult:
    """Export one finalized segment to Parquet with its manifest beside it.

    The manifest is built by :func:`build_segment_manifest`, the same function
    the archival path uses, so a Parquet export and a WORM archive describe the
    segment identically rather than through two drifting implementations.
    """

    pa, pq = _require_pyarrow()
    segment = Path(segment_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Built first: it validates that the segment is finalized and carries the
    # cryptographic checkpoint fields, so an unfinalized segment is refused
    # before any Parquet file exists to be mistaken for a complete export.
    manifest = build_segment_manifest(segment)

    rows = [_project(node) for node in _iter_nodes(segment)]
    schema = arrow_schema()
    table = pa.Table.from_pylist(rows, schema=schema) if rows else schema.empty_table()

    parquet_path = out_dir / f"{segment.name}.parquet"
    pq.write_table(table, parquet_path, compression=compression)

    manifest_body = dict(manifest.to_dict())
    manifest_body["export"] = {
        "format": EXPORT_FORMAT,
        "parquet_file": parquet_path.name,
        "row_count": len(rows),
        "compression": compression,
        "projection": [field.name for field in schema],
        "boundary": (
            "Projection of the JSONL WAL segment for analytics. Verification is "
            "against the WAL bytes described by file_sha256, never against this table."
        ),
    }
    manifest_path = out_dir / f"{segment.name}.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest_body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return ExportResult(
        parquet_path=parquet_path,
        manifest_path=manifest_path,
        row_count=len(rows),
        segment_sha256=manifest.file_sha256,
        chain_tip=manifest.chain_tip,
        mmr_root=manifest.mmr_root,
    )


__all__ = [
    "EXPORT_FORMAT",
    "ExportResult",
    "PyArrowUnavailableError",
    "arrow_schema",
    "export_segment",
]
