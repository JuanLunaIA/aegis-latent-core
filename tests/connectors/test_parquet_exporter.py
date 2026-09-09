# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Parquet export: a faithful projection, tied back to the bytes it came from.

The export is for analytics; the WAL stays the evidence. So the tests check two
things beyond "it wrote a file": that the manifest pins the *source* segment by
digest, chain tip and MMR root, and that an unfinalized segment is refused
before any Parquet file exists to be mistaken for a complete export.

The segments here are built by committing through a real
``CryptographicAuditLedger``, not by hand-writing JSON, so the fixture cannot
drift from the format the exporter actually meets.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger

pa = pytest.importorskip("pyarrow", reason="pyarrow is the optional 'lakehouse' extra")
pq = pytest.importorskip("pyarrow.parquet", reason="pyarrow is the optional 'lakehouse' extra")

from aegis.connectors.lakehouse.parquet_exporter import (  # noqa: E402
    EXPORT_FORMAT,
    arrow_schema,
    export_segment,
)

SIGNING_KEY = "k" * 32


@pytest.fixture
def segment(tmp_path):
    """A finalized WAL segment with three committed nodes."""

    path = tmp_path / "wal.jsonl"
    ledger = CryptographicAuditLedger(str(path), signing_key=SIGNING_KEY)
    try:
        for i in range(3):
            ledger.commit_forensic(
                state_id=f"req-{i}",
                request_bytes=f"request {i}".encode(),
                response_bytes=f"response {i}".encode(),
                tenant_id="acme",
            )
    finally:
        ledger.close()
    return path


class TestExport:
    def test_every_committed_node_becomes_a_row(self, segment, tmp_path):
        result = export_segment(segment, tmp_path / "out")
        assert result.row_count == 3

        table = pq.read_table(result.parquet_path)
        assert table.num_rows == 3
        assert table.column("state_id").to_pylist() == ["req-0", "req-1", "req-2"]

    def test_the_schema_is_the_declared_projection(self, segment, tmp_path):
        result = export_segment(segment, tmp_path / "out")
        table = pq.read_table(result.parquet_path)
        assert table.schema.names == [f.name for f in arrow_schema()]

    def test_digests_are_stored_as_bytes_not_hex_text(self, segment, tmp_path):
        """32 raw bytes, not 64 characters that invite case-sensitive compares."""

        result = export_segment(segment, tmp_path / "out")
        table = pq.read_table(result.parquet_path)
        for digest in table.column("request_hash").to_pylist():
            assert isinstance(digest, bytes)
            assert len(digest) == 32

    def test_the_row_values_match_the_source_records(self, segment, tmp_path):
        result = export_segment(segment, tmp_path / "out")
        table = pq.read_table(result.parquet_path)

        source = [json.loads(line) for line in segment.read_text().splitlines() if line.strip()]
        assert table.column("request_hash").to_pylist() == [
            bytes.fromhex(node["request_hash"]) for node in source
        ]
        assert table.column("tenant_id").to_pylist() == [node["tenant_id"] for node in source]

    def test_zstd_compression_is_the_default(self, segment, tmp_path):
        result = export_segment(segment, tmp_path / "out")
        metadata = pq.ParquetFile(result.parquet_path).metadata
        codecs = {
            metadata.row_group(g).column(c).compression
            for g in range(metadata.num_row_groups)
            for c in range(metadata.num_columns)
        }
        assert codecs <= {"ZSTD"}


class TestManifest:
    def test_the_manifest_pins_the_source_segment_by_digest(self, segment, tmp_path):
        result = export_segment(segment, tmp_path / "out")
        body = json.loads(result.manifest_path.read_text())

        assert body["format"] == "aegis-wal-segment-manifest-v1"
        assert body["file_sha256"] == hashlib.sha256(segment.read_bytes()).hexdigest()
        assert body["file_sha256"] == result.segment_sha256

    def test_the_manifest_carries_the_chain_tip_and_mmr_root(self, segment, tmp_path):
        """Derived independently from the terminal record, not read back.

        ``node_hash`` is not a serialized field — it is recomputed by
        ``AuditNode.from_dict``. Reconstructing it here rather than trusting the
        manifest is what makes this a check instead of a tautology.
        """

        from aegis.core.crypto_audit import AuditNode

        result = export_segment(segment, tmp_path / "out")
        body = json.loads(result.manifest_path.read_text())

        terminal_record = json.loads(segment.read_text().splitlines()[-1])
        terminal_node = AuditNode.from_dict(terminal_record)

        assert body["chain_tip"] == terminal_node.node_hash == result.chain_tip
        assert body["mmr_root"] == terminal_record["merkle_root"] == result.mmr_root

    def test_the_manifest_records_the_export_and_its_boundary(self, segment, tmp_path):
        result = export_segment(segment, tmp_path / "out")
        export = json.loads(result.manifest_path.read_text())["export"]

        assert export["format"] == EXPORT_FORMAT
        assert export["row_count"] == 3
        assert export["parquet_file"] == result.parquet_path.name
        # The projection boundary must travel with the data, not only the docs.
        assert "never against this table" in export["boundary"]

    def test_the_manifest_uses_the_same_builder_as_the_archival_path(self, segment, tmp_path):
        """Two implementations of one manifest would drift; this pins one."""

        from aegis.storage.segment_manifest import build_segment_manifest

        result = export_segment(segment, tmp_path / "out")
        direct = build_segment_manifest(segment).to_dict()
        exported = json.loads(result.manifest_path.read_text())
        for key, value in direct.items():
            assert exported[key] == value, key


class TestRefusal:
    def test_an_unfinalized_segment_is_refused_before_anything_is_written(self, tmp_path):
        """A partial line means the writer is still running or died mid-append."""

        bad = tmp_path / "partial.jsonl"
        bad.write_text('{"state_id": "req-0"')  # no newline, not terminated
        out = tmp_path / "out"

        with pytest.raises(ValueError):
            export_segment(bad, out)
        assert not list(out.glob("*.parquet")) if out.exists() else True

    def test_an_empty_segment_is_refused(self, tmp_path):
        empty = tmp_path / "empty.jsonl"
        empty.write_text("")
        with pytest.raises(ValueError, match="non-empty"):
            export_segment(empty, tmp_path / "out")

    def test_a_segment_without_checkpoint_fields_is_refused(self, tmp_path):
        """A record that is JSON but not an audit node must not export."""

        bogus = tmp_path / "bogus.jsonl"
        bogus.write_text(json.dumps({"hello": "world"}) + "\n")
        with pytest.raises(ValueError):
            export_segment(bogus, tmp_path / "out")
