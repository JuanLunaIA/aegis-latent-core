# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.dfir_export — PKCS#7 and E01 evidence export."""

from __future__ import annotations

import base64
import hashlib
import struct

import pytest

from aegis.core.dfir_export import (
    _EWF_SECTION_DESCRIPTOR_SIZE,
    _EWF_SIGNATURE,
    DFIRExporter,
    DFIRExportError,
    E01ExportResult,
    PKCS7ExportResult,
    _adler32,
    _build_e01,
    _canonical_json,
    _ewf_file_header,
    _section_descriptor,
)

_EVIDENCE: dict = {
    "bundle_id": "evd-001",
    "chain_hash": "abc123" * 10,
    "operator": "alice",
    "node_count": 42,
    "legal_admissibility": "Admissible",
}


# ── Helpers ───────────────────────────────────────────────────────────────────


class TestCanonicalJson:
    def test_returns_bytes(self) -> None:
        assert isinstance(_canonical_json(_EVIDENCE), bytes)

    def test_deterministic(self) -> None:
        assert _canonical_json(_EVIDENCE) == _canonical_json(dict(_EVIDENCE))

    def test_sorted_keys(self) -> None:
        a = _canonical_json({"b": 1, "a": 2})
        b = _canonical_json({"a": 2, "b": 1})
        assert a == b


class TestAdler32:
    def test_zero_bytes(self) -> None:
        assert _adler32(b"") == 1

    def test_known_value(self) -> None:
        import zlib

        result = _adler32(b"ABC")
        assert result == zlib.adler32(b"ABC") & 0xFFFFFFFF

    def test_returns_int(self) -> None:
        assert isinstance(_adler32(b"test"), int)

    def test_fits_uint32(self) -> None:
        assert 0 <= _adler32(b"data") <= 0xFFFFFFFF


class TestSectionDescriptor:
    def test_length_76(self) -> None:
        d = _section_descriptor("header", 100, 200)
        assert len(d) == 76

    def test_type_field(self) -> None:
        d = _section_descriptor("sectors", 0, 76)
        assert d[:7] == b"sectors"
        assert d[7:16] == b"\x00" * 9  # zero-padded to 16

    def test_next_offset_encoded(self) -> None:
        d = _section_descriptor("done", 12345, 76)
        next_val = struct.unpack_from("<Q", d, 16)[0]
        assert next_val == 12345

    def test_size_encoded(self) -> None:
        d = _section_descriptor("hash", 0, 999)
        size_val = struct.unpack_from("<Q", d, 24)[0]
        assert size_val == 999

    def test_crc_at_byte_72(self) -> None:
        d = _section_descriptor("done", 100, 76)
        crc_actual = struct.unpack_from("<I", d, 72)[0]
        crc_expected = _adler32(d[:72])
        assert crc_actual == crc_expected


class TestEwfFileHeader:
    def test_length_13(self) -> None:
        assert len(_ewf_file_header()) == 13

    def test_signature(self) -> None:
        hdr = _ewf_file_header()
        assert hdr[:8] == _EWF_SIGNATURE

    def test_segment_number(self) -> None:
        hdr = _ewf_file_header(segment_number=3)
        seg = struct.unpack_from("<H", hdr, 10)[0]
        assert seg == 3

    def test_default_segment_1(self) -> None:
        hdr = _ewf_file_header()
        seg = struct.unpack_from("<H", hdr, 10)[0]
        assert seg == 1


# ── E01 container ─────────────────────────────────────────────────────────────


class TestBuildE01:
    def _make(self, data: bytes | None = None) -> bytes:
        data = data or b"EVIDENCE" * 100
        return _build_e01(data, "C-001", "alice", "20260621T120000")

    def test_starts_with_ewf_signature(self) -> None:
        b = self._make()
        assert b[:8] == _EWF_SIGNATURE

    def test_returns_bytes(self) -> None:
        assert isinstance(self._make(), bytes)

    def test_min_size(self) -> None:
        b = self._make()
        # At least file header + several section descriptors
        assert len(b) > 13 + 5 * _EWF_SECTION_DESCRIPTOR_SIZE

    def test_contains_done_section(self) -> None:
        b = self._make()
        assert b"done" in b

    def test_contains_header_section(self) -> None:
        b = self._make()
        assert b"header" in b

    def test_contains_sectors_section(self) -> None:
        b = self._make()
        assert b"sectors" in b

    def test_contains_hash_section(self) -> None:
        b = self._make()
        assert b"hash" in b

    def test_evidence_in_container(self) -> None:
        evidence = b"UNIQUE_EVIDENCE_DATA_" + b"X" * 50
        b = _build_e01(evidence, "C-001", "alice", "20260621T120000")
        assert evidence in b

    def test_sector_padding(self) -> None:
        # Evidence not sector-aligned → padded to sector boundary
        evidence = b"A" * 100  # 100 bytes, not multiple of 512
        b = _build_e01(evidence, "C-001", "alice", "20260621")
        # Padded data should be in the file
        assert b"A" * 100 in b

    def test_empty_evidence(self) -> None:
        b = _build_e01(b"", "C-001", "alice", "20260621")
        assert b[:8] == _EWF_SIGNATURE

    def test_large_evidence(self) -> None:
        large = b"X" * (64 * 1024)  # 64 KiB
        b = _build_e01(large, "C-001", "alice", "20260621")
        assert large in b


# ── DFIRExporter construction ─────────────────────────────────────────────────


class TestDFIRExporterConstruction:
    def test_defaults(self) -> None:
        ex = DFIRExporter()
        assert ex.case_number == "AEGIS-CASE"
        assert ex.examiner == "aegis-operator"

    def test_custom_params(self) -> None:
        ex = DFIRExporter(case_number="C-001", examiner="bob")
        assert ex.case_number == "C-001"
        assert ex.examiner == "bob"


# ── to_pkcs7() ────────────────────────────────────────────────────────────────


class TestToPKCS7:
    def setup_method(self) -> None:
        self.ex = DFIRExporter(case_number="C-001", examiner="alice")

    def test_returns_pkcs7_result(self) -> None:
        result = self.ex.to_pkcs7(_EVIDENCE)
        assert isinstance(result, PKCS7ExportResult)

    def test_der_is_bytes(self) -> None:
        result = self.ex.to_pkcs7(_EVIDENCE)
        assert isinstance(result.der_bytes, bytes)

    def test_der_nonempty(self) -> None:
        result = self.ex.to_pkcs7(_EVIDENCE)
        assert len(result.der_bytes) > 0

    def test_cert_pem_starts_with_begin(self) -> None:
        result = self.ex.to_pkcs7(_EVIDENCE)
        assert result.cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_content_hash_hex_is_sha256(self) -> None:
        result = self.ex.to_pkcs7(_EVIDENCE)
        assert len(result.content_hash_hex) == 64
        int(result.content_hash_hex, 16)  # valid hex

    def test_content_hash_matches_json(self) -> None:
        result = self.ex.to_pkcs7(_EVIDENCE)
        expected = hashlib.sha256(_canonical_json(_EVIDENCE)).hexdigest()
        assert result.content_hash_hex == expected

    def test_timestamp_set(self) -> None:
        from datetime import datetime

        result = self.ex.to_pkcs7(_EVIDENCE)
        dt = datetime.fromisoformat(result.timestamp)
        assert dt.tzinfo is not None

    def test_to_dict_format_field(self) -> None:
        result = self.ex.to_pkcs7(_EVIDENCE)
        d = result.to_dict()
        assert d["format"] == "pkcs7-signed-data"

    def test_to_dict_has_der_b64(self) -> None:
        result = self.ex.to_pkcs7(_EVIDENCE)
        d = result.to_dict()
        assert "der_b64" in d
        base64.b64decode(d["der_b64"])  # valid base64

    def test_to_dict_has_cert_pem(self) -> None:
        result = self.ex.to_pkcs7(_EVIDENCE)
        d = result.to_dict()
        assert "-----BEGIN CERTIFICATE-----" in d["cert_pem"]

    def test_different_evidence_different_hash(self) -> None:
        r1 = self.ex.to_pkcs7({"a": 1})
        r2 = self.ex.to_pkcs7({"a": 2})
        assert r1.content_hash_hex != r2.content_hash_hex

    def test_non_serializable_raises(self) -> None:
        with pytest.raises(DFIRExportError, match="not JSON-serializable"):
            self.ex.to_pkcs7({"key": object()})  # type: ignore[arg-type]

    def test_empty_dict(self) -> None:
        result = self.ex.to_pkcs7({})
        assert len(result.der_bytes) > 0

    def test_der_starts_with_sequence(self) -> None:
        # DER-encoded SEQUENCE starts with 0x30
        result = self.ex.to_pkcs7(_EVIDENCE)
        assert result.der_bytes[0] == 0x30


# ── to_e01() ──────────────────────────────────────────────────────────────────


class TestToE01:
    def setup_method(self) -> None:
        self.ex = DFIRExporter(case_number="C-001", examiner="alice")

    def test_returns_e01_result(self) -> None:
        result = self.ex.to_e01(_EVIDENCE)
        assert isinstance(result, E01ExportResult)

    def test_e01_bytes_nonempty(self) -> None:
        result = self.ex.to_e01(_EVIDENCE)
        assert len(result.e01_bytes) > 0

    def test_starts_with_ewf_signature(self) -> None:
        result = self.ex.to_e01(_EVIDENCE)
        assert result.e01_bytes[:8] == _EWF_SIGNATURE

    def test_md5_hex_length(self) -> None:
        result = self.ex.to_e01(_EVIDENCE)
        assert len(result.md5_hex) == 32
        int(result.md5_hex, 16)

    def test_sha256_hex_length(self) -> None:
        result = self.ex.to_e01(_EVIDENCE)
        assert len(result.sha256_hex) == 64
        int(result.sha256_hex, 16)

    def test_md5_matches_content(self) -> None:
        result = self.ex.to_e01(_EVIDENCE)
        expected = hashlib.md5(_canonical_json(_EVIDENCE)).hexdigest()  # noqa: S324
        assert result.md5_hex == expected

    def test_sha256_matches_content(self) -> None:
        result = self.ex.to_e01(_EVIDENCE)
        expected = hashlib.sha256(_canonical_json(_EVIDENCE)).hexdigest()
        assert result.sha256_hex == expected

    def test_byte_count(self) -> None:
        result = self.ex.to_e01(_EVIDENCE)
        expected = len(_canonical_json(_EVIDENCE))
        assert result.byte_count == expected

    def test_timestamp_set(self) -> None:
        from datetime import datetime

        result = self.ex.to_e01(_EVIDENCE)
        dt = datetime.fromisoformat(result.timestamp)
        assert dt.tzinfo is not None

    def test_to_dict_format(self) -> None:
        result = self.ex.to_e01(_EVIDENCE)
        d = result.to_dict()
        assert d["format"] == "ewf-e01"

    def test_to_dict_e01_b64(self) -> None:
        result = self.ex.to_e01(_EVIDENCE)
        d = result.to_dict()
        assert "e01_b64" in d
        raw = base64.b64decode(d["e01_b64"])
        assert raw == result.e01_bytes

    def test_non_serializable_raises(self) -> None:
        with pytest.raises(DFIRExportError, match="not JSON-serializable"):
            self.ex.to_e01({"key": object()})  # type: ignore[arg-type]

    def test_different_evidence_different_hashes(self) -> None:
        r1 = self.ex.to_e01({"a": 1})
        r2 = self.ex.to_e01({"a": 2})
        assert r1.sha256_hex != r2.sha256_hex

    def test_empty_evidence_dict(self) -> None:
        result = self.ex.to_e01({})
        assert result.e01_bytes[:8] == _EWF_SIGNATURE

    def test_large_evidence(self) -> None:
        large = {"data": "A" * 10000}
        result = self.ex.to_e01(large)
        assert result.byte_count > 10000
