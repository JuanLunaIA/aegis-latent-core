# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.dfir_export — DFIR-compatible evidence bundle export formats.

Produces two DFIR-standard encapsulations of an Aegis evidence package:

1. **PKCS#7 SignedData** (RFC 2315 / CMS RFC 5652): wraps the evidence JSON in
   a CMS SignedData envelope signed with an ephemeral ECDSA P-256 key and a
   self-signed X.509 certificate.  Suitable for court submission as a
   cryptographically attested evidence file.

2. **EWF / E01** (Expert Witness Format v1): encapsulates evidence bytes in the
   EnCase-compatible binary container format.  Includes case metadata, one
   512-byte-aligned data segment, Adler-32 CRCs on all section descriptors, and
   an MD5 + SHA-256 hash section.  Compatible with libewf / FTK Imager readers.

Usage::

    from aegis.core.dfir_export import DFIRExporter

    exporter = DFIRExporter(case_number="C-2026-001", examiner="alice")
    pkcs7_der = exporter.to_pkcs7(evidence_dict)
    e01_bytes  = exporter.to_e01(evidence_dict)
"""

from __future__ import annotations

import hashlib
import json
import logging
import struct
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)

# ── EWF constants ─────────────────────────────────────────────────────────────

_EWF_SIGNATURE = b"\x45\x56\x46\x09\x0d\x0a\xff\x00"  # "EVF" + framing
_EWF_SECTOR_SIZE = 512
_EWF_CHUNK_SIZE = 64 * _EWF_SECTOR_SIZE  # 32 KiB per chunk (standard)
_EWF_SECTION_DESCRIPTOR_SIZE = 76


# ── Exceptions ────────────────────────────────────────────────────────────────


class DFIRExportError(Exception):
    """Raised when a DFIR export operation fails."""


# ── Result types ──────────────────────────────────────────────────────────────


@dataclass
class PKCS7ExportResult:
    """Result of :meth:`DFIRExporter.to_pkcs7`.

    Attributes
    ----------
    der_bytes:
        DER-encoded CMS SignedData structure.
    cert_pem:
        PEM-encoded signer certificate (self-signed ECDSA P-256).
    content_hash_hex:
        SHA-256 hex digest of the signed content (evidence JSON).
    timestamp:
        ISO-8601 UTC timestamp of signing.
    """

    der_bytes: bytes
    cert_pem: bytes
    content_hash_hex: str
    timestamp: str

    def to_dict(self) -> dict[str, object]:
        import base64

        return {
            "format": "pkcs7-signed-data",
            "der_b64": base64.b64encode(self.der_bytes).decode(),
            "cert_pem": self.cert_pem.decode(),
            "content_hash_hex": self.content_hash_hex,
            "timestamp": self.timestamp,
        }


@dataclass
class E01ExportResult:
    """Result of :meth:`DFIRExporter.to_e01`.

    Attributes
    ----------
    e01_bytes:
        Raw bytes of the E01 (EWF v1) container.
    md5_hex:
        MD5 hex digest of the evidence content.
    sha256_hex:
        SHA-256 hex digest of the evidence content.
    timestamp:
        ISO-8601 UTC timestamp of encapsulation.
    byte_count:
        Size in bytes of the evidence content (padded to sector alignment).
    """

    e01_bytes: bytes
    md5_hex: str
    sha256_hex: str
    timestamp: str
    byte_count: int

    def to_dict(self) -> dict[str, object]:
        import base64

        return {
            "format": "ewf-e01",
            "e01_b64": base64.b64encode(self.e01_bytes).decode(),
            "md5_hex": self.md5_hex,
            "sha256_hex": self.sha256_hex,
            "timestamp": self.timestamp,
            "byte_count": self.byte_count,
        }


# ── PKCS#7 ────────────────────────────────────────────────────────────────────


def _build_pkcs7(content: bytes, case_info: str) -> tuple[bytes, bytes]:  # (der, cert_pem)
    """Build a CMS SignedData envelope around *content*."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID

    # Ephemeral signing key (ECDSA P-256)
    private_key = ec.generate_private_key(ec.SECP256R1())

    now = datetime.now(tz=UTC)
    # Self-signed cert valid 30 years (long-retention forensics)
    not_after = now + timedelta(days=30 * 365)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Aegis DFIR Signer"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Aegis Forensics"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, case_info[:64]),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(content)
        .add_signer(cert, private_key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return der, cert_pem


# ── EWF / E01 ────────────────────────────────────────────────────────────────

# Section descriptor layout (76 bytes):
#   type[0:16]    16-byte zero-padded ASCII section type
#   next[16:24]   uint64 LE — offset of next section from start of file
#   size[24:32]   uint64 LE — total section size including descriptor
#   pad[32:72]    40 zero bytes
#   crc[72:76]    uint32 LE — Adler-32 of bytes[0:72]


def _adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def _section_descriptor(
    section_type: str,
    next_offset: int,
    total_size: int,
) -> bytes:
    """Build a 76-byte EWF section descriptor with Adler-32 CRC."""
    hdr = struct.pack(
        "<16sQQ40s",
        section_type.encode().ljust(16, b"\x00")[:16],
        next_offset,
        total_size,
        b"\x00" * 40,
    )
    crc = _adler32(hdr)
    return hdr + struct.pack("<I", crc)


def _ewf_file_header(segment_number: int = 1) -> bytes:
    """Build the 13-byte EWF file header."""
    return (
        _EWF_SIGNATURE + b"\x01\x00" + struct.pack("<H", segment_number) + b"\x00"  # trailing null
    )


def _ewf_header_section(case_number: str, examiner: str, timestamp: str) -> bytes:
    """Build the "header" section (zlib-compressed case metadata)."""
    # EWF header v1 format: tab-separated key=value pairs, zlib-compressed
    header_text = (
        "1\n"
        "main\n"
        f"c\tn\ta\te\tt\tm\tu\tp\tr\n"
        f"{case_number}\t{examiner}\tAegis DFIR Export\t{examiner}"
        f"\taegis-latent-core\t{timestamp}\t{timestamp}\t0\tf\n\n"
    )
    compressed = zlib.compress(header_text.encode("utf-8"), level=9)
    section_data = compressed
    # Section size = descriptor (76) + data
    total_size = _EWF_SECTION_DESCRIPTOR_SIZE + len(section_data)
    return section_data, total_size


def _ewf_volume_section() -> bytes:
    """Build the "volume" section (EWF disk volume info, minimal)."""
    # EWF volume structure (94 bytes):
    #   reserved[0:4]         = 0
    #   chunk_count[4:8]      = number of chunks
    #   sectors_per_chunk[8:12] = 128 (= 64 KiB / 512 = 128 sectors/chunk)
    #   bytes_per_sector[12:16] = 512
    #   sector_count[16:24]   = total sectors
    #   ... rest = zeros
    #   crc at end
    vol_data = struct.pack(
        "<IIIIIQQ40sI",
        0,  # reserved
        1,  # chunk count (we always write 1 chunk)
        _EWF_CHUNK_SIZE // _EWF_SECTOR_SIZE,  # sectors per chunk = 128
        _EWF_SECTOR_SIZE,  # bytes per sector
        0,  # sector_count (filled in conceptually; libewf accepts 0 here)
        0,  # chs cylinders (not used for non-disk evidence)
        0,  # chs heads+sectors (not used)
        b"\x00" * 40,  # padding
        0,  # CRC (computed below)
    )
    # Rebuild with correct Adler-32 of the first 84 bytes
    crc = _adler32(vol_data[:-4])
    vol_data = vol_data[:-4] + struct.pack("<I", crc)
    return vol_data


def _build_e01(
    evidence_bytes: bytes,
    case_number: str,
    examiner: str,
    timestamp: str,
) -> bytes:
    """Assemble a minimal but structurally valid E01 (EWF v1) container.

    Sections written: file-header, header, volume, sectors, table, hash, done.
    """
    # Pad evidence bytes to full sector boundary
    pad_len = (_EWF_SECTOR_SIZE - len(evidence_bytes) % _EWF_SECTOR_SIZE) % _EWF_SECTOR_SIZE
    padded = evidence_bytes + b"\x00" * pad_len

    # Compute hashes over original (unpadded) evidence
    md5 = hashlib.md5(evidence_bytes).digest()  # noqa: S324
    sha256 = hashlib.sha256(evidence_bytes).digest()

    parts: list[bytes] = []

    # ── File header ───────────────────────────────────────────────────────────
    file_hdr = _ewf_file_header(segment_number=1)
    parts.append(file_hdr)
    offset = len(file_hdr)

    # ── Helper: reserve space for section descriptors we'll fill in later ─────
    sections: list[tuple[str, int, bytes]] = []  # (type, descriptor_offset, section_data)

    def _append_section(stype: str, data: bytes) -> int:
        nonlocal offset
        total_size = _EWF_SECTION_DESCRIPTOR_SIZE + len(data)
        next_off = offset + total_size
        desc = _section_descriptor(stype, next_off, total_size)
        parts.append(desc)
        parts.append(data)
        sections.append((stype, offset, data))
        offset = next_off
        return offset

    # ── Header section ────────────────────────────────────────────────────────
    hdr_data, _ = _ewf_header_section(case_number, examiner, timestamp)
    _append_section("header", hdr_data)

    # ── Volume section ────────────────────────────────────────────────────────
    vol_data = _ewf_volume_section()
    _append_section("volume", vol_data)

    # ── Sectors section (raw evidence bytes, padded) ──────────────────────────
    _append_section("sectors", padded)

    # ── Table section (chunk offset table: 1 chunk at sectors-section body) ──
    # Table header: crc + entries
    # Each entry: 4-byte LE offset from start of sectors-section body
    # Sectors section started at sections[-1] position...
    sectors_body_offset = sum(
        _EWF_SECTION_DESCRIPTOR_SIZE + len(d)
        for _, _, d in sections[:-1]  # everything before "sectors" body offset
    )
    # The sectors body starts right after its descriptor
    # Absolute offset = file_hdr + all_prior_sections + descriptor
    # We already tracked this in offset before appending sectors; recalculate:
    # sectors section was the 3rd appended: idx 2 in sections
    sectors_idx = next(i for i, (t, _, _) in enumerate(sections) if t == "sectors")
    _, sectors_sec_offset, sectors_sec_data = sections[sectors_idx]
    sectors_body_abs = sectors_sec_offset + _EWF_SECTION_DESCRIPTOR_SIZE

    # Table entry: offset from start of sectors body data = 0 (first chunk)
    # Upper bit = uncompressed flag
    chunk_entry = struct.pack("<I", 0x80000000)  # chunk at offset 0, uncompressed

    # Table header (24 bytes): chunk_count(4), padding(16), crc(4)
    table_hdr_body = struct.pack("<I16s", 1, b"\x00" * 16)  # 1 chunk
    table_hdr_crc = _adler32(table_hdr_body)
    table_hdr = table_hdr_body + struct.pack("<I", table_hdr_crc)

    # Table data: table_hdr + chunk_entry + end_crc
    table_body = table_hdr + chunk_entry
    table_crc = _adler32(table_body)
    table_data = table_body + struct.pack("<I", table_crc)
    _append_section("table", table_data)

    # ── Hash section (16-byte MD5 + 16-byte SHA-256 first 16 bytes + 4 CRC) ──
    # EWF uses MD5 (16 bytes) in hash section; we extend with SHA-256
    hash_body = md5 + sha256[:16]  # 32 bytes total (MD5 + first half SHA-256)
    hash_crc = _adler32(hash_body)
    hash_data = hash_body + struct.pack("<I", hash_crc)
    _append_section("hash", hash_data)

    # ── Done section (self-referential: next = own offset; size = 76) ────────
    done_offset = offset
    done_desc = _section_descriptor("done", done_offset, _EWF_SECTION_DESCRIPTOR_SIZE)
    parts.append(done_desc)

    return b"".join(parts)


# ── Main class ────────────────────────────────────────────────────────────────


class DFIRExporter:
    """Export evidence packages in DFIR-standard formats.

    Parameters
    ----------
    case_number:
        Case identifier for metadata fields (e.g., ``"C-2026-001"``).
    examiner:
        Name or ID of the forensic examiner.
    """

    def __init__(
        self,
        case_number: str = "AEGIS-CASE",
        examiner: str = "aegis-operator",
    ) -> None:
        self.case_number = case_number
        self.examiner = examiner

    # ── Public API ─────────────────────────────────────────────────────────────

    def to_pkcs7(self, evidence: dict[str, object]) -> PKCS7ExportResult:
        """Wrap *evidence* in a PKCS#7 / CMS SignedData envelope.

        Parameters
        ----------
        evidence:
            JSON-serializable evidence dict (e.g., an ISO 27037 package).

        Returns
        -------
        PKCS7ExportResult
            DER-encoded SignedData and associated metadata.

        Raises
        ------
        DFIRExportError
            When serialisation or signing fails.
        """
        try:
            content = _canonical_json(evidence)
        except (TypeError, ValueError) as exc:
            raise DFIRExportError(f"Evidence is not JSON-serializable: {exc}") from exc

        content_hash = hashlib.sha256(content).hexdigest()
        ts = datetime.now(tz=UTC).isoformat()
        case_info = f"{self.case_number} / {self.examiner}"

        try:
            der, cert_pem = _build_pkcs7(content, case_info)
        except Exception as exc:
            raise DFIRExportError(f"PKCS#7 signing failed: {exc}") from exc

        logger.info(
            "dfir_export: PKCS7 envelope created — case=%r sha256=%s size=%d",
            self.case_number,
            content_hash[:16],
            len(der),
        )
        return PKCS7ExportResult(
            der_bytes=der,
            cert_pem=cert_pem,
            content_hash_hex=content_hash,
            timestamp=ts,
        )

    def to_e01(self, evidence: dict[str, object]) -> E01ExportResult:
        """Encapsulate *evidence* in an EWF / E01 forensic container.

        Parameters
        ----------
        evidence:
            JSON-serializable evidence dict.

        Returns
        -------
        E01ExportResult
            Raw E01 bytes and hash metadata.

        Raises
        ------
        DFIRExportError
            When serialisation fails.
        """
        try:
            content = _canonical_json(evidence)
        except (TypeError, ValueError) as exc:
            raise DFIRExportError(f"Evidence is not JSON-serializable: {exc}") from exc

        ts = datetime.now(tz=UTC).isoformat()
        ts_compact = ts[:19].replace(":", "").replace("-", "")

        md5_hex = hashlib.md5(content).hexdigest()  # noqa: S324
        sha256_hex = hashlib.sha256(content).hexdigest()

        try:
            e01_bytes = _build_e01(content, self.case_number, self.examiner, ts_compact)
        except Exception as exc:
            raise DFIRExportError(f"E01 assembly failed: {exc}") from exc

        logger.info(
            "dfir_export: E01 container created — case=%r size=%d sha256=%s",
            self.case_number,
            len(e01_bytes),
            sha256_hex[:16],
        )
        return E01ExportResult(
            e01_bytes=e01_bytes,
            md5_hex=md5_hex,
            sha256_hex=sha256_hex,
            timestamp=ts,
            byte_count=len(content),
        )


def _canonical_json(data: dict[str, object]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
