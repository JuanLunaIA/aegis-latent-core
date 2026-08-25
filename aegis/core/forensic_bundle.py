"""Bounded forensic bundle construction for authenticated audit exports."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import struct
import textwrap
import zipfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import cbor2

_MAX_BUNDLE_BYTES = 64 * 1024 * 1024
_MAX_NODES = 1_000
_JCS_MAX_SAFE_INTEGER = (1 << 53) - 1
_CBOR_MAX_UINT = (1 << 64) - 1
_CBOR_MIN_INT = -(1 << 64)


class ForensicBundleError(ValueError):
    """The requested export cannot be represented under the bundle contract."""


def _jcs_bytes(value: Mapping[str, Any]) -> bytes:
    """Canonicalize the restricted manifest data model per RFC 8785.

    Bundle manifests intentionally contain only dictionaries with string keys,
    arrays, strings, booleans, nulls, and integers. For this restricted domain,
    UTF-8 JSON with sorted keys, no insignificant whitespace, and no ASCII
    escaping is RFC 8785 canonical output without an ECMAScript float formatter.
    """

    def normalize(item: Any) -> Any:
        if item is None or isinstance(item, bool):
            return item
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ForensicBundleError("JCS strings must contain Unicode scalar values") from exc
            return item
        if isinstance(item, int):
            if not -_JCS_MAX_SAFE_INTEGER <= item <= _JCS_MAX_SAFE_INTEGER:
                raise ForensicBundleError("JCS integers must remain in the I-JSON safe range")
            return item
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            return [normalize(child) for child in item]
        if isinstance(item, Mapping):
            if not all(isinstance(key, str) for key in item):
                raise ForensicBundleError("JCS manifest keys must be strings")
            if not all(key.isascii() for key in item):
                raise ForensicBundleError("JCS manifest keys must be ASCII")
            return {key: normalize(child) for key, child in item.items()}
        raise ForensicBundleError(f"unsupported JCS manifest type: {type(item).__name__}")

    material = normalize(value)
    return json.dumps(
        material,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _dag_cbor_value(value: Any) -> Any:
    if value is None or isinstance(value, (bytes, bool)):
        return value
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ForensicBundleError(
                "DAG-CBOR strings must contain Unicode scalar values"
            ) from exc
        return value
    if isinstance(value, int):
        if not _CBOR_MIN_INT <= value <= _CBOR_MAX_UINT:
            raise ForensicBundleError("DAG-CBOR integer is outside native CBOR bounds")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ForensicBundleError("DAG-CBOR does not accept non-finite floats")
        if value == 0.0 and math.copysign(1.0, value) < 0:
            raise ForensicBundleError("DAG-CBOR does not accept negative zero")
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ForensicBundleError("DAG-CBOR map keys must be strings")
        for key in value:
            try:
                key.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ForensicBundleError(
                    "DAG-CBOR map keys must contain Unicode scalar values"
                ) from exc
        return {key: _dag_cbor_value(child) for key, child in value.items()}
    if isinstance(value, Sequence):
        return [_dag_cbor_value(child) for child in value]
    raise ForensicBundleError(f"unsupported DAG-CBOR type: {type(value).__name__}")


def _varint(value: int) -> bytes:
    if value < 0:
        raise ForensicBundleError("varint input must be non-negative")
    encoded = bytearray()
    while True:
        octet = value & 0x7F
        value >>= 7
        encoded.append(octet | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def _dag_cbor_cid(payload: bytes) -> str:
    digest = hashlib.sha256(payload).digest()
    cid_bytes = _varint(1) + _varint(0x71) + _varint(0x12) + _varint(len(digest)) + digest
    return "b" + base64.b32encode(cid_bytes).decode("ascii").lower().rstrip("=")


def canonical_jcs_bytes(value: Mapping[str, Any]) -> bytes:
    """Return RFC 8785 bytes for the bundle's restricted canonical domain."""
    return _jcs_bytes(value)


def canonical_dag_cbor_bytes(value: Any) -> bytes:
    """Return deterministic DAG-CBOR bytes for the supported evidence domain."""

    def encode_float64(encoder: Any, item: float) -> None:
        encoder.write(b"\xfb" + struct.pack(">d", item))

    return cbor2.dumps(
        _dag_cbor_value(value),
        canonical=True,
        encoders={float: encode_float64},
    )


def dag_cbor_cid(payload: bytes) -> str:
    """Return a base32 CIDv1 using the dag-cbor codec and SHA2-256 multihash."""
    return _dag_cbor_cid(payload)


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_report(lines: Sequence[str]) -> bytes:
    wrapped: list[str] = []
    for line in lines:
        wrapped.extend(textwrap.wrap(line, width=92, replace_whitespace=True) or [""])
    pages = [wrapped[index : index + 52] for index in range(0, len(wrapped), 52)] or [[]]
    font_id = 3 + len(pages) * 2
    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: (
            f"<< /Type /Pages /Count {len(pages)} /Kids "
            f"[{' '.join(f'{3 + page * 2} 0 R' for page in range(len(pages)))}] >>"
        ).encode("ascii"),
        font_id: b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    }
    for index, page_lines in enumerate(pages):
        page_id = 3 + index * 2
        content_id = page_id + 1
        stream_lines = ["BT", "/F1 9 Tf", "48 760 Td", "12 TL"]
        stream_lines.extend(f"({_pdf_escape(line)}) Tj T*" for line in page_lines)
        stream_lines.append("ET")
        stream = "\n".join(stream_lines).encode("latin-1", errors="replace")
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
        objects[content_id] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream"
        )

    result = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0] * (font_id + 1)
    for object_id in range(1, font_id + 1):
        offsets[object_id] = len(result)
        result.extend(f"{object_id} 0 obj\n".encode("ascii"))
        result.extend(objects[object_id])
        result.extend(b"\nendobj\n")
    xref = len(result)
    result.extend(f"xref\n0 {font_id + 1}\n".encode("ascii"))
    result.extend(b"0000000000 65535 f \n")
    for object_id in range(1, font_id + 1):
        result.extend(f"{offsets[object_id]:010d} 00000 n \n".encode("ascii"))
    result.extend(
        f"trailer\n<< /Size {font_id + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(result)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _verify_script(expected: Mapping[str, str]) -> bytes:
    checks = "\n".join(f"check '{name}' '{digest}'" for name, digest in sorted(expected.items()))
    script = f"""#!/bin/sh
set -eu
check() {{
  file=$1
  expected=$2
  actual=$(openssl dgst -sha256 -r -- "$file" | awk '{{print $1}}')
  if [ "$actual" != "$expected" ]; then
    echo "FAIL $file expected=$expected actual=$actual" >&2
    exit 1
  fi
  echo "OK   $file $actual"
}}
{checks}
echo "Embedded file-byte SHA-256 values match this unauthenticated script."
echo "This does not authenticate the script or archive and does not verify canonical encodings, signatures, MMR proofs, or a trusted root."
"""
    return script.encode("utf-8")


def build_forensic_bundle(
    nodes: Sequence[Any],
    *,
    operator: str,
    acquisition_reason: str,
    generated_at: datetime | None = None,
    scope_start: datetime | None = None,
    scope_end: datetime | None = None,
    max_bundle_bytes: int = _MAX_BUNDLE_BYTES,
) -> bytes:
    """Build a bounded, self-verifying ZIP from retained audit nodes."""
    if not operator.strip() or len(operator) > 200:
        raise ForensicBundleError("operator must contain 1-200 characters")
    if not acquisition_reason.strip() or len(acquisition_reason) > 500:
        raise ForensicBundleError("acquisition_reason must contain 1-500 characters")
    if not nodes:
        raise ForensicBundleError("the requested retained window contains no audit nodes")
    if len(nodes) > _MAX_NODES:
        raise ForensicBundleError(f"a forensic bundle is limited to {_MAX_NODES} nodes")
    if max_bundle_bytes < 1 or max_bundle_bytes > _MAX_BUNDLE_BYTES:
        raise ForensicBundleError("invalid forensic bundle byte limit")

    created = (generated_at or datetime.now(tz=UTC)).astimezone(UTC).replace(microsecond=0)
    scoped_start = scope_start.astimezone(UTC).replace(microsecond=0) if scope_start else None
    scoped_end = scope_end.astimezone(UTC).replace(microsecond=0) if scope_end else None
    records: list[dict[str, Any]] = []
    proofs: list[dict[str, Any]] = []
    signatures: list[dict[str, Any]] = []
    for node in nodes:
        record = dict(node.to_dict())
        record["node_hash"] = node.node_hash
        records.append(record)
        if node.mmr_proof is not None and node.mmr_leaf_hash:
            proofs.append(
                {
                    "state_id": node.state_id,
                    "leaf_hash": node.mmr_leaf_hash,
                    "leaf_index": node.mmr_leaf_index,
                    "leaf_count": node.mmr_leaf_count,
                    "root": node.merkle_root,
                    "proof": node.mmr_proof,
                }
            )
        signatures.append(
            {
                "state_id": node.state_id,
                "node_hash": node.node_hash,
                "scheme": node.signature_scheme,
                "signature": node.signature,
                "public_key": node.public_key,
            }
        )

    ledger_cbor = canonical_dag_cbor_bytes(records)
    proof_json = _jcs_bytes({"proofs": proofs, "version": "aegis-mmr-proof-set-v1"})
    root = records[-1].get("merkle_root", "")
    integrity_lines = [
        "AEGIS LATENT CORE - FORENSIC AUDIT CERTIFICATE",
        f"Generated UTC: {created.isoformat().replace('+00:00', 'Z')}",
        f"Operator: {operator.strip()}",
        f"Acquisition reason: {acquisition_reason.strip()}",
        f"Requested range start: {scoped_start.isoformat().replace('+00:00', 'Z') if scoped_start else 'not-specified'}",
        f"Requested range end: {scoped_end.isoformat().replace('+00:00', 'Z') if scoped_end else 'not-specified'}",
        f"Retained audit nodes: {len(records)}",
        f"Terminal MMR root: {root}",
        "Testability declaration: SHA-256 file digests can be independently recomputed with VERIFY.sh.",
        "Testability declaration: MMR proof paths can be recomputed using docs/api/MMR_PROOF_V1.md.",
        "Boundary: this package records technical integrity evidence; it does not determine legal admissibility.",
        "Boundary: timestamps and roots require an independently trusted checkpoint for third-party assurance.",
    ]
    for signature in signatures:
        integrity_lines.append(
            f"Node {signature['state_id']} hash={signature['node_hash']} scheme={signature['scheme']} "
            f"signature={signature['signature']} public_key={signature['public_key'] or 'not-disclosed'}"
        )
    certificate_pdf = _pdf_report(integrity_lines)

    evidence_files = {
        "audit_certificate.pdf": certificate_pdf,
        "ledger_slice.cbor": ledger_cbor,
        "merkle_proof.json": proof_json,
    }
    manifest_payload: dict[str, Any] = {
        "bundle_version": "aegis-forensic-bundle-v1",
        "canonicalization": "RFC8785-JCS-restricted-integer-domain",
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "operator": operator.strip(),
        "acquisition_reason": acquisition_reason.strip(),
        "scope_start": (scoped_start.isoformat().replace("+00:00", "Z") if scoped_start else None),
        "scope_end": scoped_end.isoformat().replace("+00:00", "Z") if scoped_end else None,
        "node_count": len(records),
        "terminal_mmr_root": root,
        "ledger_slice_cid": _dag_cbor_cid(ledger_cbor),
        "files": [
            {"name": name, "sha256": _sha256(payload), "size": len(payload)}
            for name, payload in sorted(evidence_files.items())
        ],
        "signatures": signatures,
        "limitations": [
            "retained-memory-window only",
            "technical integrity evidence is not a legal admissibility determination",
            "verify roots against an independently trusted checkpoint",
        ],
    }
    payload_seal = _sha256(_jcs_bytes(manifest_payload))
    manifest = _jcs_bytes({**manifest_payload, "manifest_payload_sha256": payload_seal})
    evidence_files["manifest.json"] = manifest
    verify = _verify_script({name: _sha256(payload) for name, payload in evidence_files.items()})

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, payload in sorted(evidence_files.items()):
            info = zipfile.ZipInfo(name, date_time=created.timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            bundle.writestr(info, payload)
        verify_info = zipfile.ZipInfo("VERIFY.sh", date_time=created.timetuple()[:6])
        verify_info.compress_type = zipfile.ZIP_DEFLATED
        verify_info.external_attr = 0o755 << 16
        bundle.writestr(verify_info, verify)
    result = archive.getvalue()
    if len(result) > max_bundle_bytes:
        raise ForensicBundleError("forensic bundle exceeds the configured byte limit")
    return result
