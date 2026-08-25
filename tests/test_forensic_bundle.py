# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import zipfile
from datetime import UTC, datetime

import cbor2
import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.forensic_bundle import (
    ForensicBundleError,
    build_forensic_bundle,
    canonical_dag_cbor_bytes,
    canonical_jcs_bytes,
)


def _node(tmp_path):
    ledger = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "audit.jsonl"),
        signing_key="test-signing-key",
    )
    node = ledger.commit_forensic(
        state_id="request-1",
        request_bytes=b'{"prompt":"hello"}',
        response_bytes=b'{"answer":"world"}',
        tenant_id="tenant-a",
        model="model-a",
        endpoint="chat.completions",
    )
    ledger.close()
    return node


def test_forensic_bundle_contains_exact_contract_and_valid_digests(tmp_path) -> None:
    archive = build_forensic_bundle(
        [_node(tmp_path)],
        operator="Examiner A",
        acquisition_reason="Authorized incident review",
        generated_at=datetime(2026, 8, 22, 2, 0, tzinfo=UTC),
    )
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        assert set(bundle.namelist()) == {
            "VERIFY.sh",
            "audit_certificate.pdf",
            "ledger_slice.cbor",
            "manifest.json",
            "merkle_proof.json",
        }
        assert bundle.read("audit_certificate.pdf").startswith(b"%PDF-1.4")
        records = cbor2.loads(bundle.read("ledger_slice.cbor"))
        assert records[0]["state_id"] == "request-1"
        proofs = json.loads(bundle.read("merkle_proof.json"))
        assert proofs["proofs"][0]["state_id"] == "request-1"
        manifest_bytes = bundle.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        assert (
            manifest_bytes
            == json.dumps(
                manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode()
        )
        assert manifest["ledger_slice_cid"].startswith("bafy")
        for entry in manifest["files"]:
            payload = bundle.read(entry["name"])
            assert hashlib.sha256(payload).hexdigest() == entry["sha256"]
            assert len(payload) == entry["size"]
        assert b"openssl dgst -sha256" in bundle.read("VERIFY.sh")
        assert b"does not authenticate the script or archive" in bundle.read("VERIFY.sh")


def test_restricted_jcs_rejects_non_ascii_keys_unsafe_integers_and_surrogates() -> None:
    assert canonical_jcs_bytes({"safe": (1 << 53) - 1}) == b'{"safe":9007199254740991}'
    with pytest.raises(ForensicBundleError, match="ASCII"):
        canonical_jcs_bytes({"caf\N{LATIN SMALL LETTER E WITH ACUTE}": 1})
    with pytest.raises(ForensicBundleError, match="safe range"):
        canonical_jcs_bytes({"value": 1 << 53})
    with pytest.raises(ForensicBundleError, match="Unicode scalar"):
        canonical_jcs_bytes({"value": "\ud800"})


def test_dag_cbor_uses_float64_and_rejects_invalid_values() -> None:
    assert canonical_dag_cbor_bytes(1.5) == b"\xfb?\xf8\x00\x00\x00\x00\x00\x00"
    assert canonical_dag_cbor_bytes((1 << 64) - 1).startswith(b"\x1b")
    assert canonical_dag_cbor_bytes(-(1 << 64)).startswith(b"\x3b")
    for invalid in (-(1 << 64) - 1, 1 << 64):
        with pytest.raises(ForensicBundleError, match="native CBOR bounds"):
            canonical_dag_cbor_bytes(invalid)
    for invalid in (-0.0, float("nan"), float("inf"), -float("inf")):
        with pytest.raises(ForensicBundleError):
            canonical_dag_cbor_bytes(invalid)
    with pytest.raises(ForensicBundleError, match="Unicode scalar"):
        canonical_dag_cbor_bytes("\ud800")


def test_verify_script_rejects_file_tamper_but_is_not_authentication(tmp_path) -> None:
    archive = build_forensic_bundle(
        [_node(tmp_path)],
        operator="Examiner A",
        acquisition_reason="Authorized incident review",
        generated_at=datetime(2026, 8, 22, 2, 0, tzinfo=UTC),
    )
    extracted = tmp_path / "bundle"
    extracted.mkdir()
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for name in bundle.namelist():
            assert name in {
                "VERIFY.sh",
                "audit_certificate.pdf",
                "ledger_slice.cbor",
                "manifest.json",
                "merkle_proof.json",
            }
            (extracted / name).write_bytes(bundle.read(name))

    verifier = extracted / "VERIFY.sh"
    verifier.chmod(0o700)
    clean = subprocess.run(
        ["./VERIFY.sh"], cwd=extracted, check=False, capture_output=True, text=True
    )
    assert clean.returncode == 0

    ledger = extracted / "ledger_slice.cbor"
    original_digest = hashlib.sha256(ledger.read_bytes()).hexdigest()
    ledger.write_bytes(ledger.read_bytes() + b"tamper")
    tampered_digest = hashlib.sha256(ledger.read_bytes()).hexdigest()
    rejected = subprocess.run(
        ["./VERIFY.sh"], cwd=extracted, check=False, capture_output=True, text=True
    )
    assert rejected.returncode != 0

    verifier.write_text(verifier.read_text().replace(original_digest, tampered_digest))
    verifier.chmod(0o700)
    co_tampered = subprocess.run(
        ["./VERIFY.sh"], cwd=extracted, check=False, capture_output=True, text=True
    )
    assert co_tampered.returncode == 0


def test_forensic_bundle_rejects_empty_or_unbounded_requests(tmp_path) -> None:
    with pytest.raises(ForensicBundleError, match="no audit nodes"):
        build_forensic_bundle([], operator="A", acquisition_reason="B")
    with pytest.raises(ForensicBundleError, match="byte limit"):
        build_forensic_bundle(
            [_node(tmp_path)],
            operator="A",
            acquisition_reason="B",
            max_bundle_bytes=0,
        )
