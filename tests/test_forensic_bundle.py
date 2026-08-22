# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime

import cbor2
import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.forensic_bundle import ForensicBundleError, build_forensic_bundle


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
