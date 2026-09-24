"""
tests/test_sdk_bundle_contract.py — the gateway's bundle and the SDK's fixture must not drift.

The Python SDK's ``aegis-sdk verify`` is tested in the SDK's own CI job, which
installs only the SDK and therefore checks a committed, gateway-issued bundle
(``sdk/shared/forensic-bundle-v1.zip``) rather than building one. That leaves a
gap: change the bundle format here and the SDK's tests keep passing against a
fixture no gateway produces any more.

This module closes it from the gateway side. It builds a fresh bundle with the
same generator the fixture came from and asserts the two agree on every
structural fact the verifier depends on — member names, manifest and entry
field sets, proof-set version, proof versions. Where the SDK is importable it
also verifies the fresh bundle end to end.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "sdk" / "shared" / "forensic-bundle-v1.zip"
FIXTURE_KEY = ROOT / "sdk" / "shared" / "forensic-bundle-v1.pub.hex"


def _generator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "generate_sdk_bundle_fixture", ROOT / "scripts" / "generate_sdk_bundle_fixture.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


def _shape(raw: bytes) -> dict[str, Any]:
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = sorted(archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))
        proofs = json.loads(archive.read("merkle_proof.json"))
    return {
        "members": names,
        "manifest_keys": sorted(manifest),
        "bundle_version": manifest["bundle_version"],
        "canonicalization": manifest["canonicalization"],
        "file_entry_keys": sorted({key for entry in manifest["files"] for key in entry}),
        "file_names": sorted(entry["name"] for entry in manifest["files"]),
        "signature_entry_keys": sorted({key for entry in manifest["signatures"] for key in entry}),
        "proof_set_keys": sorted(proofs),
        "proof_set_version": proofs["version"],
        "proof_entry_keys": sorted({key for entry in proofs["proofs"] for key in entry}),
        "proof_versions": sorted({entry["proof"]["version"] for entry in proofs["proofs"]}),
        "cid_prefix": manifest["ledger_slice_cid"][:4],
    }


@pytest.fixture
def fresh_bundle(tmp_path: Path) -> bytes:
    return _generator().build_fixture_bundle(tmp_path)


def test_a_fresh_bundle_has_the_committed_fixtures_shape(fresh_bundle: bytes) -> None:
    assert _shape(fresh_bundle) == _shape(FIXTURE.read_bytes()), (
        "the forensic bundle format changed; re-run "
        "`python scripts/generate_sdk_bundle_fixture.py` and update aegis_sdk.bundle to match"
    )


def test_the_committed_public_key_is_the_generators(tmp_path: Path) -> None:
    assert FIXTURE_KEY.read_bytes() == _generator().fixture_public_key_hex()


def test_the_sdk_verifies_a_fresh_gateway_bundle(fresh_bundle: bytes) -> None:
    bundle = pytest.importorskip("aegis_sdk.bundle")
    key = bundle.load_ed25519_public_key(FIXTURE_KEY.read_bytes())
    assert bundle.verify_bundle(fresh_bundle, public_key=key).result == "verified"
    assert bundle.verify_bundle(fresh_bundle).result == "incomplete"


def test_the_sdk_reports_an_unsigned_gateway_bundle_as_incomplete(tmp_path: Path) -> None:
    bundle = pytest.importorskip("aegis_sdk.bundle")
    unsigned = _generator().build_fixture_bundle(tmp_path, signed=False)
    report = bundle.verify_bundle(unsigned)
    assert report.result == "incomplete"
    key = bundle.load_ed25519_public_key(FIXTURE_KEY.read_bytes())
    assert bundle.verify_bundle(unsigned, public_key=key).result == "failed"
