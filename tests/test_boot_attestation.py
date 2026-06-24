# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.boot_attestation — signed golden-measurement manifests."""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import MagicMock

import pytest

from aegis.core.boot_attestation import (
    BootAttestationError,
    BootAttestationManager,
    GoldenManifest,
    _canonical_payload,
    load_signed_manifest,
)
from aegis.core.pqc_signer import PQCSigner, backend_available

_REAL_PQC = backend_available()
requires_pqc = pytest.mark.skipif(
    not _REAL_PQC, reason="aegis_rust ML-DSA-65 backend not installed"
)

_M = {"0": "a" * 64, "1": "b" * 64}
_HMAC_KEY = b"vendor-provisioning-key-0123456789"


def _write_hmac_manifest(
    tmp_path, *, version="2026.06-rev1", measurements=None, key=_HMAC_KEY, tamper=False
):
    measurements = measurements if measurements is not None else dict(_M)
    payload = _canonical_payload(version, measurements)
    sig = hmac.new(key, payload, hashlib.sha512).hexdigest()
    doc = {
        "version": version,
        "measurements": measurements,
        "algorithm": "hmac-sha512",
        "signature": sig,
    }
    if tamper:
        # Flip a measurement *after* signing — signature must no longer verify.
        doc["measurements"] = {**measurements, "0": "f" * 64}
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(doc))
    return p


# ── HMAC manifest ─────────────────────────────────────────────────────────────


class TestHmacManifest:
    def test_valid_manifest_loads(self, tmp_path):
        path = _write_hmac_manifest(tmp_path)
        manifest = load_signed_manifest(path, hmac_key=_HMAC_KEY)
        assert isinstance(manifest, GoldenManifest)
        assert manifest.version == "2026.06-rev1"
        assert manifest.measurements == {0: "a" * 64, 1: "b" * 64}

    def test_tampered_measurements_rejected(self, tmp_path):
        path = _write_hmac_manifest(tmp_path, tamper=True)
        with pytest.raises(BootAttestationError, match="verification FAILED"):
            load_signed_manifest(path, hmac_key=_HMAC_KEY)

    def test_wrong_key_rejected(self, tmp_path):
        path = _write_hmac_manifest(tmp_path)
        with pytest.raises(BootAttestationError, match="verification FAILED"):
            load_signed_manifest(path, hmac_key=b"the-wrong-key")

    def test_missing_hmac_key_rejected(self, tmp_path):
        path = _write_hmac_manifest(tmp_path)
        with pytest.raises(BootAttestationError, match="requires an hmac_key"):
            load_signed_manifest(path)


# ── malformation handling ─────────────────────────────────────────────────────


class TestManifestMalformation:
    def test_missing_file(self, tmp_path):
        with pytest.raises(BootAttestationError, match="not found"):
            load_signed_manifest(tmp_path / "nope.json", hmac_key=_HMAC_KEY)

    def test_not_json(self, tmp_path):
        p = tmp_path / "m.json"
        p.write_text("{not json")
        with pytest.raises(BootAttestationError, match="readable JSON"):
            load_signed_manifest(p, hmac_key=_HMAC_KEY)

    def test_missing_signature(self, tmp_path):
        p = tmp_path / "m.json"
        p.write_text(json.dumps({"version": "v", "measurements": _M, "algorithm": "hmac-sha512"}))
        with pytest.raises(BootAttestationError, match="signature' is missing"):
            load_signed_manifest(p, hmac_key=_HMAC_KEY)

    def test_bad_measurement_hex(self, tmp_path):
        bad = {"0": "not-hex"}
        payload = _canonical_payload("v", bad)
        sig = hmac.new(_HMAC_KEY, payload, hashlib.sha512).hexdigest()
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {"version": "v", "measurements": bad, "algorithm": "hmac-sha512", "signature": sig}
            )
        )
        with pytest.raises(BootAttestationError, match="64-char lowercase hex"):
            load_signed_manifest(p, hmac_key=_HMAC_KEY)

    def test_unsupported_algorithm(self, tmp_path):
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {"version": "v", "measurements": _M, "algorithm": "rot13", "signature": "ab"}
            )
        )
        with pytest.raises(BootAttestationError, match="unsupported manifest algorithm"):
            load_signed_manifest(p, hmac_key=_HMAC_KEY)

    def test_empty_measurements(self, tmp_path):
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {"version": "v", "measurements": {}, "algorithm": "hmac-sha512", "signature": "ab"}
            )
        )
        with pytest.raises(BootAttestationError, match="non-empty object"):
            load_signed_manifest(p, hmac_key=_HMAC_KEY)


# ── ML-DSA manifest ───────────────────────────────────────────────────────────


class TestMlDsaManifest:
    @requires_pqc
    def test_valid_ml_dsa_manifest_loads(self, tmp_path):
        signer = PQCSigner(require_real=True)
        payload = _canonical_payload("v1", _M)
        sig = signer.sign(payload).hex()
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {"version": "v1", "measurements": _M, "algorithm": "ml-dsa-65", "signature": sig}
            )
        )
        manifest = load_signed_manifest(p, public_key=signer.public_key)
        assert manifest.measurements == {0: "a" * 64, 1: "b" * 64}

    @requires_pqc
    def test_ml_dsa_wrong_public_key_rejected(self, tmp_path):
        signer, other = PQCSigner(require_real=True), PQCSigner(require_real=True)
        payload = _canonical_payload("v1", _M)
        sig = signer.sign(payload).hex()
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {"version": "v1", "measurements": _M, "algorithm": "ml-dsa-65", "signature": sig}
            )
        )
        with pytest.raises(BootAttestationError, match="verification FAILED"):
            load_signed_manifest(p, public_key=other.public_key)

    @requires_pqc
    def test_ml_dsa_missing_public_key_rejected(self, tmp_path):
        signer = PQCSigner(require_real=True)
        payload = _canonical_payload("v1", _M)
        sig = signer.sign(payload).hex()
        p = tmp_path / "m.json"
        p.write_text(
            json.dumps(
                {"version": "v1", "measurements": _M, "algorithm": "ml-dsa-65", "signature": sig}
            )
        )
        with pytest.raises(BootAttestationError, match="requires a vendor public_key"):
            load_signed_manifest(p)


# ── BootAttestationManager ────────────────────────────────────────────────────


class TestBootAttestationManager:
    def _manager(self):
        manifest = GoldenManifest(version="v", measurements={0: "a" * 64, 1: "b" * 64})
        return BootAttestationManager(manifest)

    def test_requires_golden_manifest_type(self):
        with pytest.raises(TypeError):
            BootAttestationManager({0: "a" * 64})  # type: ignore[arg-type]

    def test_verify_boot_state_passes_when_all_match(self):
        mgr = self._manager()
        mgr._tpms[0] = MagicMock(get_pcr_value=MagicMock(return_value="a" * 64))
        mgr._tpms[1] = MagicMock(get_pcr_value=MagicMock(return_value="b" * 64))
        assert mgr.verify_boot_state() is True

    def test_verify_boot_state_fails_on_mismatch(self):
        mgr = self._manager()
        mgr._tpms[0] = MagicMock(get_pcr_value=MagicMock(return_value="a" * 64))
        mgr._tpms[1] = MagicMock(get_pcr_value=MagicMock(return_value="0" * 64))
        assert mgr.verify_boot_state() is False

    def test_from_signed_manifest(self, tmp_path):
        path = _write_hmac_manifest(tmp_path)
        mgr = BootAttestationManager.from_signed_manifest(path, hmac_key=_HMAC_KEY)
        assert set(mgr.manifest.measurements) == {0, 1}

    def test_measure_component_missing_file_raises(self, tmp_path):
        mgr = self._manager()
        with pytest.raises(RuntimeError, match="Boot integrity failure"):
            mgr.measure_component(0, str(tmp_path / "does-not-exist.bin"))
