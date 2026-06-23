# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for offline license validation (aegis.core.offline_license)."""

from __future__ import annotations

import json
import time

import pytest

from aegis.core.offline_license import (
    LicenseError,
    LicenseRecord,
    LicenseValidationResult,
    OfflineLicenseValidator,
    _canonical_json,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_KEY_HEX = "a" * 64
_OTHER_KEY_HEX = "b" * 64


def _make_license(
    licensee: str = "Acme Corp",
    features: list[str] | None = None,
    days_valid: int = 365,
    key_hex: str = _KEY_HEX,
) -> dict:
    if features is None:
        features = ["enterprise", "pqc"]
    return OfflineLicenseValidator.generate_license(licensee, features, days_valid, key_hex)


def _write_license(tmp_path, data: dict) -> str:
    path = str(tmp_path / "license.json")
    with open(path, "w") as fh:
        json.dump(data, fh)
    return path


# ── _canonical_json ───────────────────────────────────────────────────────────


class TestCanonicalJson:
    def test_sorts_keys(self):
        result = _canonical_json({"z": 1, "a": 2})
        assert result.index('"a"') < result.index('"z"')

    def test_no_extra_whitespace(self):
        result = _canonical_json({"k": "v"})
        assert " " not in result

    def test_nested_dict(self):
        result = _canonical_json({"b": {"y": 1, "x": 2}, "a": 0})
        parsed = json.loads(result)
        assert parsed == {"a": 0, "b": {"x": 2, "y": 1}}


# ── LicenseRecord ─────────────────────────────────────────────────────────────


class TestLicenseRecord:
    def test_frozen(self):
        r = LicenseRecord(
            licensee="Test",
            issued_at=1000.0,
            expires_at=2000.0,
            features=frozenset(["a"]),
            license_id="uuid-1",
            signature="abc123",
        )
        with pytest.raises((AttributeError, TypeError)):
            r.licensee = "Other"  # type: ignore[misc]

    def test_features_is_frozenset(self):
        r = LicenseRecord(
            licensee="X",
            issued_at=0.0,
            expires_at=0.0,
            features=frozenset(["f1"]),
            license_id="id",
            signature="sig",
        )
        assert isinstance(r.features, frozenset)


# ── generate_license ──────────────────────────────────────────────────────────


class TestGenerateLicense:
    def test_returns_dict_with_required_keys(self):
        d = _make_license()
        for key in ("licensee", "issued_at", "expires_at", "features", "license_id", "signature"):
            assert key in d

    def test_licensee_stored(self):
        d = _make_license(licensee="Corp X")
        assert d["licensee"] == "Corp X"

    def test_features_sorted(self):
        d = _make_license(features=["pqc", "enterprise", "hipaa"])
        assert d["features"] == sorted(["pqc", "enterprise", "hipaa"])

    def test_expires_at_in_future(self):
        d = _make_license(days_valid=30)
        assert d["expires_at"] > time.time()

    def test_unique_license_ids(self):
        d1 = _make_license()
        d2 = _make_license()
        assert d1["license_id"] != d2["license_id"]

    def test_signature_is_hex_string(self):
        d = _make_license()
        assert isinstance(d["signature"], str)
        bytes.fromhex(d["signature"])


# ── sign_license ──────────────────────────────────────────────────────────────


class TestSignLicense:
    def test_deterministic(self):
        payload = {"a": 1, "b": 2}
        s1 = OfflineLicenseValidator.sign_license(payload, _KEY_HEX)
        s2 = OfflineLicenseValidator.sign_license(payload, _KEY_HEX)
        assert s1 == s2

    def test_different_key_different_sig(self):
        payload = {"a": 1}
        s1 = OfflineLicenseValidator.sign_license(payload, _KEY_HEX)
        s2 = OfflineLicenseValidator.sign_license(payload, _OTHER_KEY_HEX)
        assert s1 != s2

    def test_key_order_independent(self):
        s1 = OfflineLicenseValidator.sign_license({"a": 1, "b": 2}, _KEY_HEX)
        s2 = OfflineLicenseValidator.sign_license({"b": 2, "a": 1}, _KEY_HEX)
        assert s1 == s2

    def test_invalid_key_hex_raises(self):
        with pytest.raises((ValueError, Exception)):
            OfflineLicenseValidator.sign_license({"k": "v"}, "not-hex")


# ── validate — happy path ─────────────────────────────────────────────────────


class TestValidateHappyPath:
    def test_valid_license(self, tmp_path):
        d = _make_license()
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        result = v.validate()
        assert result.valid is True
        assert result.record is not None
        assert result.days_remaining > 0

    def test_reason_says_valid(self, tmp_path):
        d = _make_license()
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        result = v.validate()
        assert "valid" in result.reason.lower()

    def test_record_fields_populated(self, tmp_path):
        d = _make_license(licensee="Acme", features=["enterprise"])
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        result = v.validate()
        assert result.record.licensee == "Acme"
        assert "enterprise" in result.record.features


# ── validate — expired ────────────────────────────────────────────────────────


class TestValidateExpired:
    def test_expired_license(self, tmp_path):
        d = _make_license(days_valid=-10, key_hex=_KEY_HEX)
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        result = v.validate()
        assert result.valid is False
        assert result.days_remaining < 0

    def test_expired_reason_mentions_expired(self, tmp_path):
        d = _make_license(days_valid=-5, key_hex=_KEY_HEX)
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        result = v.validate()
        assert "expired" in result.reason.lower()

    def test_expired_record_still_present(self, tmp_path):
        d = _make_license(days_valid=-1, key_hex=_KEY_HEX)
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        result = v.validate()
        assert result.record is not None


# ── validate — tampered ───────────────────────────────────────────────────────


class TestValidateTampered:
    def test_tampered_licensee(self, tmp_path):
        d = _make_license()
        d["licensee"] = "Hacker Inc"
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        result = v.validate()
        assert result.valid is False
        assert "tampered" in result.reason.lower() or "signature" in result.reason.lower()

    def test_tampered_features(self, tmp_path):
        d = _make_license(features=["enterprise"])
        d["features"].append("hipaa")
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        result = v.validate()
        assert result.valid is False

    def test_tampered_expires_at(self, tmp_path):
        d = _make_license(days_valid=30)
        d["expires_at"] = d["expires_at"] + 100 * 86400
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        result = v.validate()
        assert result.valid is False

    def test_wrong_key(self, tmp_path):
        d = _make_license(key_hex=_KEY_HEX)
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_OTHER_KEY_HEX)
        result = v.validate()
        assert result.valid is False


# ── validate — missing file ───────────────────────────────────────────────────


class TestValidateMissingFile:
    def test_missing_file_returns_invalid(self, tmp_path):
        v = OfflineLicenseValidator(
            license_path=str(tmp_path / "nonexistent.json"),
            license_key_hex=_KEY_HEX,
        )
        result = v.validate()
        assert result.valid is False
        assert result.record is None

    def test_missing_file_reason_mentions_not_found(self, tmp_path):
        v = OfflineLicenseValidator(
            license_path=str(tmp_path / "nonexistent.json"),
            license_key_hex=_KEY_HEX,
        )
        result = v.validate()
        assert "not found" in result.reason.lower() or "license" in result.reason.lower()

    def test_malformed_json(self, tmp_path):
        path = str(tmp_path / "bad.json")
        with open(path, "w") as fh:
            fh.write("not valid json{{")
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        result = v.validate()
        assert result.valid is False


# ── has_feature ───────────────────────────────────────────────────────────────


class TestHasFeature:
    def test_has_feature_present(self, tmp_path):
        d = _make_license(features=["enterprise", "pqc"])
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        assert v.has_feature("enterprise") is True

    def test_has_feature_absent(self, tmp_path):
        d = _make_license(features=["enterprise"])
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        assert v.has_feature("hipaa") is False

    def test_has_feature_expired_returns_false(self, tmp_path):
        d = _make_license(features=["enterprise"], days_valid=-1)
        path = _write_license(tmp_path, d)
        v = OfflineLicenseValidator(license_path=path, license_key_hex=_KEY_HEX)
        assert v.has_feature("enterprise") is False

    def test_has_feature_missing_file_returns_false(self, tmp_path):
        v = OfflineLicenseValidator(
            license_path=str(tmp_path / "missing.json"),
            license_key_hex=_KEY_HEX,
        )
        assert v.has_feature("enterprise") is False


# ── from_env ──────────────────────────────────────────────────────────────────


class TestFromEnv:
    def test_from_env_reads_vars(self, tmp_path, monkeypatch):
        d = _make_license()
        path = _write_license(tmp_path, d)
        monkeypatch.setenv("AEGIS_LICENSE_FILE", path)
        monkeypatch.setenv("AEGIS_LICENSE_KEY", _KEY_HEX)
        monkeypatch.delenv("AEGIS_SIGNING_KEY", raising=False)
        v = OfflineLicenseValidator.from_env()
        assert v.validate().valid is True

    def test_from_env_missing_file_var(self, monkeypatch):
        monkeypatch.delenv("AEGIS_LICENSE_FILE", raising=False)
        monkeypatch.setenv("AEGIS_LICENSE_KEY", _KEY_HEX)
        with pytest.raises(LicenseError, match="AEGIS_LICENSE_FILE"):
            OfflineLicenseValidator.from_env()

    def test_from_env_missing_key_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGIS_LICENSE_FILE", str(tmp_path / "x.json"))
        monkeypatch.delenv("AEGIS_LICENSE_KEY", raising=False)
        with pytest.raises(LicenseError, match="AEGIS_LICENSE_KEY"):
            OfflineLicenseValidator.from_env()

    def test_from_env_key_equals_signing_key_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGIS_LICENSE_FILE", str(tmp_path / "x.json"))
        monkeypatch.setenv("AEGIS_LICENSE_KEY", _KEY_HEX)
        monkeypatch.setenv("AEGIS_SIGNING_KEY", _KEY_HEX)
        with pytest.raises(LicenseError, match="AEGIS_SIGNING_KEY"):
            OfflineLicenseValidator.from_env()

    def test_from_env_different_signing_key_ok(self, tmp_path, monkeypatch):
        d = _make_license()
        path = _write_license(tmp_path, d)
        monkeypatch.setenv("AEGIS_LICENSE_FILE", path)
        monkeypatch.setenv("AEGIS_LICENSE_KEY", _KEY_HEX)
        monkeypatch.setenv("AEGIS_SIGNING_KEY", _OTHER_KEY_HEX)
        v = OfflineLicenseValidator.from_env()
        assert v.validate().valid is True


# ── LicenseValidationResult ───────────────────────────────────────────────────


class TestLicenseValidationResult:
    def test_result_attributes(self):
        r = LicenseValidationResult(valid=True, record=None, reason="ok", days_remaining=30)
        assert r.valid is True
        assert r.days_remaining == 30
