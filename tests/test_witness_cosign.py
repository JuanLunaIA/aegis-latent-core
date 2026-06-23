# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.witness_cosign."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegis.core.witness_cosign import (
    _DEFAULT_REQUIRED,
    _DEFAULT_TOTAL,
    _DEFAULT_VALIDITY_SECONDS,
    _MIN_VALIDITY_SECONDS,
    CoSignGateResult,
    CoSignVerifyResult,
    WitnessCoSignError,
    WitnessCoSignGate,
    WitnessSignature,
    _canonical_body,
    _derive_witness_key,
    _hmac_sign,
    _hmac_verify,
)

_KEY = "test-signing-key-for-witness-cosign"  # noqa: S105


# ── Low-level helpers ─────────────────────────────────────────────────────────


class TestKeyDerivation:
    def test_different_witnesses_different_keys(self):
        k1 = _derive_witness_key(_KEY, "alice")
        k2 = _derive_witness_key(_KEY, "bob")
        assert k1 != k2

    def test_same_inputs_same_key(self):
        k1 = _derive_witness_key(_KEY, "alice")
        k2 = _derive_witness_key(_KEY, "alice")
        assert k1 == k2

    def test_key_is_bytes(self):
        k = _derive_witness_key(_KEY, "alice")
        assert isinstance(k, bytes)


class TestHMACHelpers:
    def test_sign_and_verify(self):
        key = _derive_witness_key(_KEY, "alice")
        data = b"test canonical body"
        sig = _hmac_sign(key, data)
        assert _hmac_verify(key, data, sig)

    def test_verify_rejects_wrong_key(self):
        key1 = _derive_witness_key(_KEY, "alice")
        key2 = _derive_witness_key(_KEY, "bob")
        data = b"some data"
        sig = _hmac_sign(key1, data)
        assert not _hmac_verify(key2, data, sig)

    def test_verify_rejects_tampered_data(self):
        key = _derive_witness_key(_KEY, "alice")
        sig = _hmac_sign(key, b"original data")
        assert not _hmac_verify(key, b"tampered data", sig)

    def test_sig_is_hex_string(self):
        key = _derive_witness_key(_KEY, "alice")
        sig = _hmac_sign(key, b"data")
        assert isinstance(sig, str)
        int(sig, 16)  # must be valid hex


class TestCanonicalBody:
    def test_deterministic(self):
        b1 = _canonical_body(
            "sid", "w1", "pkg", "2026-01-01T00:00:00+00:00", "2026-01-01T01:00:00+00:00"
        )
        b2 = _canonical_body(
            "sid", "w1", "pkg", "2026-01-01T00:00:00+00:00", "2026-01-01T01:00:00+00:00"
        )
        assert b1 == b2

    def test_different_fields_different_body(self):
        b1 = _canonical_body("sid1", "w1", "pkg", "t1", "t2")
        b2 = _canonical_body("sid2", "w1", "pkg", "t1", "t2")
        assert b1 != b2

    def test_is_bytes(self):
        b = _canonical_body("sid", "w", "pkg", "t1", "t2")
        assert isinstance(b, bytes)

    def test_sorted_keys_in_json(self):
        import json

        b = _canonical_body("sid", "witness", "pkg-1", "2026-01-01", "2026-01-02")
        data = json.loads(b.decode())
        assert list(data.keys()) == sorted(data.keys())


# ── WitnessSignature ──────────────────────────────────────────────────────────


class TestWitnessSignature:
    def _make(self, **kwargs):
        defaults = dict(
            sig_id="sig-001",
            witness_id="alice",
            package_id="pkg-001",
            issued_at="2026-01-01T00:00:00+00:00",
            expires_at="2026-01-01T01:00:00+00:00",
            signature="abcdef1234567890",
        )
        defaults.update(kwargs)
        return WitnessSignature(**defaults)

    def test_to_dict_keys(self):
        s = self._make()
        assert set(s.to_dict().keys()) == {
            "sig_id",
            "witness_id",
            "package_id",
            "issued_at",
            "expires_at",
            "signature",
        }

    def test_to_dict_values(self):
        s = self._make(witness_id="bob", package_id="pkg-xyz")
        d = s.to_dict()
        assert d["witness_id"] == "bob"
        assert d["package_id"] == "pkg-xyz"


# ── WitnessCoSignGate construction ───────────────────────────────────────────


class TestGateConstruction:
    def test_defaults(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        assert g.required == _DEFAULT_REQUIRED
        assert g.total == _DEFAULT_TOTAL
        assert g._validity_seconds == _DEFAULT_VALIDITY_SECONDS

    def test_custom_required_total(self):
        g = WitnessCoSignGate(required=3, total=5, signing_key=_KEY)
        assert g.required == 3
        assert g.total == 5

    def test_required_1_of_1(self):
        g = WitnessCoSignGate(required=1, total=1, signing_key=_KEY)
        assert g.required == 1

    def test_required_greater_than_total_raises(self):
        with pytest.raises(ValueError, match="total"):
            WitnessCoSignGate(required=3, total=2, signing_key=_KEY)

    def test_required_zero_raises(self):
        with pytest.raises(ValueError, match="required"):
            WitnessCoSignGate(required=0, total=3, signing_key=_KEY)

    def test_validity_clamped_to_minimum(self):
        g = WitnessCoSignGate(signing_key=_KEY, validity_seconds=10)
        assert g._validity_seconds == _MIN_VALIDITY_SECONDS

    def test_validity_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_WITNESS_VALIDITY", "120")
        g = WitnessCoSignGate(signing_key=_KEY)
        assert g._validity_seconds == 120

    def test_invalid_validity_env_uses_default(self, monkeypatch):
        monkeypatch.setenv("AEGIS_WITNESS_VALIDITY", "notanumber")
        g = WitnessCoSignGate(signing_key=_KEY)
        assert g._validity_seconds == _DEFAULT_VALIDITY_SECONDS

    def test_signing_key_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SIGNING_KEY", "env-key-value")  # noqa: S106
        g = WitnessCoSignGate()
        assert g._signing_key == "env-key-value"

    def test_explicit_key_overrides_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SIGNING_KEY", "env-key")  # noqa: S106
        g = WitnessCoSignGate(signing_key="explicit-key")  # noqa: S106
        assert g._signing_key == "explicit-key"


# ── sign ──────────────────────────────────────────────────────────────────────


class TestSign:
    def test_sign_returns_witness_signature(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        assert isinstance(sig, WitnessSignature)

    def test_sign_witness_id(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        assert sig.witness_id == "alice"

    def test_sign_package_id(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        assert sig.package_id == "pkg-001"

    def test_sign_unique_sig_ids(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig1 = g.sign("alice", "pkg-001")
        sig2 = g.sign("alice", "pkg-001")
        assert sig1.sig_id != sig2.sig_id

    def test_sign_timestamps_set(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        assert sig.issued_at != ""
        assert sig.expires_at != ""
        assert sig.issued_at < sig.expires_at

    def test_sign_without_key_raises(self):
        g = WitnessCoSignGate(signing_key="")
        with pytest.raises(WitnessCoSignError, match="AEGIS_SIGNING_KEY"):
            g.sign("alice", "pkg-001")

    def test_sign_signature_is_hex(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        int(sig.signature, 16)

    def test_different_witnesses_different_signatures(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig_a = g.sign("alice", "pkg-001")
        sig_b = g.sign("bob", "pkg-001")
        assert sig_a.signature != sig_b.signature


# ── verify_signature ──────────────────────────────────────────────────────────


class TestVerifySignature:
    def test_valid_signature(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        result = g.verify_signature(sig)
        assert result.valid is True

    def test_valid_result_fields(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        result = g.verify_signature(sig)
        assert result.sig_id == sig.sig_id
        assert result.witness_id == "alice"
        assert result.reason == ""

    def test_expired_signature_rejected(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        # Manually expire
        sig.expires_at = (datetime.now(tz=UTC) - timedelta(seconds=1)).isoformat()
        result = g.verify_signature(sig)
        assert result.valid is False
        assert "expired" in result.reason.lower()

    def test_tampered_signature_rejected(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        sig.signature = "0" * 64
        result = g.verify_signature(sig)
        assert result.valid is False
        assert "verification failed" in result.reason

    def test_tampered_package_id_rejected(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        sig.package_id = "pkg-TAMPERED"
        result = g.verify_signature(sig)
        assert result.valid is False

    def test_tampered_witness_id_rejected(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        sig.witness_id = "mallory"
        result = g.verify_signature(sig)
        assert result.valid is False

    def test_malformed_expires_at_rejected(self):
        g = WitnessCoSignGate(signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        sig.expires_at = "not-a-date"
        result = g.verify_signature(sig)
        assert result.valid is False
        assert "malformed" in result.reason.lower()

    def test_no_key_cannot_verify(self):
        g_sign = WitnessCoSignGate(signing_key=_KEY)
        sig = g_sign.sign("alice", "pkg-001")
        g_verify = WitnessCoSignGate(signing_key="")
        result = g_verify.verify_signature(sig)
        assert result.valid is False


# ── check_threshold ───────────────────────────────────────────────────────────


class TestCheckThreshold:
    def test_two_of_three_passes(self):
        g = WitnessCoSignGate(required=2, total=3, signing_key=_KEY)
        sig_a = g.sign("alice", "pkg-001")
        sig_b = g.sign("bob", "pkg-001")
        result = g.check_threshold("pkg-001", [sig_a, sig_b])
        assert result.threshold_met is True
        assert result.valid_count == 2

    def test_three_of_three_passes(self):
        g = WitnessCoSignGate(required=2, total=3, signing_key=_KEY)
        sigs = [g.sign(w, "pkg-001") for w in ["alice", "bob", "carol"]]
        result = g.check_threshold("pkg-001", sigs)
        assert result.threshold_met is True
        assert result.valid_count == 3

    def test_one_of_three_fails(self):
        g = WitnessCoSignGate(required=2, total=3, signing_key=_KEY)
        sig_a = g.sign("alice", "pkg-001")
        result = g.check_threshold("pkg-001", [sig_a])
        assert result.threshold_met is False
        assert result.valid_count == 1

    def test_empty_signatures_fails(self):
        g = WitnessCoSignGate(required=2, total=3, signing_key=_KEY)
        result = g.check_threshold("pkg-001", [])
        assert result.threshold_met is False
        assert result.valid_count == 0

    def test_wrong_package_rejected(self):
        g = WitnessCoSignGate(required=1, total=3, signing_key=_KEY)
        sig = g.sign("alice", "pkg-OTHER")
        result = g.check_threshold("pkg-001", [sig])
        assert result.threshold_met is False
        assert len(result.rejected) == 1
        assert "mismatch" in result.rejected[0]["reason"]

    def test_duplicate_witness_counted_once(self):
        g = WitnessCoSignGate(required=2, total=3, signing_key=_KEY)
        sig1 = g.sign("alice", "pkg-001")
        sig2 = g.sign("alice", "pkg-001")  # same witness, second sig
        result = g.check_threshold("pkg-001", [sig1, sig2])
        assert result.valid_count == 1
        assert len(result.rejected) == 1
        assert "duplicate" in result.rejected[0]["reason"].lower()

    def test_valid_witnesses_listed(self):
        g = WitnessCoSignGate(required=2, total=3, signing_key=_KEY)
        sig_a = g.sign("alice", "pkg-001")
        sig_b = g.sign("bob", "pkg-001")
        result = g.check_threshold("pkg-001", [sig_a, sig_b])
        assert "alice" in result.valid_witnesses
        assert "bob" in result.valid_witnesses

    def test_required_in_result(self):
        g = WitnessCoSignGate(required=3, total=5, signing_key=_KEY)
        result = g.check_threshold("pkg-001", [])
        assert result.required == 3

    def test_to_dict(self):
        g = WitnessCoSignGate(required=2, total=3, signing_key=_KEY)
        sig_a = g.sign("alice", "pkg-001")
        sig_b = g.sign("bob", "pkg-001")
        result = g.check_threshold("pkg-001", [sig_a, sig_b])
        d = result.to_dict()
        assert d["threshold_met"] is True
        assert d["valid_count"] == 2
        assert "alice" in d["valid_witnesses"]


# ── gate_export ───────────────────────────────────────────────────────────────


class TestGateExport:
    def test_passes_with_sufficient_sigs(self):
        g = WitnessCoSignGate(required=2, total=3, signing_key=_KEY)
        sig_a = g.sign("alice", "pkg-001")
        sig_b = g.sign("bob", "pkg-001")
        g.gate_export("pkg-001", [sig_a, sig_b])  # must not raise

    def test_raises_with_insufficient_sigs(self):
        g = WitnessCoSignGate(required=2, total=3, signing_key=_KEY)
        sig_a = g.sign("alice", "pkg-001")
        with pytest.raises(WitnessCoSignError, match="threshold"):
            g.gate_export("pkg-001", [sig_a])

    def test_raises_with_wrong_package(self):
        g = WitnessCoSignGate(required=1, total=3, signing_key=_KEY)
        sig = g.sign("alice", "pkg-OTHER")
        with pytest.raises(WitnessCoSignError):
            g.gate_export("pkg-001", [sig])

    def test_one_of_one_passes(self):
        g = WitnessCoSignGate(required=1, total=1, signing_key=_KEY)
        sig = g.sign("alice", "pkg-001")
        g.gate_export("pkg-001", [sig])  # must not raise

    def test_error_mentions_package_id(self):
        g = WitnessCoSignGate(required=2, total=3, signing_key=_KEY)
        sig_a = g.sign("alice", "pkg-XYZ")
        with pytest.raises(WitnessCoSignError, match="pkg-XYZ"):
            g.gate_export("pkg-XYZ", [sig_a])


# ── CoSignVerifyResult / CoSignGateResult ─────────────────────────────────────


class TestDataClasses:
    def test_cosign_verify_result_defaults(self):
        r = CoSignVerifyResult(valid=True)
        assert r.reason == ""
        assert r.sig_id == ""
        assert r.witness_id == ""

    def test_cosign_gate_result_defaults(self):
        r = CoSignGateResult(threshold_met=False, valid_count=0, required=2)
        assert r.valid_witnesses == []
        assert r.rejected == []

    def test_gate_result_to_dict(self):
        r = CoSignGateResult(
            threshold_met=True,
            valid_count=2,
            required=2,
            valid_witnesses=["alice", "bob"],
            rejected=[],
        )
        d = r.to_dict()
        assert d["threshold_met"] is True
        assert d["valid_count"] == 2
        assert d["required"] == 2
        assert d["valid_witnesses"] == ["alice", "bob"]
        assert d["rejected"] == []
