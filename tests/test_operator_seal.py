# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Copyright (c) 2026 Juan Luna. All rights reserved.
"""Tests for aegis.core.operator_seal."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from aegis.core.operator_seal import (
    _BUNDLE_EXPORT_ACTION,
    _DEFAULT_VALIDITY_SECONDS,
    _MIN_VALIDITY_SECONDS,
    OperatorAttestation,
    OperatorSealError,
    OperatorSealGate,
    OperatorSealVerifyResult,
    _canonical_body,
    _hmac_sign,
    _hmac_verify,
)

# ── HSM test doubles backed by REAL asymmetric crypto ─────────────────────────
# These mocks reproduce exactly what aegis.core.hsm.HSMSigningBackend.sign()
# returns — (signature_bytes, public_key_hex, scheme) — using the same
# signature formats a PKCS#11 token emits (raw r‖s for ECDSA, raw RSA-PSS),
# so the operator_seal verify path is exercised against genuine signatures
# without needing a physical HSM / SoftHSM in CI.


def _make_ecdsa_hsm() -> MagicMock:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    priv = ec.generate_private_key(ec.SECP256R1())
    pub_hex = (
        priv.public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        .hex()
    )

    def _sign(data: bytes):
        der_sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der_sig)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")  # PKCS#11 raw r‖s
        return raw, pub_hex, "pkcs11-ecdsa-sha256"

    m = MagicMock()
    m._available = True
    m.sign.side_effect = _sign
    return m


def _make_rsa_hsm() -> MagicMock:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_hex = (
        priv.public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        .hex()
    )

    def _sign(data: bytes):
        sig = priv.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return sig, pub_hex, "pkcs11-rsa-pss-sha256"

    m = MagicMock()
    m._available = True
    m.sign.side_effect = _sign
    return m


# ── _canonical_body ───────────────────────────────────────────────────────────


class TestCanonicalBody:
    def test_returns_bytes(self):
        body = _canonical_body("aid", "op1", "pkg1", "bundle_export", "t1", "t2")
        assert isinstance(body, bytes)

    def test_deterministic(self):
        a = _canonical_body("aid", "op", "pkg", "bundle_export", "t1", "t2")
        b = _canonical_body("aid", "op", "pkg", "bundle_export", "t1", "t2")
        assert a == b

    def test_different_fields_produce_different_bodies(self):
        a = _canonical_body("aid1", "op", "pkg", "bundle_export", "t1", "t2")
        b = _canonical_body("aid2", "op", "pkg", "bundle_export", "t1", "t2")
        assert a != b

    def test_all_fields_included(self):
        body = _canonical_body(
            "myid", "operator1", "package1", "bundle_export", "2026-01-01", "2026-01-02"
        )
        decoded = body.decode()
        assert "myid" in decoded
        assert "operator1" in decoded
        assert "package1" in decoded
        assert "bundle_export" in decoded


# ── _hmac_sign / _hmac_verify ─────────────────────────────────────────────────


class TestHMACHelpers:
    def test_sign_returns_hex_string(self):
        sig = _hmac_sign("key", b"data")
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA-256 hex

    def test_verify_correct(self):
        sig = _hmac_sign("key", b"data")
        assert _hmac_verify("key", b"data", sig)

    def test_verify_wrong_key(self):
        sig = _hmac_sign("key1", b"data")
        assert not _hmac_verify("key2", b"data", sig)

    def test_verify_tampered_data(self):
        sig = _hmac_sign("key", b"original")
        assert not _hmac_verify("key", b"tampered", sig)

    def test_verify_tampered_signature(self):
        assert not _hmac_verify("key", b"data", "a" * 64)


# ── OperatorAttestation.to_dict ───────────────────────────────────────────────


class TestOperatorAttestationToDict:
    def _attestation(self):
        return OperatorAttestation(
            attestation_id="att-001",
            operator_id="badge-123",
            package_id="pkg-abc",
            action="bundle_export",
            issued_at="2026-01-01T00:00:00+00:00",
            expires_at="2026-01-01T01:00:00+00:00",
            signature="aabbcc",
            signature_scheme="hmac-sha256",
        )

    def test_to_dict_keys(self):
        d = self._attestation().to_dict()
        assert set(d.keys()) == {
            "attestation_id",
            "operator_id",
            "package_id",
            "action",
            "issued_at",
            "expires_at",
            "signature",
            "signature_scheme",
            "public_key",
        }

    def test_to_dict_values(self):
        d = self._attestation().to_dict()
        assert d["attestation_id"] == "att-001"
        assert d["operator_id"] == "badge-123"
        assert d["signature_scheme"] == "hmac-sha256"


# ── OperatorSealVerifyResult ──────────────────────────────────────────────────


class TestOperatorSealVerifyResult:
    def test_valid_defaults(self):
        r = OperatorSealVerifyResult(valid=True)
        assert r.valid is True
        assert r.reason == ""
        assert r.attestation_id == ""
        assert r.operator_id == ""

    def test_invalid_with_reason(self):
        r = OperatorSealVerifyResult(
            valid=False, reason="expired", attestation_id="x", operator_id="y"
        )
        assert r.valid is False
        assert r.reason == "expired"


# ── OperatorSealGate construction ─────────────────────────────────────────────


class TestOperatorSealGateConstruction:
    def test_signing_key_from_param(self):
        gate = OperatorSealGate(signing_key="mykey")  # noqa: S106
        assert gate._signing_key == "mykey"

    def test_signing_key_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SIGNING_KEY", "envkey")
        gate = OperatorSealGate()
        assert gate._signing_key == "envkey"

    def test_default_validity(self, monkeypatch):
        monkeypatch.delenv("AEGIS_OPERATOR_SEAL_VALIDITY", raising=False)
        gate = OperatorSealGate(signing_key="k")  # noqa: S106
        assert gate._validity_seconds == _DEFAULT_VALIDITY_SECONDS

    def test_custom_validity(self):
        gate = OperatorSealGate(signing_key="k", validity_seconds=120)  # noqa: S106
        assert gate._validity_seconds == 120

    def test_validity_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_OPERATOR_SEAL_VALIDITY", "7200")
        gate = OperatorSealGate(signing_key="k")  # noqa: S106
        assert gate._validity_seconds == 7200

    def test_invalid_validity_env_uses_default(self, monkeypatch):
        monkeypatch.setenv("AEGIS_OPERATOR_SEAL_VALIDITY", "bad")
        gate = OperatorSealGate(signing_key="k")  # noqa: S106
        assert gate._validity_seconds == _DEFAULT_VALIDITY_SECONDS

    def test_validity_clamped_to_minimum(self):
        gate = OperatorSealGate(signing_key="k", validity_seconds=10)  # noqa: S106
        assert gate._validity_seconds == _MIN_VALIDITY_SECONDS

    def test_no_key_no_hsm_gate_still_constructs(self):
        gate = OperatorSealGate(signing_key="")
        assert gate._signing_key == ""

    def test_hsm_backend_stored(self):
        mock_hsm = MagicMock()
        gate = OperatorSealGate(signing_key="k", hsm_backend=mock_hsm)  # noqa: S106
        assert gate._hsm is mock_hsm


# ── create_attestation ────────────────────────────────────────────────────────


class TestCreateAttestation:
    def _gate(self):
        return OperatorSealGate(signing_key="test-signing-key")  # noqa: S106

    def test_creates_attestation(self):
        att = self._gate().create_attestation("op1", "pkg1")
        assert isinstance(att, OperatorAttestation)

    def test_attestation_fields_set(self):
        att = self._gate().create_attestation("op1", "pkg1")
        assert att.operator_id == "op1"
        assert att.package_id == "pkg1"
        assert att.action == _BUNDLE_EXPORT_ACTION
        assert att.signature_scheme == "hmac-sha256"

    def test_attestation_id_is_uuid(self):
        import uuid

        att = self._gate().create_attestation("op1")
        uuid.UUID(att.attestation_id)  # must not raise

    def test_issued_at_and_expires_at_set(self):
        att = self._gate().create_attestation("op1")
        assert att.issued_at
        assert att.expires_at
        issued = datetime.fromisoformat(att.issued_at)
        expires = datetime.fromisoformat(att.expires_at)
        assert expires > issued

    def test_validity_window_respected(self):
        gate = OperatorSealGate(signing_key="k", validity_seconds=600)  # noqa: S106
        att = gate.create_attestation("op1")
        issued = datetime.fromisoformat(att.issued_at)
        expires = datetime.fromisoformat(att.expires_at)
        delta = (expires - issued).total_seconds()
        assert 595 <= delta <= 605

    def test_signature_is_hex(self):
        att = self._gate().create_attestation("op1")
        bytes.fromhex(att.signature)  # must not raise

    def test_no_key_raises(self, monkeypatch):
        monkeypatch.delenv("AEGIS_SIGNING_KEY", raising=False)
        gate = OperatorSealGate(signing_key="")
        with pytest.raises(OperatorSealError, match="AEGIS_SIGNING_KEY"):
            gate.create_attestation("op1")

    def test_broad_attestation_empty_package_id(self):
        att = self._gate().create_attestation("op1", package_id="")
        assert att.package_id == ""

    def test_unique_attestation_ids(self):
        gate = self._gate()
        ids = {gate.create_attestation("op1").attestation_id for _ in range(5)}
        assert len(ids) == 5

    def test_hsm_preferred_when_available(self):
        mock_hsm = _make_ecdsa_hsm()
        gate = OperatorSealGate(signing_key="k", hsm_backend=mock_hsm)  # noqa: S106
        att = gate.create_attestation("op1")
        assert att.signature_scheme == "pkcs11-ecdsa-sha256"
        assert att.public_key != ""
        mock_hsm.sign.assert_called_once()

    def test_hsm_failure_falls_back_to_hmac(self):
        mock_hsm = MagicMock()
        mock_hsm._available = True
        mock_hsm.sign.side_effect = RuntimeError("HSM token error")
        gate = OperatorSealGate(signing_key="k", hsm_backend=mock_hsm)  # noqa: S106
        att = gate.create_attestation("op1")
        assert att.signature_scheme == "hmac-sha256"


# ── verify_attestation ────────────────────────────────────────────────────────


class TestVerifyAttestation:
    def _gate(self):
        return OperatorSealGate(signing_key="test-signing-key")  # noqa: S106

    def test_valid_attestation_verifies(self):
        gate = self._gate()
        att = gate.create_attestation("op1", "pkg1")
        result = gate.verify_attestation(att)
        assert result.valid is True
        assert result.attestation_id == att.attestation_id
        assert result.operator_id == "op1"

    def test_tampered_signature_rejected(self):
        gate = self._gate()
        att = gate.create_attestation("op1")
        att.signature = "a" * 64  # tampered
        result = gate.verify_attestation(att)
        assert result.valid is False
        assert "Signature verification failed" in result.reason

    def test_tampered_operator_id_rejected(self):
        gate = self._gate()
        att = gate.create_attestation("op1")
        att.operator_id = "evil-op"  # tampered
        result = gate.verify_attestation(att)
        assert result.valid is False

    def test_wrong_action_rejected(self):
        gate = self._gate()
        att = gate.create_attestation("op1")
        att.action = "wrong_action"
        result = gate.verify_attestation(att)
        assert result.valid is False
        assert "action" in result.reason.lower()

    def test_expired_attestation_rejected(self):
        gate = self._gate()
        att = gate.create_attestation("op1")
        # Set expires_at in the past
        past = (datetime.now(tz=UTC) - timedelta(seconds=10)).isoformat()
        att.expires_at = past
        result = gate.verify_attestation(att)
        assert result.valid is False
        assert "expired" in result.reason.lower()

    def test_malformed_expires_at_rejected(self):
        gate = self._gate()
        att = gate.create_attestation("op1")
        att.expires_at = "not-a-date"
        result = gate.verify_attestation(att)
        assert result.valid is False
        assert "Malformed" in result.reason

    def test_wrong_key_cannot_verify(self):
        gate1 = OperatorSealGate(signing_key="key-one")  # noqa: S106
        gate2 = OperatorSealGate(signing_key="key-two")  # noqa: S106
        att = gate1.create_attestation("op1")
        result = gate2.verify_attestation(att)
        assert result.valid is False

    def test_missing_key_cannot_verify_hmac(self):
        gate = OperatorSealGate(signing_key="k")  # noqa: S106
        att = gate.create_attestation("op1")
        verifier = OperatorSealGate(signing_key="")
        result = verifier.verify_attestation(att)
        assert result.valid is False

    def test_unknown_scheme_rejected(self):
        gate = self._gate()
        att = gate.create_attestation("op1")
        att.signature_scheme = "quantum-magic"
        result = gate.verify_attestation(att)
        assert result.valid is False


# ── gate_export ───────────────────────────────────────────────────────────────


class TestGateExport:
    def _gate(self):
        return OperatorSealGate(signing_key="test-signing-key")  # noqa: S106

    def test_valid_attestation_allows_export(self):
        gate = self._gate()
        att = gate.create_attestation("op1", "pkg-abc")
        gate.gate_export("pkg-abc", att)  # must not raise

    def test_broad_attestation_allows_any_package(self):
        gate = self._gate()
        att = gate.create_attestation("op1", package_id="")
        gate.gate_export("any-package", att)  # must not raise

    def test_wrong_package_id_raises(self):
        gate = self._gate()
        att = gate.create_attestation("op1", "pkg-abc")
        with pytest.raises(OperatorSealError, match="pkg-abc"):
            gate.gate_export("pkg-xyz", att)

    def test_invalid_signature_raises(self):
        gate = self._gate()
        att = gate.create_attestation("op1", "pkg1")
        att.signature = "0" * 64  # tampered
        with pytest.raises(OperatorSealError, match="rejected"):
            gate.gate_export("pkg1", att)

    def test_expired_attestation_raises(self):
        gate = self._gate()
        att = gate.create_attestation("op1", "pkg1")
        att.expires_at = (datetime.now(tz=UTC) - timedelta(seconds=1)).isoformat()
        with pytest.raises(OperatorSealError, match="rejected"):
            gate.gate_export("pkg1", att)

    def test_gate_export_does_not_raise_when_valid(self):
        gate = self._gate()
        att = gate.create_attestation("op1", "pkg-ok")
        try:
            gate.gate_export("pkg-ok", att)
        except OperatorSealError as exc:
            pytest.fail(f"Unexpected OperatorSealError: {exc}")

    def test_tampered_operator_id_blocks_export(self):
        gate = self._gate()
        att = gate.create_attestation("op1", "pkg1")
        att.operator_id = "evil"  # tampered
        with pytest.raises(OperatorSealError):
            gate.gate_export("pkg1", att)


# ── HSM integration path ──────────────────────────────────────────────────────


class TestHSMPath:
    def test_ecdsa_sign_and_verify_round_trip(self):
        hsm = _make_ecdsa_hsm()
        gate = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        att = gate.create_attestation("op1", "pkg1")
        assert att.signature_scheme == "pkcs11-ecdsa-sha256"
        assert att.public_key
        result = gate.verify_attestation(att)
        assert result.valid is True

    def test_rsa_sign_and_verify_round_trip(self):
        hsm = _make_rsa_hsm()
        gate = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        att = gate.create_attestation("op1", "pkg1")
        assert att.signature_scheme == "pkcs11-rsa-pss-sha256"
        assert att.public_key
        result = gate.verify_attestation(att)
        assert result.valid is True

    def test_asymmetric_verify_without_hsm_present(self):
        # The whole point of an asymmetric scheme: the verifier does NOT need
        # the HSM — the published public key is sufficient.
        hsm = _make_ecdsa_hsm()
        signer = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        att = signer.create_attestation("op1", "pkg1")

        verifier = OperatorSealGate(signing_key="other-key")  # noqa: S106  (no HSM)
        result = verifier.verify_attestation(att)
        assert result.valid is True

    def test_ecdsa_tampered_body_rejected(self):
        hsm = _make_ecdsa_hsm()
        gate = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        att = gate.create_attestation("op1", "pkg1")
        att.operator_id = "evil-op"  # body no longer matches the signature
        result = gate.verify_attestation(att)
        assert result.valid is False

    def test_rsa_tampered_signature_rejected(self):
        hsm = _make_rsa_hsm()
        gate = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        att = gate.create_attestation("op1")
        # Flip the last byte of the signature.
        sig = bytearray(bytes.fromhex(att.signature))
        sig[-1] ^= 0xFF
        att.signature = bytes(sig).hex()
        result = gate.verify_attestation(att)
        assert result.valid is False

    def test_wrong_public_key_rejected(self):
        hsm = _make_ecdsa_hsm()
        gate = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        att = gate.create_attestation("op1")
        # Swap in a DIFFERENT public key — signature can no longer validate.
        other = _make_ecdsa_hsm()
        _sig, other_pub, _scheme = other.sign(b"x")
        att.public_key = other_pub
        result = gate.verify_attestation(att)
        assert result.valid is False

    def test_asymmetric_missing_public_key_rejected(self):
        hsm = _make_ecdsa_hsm()
        gate = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        att = gate.create_attestation("op1")
        att.public_key = ""  # cannot verify an asymmetric sig without the key
        result = gate.verify_attestation(att)
        assert result.valid is False

    def test_legacy_hsm_pkcs11_scheme_rejected(self):
        # The old generic 'hsm-pkcs11' label is not soundly verifiable; reject
        # rather than fall back to the previous broken re-sign comparison.
        gate = OperatorSealGate(signing_key="k")  # noqa: S106
        att = OperatorAttestation(
            attestation_id="aid",
            operator_id="op1",
            package_id="",
            action=_BUNDLE_EXPORT_ACTION,
            issued_at=datetime.now(tz=UTC).isoformat(),
            expires_at=(datetime.now(tz=UTC) + timedelta(hours=1)).isoformat(),
            signature="deadbeef",
            signature_scheme="hsm-pkcs11",
        )
        result = gate.verify_attestation(att)
        assert result.valid is False

    def test_hsm_gate_export_round_trip(self):
        hsm = _make_rsa_hsm()
        gate = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        att = gate.create_attestation("op1", "pkg1")
        # Should not raise.
        gate.gate_export("pkg1", att)

    def test_hsm_unavailable_means_not_available(self):
        hsm = MagicMock()
        hsm._available = False
        gate = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        # Should fall back to HMAC
        att = gate.create_attestation("op1")
        assert att.signature_scheme == "hmac-sha256"

    def test_hsm_sign_failure_falls_back(self):
        hsm = MagicMock()
        hsm._available = True
        hsm.sign.side_effect = RuntimeError("HSM error")
        gate = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        att = gate.create_attestation("op1")
        assert att.signature_scheme == "hmac-sha256"

    def test_hsm_no_public_key_falls_back_to_hmac(self):
        # If the HSM cannot export a public key, an asymmetric attestation would
        # be unverifiable — the gate must fall back to HMAC rather than issue one.
        hsm = MagicMock()
        hsm._available = True
        hsm.sign.return_value = (b"\x01\x02\x03", "", "pkcs11-ecdsa-sha256")
        gate = OperatorSealGate(signing_key="k", hsm_backend=hsm)  # noqa: S106
        att = gate.create_attestation("op1")
        assert att.signature_scheme == "hmac-sha256"
