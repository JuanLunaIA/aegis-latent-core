# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.artifact_signing — real HMAC-SHA512 and ML-DSA-65 signing.

Verifies the two fixes over the prior version: (1) the scheme is recorded
truthfully (no "Simulate PQC" over HMAC code), and (2) ML-DSA signatures are
verified asymmetrically with the published public key, not by re-signing.
"""

from __future__ import annotations

import secrets

import pytest

from aegis.core.artifact_signing import (
    ArtifactSigner,
    ArtifactSigningError,
    SignatureScheme,
)
from aegis.core.pqc_signer import backend_available

requires_mldsa = pytest.mark.skipif(
    not backend_available(), reason="aegis_rust ML-DSA-65 backend not installed"
)


@pytest.fixture
def artifact(tmp_path):
    p = tmp_path / "aegis-server.bin"
    p.write_bytes(b"\x7fELF" + secrets.token_bytes(4096))
    return str(p)


# ── HMAC-SHA512 scheme ────────────────────────────────────────────────────────


class TestHmacScheme:
    def test_requires_signing_key(self):
        with pytest.raises(ArtifactSigningError):
            ArtifactSigner(scheme=SignatureScheme.HMAC_SHA512)

    def test_sign_then_verify(self, artifact):
        signer = ArtifactSigner(secrets.token_bytes(32))
        meta = signer.sign_artifact(artifact, version="3.0.1")
        assert meta.scheme == "hmac-sha512"
        assert meta.public_key == ""  # symmetric — no public key
        assert signer.verify_artifact(artifact, meta) is True

    def test_tampered_artifact_fails(self, artifact):
        signer = ArtifactSigner(secrets.token_bytes(32))
        meta = signer.sign_artifact(artifact, version="1.0")
        with open(artifact, "ab") as f:
            f.write(b"backdoor")
        assert signer.verify_artifact(artifact, meta) is False

    def test_wrong_key_fails(self, artifact):
        meta = ArtifactSigner(secrets.token_bytes(32)).sign_artifact(artifact, "1.0")
        other = ArtifactSigner(secrets.token_bytes(32))
        assert other.verify_artifact(artifact, meta) is False


# ── ML-DSA-65 scheme (real asymmetric PQC) ────────────────────────────────────


class TestMlDsaScheme:
    @requires_mldsa
    def test_sign_records_real_scheme_and_pubkey(self, artifact):
        signer = ArtifactSigner(scheme=SignatureScheme.ML_DSA_65)
        meta = signer.sign_artifact(artifact, version="3.0.1")
        assert meta.scheme == "ml-dsa-65"
        # ML-DSA-65 public key is 1952 bytes → 3904 hex chars.
        assert len(bytes.fromhex(meta.public_key)) == 1952
        assert len(bytes.fromhex(meta.signature)) == 3309

    @requires_mldsa
    def test_asymmetric_verify_without_private_key(self, artifact):
        # A fresh signer (different keypair) must still verify using the
        # published public key in the metadata — proving real asymmetry.
        meta = ArtifactSigner(scheme=SignatureScheme.ML_DSA_65).sign_artifact(artifact, "1.0")
        verifier = ArtifactSigner(scheme=SignatureScheme.ML_DSA_65)
        assert verifier.verify_artifact(artifact, meta) is True

    @requires_mldsa
    def test_tampered_artifact_fails(self, artifact):
        signer = ArtifactSigner(scheme=SignatureScheme.ML_DSA_65)
        meta = signer.sign_artifact(artifact, "1.0")
        with open(artifact, "ab") as f:
            f.write(b"x")
        assert signer.verify_artifact(artifact, meta) is False

    @requires_mldsa
    def test_tampered_signature_fails(self, artifact):
        signer = ArtifactSigner(scheme=SignatureScheme.ML_DSA_65)
        meta = signer.sign_artifact(artifact, "1.0")
        bad_sig = bytearray(bytes.fromhex(meta.signature))
        bad_sig[0] ^= 0xFF
        from dataclasses import replace

        tampered = replace(meta, signature=bytes(bad_sig).hex())
        assert signer.verify_artifact(artifact, tampered) is False

    @requires_mldsa
    def test_malformed_hex_fails_closed(self, artifact):
        signer = ArtifactSigner(scheme=SignatureScheme.ML_DSA_65)
        meta = signer.sign_artifact(artifact, "1.0")
        from dataclasses import replace

        assert signer.verify_artifact(artifact, replace(meta, signature="zz")) is False


# ── Metadata ──────────────────────────────────────────────────────────────────


def test_metadata_to_dict_roundtrip(artifact):
    meta = ArtifactSigner(secrets.token_bytes(16)).sign_artifact(artifact, "9.9")
    d = meta.to_dict()
    assert d["version"] == "9.9"
    assert d["scheme"] == "hmac-sha512"
    assert set(d) == {
        "artifact_id",
        "sha256",
        "signature",
        "scheme",
        "timestamp",
        "version",
        "public_key",
    }
