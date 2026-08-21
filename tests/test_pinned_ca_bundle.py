# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for pinned CA bundle verification (aegis.core.pinned_ca_bundle)."""

from __future__ import annotations

import datetime
import hashlib

import pytest

from aegis.core.pinned_ca_bundle import (
    PinnedCABundle,
    PinnedCAError,
    PinnedCert,
)

# ── Test cert helpers ──────────────────────────────────────────────────────────

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

_skip_no_crypto = pytest.mark.skipif(
    not _CRYPTO_AVAILABLE, reason="cryptography package not available"
)


def _make_cert_pem(cn: str = "test-ca") -> bytes:
    """Generate a minimal self-signed X.509 certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_to_fingerprint(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


# ── PinnedCert dataclass ──────────────────────────────────────────────────────


class TestPinnedCert:
    def test_frozen(self):
        pc = PinnedCert(sha256_fingerprint="a" * 64, label="test", added_at=0.0)
        with pytest.raises((AttributeError, TypeError)):
            pc.label = "other"  # type: ignore[misc]

    def test_attributes(self):
        pc = PinnedCert(sha256_fingerprint="f" * 64, label="root-ca", added_at=1000.0)
        assert pc.sha256_fingerprint == "f" * 64
        assert pc.label == "root-ca"
        assert pc.added_at == 1000.0


# ── compute_fingerprint ───────────────────────────────────────────────────────


@_skip_no_crypto
class TestComputeFingerprint:
    def test_returns_lowercase_hex(self):
        cert_pem = _make_cert_pem()
        fp = PinnedCABundle.compute_fingerprint(cert_pem)
        assert fp == fp.lower()
        assert len(fp) == 64

    def test_matches_manual_computation(self):
        cert_pem = _make_cert_pem()
        fp = PinnedCABundle.compute_fingerprint(cert_pem)
        expected = _pem_to_fingerprint(cert_pem)
        assert fp == expected

    def test_different_certs_different_fingerprints(self):
        fp1 = PinnedCABundle.compute_fingerprint(_make_cert_pem("ca-a"))
        fp2 = PinnedCABundle.compute_fingerprint(_make_cert_pem("ca-b"))
        assert fp1 != fp2

    def test_same_cert_same_fingerprint(self):
        cert_pem = _make_cert_pem()
        assert PinnedCABundle.compute_fingerprint(cert_pem) == PinnedCABundle.compute_fingerprint(
            cert_pem
        )


# ── add_pinned_cert ───────────────────────────────────────────────────────────


@_skip_no_crypto
class TestAddPinnedCert:
    def test_add_returns_pinned_cert(self):
        bundle = PinnedCABundle()
        cert_pem = _make_cert_pem()
        pc = bundle.add_pinned_cert(cert_pem, label="root")
        assert isinstance(pc, PinnedCert)
        assert pc.label == "root"

    def test_add_increases_count(self):
        bundle = PinnedCABundle()
        assert bundle.count() == 0
        bundle.add_pinned_cert(_make_cert_pem())
        assert bundle.count() == 1

    def test_fingerprint_matches_compute(self):
        bundle = PinnedCABundle()
        cert_pem = _make_cert_pem()
        pc = bundle.add_pinned_cert(cert_pem)
        expected = PinnedCABundle.compute_fingerprint(cert_pem)
        assert pc.sha256_fingerprint == expected

    def test_default_label_empty(self):
        bundle = PinnedCABundle()
        pc = bundle.add_pinned_cert(_make_cert_pem())
        assert pc.label == ""


# ── add_pinned_fingerprint ────────────────────────────────────────────────────


class TestAddPinnedFingerprint:
    def test_add_raw_fingerprint(self):
        bundle = PinnedCABundle()
        fp = "a" * 64
        pc = bundle.add_pinned_fingerprint(fp, label="manual")
        assert pc.sha256_fingerprint == fp
        assert bundle.count() == 1

    def test_normalizes_uppercase(self):
        bundle = PinnedCABundle()
        fp = "A" * 64
        pc = bundle.add_pinned_fingerprint(fp)
        assert pc.sha256_fingerprint == "a" * 64

    def test_strips_colons(self):
        bundle = PinnedCABundle()
        raw = ":".join(["ab"] * 32)
        pc = bundle.add_pinned_fingerprint(raw)
        assert ":" not in pc.sha256_fingerprint

    def test_invalid_length_raises(self):
        bundle = PinnedCABundle()
        with pytest.raises(PinnedCAError):
            bundle.add_pinned_fingerprint("abc123")


# ── verify_cert ───────────────────────────────────────────────────────────────


@_skip_no_crypto
class TestVerifyCert:
    def test_trusted_when_pinned(self):
        bundle = PinnedCABundle()
        cert_pem = _make_cert_pem()
        bundle.add_pinned_cert(cert_pem, label="root")
        result = bundle.verify_cert(cert_pem)
        assert result.trusted is True
        assert result.matched_fingerprint is not None

    def test_untrusted_when_not_pinned(self):
        bundle = PinnedCABundle()
        result = bundle.verify_cert(_make_cert_pem())
        assert result.trusted is False
        assert result.matched_fingerprint is None

    def test_result_has_subject_and_issuer(self):
        bundle = PinnedCABundle()
        cert_pem = _make_cert_pem(cn="my-ca")
        result = bundle.verify_cert(cert_pem)
        assert "my-ca" in result.cert_subject or result.cert_subject
        assert result.cert_issuer

    def test_untrusted_reason_mentions_pinned(self):
        bundle = PinnedCABundle()
        result = bundle.verify_cert(_make_cert_pem())
        assert "pinned" in result.reason.lower()

    def test_matched_fingerprint_is_correct(self):
        bundle = PinnedCABundle()
        cert_pem = _make_cert_pem()
        expected_fp = PinnedCABundle.compute_fingerprint(cert_pem)
        bundle.add_pinned_fingerprint(expected_fp)
        result = bundle.verify_cert(cert_pem)
        assert result.matched_fingerprint == expected_fp


# ── verify_cert_chain ─────────────────────────────────────────────────────────


@_skip_no_crypto
class TestVerifyCertChain:
    def test_trusted_when_any_in_chain_pinned(self):
        bundle = PinnedCABundle()
        leaf_pem = _make_cert_pem("leaf")
        root_pem = _make_cert_pem("root")
        bundle.add_pinned_cert(root_pem, label="root")
        result = bundle.verify_cert_chain([leaf_pem, root_pem])
        assert result.trusted is True

    def test_trusted_when_leaf_pinned(self):
        bundle = PinnedCABundle()
        leaf_pem = _make_cert_pem("leaf")
        bundle.add_pinned_cert(leaf_pem, label="leaf")
        result = bundle.verify_cert_chain([leaf_pem, _make_cert_pem("intermediate")])
        assert result.trusted is True

    def test_untrusted_when_none_pinned(self):
        bundle = PinnedCABundle()
        result = bundle.verify_cert_chain([_make_cert_pem("a"), _make_cert_pem("b")])
        assert result.trusted is False

    def test_empty_chain_untrusted(self):
        bundle = PinnedCABundle()
        result = bundle.verify_cert_chain([])
        assert result.trusted is False
        assert "empty" in result.reason.lower()

    def test_single_cert_chain(self):
        bundle = PinnedCABundle()
        cert_pem = _make_cert_pem()
        bundle.add_pinned_cert(cert_pem)
        result = bundle.verify_cert_chain([cert_pem])
        assert result.trusted is True


# ── list_pinned / count ───────────────────────────────────────────────────────


class TestListAndCount:
    def test_empty_bundle(self):
        bundle = PinnedCABundle()
        assert bundle.count() == 0
        assert bundle.list_pinned() == []

    def test_list_returns_copy(self):
        bundle = PinnedCABundle()
        bundle.add_pinned_fingerprint("a" * 64, label="one")
        lst = bundle.list_pinned()
        lst.clear()
        assert bundle.count() == 1

    def test_count_increments(self):
        bundle = PinnedCABundle()
        for i in range(3):
            bundle.add_pinned_fingerprint(hex(i + 1)[2:].zfill(64), label=str(i))
        assert bundle.count() == 3


# ── from_env ──────────────────────────────────────────────────────────────────


class TestFromEnv:
    def test_from_env_empty_when_no_var(self, monkeypatch):
        monkeypatch.delenv("AEGIS_PINNED_CA_FINGERPRINTS", raising=False)
        bundle = PinnedCABundle.from_env()
        assert bundle.count() == 0

    def test_from_env_loads_fingerprints(self, monkeypatch):
        fp1 = "a" * 64
        fp2 = "b" * 64
        monkeypatch.setenv("AEGIS_PINNED_CA_FINGERPRINTS", f"{fp1},{fp2}")
        monkeypatch.delenv("AEGIS_PINNED_CA_LABELS", raising=False)
        bundle = PinnedCABundle.from_env()
        assert bundle.count() == 2
        fps = {p.sha256_fingerprint for p in bundle.list_pinned()}
        assert fp1 in fps
        assert fp2 in fps

    def test_from_env_with_labels(self, monkeypatch):
        fp1 = "c" * 64
        monkeypatch.setenv("AEGIS_PINNED_CA_FINGERPRINTS", fp1)
        monkeypatch.setenv("AEGIS_PINNED_CA_LABELS", "my-root")
        bundle = PinnedCABundle.from_env()
        assert bundle.list_pinned()[0].label == "my-root"

    def test_from_env_whitespace_stripped(self, monkeypatch):
        fp = "d" * 64
        monkeypatch.setenv("AEGIS_PINNED_CA_FINGERPRINTS", f"  {fp}  ")
        monkeypatch.delenv("AEGIS_PINNED_CA_LABELS", raising=False)
        bundle = PinnedCABundle.from_env()
        assert bundle.count() == 1
        assert bundle.list_pinned()[0].sha256_fingerprint == fp
