"""
tests/test_forensic_bundle_manifest_signature.py — breaking VERIFY.sh's circle.

The export bundle's integrity story used to close on itself: ``VERIFY.sh``
compared each file against digests embedded in ``VERIFY.sh``, and both travelled
inside the same unsigned ZIP. An attacker who could rewrite a record could
rewrite the digest beside it, and the script printed ``OK`` for every line.

An Ed25519 signature over ``manifest.json`` breaks that circle — but only
against a public key the verifier already holds. These tests pin both halves:

* the signature detects a tampered manifest (the fix), and
* the public key is **not** in the archive (why the fix is real rather than
  relocated). Shipping the key beside the signature would restore the exact
  circularity, since whoever rewrote the manifest would rewrite the key too.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.forensic_bundle import ForensicBundleError, build_forensic_bundle

SEED = bytes(range(32))


def _node(tmp_path):
    """One real committed audit node, as the export endpoint would see it."""
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


def _build(tmp_path, **kwargs: object) -> bytes:
    return build_forensic_bundle(
        [_node(tmp_path)],
        operator="auditor",
        acquisition_reason="regression test",
        generated_at=datetime(2026, 9, 16, tzinfo=UTC),
        **kwargs,  # type: ignore[arg-type]
    )


def _names(bundle: bytes) -> set[str]:
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        return set(archive.namelist())


def _read(bundle: bytes, name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        return archive.read(name)


def test_unsigned_bundle_is_unchanged_and_says_so(tmp_path) -> None:
    """Signing is opt-in; without a key the bundle keeps its previous shape."""
    bundle = _build(tmp_path)
    assert "manifest.json.sig" not in _names(bundle)
    script = _read(bundle, "VERIFY.sh").decode()
    assert "AEGIS_BUNDLE_PUBKEY" not in script
    assert "does not authenticate the script or archive" in script


def test_signed_bundle_carries_a_verifiable_signature(tmp_path) -> None:
    bundle = _build(tmp_path, manifest_signing_key=SEED)
    assert "manifest.json.sig" in _names(bundle)

    manifest = _read(bundle, "manifest.json")
    signature = _read(bundle, "manifest.json.sig")
    public = Ed25519PrivateKey.from_private_bytes(SEED).public_key()
    public.verify(signature, manifest)  # raises on failure


def test_signature_covers_the_exact_bytes_in_the_archive(tmp_path) -> None:
    """A signature over a re-encoding would verify against bytes nobody sees."""
    bundle = _build(tmp_path, manifest_signing_key=SEED)
    manifest = _read(bundle, "manifest.json")
    signature = _read(bundle, "manifest.json.sig")
    public = Ed25519PrivateKey.from_private_bytes(SEED).public_key()

    public.verify(signature, manifest)
    with pytest.raises(InvalidSignature):
        public.verify(signature, manifest + b" ")


def test_tampered_manifest_fails_verification(tmp_path) -> None:
    """The finding, reproduced: edit the manifest, verification must reject it."""
    bundle = _build(tmp_path, manifest_signing_key=SEED)
    manifest = _read(bundle, "manifest.json")
    signature = _read(bundle, "manifest.json.sig")

    tampered = manifest.replace(b'"node_count":1', b'"node_count":2')
    assert tampered != manifest, "the tamper must actually change the bytes"

    public = Ed25519PrivateKey.from_private_bytes(SEED).public_key()
    with pytest.raises(InvalidSignature):
        public.verify(signature, tampered)


def test_a_different_key_does_not_verify(tmp_path) -> None:
    bundle = _build(tmp_path, manifest_signing_key=SEED)
    manifest = _read(bundle, "manifest.json")
    signature = _read(bundle, "manifest.json.sig")

    other = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(InvalidSignature):
        other.verify(signature, manifest)


def test_the_public_key_is_not_shipped_in_the_archive(tmp_path) -> None:
    """The property that makes the signature worth having.

    If the key rode along, an attacker rewriting `manifest.json` would rewrite
    the key and re-sign — and `VERIFY.sh` would print OK, exactly as it did
    before the signature existed.
    """
    bundle = _build(tmp_path, manifest_signing_key=SEED)
    public_raw = Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes_raw()

    assert public_raw not in bundle
    assert public_raw.hex().encode() not in bundle
    assert "manifest.json.pub" not in _names(bundle)


def test_verify_script_requires_an_out_of_band_key_and_fails_closed(tmp_path) -> None:
    script = _read(_build(tmp_path, manifest_signing_key=SEED), "VERIFY.sh").decode()
    assert "AEGIS_BUNDLE_PUBKEY" in script
    assert "INVALID SIGNATURE: MANIFEST TAMPERED" in script
    assert "exit 1" in script
    # It must not claim authentication when no key was supplied.
    assert "detect corruption, not tampering" in script
    assert "OUT OF BAND" in script


def test_a_wrong_length_key_is_refused_rather_than_padded(tmp_path) -> None:
    with pytest.raises(ForensicBundleError, match="must be 32 bytes"):
        _build(tmp_path, manifest_signing_key=b"\x00" * 31)
