"""
tests/test_rust_extension.py — aegis_rust PyO3 extension (skipped when not built).
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import pathlib
import unittest

import pytest


def _source_version() -> str:
    """The single source of truth for the release version.

    Assertions below check the *repository's* version, not a fixture's, so they
    read it rather than restating it. A hard-coded literal here turns every
    version bump into a spurious test failure and asserts agreement with a
    constant instead of with the release being cut.
    """
    import tomllib

    root = pathlib.Path(__file__).resolve().parents[1]
    with (root / "pyproject.toml").open("rb") as stream:
        version: str = tomllib.load(stream)["project"]["version"]
    return version


try:
    import aegis_rust

    RUST_BUILT = True
except ImportError:
    RUST_BUILT = False


@pytest.mark.skipif(not RUST_BUILT, reason="aegis_rust extension not installed")
class TestAegisRustExtension:
    def test_import_and_version(self) -> None:
        assert hasattr(aegis_rust, "RustForwarder")
        assert aegis_rust.__version__ == _source_version()

    def test_pqc_sign_verify_roundtrip(self) -> None:
        kp = aegis_rust.generate_pqc_keypair()
        message = b"merkle-root-forensic-test"
        signature = kp.sign(message)
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        assert aegis_rust.verify_pqc_signature(message, signature, kp.public_key)
        assert not aegis_rust.verify_pqc_signature(b"tampered", signature, kp.public_key)

    def test_mmr_add_leaf(self) -> None:
        mmr = aegis_rust.MmrAccumulator()
        root_a = mmr.add_leaf(b"leaf-a")
        root_b = mmr.add_leaf(b"leaf-b")
        assert root_a != root_b
        assert len(root_a) == 64

    def test_hash_and_hmac(self) -> None:
        digest = aegis_rust.hash_sha256(b"payload")
        assert len(digest) == 64
        mac = aegis_rust.hmac_sign(b"secret", b"message")
        assert len(mac) == 32

    def test_forward_json_sync_mock_server(self) -> None:
        from pytest_httpserver import HTTPServer

        with HTTPServer(host="127.0.0.1", port=0) as server:
            server.expect_request("/v1/chat/completions").respond_with_json(
                {"id": "chatcmpl-test", "choices": []},
                status=200,
            )
            base = server.url_for("").rstrip("/")
            fwd = aegis_rust.RustForwarder.new(base, "")
            resp = fwd.forward_json_sync(
                "/v1/chat/completions",
                {"model": "test", "messages": [{"role": "user", "content": "hi"}]},
            )
            assert resp.status_code == 200
            payload = resp.json()
            assert payload["id"] == "chatcmpl-test"
            assert b"choices" in resp.content


@pytest.mark.skipif(not RUST_BUILT, reason="aegis_rust extension not installed")
class TestCryptoAuditWithRustPqc(unittest.TestCase):
    def test_ledger_uses_ml_dsa_when_rust_available(self) -> None:
        import tempfile

        from aegis.core.crypto_audit import CryptographicAuditLedger

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            path = tmp.name
        try:
            with CryptographicAuditLedger(path, signing_key="hmac-fallback-key") as ledger:
                node = ledger.commit_forensic(
                    state_id="rust-pqc-test",
                    request_bytes=b'{"prompt":"x"}',
                    response_bytes=b'{"ok":true}',
                    entropy=1.0,
                    tenant_id="t",
                    model="m",
                    endpoint="chat.completions",
                )
                self.assertEqual(node.signature_scheme, "pqc-ml-dsa")
                self.assertFalse(node.is_fallback)
                ok, idx = ledger.verify_integrity()
                self.assertTrue(ok, msg=f"integrity failed at index {idx}")
        finally:
            import os

            if os.path.exists(path):
                os.unlink(path)
