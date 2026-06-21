# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.rust_integration — Rust extension helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from aegis.core.rust_integration import (
    generate_pqc_keypair,
    has_rust,
    new_rust_forwarder,
    verify_pqc_signature,
)


# ── has_rust ──────────────────────────────────────────────────────────────────


def test_has_rust_returns_bool():
    result = has_rust()
    assert isinstance(result, bool)


# ── new_rust_forwarder — no rust ──────────────────────────────────────────────


def test_new_rust_forwarder_returns_none_when_no_rust():
    with patch("aegis.core.rust_integration._HAS_RUST", False):
        result = new_rust_forwarder("http://localhost", "key")
    assert result is None


def test_new_rust_forwarder_with_rust_success():
    mock_forwarder = MagicMock()
    mock_aegis_rust = MagicMock()
    mock_aegis_rust.RustForwarder.new.return_value = mock_forwarder

    with (
        patch("aegis.core.rust_integration._HAS_RUST", True),
        patch("aegis.core.rust_integration.aegis_rust", mock_aegis_rust),
    ):
        result = new_rust_forwarder("http://localhost", "api-key", 30, 5)

    assert result is mock_forwarder
    mock_aegis_rust.RustForwarder.new.assert_called_once_with("http://localhost", "api-key", 30, 5)


def test_new_rust_forwarder_with_rust_exception_returns_none():
    mock_aegis_rust = MagicMock()
    mock_aegis_rust.RustForwarder.new.side_effect = ValueError("bad args")

    with (
        patch("aegis.core.rust_integration._HAS_RUST", True),
        patch("aegis.core.rust_integration.aegis_rust", mock_aegis_rust),
    ):
        result = new_rust_forwarder("bad-url", "key")

    assert result is None


# ── generate_pqc_keypair — no rust ───────────────────────────────────────────


def test_generate_pqc_keypair_returns_none_when_no_rust():
    with patch("aegis.core.rust_integration._HAS_RUST", False):
        result = generate_pqc_keypair()
    assert result is None


def test_generate_pqc_keypair_with_rust_returns_bytes():
    mock_kp = MagicMock()
    mock_kp.public_key = b"pk-bytes-32-chars-placeholder-xx"
    mock_aegis_rust = MagicMock()
    mock_aegis_rust.generate_pqc_keypair.return_value = mock_kp

    with (
        patch("aegis.core.rust_integration._HAS_RUST", True),
        patch("aegis.core.rust_integration.aegis_rust", mock_aegis_rust),
    ):
        result = generate_pqc_keypair()

    assert isinstance(result, bytes)
    assert result == bytes(mock_kp.public_key)


def test_generate_pqc_keypair_exception_returns_none():
    mock_aegis_rust = MagicMock()
    mock_aegis_rust.generate_pqc_keypair.side_effect = RuntimeError("PQC failed")

    with (
        patch("aegis.core.rust_integration._HAS_RUST", True),
        patch("aegis.core.rust_integration.aegis_rust", mock_aegis_rust),
    ):
        result = generate_pqc_keypair()

    assert result is None


# ── verify_pqc_signature — no rust ───────────────────────────────────────────


def test_verify_pqc_signature_returns_false_when_no_rust():
    with patch("aegis.core.rust_integration._HAS_RUST", False):
        result = verify_pqc_signature(b"data", b"sig", b"pk")
    assert result is False


def test_verify_pqc_signature_with_rust_valid():
    mock_aegis_rust = MagicMock()
    mock_aegis_rust.verify_pqc_signature.return_value = True

    with (
        patch("aegis.core.rust_integration._HAS_RUST", True),
        patch("aegis.core.rust_integration.aegis_rust", mock_aegis_rust),
    ):
        result = verify_pqc_signature(b"data", b"sig", b"pk")

    assert result is True


def test_verify_pqc_signature_with_rust_invalid():
    mock_aegis_rust = MagicMock()
    mock_aegis_rust.verify_pqc_signature.return_value = False

    with (
        patch("aegis.core.rust_integration._HAS_RUST", True),
        patch("aegis.core.rust_integration.aegis_rust", mock_aegis_rust),
    ):
        result = verify_pqc_signature(b"data", b"bad-sig", b"pk")

    assert result is False


def test_verify_pqc_signature_exception_returns_false():
    mock_aegis_rust = MagicMock()
    mock_aegis_rust.verify_pqc_signature.side_effect = Exception("verify error")

    with (
        patch("aegis.core.rust_integration._HAS_RUST", True),
        patch("aegis.core.rust_integration.aegis_rust", mock_aegis_rust),
    ):
        result = verify_pqc_signature(b"data", b"sig", b"pk")

    assert result is False
