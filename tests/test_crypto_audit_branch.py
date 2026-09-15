# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
tests/test_crypto_audit_branch.py — 100% branch coverage for aegis/core/crypto_audit.py.

AAA structure throughout. No mocks of business logic — only infrastructure
side-effects (OS errors, unavailable extension) are patched.
"""

from __future__ import annotations

import importlib
import os
from unittest.mock import MagicMock, patch

import aegis.core.crypto_audit as _module
from aegis.core.crypto_audit import (
    CryptographicAuditLedger,
    PQCSignatureAnchor,
    SignatureAssurance,
    _build_signed_payload,
    _hmac_sign,
    _hmac_verify,
)

# ── RUST_AVAILABLE = True branch (lines ~65-67) ───────────────────────────────


def test_rust_available_true_branch(tmp_path):
    """Reload crypto_audit with aegis_rust mocked so the True branch is covered."""
    mock_rust = MagicMock()
    mock_keypair = MagicMock()
    mock_keypair.sign.return_value = bytes(64)
    mock_keypair.public_key = bytes(32)
    mock_rust.generate_pqc_keypair.return_value = mock_keypair

    orig = _module.RUST_AVAILABLE
    try:
        with patch.dict("sys.modules", {"aegis_rust": mock_rust}):
            importlib.reload(_module)
            assert _module.RUST_AVAILABLE is True
    finally:
        # Restore — reload without mocked aegis_rust so normal state resumes.
        importlib.reload(_module)
        assert _module.RUST_AVAILABLE == orig


# ── signature_assurance — chain-history-based lattice (line ~273) ────────────


def test_signature_assurance_compromised_ephemeral_when_fallback_node(tmp_path):
    """
    Arrange: ledger with no signing key and no Rust → Ed25519 fallback used.
    Act:     commit one record.
    Assert:  is_fallback=True → signature_assurance == COMPROMISED_EPHEMERAL.
    """
    with patch("aegis.core.crypto_audit.RUST_AVAILABLE", False):
        ledger = CryptographicAuditLedger(str(tmp_path / "wal.jsonl"), signing_key="")
        node = ledger.commit_forensic(state_id="x1", request_bytes=b"payload")
        assert node.is_fallback is True
        assert ledger.signature_assurance == SignatureAssurance.COMPROMISED_EPHEMERAL
        ledger.close()


def test_signature_assurance_symmetric_authenticated_with_signing_key(tmp_path):
    """A committed HMAC-signed node reports SYMMETRIC_AUTHENTICATED."""
    ledger = CryptographicAuditLedger(str(tmp_path / "wal.jsonl"), signing_key="secret")
    ledger.commit_forensic(state_id="x1", request_bytes=b"payload")
    assert ledger.signature_assurance == SignatureAssurance.SYMMETRIC_AUTHENTICATED
    ledger.close()


def test_signature_assurance_reflects_configured_ceiling_on_empty_chain(tmp_path):
    """An empty chain has no signing history to report, so this falls back to
    the tier the next commit would use under the current configuration —
    COMPROMISED_EPHEMERAL when no key, PQC identity, or HSM is configured."""
    ledger = CryptographicAuditLedger(str(tmp_path / "wal.jsonl"), signing_key="")
    assert ledger.signature_assurance == SignatureAssurance.COMPROMISED_EPHEMERAL
    ledger.close()


def test_signature_assurance_does_not_launder_historical_fallback_nodes(tmp_path):
    """The defect this lattice replaces: the former ``legal_admissibility``
    read ``self._signing_key`` (current config), not chain history, so a WAL
    written entirely under ed25519-fallback reported "High" the instant a
    later process reopened it with a signing key. signature_assurance must
    stay COMPROMISED_EPHEMERAL, because the historical node was never
    re-signed under the new key."""
    wal_path = str(tmp_path / "wal.jsonl")
    with patch("aegis.core.crypto_audit.RUST_AVAILABLE", False):
        first = CryptographicAuditLedger(wal_path, signing_key="")
        first.commit_forensic(state_id="x1", request_bytes=b"payload")
        first.close()

    reopened = CryptographicAuditLedger(wal_path, signing_key="a-new-key")
    assert reopened.signature_assurance == SignatureAssurance.COMPROMISED_EPHEMERAL
    reopened.close()


# ── close() — OSError in flush/fsync suppressed (lines ~458-459) ─────────────


def test_close_oserror_in_fsync_suppressed(tmp_path):
    """
    Arrange: ledger with open WAL handle.
    Act:     patch os.fsync to raise OSError, then call close().
    Assert:  no exception propagates; handle is closed.
    """
    ledger = CryptographicAuditLedger(str(tmp_path / "wal.jsonl"), signing_key="k")
    assert ledger._wal_handle is not None
    with patch("os.fsync", side_effect=OSError("disk error")):
        ledger.close()  # must not raise
    assert ledger._wal_handle is None


# ── _open_wal() — OSError branches ───────────────────────────────────────────


def test_open_wal_chmod_oserror_suppressed(tmp_path):
    """
    Arrange: chmod raises OSError (pre-existing WAL with restricted permissions).
    Act:     create ledger (which calls _open_wal in __init__).
    Assert:  WAL handle still opened; chmod error swallowed.
    """
    wal = tmp_path / "wal.jsonl"
    wal.touch()
    with patch("os.chmod", side_effect=OSError("permission denied")):
        ledger = CryptographicAuditLedger(str(wal), signing_key="k")
    assert ledger._wal_handle is not None
    ledger.close()


def test_open_wal_osopen_failure_fallback(tmp_path):
    """
    Arrange: os.open raises OSError so _wal_handle stays None.
    Act:     commit_forensic, which calls _persist_node with handle=None.
    Assert:  fallback write path executes; WAL file created; node returned.
    """
    wal = tmp_path / "sub" / "wal.jsonl"

    real_open = os.open
    call_count = {"n": 0}

    def _failing_open(path, flags, mode=0o777):
        call_count["n"] += 1
        if call_count["n"] <= 1:  # first call (from _open_wal in __init__) fails
            raise OSError("cannot open")
        return real_open(path, flags, mode)

    with patch("os.open", side_effect=_failing_open):
        ledger = CryptographicAuditLedger(str(wal), signing_key="k")
        # _wal_handle is None because _open_wal failed
        assert ledger._wal_handle is None

    # Now call commit_forensic — this triggers the else branch in _persist_node
    node = ledger.commit_forensic(state_id="fb-test", request_bytes=b"data")
    assert node.state_id == "fb-test"
    assert wal.exists()


# ── _sign() — PQC Rust paths (lines ~519-526) ────────────────────────────────


def test_sign_pqc_success_path(tmp_path):
    """
    Arrange: patch RUST_AVAILABLE=True and provide a mock aegis_rust.
    Act:     commit one node.
    Assert:  signature_scheme == "pqc-ml-dsa", is_fallback=False.
    """
    # Tier 2 signs under a persistent identity rather than a keypair minted
    # per call, so the seam to patch is the identity accessor, not the Rust
    # keygen function that no longer sits on the signing path.
    mock_signer = MagicMock()
    mock_signer.sign.return_value = bytes(64)
    mock_signer.public_key = bytes(32)

    with (
        # The class the test constructs, not ``_module.CryptographicAuditLedger``:
        # a fixture in this file reloads the module, so the two names can be
        # different class objects and patching the reloaded one does nothing.
        patch.object(
            CryptographicAuditLedger,
            "_pqc_signer",
            lambda self: mock_signer,
        ),
    ):
        ledger = CryptographicAuditLedger(str(tmp_path / "wal.jsonl"), signing_key="")
        node = ledger.commit_forensic(state_id="pqc-ok", request_bytes=b"req")
    assert node.signature_scheme == "pqc-ml-dsa"
    assert node.is_fallback is False
    ledger.close()


def test_sign_pqc_failure_falls_back_to_hmac(tmp_path):
    """
    Arrange: RUST_AVAILABLE=True but generate_pqc_keypair raises.
    Act:     commit — the except block is exercised, falls back to HMAC.
    Assert:  signature_scheme == "hmac-sha256".
    """
    mock_rust = MagicMock()
    mock_rust.generate_pqc_keypair.side_effect = RuntimeError("PQC unavailable")

    with (
        patch.object(_module, "RUST_AVAILABLE", True),
        patch.object(_module, "aegis_rust", mock_rust, create=True),
    ):
        ledger = CryptographicAuditLedger(str(tmp_path / "wal.jsonl"), signing_key="hmackey")
        node = ledger.commit_forensic(state_id="pqc-fail", request_bytes=b"req")
    assert node.signature_scheme == "hmac-sha256"
    assert node.is_fallback is False
    ledger.close()


# ── _persist_node() — fallback when _wal_handle is None (lines ~543-558) ─────


def test_persist_node_fallback_when_wal_handle_none(tmp_path):
    """
    Arrange: create a ledger, then manually null out _wal_handle.
    Act:     commit_forensic — triggers the else branch in _persist_node.
    Assert:  node committed; WAL file contains the JSON line.
    """
    wal = tmp_path / "wal.jsonl"
    ledger = CryptographicAuditLedger(str(wal), signing_key="k")
    # Close the handle manually to simulate _open_wal failure scenario.
    ledger._wal_handle.close()
    ledger._wal_handle = None

    node = ledger.commit_forensic(state_id="fallback-write", request_bytes=b"data")
    assert node.state_id == "fallback-write"
    assert wal.exists()
    lines = [ln for ln in wal.read_text().splitlines() if ln.strip()]
    assert len(lines) == 1


# ── _load_from_wal() — empty line skip (line ~572) ───────────────────────────


def test_load_from_wal_skips_empty_lines(tmp_path):
    """
    Arrange: WAL file with an empty line between two valid JSON records.
    Act:     create a new ledger pointing at this WAL (triggers _load_from_wal).
    Assert:  both records loaded; empty line silently skipped.
    """
    wal = tmp_path / "wal.jsonl"
    # Build two real WAL records by committing through a first ledger.
    first = CryptographicAuditLedger(str(wal), signing_key="k")
    first.commit_forensic(state_id="a", request_bytes=b"A")
    first.commit_forensic(state_id="b", request_bytes=b"B")
    first.close()

    # Insert an empty line between the two JSON records.
    text = wal.read_text()
    lines = text.splitlines(keepends=True)
    with_blank = lines[0] + "\n" + lines[1]
    wal.write_text(with_blank)

    second = CryptographicAuditLedger(str(wal), signing_key="k")
    assert len(second.chain) == 2  # both records loaded
    second.close()


def test_load_from_wal_corrupt_line_stops_reconstruction(tmp_path):
    """Corrupt WAL line halts reconstruction and sets fault_state."""
    wal = tmp_path / "wal.jsonl"
    first = CryptographicAuditLedger(str(wal), signing_key="k")
    first.commit_forensic(state_id="good", request_bytes=b"data")
    first.close()

    # Append a corrupt JSON line.
    with open(str(wal), "a") as f:
        f.write("{corrupt json\n")

    second = CryptographicAuditLedger(str(wal), signing_key="k")
    assert second._fault_state == "wal_corrupt"
    second.close()


# ── PQCSignatureAnchor.verify() (line ~597) ───────────────────────────────────


def test_pqc_anchor_verify_always_false():
    """
    Arrange: PQCSignatureAnchor with dummy public key.
    Act:     call verify().
    Assert:  always returns False (stateless anchor, no key material).
    """
    anchor = PQCSignatureAnchor(public_key=b"dummy")
    result = anchor.verify(data=b"hello", signature=b"sig")
    assert result is False


# ── verify_integrity() — tamper detection branch ──────────────────────────────


def test_verify_integrity_detects_in_memory_tamper(tmp_path):
    """
    Arrange: commit a node, then overwrite its state_id (breaks node_hash).
    Act:     verify_integrity().
    Assert:  returns (False, 0).
    """
    ledger = CryptographicAuditLedger(str(tmp_path / "wal.jsonl"), signing_key="k")
    ledger.commit_forensic(state_id="original", request_bytes=b"data")
    # Directly mutate a field — breaks the node_hash vs __creation_hash__ check.
    ledger.chain[0].state_id = "tampered"
    ok, idx = ledger.verify_integrity()
    assert ok is False
    assert idx == 0
    ledger.close()


def test_verify_integrity_detects_prev_hash_mismatch(tmp_path):
    """
    Arrange: commit two nodes, then break the chain link.
    Act:     verify_integrity().
    Assert:  returns (False, 1).
    """
    ledger = CryptographicAuditLedger(str(tmp_path / "wal.jsonl"), signing_key="k")
    ledger.commit_forensic(state_id="n0", request_bytes=b"A")
    ledger.commit_forensic(state_id="n1", request_bytes=b"B")
    # Break the chain linkage on node 1.
    ledger.chain[1].prev_hash = "0" * 64
    # Also reset __creation_hash__ so tamper check doesn't fire first.
    ledger.chain[1].__creation_hash__ = ledger.chain[1].node_hash
    ok, idx = ledger.verify_integrity()
    assert ok is False
    assert idx == 1
    ledger.close()


def test_verify_integrity_detects_hmac_mismatch(tmp_path):
    """
    Arrange: commit with signing key and no Rust (forces HMAC), then alter the signature.
    Act:     verify_integrity() with same signing key.
    Assert:  (False, 0).
    """
    with patch("aegis.core.crypto_audit.RUST_AVAILABLE", False):
        ledger = CryptographicAuditLedger(str(tmp_path / "wal.jsonl"), signing_key="secret")
        ledger.commit_forensic(state_id="sig-test", request_bytes=b"req")
        node = ledger.chain[0]
        node.signature = "00" * 32  # corrupt
        node.__creation_hash__ = node.node_hash  # reset so tamper check passes
        ok, idx = ledger.verify_integrity()
        assert ok is False
        assert idx == 0
        ledger.close()


# ── _build_signed_payload and HMAC helpers ────────────────────────────────────


def test_build_signed_payload_canonical():
    """Signed payload is deterministic pipe-delimited encoding."""
    payload = _build_signed_payload("prev", "root", "req", "resp")
    assert payload == b"prev|root|req|resp"


def test_hmac_round_trip():
    sig = _hmac_sign("key", b"data")
    assert _hmac_verify("key", b"data", sig)
    assert not _hmac_verify("key", b"other", sig)


# ── AuditNode.from_dict backward compat ──────────────────────────────────────


def test_audit_node_from_dict_legacy_payload_field(tmp_path):
    """from_dict handles old WAL records that use 'payload' instead of 'request_hash'."""
    ledger = CryptographicAuditLedger(str(tmp_path / "wal.jsonl"), signing_key="k")
    node = ledger.commit_forensic(state_id="compat", request_bytes=b"req")
    d = node.to_dict()
    # Simulate old WAL field.
    d["payload"] = d.pop("request_hash")
    from aegis.core.crypto_audit import AuditNode

    restored = AuditNode.from_dict(d)
    assert restored.state_id == "compat"
    ledger.close()
