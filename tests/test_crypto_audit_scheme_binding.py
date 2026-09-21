# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""REG-D06 — the declared signature scheme is fenced, dispatched, and floored.

The v5.0.1-prep audit reproduced this attack first-hand (independent parent
re-run of the delegated finding): rewriting ``signature_scheme`` on every WAL
line left ``verify_integrity() == (True, None)`` while ``signature_assurance``
reported ``ASYMMETRIC_HARDWARE_ATTESTED`` and every per-node status was
``unverified``.

These tests pin the fixed behaviour on the same real-ledger path — write a
chain, rewrite the WAL the way the attack did, reopen, and ask the ledger:
a label rewrite is a positive detection (``invalid``), it fails
``verify_integrity``, and it cannot buy a stronger tier from the assurance
property. The last test pins the *documented residual* (UC-054): material
that is well-shaped for a tier this build has no verifier for cannot be
distinguished from a fabricated, well-shaped claim.
"""

from __future__ import annotations

import json

from aegis.core.crypto_audit import (
    CryptographicAuditLedger,
    SignatureAssurance,
    scheme_material_inconsistency,
)

# ── helpers ───────────────────────────────────────────────────────────────────


def _commit_chain(wal_path, *, count: int = 3, **ledger_kwargs) -> None:
    ledger = CryptographicAuditLedger(persistence_path=str(wal_path), **ledger_kwargs)
    try:
        for index in range(count):
            ledger.commit_forensic(
                state_id=f"s{index}",
                request_bytes=b"req",
                response_bytes=b"resp",
                tenant_id="tenant-a",
            )
    finally:
        ledger.close()


def _rewrite_wal(wal_path, **fields: str) -> int:
    """Rewrite the named JSON fields on every WAL line; return the count."""

    lines = [line for line in open(wal_path, encoding="utf-8").read().split("\n") if line.strip()]
    rewritten = 0
    out: list[str] = []
    for line in lines:
        record = json.loads(line)
        for key, value in fields.items():
            if key in record:
                record[key] = value
                rewritten += 1
        out.append(json.dumps(record, separators=(",", ":")))
    with open(wal_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")
    return rewritten


def _reopen(wal_path, **ledger_kwargs) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(persistence_path=str(wal_path), **ledger_kwargs)


# ── baseline ──────────────────────────────────────────────────────────────────


def test_untampered_hmac_chain_stays_green(tmp_path):
    wal = tmp_path / "audit.jsonl"
    _commit_chain(wal, signing_key="reg-d06-key")
    ledger = _reopen(wal, signing_key="reg-d06-key")
    try:
        assert ledger.verify_integrity() == (True, None)
        assert ledger.signature_assurance == SignatureAssurance.SYMMETRIC_AUTHENTICATED
        assert {ledger.signature_status(node) for node in ledger.chain} == {"valid"}
    finally:
        ledger.close()


# ── the reproduced attack ─────────────────────────────────────────────────────


def test_label_rewrite_to_hardware_tier_fails_integrity(tmp_path):
    wal = tmp_path / "audit.jsonl"
    _commit_chain(wal, signing_key="reg-d06-key")
    assert _rewrite_wal(wal, signature_scheme="pkcs11-rsa-pss-sha256") == 3

    ledger = _reopen(wal, signing_key="reg-d06-key")
    try:
        assert ledger.verify_integrity() == (False, 0)
        assert {ledger.signature_status(node) for node in ledger.chain} == {"invalid"}
        assert ledger.signature_assurance == SignatureAssurance.UNSIGNED
    finally:
        ledger.close()


def test_unknown_scheme_label_is_invalid_not_unverified(tmp_path):
    wal = tmp_path / "audit.jsonl"
    _commit_chain(wal, count=1, signing_key="reg-d06-key")
    _rewrite_wal(wal, signature_scheme="totally-made-up")

    ledger = _reopen(wal, signing_key="reg-d06-key")
    try:
        node = ledger.chain[0]
        assert (
            scheme_material_inconsistency(node) == "unrecognised signature scheme 'totally-made-up'"
        )
        assert ledger.signature_status(node) == "invalid"
        assert ledger.verify_integrity() == (False, 0)
    finally:
        ledger.close()


def test_hmac_material_carrying_a_public_key_is_inconsistent(tmp_path):
    wal = tmp_path / "audit.jsonl"
    _commit_chain(wal, count=1, signing_key="reg-d06-key")
    _rewrite_wal(wal, public_key="ab" * 32)

    ledger = _reopen(wal, signing_key="reg-d06-key")
    try:
        node = ledger.chain[0]
        reason = scheme_material_inconsistency(node)
        assert reason is not None
        assert "does not carry a public key" in reason
        assert ledger.signature_status(node) == "invalid"
    finally:
        ledger.close()


# ── legitimate chains keep their behaviour ────────────────────────────────────


def test_ed25519_fallback_chain_verifies_with_its_recorded_key(tmp_path):
    wal = tmp_path / "audit.jsonl"
    _commit_chain(wal, count=2)  # no signing key: Ed25519 ephemeral fallback

    ledger = _reopen(wal)
    try:
        node = ledger.chain[0]
        assert node.signature_scheme == "ed25519-fallback"
        assert scheme_material_inconsistency(node) is None
        assert ledger.signature_status(node) == "valid"
        assert ledger.verify_integrity() == (True, None)
        assert ledger.signature_assurance == SignatureAssurance.COMPROMISED_EPHEMERAL
    finally:
        ledger.close()


def test_pkcs11_labelled_node_without_public_key_is_invalid(tmp_path):
    """A relabel to an unverifiable tier is caught when the material is empty."""

    wal = tmp_path / "audit.jsonl"
    _commit_chain(wal, count=1, signing_key="reg-d06-key")
    assert _rewrite_wal(wal, signature_scheme="pkcs11-ecdsa-sha256") == 1

    ledger = _reopen(wal, signing_key="reg-d06-key")
    try:
        node = ledger.chain[0]
        reason = scheme_material_inconsistency(node)
        assert reason is not None
        assert "requires a public key" in reason
        assert ledger.signature_status(node) == "invalid"
    finally:
        ledger.close()


# ── documented residual boundary (UC-054) ─────────────────────────────────────


def test_well_shaped_claim_for_an_unverifiable_tier_reports_unverified(tmp_path):
    """The residual this fix does not close, pinned so it stays visible.

    Rewriting the label AND supplying well-shaped material for a tier this
    build has no verifier for is shape-consistent, so it reads as
    ``unverified`` rather than ``invalid``, and the sweep does not fail on
    it. Distinguishing a fabricated claim from a genuine HSM signature needs
    the deployment's PKCS#11 library — the boundary is published as UC-054.

    AUD-27 (2026-09-21) bound the label into the signed payload, which removes
    the *other* half of this residual for records written since: the claim can no
    longer be rewritten without invalidating the signature, so a deployment that
    holds the tier's key rejects it. This record still reads ``unverified`` here
    because that half is exactly what this build cannot do. The binding —
    including that the same relabel is refused once a verifier exists, and that a
    pre-binding record keeps the old reading — is pinned in
    ``tests/test_signature_scheme_binding.py``.
    """

    wal = tmp_path / "audit.jsonl"
    _commit_chain(wal, count=1, signing_key="reg-d06-key")
    _rewrite_wal(
        wal,
        signature_scheme="pkcs11-rsa-pss-sha256",
        signature="ab" * 256,
        public_key="cd" * 256,
    )

    ledger = _reopen(wal, signing_key="reg-d06-key")
    try:
        node = ledger.chain[0]
        assert scheme_material_inconsistency(node) is None
        assert ledger.signature_status(node) == "unverified"
        assert ledger.verify_integrity() == (True, None)  # non-fatal by design
        assert (
            ledger.signature_assurance == SignatureAssurance.ASYMMETRIC_HARDWARE_ATTESTED
        )  # residual: the claim is well-shaped and this build cannot check it
    finally:
        ledger.close()
