# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""REG-D14 — the Part 11 signer annotation is bound by the node signature.

The v5.0.1-prep audit (AF-020) found that ``signer_name``, ``signature_meaning``
and the admission ``status`` were absent from ``node_hash``, from the signed
payload and from the MMR leaf, while ``export_part11_signatures`` presented
``node_hash`` as the annotation's "tamper-evident binding". An attacker with WAL
write access could rewrite who signed a record, what the signature meant, and
whether a refused request had been rejected or admitted, with verification
unchanged.

These tests drive the same real-ledger path the sibling REG-D06 tests use: write
a chain, rewrite the WAL the way the attack did, reopen, and ask the ledger. The
binding is value-derived and additive, so the two boundary cases are pinned as
well — a record signed before the binding still verifies (its signature is over
the pre-binding material), and that record's annotation stays rewritable, which
is the part of UC-055 that cannot be fixed for already-written WAL.
"""

from __future__ import annotations

import json

from aegis.core.crypto_audit import (
    CryptographicAuditLedger,
    _build_prebinding_signed_payload,
    _hmac_sign,
)
from aegis.core.forensic import WAF_VERDICT_UNRECORDED

KEY = "reg-d14-key"


# ── helpers ───────────────────────────────────────────────────────────────────


def _commit_annotated_chain(wal_path, *, count: int = 3) -> None:
    ledger = CryptographicAuditLedger(persistence_path=str(wal_path), signing_key=KEY)
    try:
        for index in range(count):
            ledger.commit_forensic(
                state_id=f"s{index}",
                request_bytes=b"req",
                response_bytes=b"resp",
                tenant_id="tenant-a",
                signer_name="Dr. Alice Example",
                signature_meaning="authored",
            )
        ledger.commit_rejection(
            request_bytes=b"blocked",
            rejection_code=403,
            reason_category="waf_block",
            tenant_id="tenant-a",
            state_id="rejected-1",
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


def _downgrade_to_prebinding_signatures(wal_path) -> int:
    """Re-sign every WAL line with the pre-binding digest, on disk.

    This is what a chain written before the binding looks like: the signature
    covers the fields that were signed then, and nothing about the annotation.
    """
    lines = [line for line in open(wal_path, encoding="utf-8").read().split("\n") if line.strip()]
    out: list[str] = []
    for line in lines:
        record = json.loads(line)
        record["signature"] = _hmac_sign(
            KEY,
            _build_prebinding_signed_payload(
                prev_hash=record["prev_hash"],
                merkle_root=record["merkle_root"],
                request_hash=record["request_hash"],
                response_hash=record["response_hash"],
                waf_verdict=record.get("waf_verdict", WAF_VERDICT_UNRECORDED),
            ),
        )
        out.append(json.dumps(record, separators=(",", ":")))
    with open(wal_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")
    return len(out)


def _reopen(wal_path) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(persistence_path=str(wal_path), signing_key=KEY)


def _tampered(wal_path, **fields: str) -> CryptographicAuditLedger:
    rewritten = _rewrite_wal(wal_path, **fields)
    assert rewritten, f"none of {sorted(fields)} were present in the WAL"
    return _reopen(wal_path)


# ── baseline ──────────────────────────────────────────────────────────────────


def test_annotated_chain_verifies_with_the_annotation_bound(tmp_path):
    wal = tmp_path / "audit.jsonl"
    _commit_annotated_chain(wal)
    ledger = _reopen(wal)
    try:
        assert ledger.verify_integrity() == (True, None)
        assert {ledger.signature_status(node) for node in ledger.chain} == {"valid"}
        assert [node.signer_name for node in list(ledger.chain)[:3]] == ["Dr. Alice Example"] * 3
        assert ledger.chain[3].status == "rejected"
    finally:
        ledger.close()


# ── the attack the audit described ────────────────────────────────────────────


def test_rewriting_the_signer_name_invalidates_the_signature(tmp_path):
    wal = tmp_path / "audit.jsonl"
    _commit_annotated_chain(wal)
    ledger = _tampered(wal, signer_name="Dr. Mallory Impostor")
    try:
        assert ledger.chain[0].signer_name == "Dr. Mallory Impostor"
        assert ledger.signature_status(ledger.chain[0]) == "invalid"
        assert ledger.verify_integrity() == (False, 0)
    finally:
        ledger.close()


def test_rewriting_the_signature_meaning_invalidates_the_signature(tmp_path):
    wal = tmp_path / "audit.jsonl"
    _commit_annotated_chain(wal)
    ledger = _tampered(wal, signature_meaning="approved")
    try:
        assert ledger.signature_status(ledger.chain[1]) == "invalid"
        assert ledger.verify_integrity() == (False, 0)
    finally:
        ledger.close()


def test_blanking_both_annotation_fields_invalidates_the_signature(tmp_path):
    """The case a pre-binding fallback could wrongly accept, and must not.

    Blanking the annotation rebuilds the *pre-binding* field list, so this is
    the test that pins the fallback as unreachable for a node written by this
    build: its stored signature is over the annotated material, so the shorter
    list cannot match.
    """
    wal = tmp_path / "audit.jsonl"
    _commit_annotated_chain(wal)
    ledger = _tampered(wal, signer_name="", signature_meaning="")
    try:
        assert ledger.chain[0].signer_name == ""
        assert ledger.signature_status(ledger.chain[0]) == "invalid"
        assert ledger.verify_integrity() == (False, 0)
    finally:
        ledger.close()


def test_relabelling_a_rejection_as_committed_invalidates_the_signature(tmp_path):
    """The compliance-relevant direction: a refusal rewritten as an admission."""
    wal = tmp_path / "audit.jsonl"
    _commit_annotated_chain(wal)
    ledger = _tampered(wal, status="committed")
    try:
        rejection = next(node for node in ledger.chain if node.state_id == "rejected-1")
        assert rejection.status == "committed"
        assert ledger.signature_status(rejection) == "invalid"
        assert ledger.verify_integrity() == (False, 3)
    finally:
        ledger.close()


def test_relabelling_a_committed_node_as_rejected_invalidates_the_signature(tmp_path):
    wal = tmp_path / "audit.jsonl"
    _commit_annotated_chain(wal)
    ledger = _tampered(wal, status="rejected")
    try:
        assert ledger.signature_status(ledger.chain[0]) == "invalid"
        assert ledger.verify_integrity() == (False, 0)
    finally:
        ledger.close()


def test_a_status_outside_the_closed_vocabulary_is_invalid(tmp_path):
    wal = tmp_path / "audit.jsonl"
    _commit_annotated_chain(wal)
    ledger = _tampered(wal, status="approved")
    try:
        assert ledger.signature_status(ledger.chain[0]) == "invalid"
    finally:
        ledger.close()


# ── the boundary that remains (UC-055) ────────────────────────────────────────


def test_a_record_signed_before_the_binding_still_verifies(tmp_path):
    """Chains written before this change stay verifiable.

    A rejection record is re-signed on disk with the pre-binding digest — exactly
    what an older build wrote, when ``status`` was never part of the signed
    material — and the ledger must accept it, because rejecting it would
    invalidate every chain already on disk. The chain is a single node because
    ``node_hash`` covers the signature, so re-signing a line changes its hash and
    would break the *next* line's linkage: that is a property of the node hash,
    not of this binding.
    """
    wal = tmp_path / "audit.jsonl"
    _commit_annotated_chain(wal, count=0)
    assert _downgrade_to_prebinding_signatures(wal) == 1
    ledger = _reopen(wal)
    try:
        assert ledger.chain[0].status == "rejected"
        assert {ledger.signature_status(node) for node in ledger.chain} == {"valid"}
        assert ledger.verify_integrity() == (True, None)
    finally:
        ledger.close()


def test_a_prebinding_record_keeps_its_unbound_annotation(tmp_path):
    """UC-055, pinned: the fallback protects old records, not their annotation.

    On a record whose stored signature is over the pre-binding material, the
    annotation can still be rewritten and verify — the fallback cannot tell a
    rewrite from the original, because nothing in that record ever committed to
    the value. This is the part of the finding that no verification-time change
    could fix for WAL that already exists, and it is asserted here so no reader
    assumes otherwise.
    """
    wal = tmp_path / "audit.jsonl"
    _commit_annotated_chain(wal, count=0)
    _downgrade_to_prebinding_signatures(wal)
    ledger = _reopen(wal)
    try:
        assert {ledger.signature_status(node) for node in ledger.chain} == {"valid"}
    finally:
        ledger.close()

    _rewrite_wal(wal, signer_name="Dr. Mallory Impostor", signature_meaning="approved")
    ledger = _reopen(wal)
    try:
        assert ledger.chain[0].signer_name == "Dr. Mallory Impostor"
        assert {ledger.signature_status(node) for node in ledger.chain} == {"valid"}
        assert ledger.verify_integrity() == (True, None)
    finally:
        ledger.close()


def test_a_freshly_written_chain_is_not_reachable_by_the_fallback(tmp_path):
    """The fallback offers a second shape; it must never accept an edit.

    Same rewrite as the test above, on records this build signed: the annotated
    payload is what the stored signature covers, so the pre-binding candidate
    cannot match and the ledger reports a violation instead.
    """
    wal = tmp_path / "audit.jsonl"
    _commit_annotated_chain(wal, count=2)
    _rewrite_wal(wal, signer_name="Dr. Mallory Impostor")
    ledger = _reopen(wal)
    try:
        assert {ledger.signature_status(node) for node in ledger.chain} == {"invalid"}
        assert ledger.verify_integrity() == (False, 0)
    finally:
        ledger.close()
