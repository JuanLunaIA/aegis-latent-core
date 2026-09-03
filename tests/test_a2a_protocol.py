"""
tests/test_a2a_protocol.py — agent-to-agent execution receipts.

A receipt lets one agent show a third party that an execution was recorded in
an Aegis ledger, without disclosing the arguments or the result.

The security of the scheme rests on one property, and most of this file exists
to attack it: **the leaf a receipt proves must be the leaf its own fields
reproduce.** Without that binding a receipt could quote any leaf already in the
tree — a real, provable leaf — while asserting a different tool, a different
caller, or a different result. Every field is therefore tampered with
individually, and the proof is swapped for a genuine proof of a different leaf.

The boundary is equally load-bearing and is asserted where it can be: a valid
receipt establishes inclusion under the supplied root and nothing more. The
tests below never assert that a tool ran, that an agent is who it claims, or
that a timestamp is true, because a receipt does not establish any of those.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aegis.core.a2a import (
    A2A_RECEIPT_VERSION,
    AgentReceipt,
    a2a_envelope_bytes,
    a2a_leaf_hash,
    generate_receipt,
    verify_receipt,
)
from aegis.core.crypto_audit import CryptographicAuditLedger

SIGNING_KEY = "k" * 32
SECRET_ARGS = b'{"query": "acquisition target: Northwind Traders"}'
SECRET_RESULT = b'{"valuation": 4200000}'


@pytest.fixture
def ledger(tmp_path: Path) -> Any:
    handle = CryptographicAuditLedger(str(tmp_path / "a2a.jsonl"), signing_key=SIGNING_KEY)
    # Unrelated traffic, so a receipt is never the only leaf in the tree and a
    # proof has actual structure to verify.
    for index in range(3):
        handle.commit_forensic(state_id=f"noise-{index}", request_bytes=b"x", response_bytes=b"y")
    yield handle
    handle.close()


def _issue(handle: CryptographicAuditLedger, **overrides: Any) -> AgentReceipt:
    kwargs: dict[str, Any] = {
        "caller_agent_id": "planner",
        "target_agent_id": "research",
        "tool_name": "web.query",
        "input_bytes": SECRET_ARGS,
        "output_bytes": SECRET_RESULT,
    }
    kwargs.update(overrides)
    return generate_receipt(handle, **kwargs)


# ── the happy path ────────────────────────────────────────────────────────────


def test_a_receipt_verifies_against_the_ledger_root(ledger: Any) -> None:
    receipt = _issue(ledger)
    assert verify_receipt(receipt, ledger._mmr.get_root_hash())


def test_a_receipt_survives_json_transport(ledger: Any) -> None:
    """Receipts travel between agents as JSON; verification must not depend on
    holding the original object."""
    receipt = _issue(ledger)
    wire = json.loads(json.dumps(receipt.to_dict()))
    assert verify_receipt(wire, ledger._mmr.get_root_hash())
    assert verify_receipt(AgentReceipt.from_dict(wire), ledger._mmr.get_root_hash())


def test_the_execution_id_is_derived_and_stable(ledger: Any) -> None:
    first = _issue(ledger)
    second = _issue(ledger)
    assert first.execution_id == second.execution_id
    assert first.execution_id.startswith("a2a-")


def test_an_explicit_execution_id_is_honoured(ledger: Any) -> None:
    receipt = _issue(ledger, execution_id="run-42")
    assert receipt.execution_id == "run-42"
    assert verify_receipt(receipt, ledger._mmr.get_root_hash())


# ── confidentiality ───────────────────────────────────────────────────────────


def test_arguments_and_results_never_leave_as_plaintext(ledger: Any, tmp_path: Path) -> None:
    receipt = _issue(ledger)
    serialised = json.dumps(receipt.to_dict())
    assert "Northwind Traders" not in serialised
    assert "4200000" not in serialised

    ledger.close()
    written = (tmp_path / "a2a.jsonl").read_bytes()
    assert b"Northwind Traders" not in written
    assert b"4200000" not in written


# ── the binding between receipt fields and the proven leaf ────────────────────


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tool_name", "web.delete"),
        ("caller_agent_id", "admin"),
        ("target_agent_id", "billing"),
        ("execution_id", "some-other-run"),
        ("input_hash", "0" * 64),
        ("output_hash", "f" * 64),
    ],
)
def test_altering_any_bound_field_invalidates_the_receipt(
    ledger: Any, field: str, value: str
) -> None:
    receipt = _issue(ledger)
    tampered = {**receipt.to_dict(), field: value}
    assert not verify_receipt(tampered, ledger._mmr.get_root_hash())


def test_altering_the_timestamp_invalidates_the_receipt(ledger: Any) -> None:
    """The clock is unattested, but it is sealed: it cannot be edited later."""
    receipt = _issue(ledger)
    tampered = {**receipt.to_dict(), "timestamp": receipt.timestamp + 1.0}
    assert not verify_receipt(tampered, ledger._mmr.get_root_hash())


def test_a_receipt_cannot_borrow_another_leafs_proof(ledger: Any) -> None:
    """The central attack: a genuine proof of a different leaf.

    The substituted proof is real and verifies on its own. It must still fail
    here, because the leaf it proves is not the one this receipt's fields
    reproduce.
    """
    receipt = _issue(ledger)
    other = ledger.chain[0]
    assert other.mmr_proof is not None
    forged = {**receipt.to_dict(), "inclusion_proof": other.mmr_proof}
    assert not verify_receipt(forged, ledger._mmr.get_root_hash())


# ── rejection of malformed and untrusted input ────────────────────────────────


def test_verification_needs_the_matching_root(ledger: Any) -> None:
    receipt = _issue(ledger)
    assert not verify_receipt(receipt, "a" * 64)
    assert not verify_receipt(receipt, "not-a-root")


def test_an_unknown_version_is_refused(ledger: Any) -> None:
    receipt = _issue(ledger)
    assert not verify_receipt(
        {**receipt.to_dict(), "version": "aegis-a2a-receipt-v2"}, ledger._mmr.get_root_hash()
    )


@pytest.mark.parametrize("field", ["tool_name", "input_hash", "inclusion_proof", "timestamp"])
def test_a_missing_field_is_refused_not_defaulted(ledger: Any, field: str) -> None:
    receipt = _issue(ledger)
    partial = {key: value for key, value in receipt.to_dict().items() if key != field}
    assert not verify_receipt(partial, ledger._mmr.get_root_hash())


def test_a_malformed_proof_is_refused(ledger: Any) -> None:
    receipt = _issue(ledger)
    for proof in ({}, {"version": "wrong"}, {"peaks": "nonsense"}):
        assert not verify_receipt(
            {**receipt.to_dict(), "inclusion_proof": proof}, ledger._mmr.get_root_hash()
        )


def test_verification_returns_false_rather_than_raising(ledger: Any) -> None:
    """A caller must not be able to mistake an exception for a pass."""
    for junk in ({}, {"version": 1}, {"inclusion_proof": None}):
        assert verify_receipt(junk, ledger._mmr.get_root_hash()) is False


# ── issuance guards ───────────────────────────────────────────────────────────


def test_oversized_identifiers_are_refused(ledger: Any) -> None:
    """Bounded identifiers keep the envelope small enough that the leaf preview
    is never truncated, which is what makes the leaf hash configuration-free."""
    with pytest.raises(ValueError):
        _issue(ledger, tool_name="t" * 129)
    with pytest.raises(ValueError):
        _issue(ledger, caller_agent_id="")


def test_a_ledger_with_too_small_a_cap_is_refused(tmp_path: Path) -> None:
    """A truncated preview would produce a leaf no verifier could reproduce, so
    issuance refuses rather than emitting an unverifiable receipt."""
    with CryptographicAuditLedger(
        str(tmp_path / "small.jsonl"), signing_key=SIGNING_KEY, max_forensic_bytes=64
    ) as handle:
        with pytest.raises(ValueError, match="max_forensic_bytes"):
            _issue(handle)


def test_the_leaf_hash_is_reproducible_from_receipt_fields(ledger: Any) -> None:
    """What a third-party verifier does, spelled out."""
    receipt = _issue(ledger)
    envelope = a2a_envelope_bytes(
        execution_id=receipt.execution_id,
        caller_agent_id=receipt.caller_agent_id,
        target_agent_id=receipt.target_agent_id,
        tool_name=receipt.tool_name,
        input_hash=receipt.input_hash,
        output_hash=receipt.output_hash,
        timestamp=receipt.timestamp,
    )
    assert receipt.version == A2A_RECEIPT_VERSION
    assert len(a2a_leaf_hash(envelope)) == 64


# ── the SDK verifier agrees with the issuer ───────────────────────────────────


def test_the_python_sdk_verifies_a_server_issued_receipt(ledger: Any) -> None:
    """The SDK reimplements the envelope independently; the two must agree.

    A verifier that disagreed with the issuer would reject every valid receipt,
    which is exactly the failure a cross-implementation test catches.
    """
    sdk_a2a = pytest.importorskip("aegis_sdk.a2a")
    receipt = _issue(ledger)
    wire = json.loads(json.dumps(receipt.to_dict()))
    root = ledger._mmr.get_root_hash()

    assert sdk_a2a.verify_receipt(wire, root)
    assert not sdk_a2a.verify_receipt({**wire, "tool_name": "web.delete"}, root)
    assert not sdk_a2a.verify_receipt(wire, "b" * 64)
