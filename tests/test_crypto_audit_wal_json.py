# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The WAL must stay RFC 8259 JSON (AF-051 / REG-D27).

`commit_forensic` copied caller `sampling_params` (and the merged `usage`) into
the node, and `_persist_node` serialised it with CPython's default
`allow_nan=True`, so a non-finite float produced a durable WAL line containing a
bare `NaN` / `Infinity`. Those are ECMA-262 extensions, not JSON: the probe run
for this row showed serde_json 1.0.150, Go's encoding/json and `JSON.parse` all
rejecting the line while Python's lenient replay still reported a healthy chain
— a silent cross-language verification failure in the replay authority. The
ledger's own evidence export refused the same record, so the record existed but
could not be exported.

These tests pin the ingest refusal, the pre-lock ordering (a caller error must
not latch a fault) and the strict-JSON property of everything the ledger writes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger


def _ledger(tmp_path: Path) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(persistence_path=str(tmp_path / "audit.wal.jsonl"))


def _strict_loads(line: str):
    """json.loads that refuses the ECMA-262 extensions a strict reader refuses."""

    def _reject(constant: str):
        raise AssertionError(f"non-standard JSON constant in WAL line: {constant}")

    return json.loads(line, parse_constant=_reject)


@pytest.mark.parametrize(
    "params",
    [
        {"temperature": float("nan")},
        {"temperature": float("inf")},
        {"temperature": float("-inf")},
        {"meta": [{"top_p": float("nan")}]},
        {"usage": {"total_tokens": float("inf")}},
    ],
)
def test_non_finite_sampling_params_are_refused_at_ingest(tmp_path, params) -> None:
    ledger = _ledger(tmp_path)
    wal = tmp_path / "audit.wal.jsonl"

    with pytest.raises(ValueError, match="non-finite"):
        ledger.commit_forensic(state_id="nan", request_bytes=b"{}", sampling_params=params)

    # A caller error, not a ledger fault: nothing latched, nothing committed and
    # nothing written — the refusal happens before the lock.
    assert len(ledger.chain) == 0
    assert ledger._fault_state == "healthy"
    assert not wal.exists() or wal.read_text(encoding="utf-8") == ""


def test_non_serialisable_values_are_refused_at_ingest(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    with pytest.raises(ValueError, match="not JSON-representable"):
        ledger.commit_forensic(
            state_id="bytes", request_bytes=b"{}", sampling_params={"blob": b"x"}
        )


def test_finite_params_are_committed_and_every_wal_line_is_strict_json(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    ledger.commit_forensic(
        state_id="ok-1",
        request_bytes=b'{"prompt": "hi"}',
        response_bytes=b'{"ok": true}',
        sampling_params={"temperature": 0.7, "usage": {"total_tokens": 3}},
    )
    ledger.commit_forensic(state_id="ok-2", request_bytes=b"{}", entropy=0.25)

    wal = tmp_path / "audit.wal.jsonl"
    raw = wal.read_bytes()
    assert b"NaN" not in raw, "a bare NaN token reached the WAL"
    assert b"Infinity" not in raw, "a bare Infinity token reached the WAL"

    lines = [line for line in wal.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 2
    for line in lines:
        _strict_loads(line)  # raises if a non-standard constant slips through

    # The serialiser itself is now the backstop for anything that bypasses ingest.
    for node in ledger.chain:
        json.dumps(node.to_dict(), separators=(",", ":"), allow_nan=False)


def test_a_rejected_commit_does_not_break_the_ledger(tmp_path) -> None:
    """Refusal must leave the ledger usable — the next good commit lands."""
    ledger = _ledger(tmp_path)
    with pytest.raises(ValueError):
        ledger.commit_forensic(
            state_id="bad", request_bytes=b"{}", sampling_params={"temperature": float("nan")}
        )
    node = ledger.commit_forensic(state_id="good", request_bytes=b"{}")
    assert node.state_id == "good"
    ok, reason = ledger.verify_integrity()
    assert ok, reason
