"""
tests/test_wal_repair.py — the supported way back from a torn tail.

A process killed between ``write()`` and the newline leaves a partial last line.
Replay reaches it, cannot parse it, sets ``wal_corrupt``, and every governed
endpoint refuses with ``503``. That refusal is correct and REG-017 does not
change it — appending onto a prefix you failed to read back is the failure the
evidence contract exists to prevent.

What was missing is a supported way back. Without one, an operator under
incident pressure edits an evidence file by hand, which is worse than any tool.

These tests pin the refusals as hard as the repair, because a repair tool for an
evidence log is mostly a set of things it must decline to do:

* a bad line in the **middle** is refused, not truncated — it is corruption or
  tampering, and truncating there would discard every valid record after it;
* nothing is modified without ``--apply``, and the dry run exits non-zero so a
  pipeline cannot repair a ledger by accident;
* a backup is written before the file is touched;
* a repaired WAL actually replays in the real ledger afterwards, which is the
  only thing that makes the repair worth trusting.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import importlib.util
from pathlib import Path

from aegis.core.crypto_audit import CryptographicAuditLedger

_SPEC = importlib.util.spec_from_file_location(
    "wal_repair", Path(__file__).resolve().parents[1] / "tools" / "wal_repair.py"
)
assert _SPEC is not None
assert _SPEC.loader is not None
wal_repair = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(wal_repair)

_KEY = "reg-017-test-key"


def _healthy_wal(path: Path, count: int = 3) -> None:
    ledger = CryptographicAuditLedger(str(path), signing_key=_KEY)
    for index in range(count):
        ledger.commit_forensic(state_id=f"req-{index}", request_bytes=f"body-{index}".encode())
    ledger.close()


def _tear_the_tail(path: Path) -> None:
    """Append a partial record, exactly as a kill between write and newline would."""
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"state_id": "req-torn", "timestamp": 176')


def test_a_healthy_wal_is_left_alone(tmp_path: Path) -> None:
    wal = tmp_path / "w.jsonl"
    _healthy_wal(wal)
    before = wal.read_bytes()

    assert wal_repair.repair(wal, apply=True) == 0
    assert wal.read_bytes() == before, "a healthy WAL must not be rewritten"


def test_a_torn_tail_is_detected_but_not_repaired_without_apply(tmp_path: Path) -> None:
    """The dry run must exit non-zero so a pipeline cannot repair by accident."""
    wal = tmp_path / "w.jsonl"
    _healthy_wal(wal)
    _tear_the_tail(wal)
    before = wal.read_bytes()

    assert wal_repair.repair(wal, apply=False) == 1
    assert wal.read_bytes() == before, "dry run must not modify the file"


def test_a_torn_tail_is_repaired_with_apply(tmp_path: Path) -> None:
    wal = tmp_path / "w.jsonl"
    _healthy_wal(wal, count=3)
    _tear_the_tail(wal)

    assert wal_repair.repair(wal, apply=True) == 0

    _, bad = wal_repair.scan(wal)
    assert bad is None
    assert len([ln for ln in wal.read_text().splitlines() if ln.strip()]) == 3


def test_the_original_is_backed_up_before_truncation(tmp_path: Path) -> None:
    """The removed bytes must stay recoverable.

    A torn line means a commit was in flight. Whether its governed response
    reached a caller is not knowable from the WAL, so discarding the evidence of
    the attempt would destroy the only trace of the question.
    """
    wal = tmp_path / "w.jsonl"
    _healthy_wal(wal)
    _tear_the_tail(wal)
    original = wal.read_bytes()
    backup = tmp_path / "keep.bak"

    assert wal_repair.repair(wal, apply=True, backup=backup) == 0
    assert backup.read_bytes() == original, "the backup must be byte-for-byte the original"


def test_a_bad_line_in_the_middle_is_refused(tmp_path: Path) -> None:
    """The refusal that matters most.

    Truncating to a mid-file corruption would silently discard every valid
    record after it. That is not a repair, and a tool that did it quietly would
    be more dangerous than the fault it claims to fix.
    """
    wal = tmp_path / "w.jsonl"
    _healthy_wal(wal, count=4)
    lines = wal.read_text().splitlines(keepends=True)
    lines[1] = '{"state_id": "broken", "timesta\n'
    wal.write_text("".join(lines))
    before = wal.read_bytes()

    assert wal_repair.repair(wal, apply=True) == 2
    assert wal.read_bytes() == before, "a refused WAL must not be modified"


def test_a_repaired_wal_replays_in_the_real_ledger(tmp_path: Path) -> None:
    """The property the whole tool exists for.

    Parsing is not the bar — the ledger reopening without a fault is. A repair
    that left the ledger refusing traffic would have achieved nothing.
    """
    wal = tmp_path / "w.jsonl"
    _healthy_wal(wal, count=3)
    _tear_the_tail(wal)

    faulted = CryptographicAuditLedger(str(wal), signing_key=_KEY)
    assert faulted._fault_state == "wal_corrupt", "precondition: the torn tail faults the ledger"
    faulted.close()

    assert wal_repair.repair(wal, apply=True) == 0

    recovered = CryptographicAuditLedger(str(wal), signing_key=_KEY)
    fault = recovered._fault_state
    valid, broken_at = recovered.verify_integrity()
    recovered.close()

    assert fault != "wal_corrupt", "the repaired WAL must replay without faulting"
    assert (valid, broken_at) == (True, None)


def test_an_empty_wal_is_not_a_torn_tail(tmp_path: Path) -> None:
    wal = tmp_path / "w.jsonl"
    wal.write_text("")
    assert wal_repair.repair(wal, apply=True) == 0


def test_a_missing_wal_is_an_error_not_a_silent_success(tmp_path: Path) -> None:
    try:
        wal_repair.repair(tmp_path / "absent.jsonl", apply=True)
    except SystemExit as exc:
        assert "no WAL at" in str(exc)
    else:  # pragma: no cover - the call must raise
        raise AssertionError("a missing WAL must not be reported as repaired")
