# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""A short run of the kill-and-recover harness: no acknowledged commit may be lost."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_killed_committer_loses_no_acknowledged_commit(tmp_path: Path):
    report = tmp_path / "report.json"
    result = subprocess.run(  # noqa: S603  # nosec B603 - this interpreter and a fixed script, shell=False
        [
            sys.executable, str(ROOT / "tools/qualification/wal_crash_soak.py"),
            "--rounds", "3", "--wal", str(tmp_path / "wal.jsonl"), "--json", str(report),
        ],
        capture_output=True, text=True, cwd=ROOT, timeout=180,
    )  # fmt: skip
    assert result.returncode == 0, result.stdout[-1500:]
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["rounds"] == 3
    assert data["acknowledged_lost"] == 0
    assert data["all_rounds_valid"] is True


@pytest.fixture
def quiet_ledger_log() -> Iterator[None]:
    """Stop pytest keeping the corrupt-line log record.

    The record's arguments include the parse exception, whose traceback reaches the ledger and
    so its single-writer WAL lock. Under pytest that lock would outlive ``del ledger``; in the
    harness run as a script nothing keeps the record.
    """
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _load_soak():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "wal_crash_soak", ROOT / "tools/qualification/wal_crash_soak.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _commit(soak, path: Path, first: int, count: int) -> None:
    from aegis.core.crypto_audit import CryptographicAuditLedger

    ledger = CryptographicAuditLedger(str(path), signing_key=soak.KEY)
    assert ledger._fault_state == "healthy"
    for index in range(first, first + count):
        ledger.commit_forensic(state_id=f"soak-{index:09d}", request_bytes=b"request")
    # No close(): it would write an MMR checkpoint, and this stands in for a killed writer.
    # Returning drops the last reference, which releases the single-writer lock.


def _tear(path: Path) -> None:
    """Leave what a SIGKILL inside a write leaves: a partial last record with no newline."""
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"state_id": "soak-torn", "timestamp": 12')


def test_a_torn_tail_is_healed_so_the_next_round_cannot_append_onto_it(
    tmp_path: Path, quiet_ledger_log: None
):
    """A kill inside a write leaves a partial last line. The next worker must not build on it."""
    from aegis.core.crypto_audit import CryptographicAuditLedger

    soak = _load_soak()
    wal = tmp_path / "wal.jsonl"
    _commit(soak, wal, 0, 3)
    _tear(wal)

    probe = CryptographicAuditLedger(str(wal), signing_key=soak.KEY)
    assert probe._fault_state == "wal_corrupt"
    del probe  # release the single-writer lock before the file is rewritten
    assert soak.heal_torn_tail(str(wal)) is True

    healed = CryptographicAuditLedger(str(wal), signing_key=soak.KEY)
    assert healed._fault_state == "healthy"
    assert [node.state_id for node in healed.chain] == [f"soak-{i:09d}" for i in range(3)]
    assert Path(str(wal) + ".torn.bak").is_file()


def test_damage_that_is_not_a_torn_tail_is_not_healed(tmp_path: Path):
    """A bad line in the middle is corruption; the harness must report it, not repair it."""
    soak = _load_soak()
    wal = tmp_path / "wal.jsonl"
    _commit(soak, wal, 0, 3)
    lines = wal.read_text(encoding="utf-8").splitlines(keepends=True)
    lines[1] = "not json\n"
    wal.write_text("".join(lines), encoding="utf-8")
    before = wal.read_bytes()

    assert soak.heal_torn_tail(str(wal)) is False
    assert wal.read_bytes() == before


def test_a_worker_refuses_to_commit_on_a_ledger_that_is_not_healthy(tmp_path: Path):
    """Acknowledging a commit that replay cannot reach is the failure the soak exists to catch."""
    soak = _load_soak()
    wal = tmp_path / "wal.jsonl"
    _commit(soak, wal, 0, 3)
    _tear(wal)
    before = wal.read_bytes()

    result = subprocess.run(  # noqa: S603  # nosec B603 - this interpreter and a fixed script, shell=False
        [sys.executable, str(ROOT / "tools/qualification/wal_crash_soak.py"), "--worker", str(wal), "3"],
        capture_output=True, text=True, cwd=ROOT, timeout=60,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )  # fmt: skip
    assert result.returncode == soak.WORKER_REFUSED
    assert result.stdout == ""
    assert wal.read_bytes() == before


def test_the_driver_heals_each_killed_round_and_loses_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, quiet_ledger_log: None
):
    """Every round ends in a torn tail; the driver repairs it, and the next round starts clean."""
    soak = _load_soak()

    def killed_round(wal: str, start: int, seconds: float) -> tuple[list[int], int]:
        _commit(soak, Path(wal), start, 5)  # asserts the ledger it was handed is healthy
        _tear(Path(wal))
        return list(range(start, start + 5)), start + 5

    monkeypatch.setattr(soak, "run_round", killed_round)
    report = tmp_path / "report.json"
    code = soak.main(["--rounds", "3", "--wal", str(tmp_path / "wal.jsonl"), "--json", str(report)])

    data = json.loads(report.read_text(encoding="utf-8"))
    assert code == 0
    assert data["rounds"] == 3
    assert data["torn_tails_repaired"] == 3
    assert data["acknowledged_total"] == 15
    assert data["acknowledged_lost"] == 0
    assert data["all_rounds_valid"] is True


def test_the_driver_fails_when_the_damage_is_not_a_torn_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, quiet_ledger_log: None
):
    """Repair is for a torn write only; anything else must end the soak as a failure."""
    soak = _load_soak()

    def corrupting_round(wal: str, start: int, seconds: float) -> tuple[list[int], int]:
        _commit(soak, Path(wal), start, 5)
        lines = Path(wal).read_text(encoding="utf-8").splitlines(keepends=True)
        lines[2] = "not json\n"
        Path(wal).write_text("".join(lines), encoding="utf-8")
        return list(range(start, start + 5)), start + 5

    monkeypatch.setattr(soak, "run_round", corrupting_round)
    code = soak.main(["--rounds", "3", "--wal", str(tmp_path / "wal.jsonl")])

    assert code == 1
