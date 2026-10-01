# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""The cadence reports must read only recorded facts, stop first, and reproduce.

Covers the committed blank-state baselines, week arithmetic, the weekly counts, the
placement of triggers and late gates, the owner-only acknowledgement, the monthly
model comparison (identical, drifted, engine unavailable) and the rule that the tools
send nothing.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import re
import shutil
import sys
from datetime import date
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
CADENCE = ROOT / "docs" / "cadence"
BASELINE_DAY = date(2026, 9, 29)


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "cadence", ROOT / "tools" / "cadence" / "cadence.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["cadence"] = module
    spec.loader.exec_module(module)
    return module


cad = _load()
LOG_HEADER = "id,touch1_sent,replied,call_date,pilot_proposal_sent"


def _dirs(tmp_path: Path, *, log=None, plan=None, ack=None, ledger=None) -> tuple[Path, Path]:
    val, raise_dir = tmp_path / "val", tmp_path / "raise"
    val.mkdir()
    raise_dir.mkdir()
    (val / "PLAN.json").write_text(json.dumps(plan or {}), encoding="utf-8")
    (val / "PILOTS.csv").write_text(
        "pilot_id,customer,start,end,status,fee_usd\n", encoding="utf-8"
    )
    (val / "CONTRACTS.csv").write_text(
        "contract_id,customer,type,acv_usd,signed_date\n", encoding="utf-8"
    )
    with (val / "VALIDATION_LOG.csv").open("w", newline="", encoding="utf-8") as handle:
        handle.write(LOG_HEADER + "\n")
        csv.writer(handle).writerows(log or [])
    if ack is not None:
        (val / "KILL_ACK.json").write_text(json.dumps(ack), encoding="utf-8")
    (raise_dir / "EVIDENCE.json").write_text("{}", encoding="utf-8")
    body = "date,kind,amount_usd,note\n" + "".join(f"{r}\n" for r in (ledger or []))
    (raise_dir / "RAISE_LEDGER.csv").write_text(body, encoding="utf-8")
    return val, raise_dir


def test_committed_register_is_the_blank_state_rendering():
    text = cad.register(BASELINE_DAY, cad.VALIDATION, cad.RAISE)
    assert (CADENCE / "KILL_SWITCH_REGISTER.md").read_text("utf-8") == text
    assert not re.search(r"\| (TRIGGERED|LATE)", text)


def test_committed_weekly_baseline_reproduces():
    text = cad.weekly("2026-W40", BASELINE_DAY, cad.VALIDATION, cad.RAISE)
    assert (CADENCE / "weekly" / "WEEKLY_2026-W40.md").read_text("utf-8") == text


def test_iso_week_arithmetic():
    assert cad.iso_label(date(2026, 9, 29)) == "2026-W40"
    assert cad.iso_label(date(2027, 1, 3)) == "2026-W53"
    assert cad.week_bounds("2026-W40") == (date(2026, 9, 28), date(2026, 10, 4))
    with pytest.raises(ValueError):
        cad.week_bounds("2026-40")


def test_weekly_counts_only_dated_rows_inside_the_week(tmp_path: Path):
    log = [
        ["V-1", "2026-09-28", "", "", ""],
        ["V-2", "2026-10-04", "2026-10-05", "", ""],
        ["V-3", "2026-10-05", "", "", ""],
    ]
    val, raise_dir = _dirs(tmp_path, log=log)
    text = cad.weekly("2026-W40", date(2026, 10, 4), val, raise_dir)
    assert "| First touches sent | 2 | 3 |" in text
    assert "| Replies | 0 | 1 |" in text
    assert "27 first touches remain" in text


def test_a_trigger_is_stop_number_one_and_the_owner_answer_needs_a_date(tmp_path: Path):
    plan = {"plan_start_date": "2026-01-01"}
    val, raise_dir = _dirs(tmp_path, plan=plan)
    text = cad.weekly("2026-W40", date(2026, 9, 29), val, raise_dir)
    assert text.index("KC-4 Gate 2 by month 8 TRIGGERED") < text.index("Recorded this week")
    assert "Owner answer: none" in text
    (val / "KILL_ACK.json").write_text(json.dumps({"KC-4": {"answer": "SI"}}), encoding="utf-8")
    assert "| none |" in cad.register(date(2026, 9, 29), val, raise_dir)
    (val / "KILL_ACK.json").write_text(
        json.dumps({"KC-4": {"answer": "SI", "date": "2026-09-30"}}), encoding="utf-8"
    )
    assert "SI on 2026-09-30" in cad.register(date(2026, 9, 29), val, raise_dir)


def test_late_gate_and_budget_alerts_reach_the_register(tmp_path: Path):
    ledger = ["2026-02-01,tranche_received,300000,", "2026-08-01,spend,290000,"]
    val, raise_dir = _dirs(tmp_path, plan={"plan_start_date": "2026-01-01"}, ledger=ledger)
    text = cad.register(date(2026, 9, 29), val, raise_dir)
    assert re.search(r"\| BA-95 .*\| TRIGGERED \|", text)
    assert re.search(r"\| GATE-T2 .*\| LATE \|", text)
    assert "no tranche recorded" not in text


def _fake_engine(tmp_path: Path, *, same: bool) -> Path:
    script = tmp_path / "engine.py"
    src = cad.COMMITTED
    script.write_text(
        "import shutil, sys\nfrom pathlib import Path\nout = Path(sys.argv[sys.argv.index('--out') + 1])\n"
        f"src = Path({str(src)!r})\n"
        "for name in ('model_outputs.json', 'model_tables.md'):\n"
        "    shutil.copy(src / name, out / name)\n"
        + ("" if same else "(out / 'model_tables.md').write_text('changed', encoding='utf-8')\n"),
        encoding="utf-8",
    )
    return script


def test_monthly_reports_identical_drift_and_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    val, raise_dir = _dirs(tmp_path)
    monkeypatch.setattr(cad, "ENGINE", _fake_engine(tmp_path, same=True))
    text, code = cad.monthly(BASELINE_DAY, sys.executable, val, raise_dir)
    assert code == 0
    assert text.count("IDENTICAL") == 2
    monkeypatch.setattr(cad, "ENGINE", _fake_engine(tmp_path, same=False))
    text, code = cad.monthly(BASELINE_DAY, sys.executable, val, raise_dir)
    assert code == 3
    assert "DRIFT from the committed file" in text
    text, code = cad.monthly(BASELINE_DAY, str(tmp_path / "no-such-python"), val, raise_dir)
    assert code == 4
    assert "NOT_EXECUTED" in text


def test_monthly_compares_spend_with_the_model_and_names_what_it_did_not_measure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    val, raise_dir = _dirs(
        tmp_path,
        plan={"plan_start_date": "2026-10-01"},
        ledger=["2026-10-15,spend,30000,", "2026-11-03,spend,32000,"],
    )
    monkeypatch.setattr(cad, "ENGINE", _fake_engine(tmp_path, same=True))
    text, _ = cad.monthly(date(2026, 11, 30), sys.executable, val, raise_dir)
    assert re.search(r"\| 1 \| \$30,000.00 \| \$31,102.86 \| \$-1,102.86 \|", text)
    assert "not re-measured" in text


def test_monthly_compares_the_model_claims_count_with_the_live_count():
    if shutil.which("git") is None:
        pytest.skip("no git")
    text, _ = cad.monthly(BASELINE_DAY, str(ROOT / "no-such-python"), cad.VALIDATION, cad.RAISE)
    match = re.search(r"`claims_registered`: model (\d+), live (\d+): (current|STALE)", text)
    assert match
    expected = "current" if match[1] == match[2] else "STALE"
    assert match[3] == expected


def test_wind_down_path_is_marked_and_ordered():
    text = (CADENCE / "WIND_DOWN_PATH.md").read_text("utf-8")
    assert "[COUNSEL-REVIEW-REQUIRED]" in text
    numbered = re.findall(r"^\| (\d) \|", text, re.M)
    assert numbered == [str(n) for n in range(1, 9)]
    assert "$285,000" in text


def test_tools_send_nothing_and_never_write_the_owner_files():
    source = (ROOT / "tools" / "cadence" / "cadence.py").read_text("utf-8")
    assert not re.search(r"smtplib|urllib|requests|httpx|socket|sendmail", source)
    writes = [line for line in source.splitlines() if "write_text" in line]
    assert writes
    assert all("out_dir" in line or "args.out" in line for line in writes)
