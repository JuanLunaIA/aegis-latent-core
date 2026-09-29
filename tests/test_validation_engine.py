# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The validation engine must measure honestly and halt when the plan says to.

Covers the D10.3 kill criteria as executable triggers, the owner-only
acknowledgement, the pilot generator's refusals, and the rule that the committed
log holds no prospect, date or result.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from datetime import date
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "docs" / "commercial" / "validation"


def _load(name: str, rel: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ks = _load("kill_switch_mod", "tools/validation/kill_switch.py")
pg = _load("pilot_generator_mod", "tools/validation/pilot_generator.py")
ml = _load("make_log_mod", "tools/validation/make_log.py")


def _data(tmp_path: Path, *, log=None, pilots=None, contracts=None, plan=None) -> Path:
    def write(name: str, cols: list[str], rows: list[dict[str, str]] | None) -> None:
        with (tmp_path / name).open("w", newline="", encoding="utf-8") as h:
            w = csv.DictWriter(h, fieldnames=cols)
            w.writeheader()
            w.writerows(rows or [])

    write("VALIDATION_LOG.csv", ml.LOG_COLUMNS, log)
    write("PILOTS.csv", ml.PILOT_COLUMNS, pilots)
    write("CONTRACTS.csv", ml.CONTRACT_COLUMNS, contracts)
    (tmp_path / "PLAN.json").write_text(json.dumps(plan or {}), encoding="utf-8")
    return tmp_path


def _sub(base: Path, name: str, **kw) -> Path:
    (base / name).mkdir()
    return _data(base / name, **kw)


def _status(results, cid: str) -> str:
    return next(r.status for r in results if r.id == cid)


def _sends(n: int, day: str = "2026-10-01", calls: int = 0) -> list[dict[str, str]]:
    rows = [
        dict.fromkeys(ml.LOG_COLUMNS, "") | {"id": f"V-{i:02d}", "touch1_sent": day}
        for i in range(n)
    ]
    for row in rows[:calls]:
        row["call_date"] = "2026-10-10"
    return rows


def test_committed_log_has_sixty_rows_and_no_recorded_data():
    rows = list(csv.DictReader((DATA / "VALIDATION_LOG.csv").open(encoding="utf-8")))
    assert len(rows) == 60
    assert sum(r["batch"] == "1" for r in rows) == 30
    for row in rows:
        assert all(v == "" for k, v in row.items() if k not in {"id", "batch", "segment"})


def test_committed_data_reports_no_trigger():
    results = ks.evaluate(DATA, date(2026, 9, 29))
    assert {r.status for r in results} == {ks.PENDING}


def test_make_log_refuses_to_overwrite_recorded_data(tmp_path: Path):
    ml.main(["--out", str(tmp_path)])
    log = tmp_path / "VALIDATION_LOG.csv"
    text = log.read_text(encoding="utf-8").replace("V-01,1,", "V-01,1,", 1)
    rows = list(csv.DictReader(text.splitlines()))
    rows[0]["organisation"] = "Some Org"
    with log.open("w", newline="", encoding="utf-8") as h:
        w = csv.DictWriter(h, fieldnames=ml.LOG_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    ml.main(["--out", str(tmp_path)])
    assert "Some Org" in log.read_text(encoding="utf-8")
    ml.main(["--out", str(tmp_path), "--force"])
    assert "Some Org" not in log.read_text(encoding="utf-8")


def test_kc1_pending_until_thirty_messages_then_triggers_after_the_window(tmp_path: Path):
    few = _sub(tmp_path, "a", log=_sends(29))
    assert _status(ks.evaluate(few, date(2027, 1, 1)), "KC-1") == ks.PENDING
    thirty = _sub(tmp_path, "b", log=_sends(30, "2026-10-01"))
    assert _status(ks.evaluate(thirty, date(2026, 10, 20)), "KC-1") == ks.PENDING
    assert _status(ks.evaluate(thirty, date(2026, 11, 2)), "KC-1") == ks.TRIGGERED


def test_kc1_ok_with_two_calls_inside_the_window(tmp_path: Path):
    data = _data(tmp_path, log=_sends(30, "2026-10-01", calls=2))
    assert _status(ks.evaluate(data, date(2027, 6, 1)), "KC-1") == ks.OK


def test_kc2_needs_a_minimum_sample_and_triggers_above_half(tmp_path: Path):
    pil = lambda s: dict.fromkeys(ml.PILOT_COLUMNS, "") | {"status": s}  # noqa: E731
    two = _sub(tmp_path, "x", pilots=[pil("not_converted")] * 2)
    assert _status(ks.evaluate(two, date(2027, 1, 1)), "KC-2") == ks.PENDING
    bad = _sub(tmp_path, "y", pilots=[pil("converted"), pil("not_converted"), pil("churned")])
    assert _status(ks.evaluate(bad, date(2027, 1, 1)), "KC-2") == ks.TRIGGERED
    fine = _sub(tmp_path, "z", pilots=[pil("converted"), pil("converted"), pil("not_converted")])
    assert _status(ks.evaluate(fine, date(2027, 1, 1)), "KC-2") == ks.OK


def test_kc3_triggers_only_when_all_first_three_annual_contracts_are_below_the_floor(
    tmp_path: Path,
):
    def con(acv: int, day: str) -> dict[str, str]:
        return dict.fromkeys(ml.CONTRACT_COLUMNS, "") | {
            "type": "annual",
            "acv_usd": str(acv),
            "signed_date": day,
        }

    (tmp_path / "lo").mkdir()
    low = _data(
        tmp_path / "lo",
        contracts=[con(10000, "2027-01-01"), con(14000, "2027-02-01"), con(9000, "2027-03-01")],
    )
    assert _status(ks.evaluate(low, date(2027, 4, 1)), "KC-3") == ks.TRIGGERED
    (tmp_path / "hi").mkdir()
    mixed = _data(
        tmp_path / "hi",
        contracts=[con(10000, "2027-01-01"), con(30000, "2027-02-01"), con(9000, "2027-03-01")],
    )
    assert _status(ks.evaluate(mixed, date(2027, 4, 1)), "KC-3") == ks.OK


def test_month_deadlines_need_a_plan_start_and_fire_after_it(tmp_path: Path):
    plan = {"plan_start_date": "2027-01-31"}
    data = _data(tmp_path, plan=plan)
    assert ks.add_months(date(2027, 1, 31), 1) == date(2027, 2, 28)
    assert _status(ks.evaluate(data, date(2027, 9, 30)), "KC-4") == ks.PENDING
    assert _status(ks.evaluate(data, date(2027, 10, 1)), "KC-4") == ks.TRIGGERED
    assert _status(ks.evaluate(data, date(2027, 7, 1)), "KC-6") == ks.TRIGGERED
    met = _data(tmp_path, plan=plan | {"gate2_met": True, "senior_hire_start_date": "2027-05-01"})
    assert _status(ks.evaluate(met, date(2028, 1, 1)), "KC-4") == ks.OK
    assert _status(ks.evaluate(met, date(2028, 1, 1)), "KC-6") == ks.OK


def test_kc5_pentest_critical_unfixed_past_thirty_days_triggers(tmp_path: Path):
    plan = {"pentest_critical": {"found_date": "2027-06-01", "fixed_date": None}}
    data = _data(tmp_path, plan=plan)
    assert _status(ks.evaluate(data, date(2027, 6, 20)), "KC-5") == ks.PENDING
    assert _status(ks.evaluate(data, date(2027, 7, 5)), "KC-5") == ks.TRIGGERED


def test_a_trigger_halts_writes_a_memo_and_only_the_owners_si_releases_it(tmp_path: Path):
    _data(tmp_path, log=_sends(30, "2026-10-01"))
    today = ["--today", "2026-12-01"]
    assert ks.main(["--data", str(tmp_path), *today]) == 3
    assert (tmp_path / "REPLAN_MEMO_KC-1.md").exists()
    (tmp_path / "KILL_ACK.json").write_text(
        json.dumps({"KC-1": {"answer": "NO", "date": "2026-12-02"}})
    )
    assert ks.main(["--data", str(tmp_path), *today]) == 3
    (tmp_path / "KILL_ACK.json").write_text(
        json.dumps({"KC-1": {"answer": "SI", "date": "2026-12-02"}})
    )
    assert ks.main(["--data", str(tmp_path), *today]) == 0


def _facts(**over):
    base = {
        "customer": "Example Co", "sponsor": "Head of Compliance", "workload": "claims-triage assistant",
        "environments": "one non-production", "deployment_shape": "gateway", "duration_weeks": 6,
        "fee_usd": 5000, "start": "2027-02-01", "end": "2027-03-15",
    }  # fmt: skip
    return base | over


def test_pilot_generator_keeps_banner_marks_fee_and_leaves_signatures_blank():
    text = pg.render(_facts(), date(2026, 9, 29))
    assert "[COUNSEL-REVIEW-REQUIRED]" in text
    assert "5000 USD, `[HYPOTHESIS-UNVALIDATED]`" in text
    assert "`[signatory: owner action]`" in text
    assert "`[signatory: customer action]`" in text


@pytest.mark.parametrize(
    "bad",
    [
        {"workload": "claims triage and fraud review"},
        {"duration_weeks": 3},
        {"duration_weeks": 9, "end": "2027-04-05"},
        {"end": "2027-03-16"},
        {"fee_usd": -1},
        {"deployment_shape": "saas"},
        {"customer": ""},
    ],
)
def test_pilot_generator_refuses_facts_that_break_the_pilot_rules(bad):
    with pytest.raises(pg.FactsError):
        pg.render(_facts(**bad), date(2026, 9, 29))


def test_the_engine_sends_nothing():
    for rel in ("kill_switch.py", "pilot_generator.py", "make_log.py"):
        source = (ROOT / "tools" / "validation" / rel).read_text(encoding="utf-8")
        for banned in (
            "import smtplib",
            "import requests",
            "import httpx",
            "urllib.request",
            "import socket",
        ):
            assert banned not in source, f"{rel} imports {banned}"
