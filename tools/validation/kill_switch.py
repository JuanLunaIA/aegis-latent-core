# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""Evaluate the D10.3 model-kill criteria against the recorded facts.

    python tools/validation/kill_switch.py --data docs/commercial/validation [--today YYYY-MM-DD]

Inputs, all in the data directory and all written by the owner: ``VALIDATION_LOG.csv``,
``PILOTS.csv``, ``CONTRACTS.csv``, ``PLAN.json`` and, only after a trigger fires,
``KILL_ACK.json``. The tool reads them and never writes the inputs.

Each criterion is ``PENDING`` (not enough time or data), ``OK`` or ``TRIGGERED``.
A triggered criterion halts the plan: the tool writes ``REPLAN_MEMO_<id>.md`` next to
the inputs and exits 3. Work continues only when the owner records the answer
``"SI"`` for that criterion in ``KILL_ACK.json``. An agent must not create that
file; it holds the owner's decision.

Exit codes: 0 no unacknowledged trigger, 3 a trigger awaits the owner.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CRITERIA_FILE = HERE / "kill_criteria.json"
PENDING, OK, TRIGGERED = "PENDING", "OK", "TRIGGERED"


@dataclass(frozen=True)
class Result:
    id: str
    name: str
    status: str
    detail: str
    action: str


def _date(value: str | None) -> date | None:
    return date.fromisoformat(value) if value and value.strip() else None


def add_months(start: date, months: int) -> date:
    """Calendar-month addition, clamping the day to the end of a shorter month."""
    index = start.month - 1 + months
    year, month = start.year + index // 12, index % 12 + 1
    for day in (start.day, 30, 29, 28):
        try:
            return date(year, month, day)
        except ValueError:
            continue
    raise AssertionError("unreachable")


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def kc1(rows: list[dict[str, str]], params: dict[str, Any], today: date) -> tuple[str, str]:
    sends = sorted(d for d in (_date(r.get("touch1_sent")) for r in rows) if d)
    need = int(params["messages"])
    if len(sends) < need:
        return PENDING, f"{len(sends)} of {need} first touches sent"
    window = timedelta(days=int(params["window_days"]))
    reference = sends[need - 1]
    calls = [
        d
        for d in (_date(r.get("call_date")) for r in rows)
        if d and reference <= d <= reference + window
    ]
    minimum = int(params["min_calls"])
    if len(calls) >= minimum:
        return OK, f"{len(calls)} calls within {window.days} days of send #{need} ({reference})"
    if today > reference + window:
        return TRIGGERED, f"{len(calls)} calls, need {minimum}, window ended {reference + window}"
    return PENDING, f"{len(calls)} calls so far; window ends {reference + window}"


def kc2(pilots: list[dict[str, str]], params: dict[str, Any]) -> tuple[str, str]:
    concluded = [p for p in pilots if p.get("status") in {"converted", "not_converted", "churned"}]
    need = int(params["min_concluded_pilots"])
    if len(concluded) < need:
        return PENDING, f"{len(concluded)} of {need} concluded pilots"
    lost = sum(1 for p in concluded if p["status"] != "converted")
    rate = lost / len(concluded)
    text = f"{lost} of {len(concluded)} concluded pilots did not convert or churned ({rate:.0%})"
    return (TRIGGERED if rate > float(params["max_churn"]) else OK), text


def kc3(contracts: list[dict[str, str]], params: dict[str, Any]) -> tuple[str, str]:
    annual = sorted(
        (c for c in contracts if c.get("type") == "annual" and _date(c.get("signed_date"))),
        key=lambda c: str(c["signed_date"]),
    )
    need = int(params["contracts"])
    if len(annual) < need:
        return PENDING, f"{len(annual)} of {need} annual contracts signed"
    first = [float(c["acv_usd"]) for c in annual[:need]]
    floor = float(params["acv_usd_below"])
    text = f"first {need} annual ACVs: {first}"
    return (TRIGGERED if all(v < floor for v in first) else OK), text


def kc4(plan: dict[str, Any], params: dict[str, Any], today: date) -> tuple[str, str]:
    start = _date(plan.get("plan_start_date"))
    if start is None:
        return PENDING, "plan_start_date is not set"
    if plan.get("gate2_met") is True:
        return OK, "Gate 2 met"
    deadline = add_months(start, int(params["month"]))
    if today > deadline:
        return TRIGGERED, f"Gate 2 not met by {deadline}"
    return PENDING, f"Gate 2 due {deadline}"


def kc5(plan: dict[str, Any], params: dict[str, Any], today: date) -> tuple[str, str]:
    found = _date((plan.get("pentest_critical") or {}).get("found_date"))
    if found is None:
        return PENDING, "no pen-test critical recorded"
    fixed = _date((plan.get("pentest_critical") or {}).get("fixed_date"))
    limit = timedelta(days=int(params["fix_within_days"]))
    if fixed is not None:
        late = fixed - found > limit
        return (TRIGGERED if late else OK), f"found {found}, fixed {fixed}"
    if today - found > limit:
        return TRIGGERED, f"found {found}, unfixed after {limit.days} days"
    return PENDING, f"found {found}, fix due {found + limit}"


def kc6(plan: dict[str, Any], params: dict[str, Any], today: date) -> tuple[str, str]:
    start = _date(plan.get("plan_start_date"))
    if start is None:
        return PENDING, "plan_start_date is not set"
    if _date(plan.get("senior_hire_start_date")):
        return OK, f"hire started {plan['senior_hire_start_date']}"
    deadline = add_months(start, int(params["month"]))
    if today > deadline:
        return TRIGGERED, f"no senior hire started by {deadline}"
    return PENDING, f"hire due {deadline}"


def evaluate(data_dir: Path, today: date) -> list[Result]:
    criteria = {
        c["id"]: c for c in json.loads(CRITERIA_FILE.read_text(encoding="utf-8"))["criteria"]
    }
    log = _rows(data_dir / "VALIDATION_LOG.csv")
    pilots = _rows(data_dir / "PILOTS.csv")
    contracts = _rows(data_dir / "CONTRACTS.csv")
    plan_path = data_dir / "PLAN.json"
    plan: dict[str, Any] = (
        json.loads(plan_path.read_text(encoding="utf-8")) if plan_path.exists() else {}
    )
    outcomes = {
        "KC-1": kc1(log, criteria["KC-1"]["params"], today),
        "KC-2": kc2(pilots, criteria["KC-2"]["params"]),
        "KC-3": kc3(contracts, criteria["KC-3"]["params"]),
        "KC-4": kc4(plan, criteria["KC-4"]["params"], today),
        "KC-5": kc5(plan, criteria["KC-5"]["params"], today),
        "KC-6": kc6(plan, criteria["KC-6"]["params"], today),
    }
    return [
        Result(cid, criteria[cid]["name"], status, detail, criteria[cid]["action"])
        for cid, (status, detail) in outcomes.items()
    ]


def acknowledged(data_dir: Path, criterion: str) -> bool:
    path = data_dir / "KILL_ACK.json"
    if not path.exists():
        return False
    entry = json.loads(path.read_text(encoding="utf-8")).get(criterion, {})
    return bool(entry.get("answer") == "SI" and entry.get("date"))


def write_memo(data_dir: Path, result: Result, today: date) -> Path:
    path = data_dir / f"REPLAN_MEMO_{result.id}.md"
    if not path.exists():
        path.write_text(
            f"# Re-plan memo: {result.id} {result.name}\n\n"
            f"**Triggered on:** {today.isoformat()}\n"
            f"**Fact:** {result.detail}\n"
            f"**Consequence recorded in the plan (D10.3):** {result.action}\n\n"
            "The plan is halted. Nothing that depends on this criterion continues until the\n"
            f'owner records `"SI"` for {result.id} in `KILL_ACK.json`, with a date.\n\n'
            "## Options to weigh\n\n`[owner and advisers to complete]`\n",
            encoding="utf-8",
        )
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--today", type=date.fromisoformat, default=None)
    parser.add_argument("--no-memo", action="store_true", help="do not write memo files")
    args = parser.parse_args(argv)
    today = args.today or date.today()
    results = evaluate(args.data, today)
    halted = 0
    for r in results:
        note = ""
        if r.status == TRIGGERED:
            if acknowledged(args.data, r.id):
                note = "  [owner answered SI]"
            else:
                halted += 1
                note = "  [HALT: awaiting owner]"
                if not args.no_memo:
                    write_memo(args.data, r, today)
        print(f"{r.id} {r.status:<9} {r.name}: {r.detail}{note}")
    print(f"kill_switch: {'HALT' if halted else 'no unacknowledged trigger'} ({today.isoformat()})")
    return 3 if halted else 0


if __name__ == "__main__":
    sys.exit(main())
