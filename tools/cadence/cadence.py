# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Operating cadence: the weekly report, the monthly recompute and the kill-switch register.

    python tools/cadence/cadence.py weekly   [--week YYYY-Www] [--today D] [--out-dir DIR]
    python tools/cadence/cadence.py monthly  [--engine-python PY] [--today D]
    python tools/cadence/cadence.py register [--today D] [--out FILE]

Everything is read from files the owner wrote (``VALIDATION_LOG.csv``, ``PILOTS.csv``,
``CONTRACTS.csv``, ``PLAN.json``, ``KILL_ACK.json``, ``EVIDENCE.json``, ``RAISE_LEDGER.csv``) and from
``docs/assurance/ASSURANCE_STATUS.json``. Nothing is estimated and nothing is sent: an empty input
prints as zero or "not recorded". The tools never write ``KILL_ACK.json``; that file holds the
owner's decision. ``monthly`` exits 3 when the committed model outputs no longer reproduce and 4 when the engine
could not run.
"""

from __future__ import annotations

import argparse
import csv
import filecmp
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VALIDATION = ROOT / "docs" / "commercial" / "validation"
RAISE = ROOT / "docs" / "raise"
ENGINE = ROOT / "investor_packs" / "aegis_investor_pack_en" / "engine" / "aegis_financial_engine.py"
COMMITTED = ROOT / "investor_packs" / "aegis_investor_pack_en" / "data"


def _load(name: str, rel: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def iso_label(day: date) -> str:
    year, week, _ = day.isocalendar()
    return f"{year}-W{week:02d}"


def week_bounds(label: str) -> tuple[date, date]:
    match = re.fullmatch(r"(\d{4})-W(\d{2})", label)
    if not match:
        raise ValueError("week must look like 2026-W40")
    monday = date.fromisocalendar(int(match[1]), int(match[2]), 1)
    return monday, monday + timedelta(days=6)


def _in_week(value: str | None, start: date, end: date) -> bool:
    try:
        return bool(value) and start <= date.fromisoformat(str(value)) <= end
    except ValueError:
        return False


def _context(today: date, validation: Path, raise_dir: Path) -> dict[str, Any]:
    kill = _load("kill_switch", "tools/validation/kill_switch.py")
    gate = _load("tranche_gate", "tools/raise/tranche_gate.py")
    return {
        "kill": kill,
        "gate": gate,
        "results": kill.evaluate(validation, today),
        "tranches": gate.evaluate(raise_dir, validation, today),
        "plan": _json(validation / "PLAN.json"),
        "log": _rows(validation / "VALIDATION_LOG.csv"),
        "pilots": _rows(validation / "PILOTS.csv"),
        "contracts": _rows(validation / "CONTRACTS.csv"),
        "ledger": _rows(raise_dir / "RAISE_LEDGER.csv"),
        "assurance": _json(ROOT / "docs" / "assurance" / "ASSURANCE_STATUS.json"),
    }


def _ack(validation: Path, criterion: str) -> str:
    entry = _json(validation / "KILL_ACK.json").get(criterion) or {}
    return f"SI on {entry['date']}" if entry.get("answer") == "SI" and entry.get("date") else "none"


def weekly(label: str, today: date, validation: Path, raise_dir: Path) -> str:
    start, end = week_bounds(label)
    c = _context(today, validation, raise_dir)
    kill, gate = c["kill"], c["gate"]
    log = c["log"]

    def week_count(col: str) -> int:
        return sum(1 for r in log if _in_week(r.get(col), start, end))

    fired = [r for r in c["results"] if r.status == kill.TRIGGERED]
    late = [t for t in c["tranches"] if t["status"] == gate.LATE]
    out = [
        f"# WEEKLY {label} (DRAFT, generated {today.isoformat()})",
        "",
        f"Week {start.isoformat()} to {end.isoformat()}. Built only from recorded facts; nothing estimated, nothing sent.",
        "",
        "## 1. Stops first",
        "",
    ]
    if not fired and not late:
        out += ["No kill criterion is triggered and no gate is late.", ""]
    for r in fired:
        out.append(
            f"- **{r.id} {r.name} TRIGGERED**: {r.detail}. Owner answer: {_ack(validation, r.id)}. Consequence: {r.action}"
        )
    for t in late:
        out.append(f"- **{t['tranche']} gate LATE** (deadline {t['deadline']}).")
    out += ["", "## 2. Recorded this week", "", "| Measure | This week | Total |", "|---|---|---|"]
    for name, col in (
        ("First touches sent", "touch1_sent"),
        ("Replies", "replied"),
        ("Calls held", "call_date"),
        ("Pilot proposals sent", "pilot_proposal_sent"),
    ):
        out.append(
            f"| {name} | {week_count(col)} | {sum(1 for r in log if (r.get(col) or '').strip())} |"
        )
    out += [
        f"| Pilots recorded | n/a | {len(c['pilots'])} |",
        f"| Contracts recorded | n/a | {len(c['contracts'])} |",
        "",
        "## 3. Deadlines in the next 30 days",
        "",
    ]
    horizon, upcoming = today + timedelta(days=30), []
    for t in c["tranches"]:
        if (
            t["deadline"]
            and t["status"] != gate.MET
            and today <= date.fromisoformat(t["deadline"]) <= horizon
        ):
            upcoming.append(f"- {t['tranche']} gate due {t['deadline']}")
    start_plan = c["plan"].get("plan_start_date")
    if start_plan:
        from_plan = date.fromisoformat(start_plan)
        for cid, month in (("KC-4", 8), ("KC-6", 5)):
            due = kill.add_months(from_plan, month)
            if today <= due <= horizon:
                upcoming.append(f"- {cid} due {due.isoformat()}")
    out += upcoming or ["None."]
    out += ["", "## 4. Owner actions this week (derived from the state above)", ""]
    actions = []
    if not start_plan:
        actions.append(
            "Set `plan_start_date` in `PLAN.json`; KC-4, KC-6 and the gate deadlines cannot run without it."
        )
    sent = sum(1 for r in log if (r.get("touch1_sent") or "").strip())
    if sent < 30:
        actions.append(
            f"{30 - sent} first touches remain before KC-1 can be evaluated (30 needed)."
        )
    if not c["pilots"]:
        actions.append("No pilot is recorded; T2-a and KC-2 stay open.")
    for item in c["assurance"].get("items", []):
        if item["state"] in {"NOT_STARTED", "DRAFTED"}:
            actions.append(f"Assurance `{item['id']}` ({item['register']}) is {item['state']}.")
    out += [f"- {a}" for a in actions] or ["None derived."]
    out += ["", "## 5. Owner note", "", "What blocked this week: `[OWNER TO WRITE]`", ""]
    return "\n".join(out)


def register(today: date, validation: Path, raise_dir: Path) -> str:
    c = _context(today, validation, raise_dir)
    kill = c["kill"]
    terms = json.loads((ROOT / "tools" / "raise" / "terms.json").read_text(encoding="utf-8"))
    criteria = json.loads(kill.CRITERIA_FILE.read_text(encoding="utf-8"))["criteria"]
    out = [
        "# Kill-Switch Register",
        "",
        'Generated by `tools/cadence/cadence.py register`. A TRIGGERED row halts the plan until the owner records `"SI"` '
        "with a date in `KILL_ACK.json`. The agent never writes that file.",
        "",
        "| ID | Source | Condition | Status | Owner answer | Consequence |",
        "|---|---|---|---|---|---|",
    ]
    by_id = {r.id: r for r in c["results"]}
    for crit in criteria:
        r = by_id[crit["id"]]
        params = ", ".join(f"{k}={v}" for k, v in crit["params"].items())
        out.append(
            f"| {crit['id']} | `kill_criteria.json` | {crit['name']} ({params}) | {r.status}: {r.detail} | {_ack(validation, r.id)} | {crit['action']} |"
        )
    received = sum(float(r["amount_usd"]) for r in c["ledger"] if r["kind"] == "tranche_received")
    spent = sum(float(r["amount_usd"]) for r in c["ledger"] if r["kind"] == "spend")
    share = spent / received if received else 0.0
    for level, action in sorted(terms["budget_alerts"].items()):
        state = (
            "no tranche recorded"
            if not received
            else ("TRIGGERED" if share >= float(level) else "OK")
        )
        out.append(
            f"| BA-{int(float(level) * 100)} | `terms.json` | {float(level):.0%} of released capital spent | {state} | n/a | {action} |"
        )
    for t in c["tranches"]:
        if t["deadline"] or t["tranche"] != "T1":
            state = (
                t["status"] if t["deadline"] else "OPEN (no deadline until plan_start_date is set)"
            )
            out.append(
                f"| GATE-{t['tranche']} | `terms.json` | gate met by month {next(x['deadline_month'] for x in terms['tranches'] if x['id'] == t['tranche'])} | {state} | n/a | Tranche does not release; see DOWNGRADE_MEMO_DRAFT.md |"
            )
    out += [
        "",
        "Rows are recomputed on every run; a row's status is a reading of recorded facts, not a judgement.",
        "",
    ]
    return "\n".join(out)


def monthly(today: date, engine_python: str, validation: Path, raise_dir: Path) -> tuple[str, int]:
    out = [
        f"# Monthly recompute ({today.isoformat()})",
        "",
        "## 1. Model reproducibility (seed 42)",
        "",
    ]
    code = 0
    with tempfile.TemporaryDirectory() as tmp:
        failure = ""
        try:
            done = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
                [engine_python, str(ENGINE), "--out", tmp],
                capture_output=True,
                text=True,
                check=False,
                timeout=600,
            )
            if done.returncode != 0:
                tail = done.stderr.strip().splitlines()[-1:]
                failure = f"NOT_EXECUTED: engine exited {done.returncode}: {tail}"
        except (OSError, subprocess.TimeoutExpired) as exc:
            failure = f"NOT_EXECUTED: {exc}"
        if failure:
            out.append(failure)
            code = 4
        else:
            for name in ("model_outputs.json", "model_tables.md"):
                same = filecmp.cmp(Path(tmp) / name, COMMITTED / name, shallow=False)
                out.append(
                    f"- `{name}`: {'IDENTICAL to the committed file' if same else 'DRIFT from the committed file'}"
                )
                code = code or (0 if same else 3)
    inputs = _json(COMMITTED / "model_outputs.json").get("inputs", {})
    census = {"VERIFIED": 0, "MODEL": 0, "HYPOTHESIS": 0}
    for entry in inputs.values():
        tag = str(entry.get("tag", "")).split()[0].upper()
        if tag in census:
            census[tag] += 1
    out += [
        "",
        f"Input census: V {census['VERIFIED']} / M {census['MODEL']} / H {census['HYPOTHESIS']} ({len(inputs)} inputs).",
        "",
        "## 2. Verified inputs that may have gone stale",
        "",
    ]
    claims = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [sys.executable, str(ROOT / "scripts" / "verify_claims.py")],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    live = re.search(r"\((\d+) claims", claims.stdout)
    recorded = inputs.get("claims_registered", {}).get("value")
    if live and recorded is not None:
        verdict = "current" if int(live[1]) == int(recorded) else "STALE"
        out.append(f"- `claims_registered`: model {recorded}, live {live[1]}: {verdict}")
    else:
        out.append("- `claims_registered`: NOT_EXECUTED (verify_claims did not report a count)")
    out.append(
        "- `tests_passed`, benchmarks and registry prices: not re-measured by this tool; re-run the source procedure before quoting."
    )
    out += ["", "## 3. Actual spend against the model (M)", ""]
    start = _json(validation / "PLAN.json").get("plan_start_date")
    opex = _json(COMMITTED / "model_outputs.json").get("burn_runway", {}).get("opex_monthly", [])
    spend = [r for r in _rows(raise_dir / "RAISE_LEDGER.csv") if r["kind"] == "spend"]
    if not start or not spend:
        out.append("No plan start or no recorded spend: no comparison is made.")
    else:
        first = date.fromisoformat(start)
        per_month: dict[int, float] = {}
        for r in spend:
            d = date.fromisoformat(r["date"])
            idx = (d.year - first.year) * 12 + d.month - first.month
            per_month[idx] = per_month.get(idx, 0.0) + float(r["amount_usd"])
        out += ["| Plan month | Actual | Model | Difference |", "|---|---|---|---|"]
        for idx in sorted(per_month):
            model = opex[idx] if 0 <= idx < len(opex) else None
            out.append(
                f"| {idx + 1} | ${per_month[idx]:,.2f} | "
                + (
                    f"${model:,.2f} | ${per_month[idx] - model:+,.2f} |"
                    if model is not None
                    else "outside model | n/a |"
                )
            )
    out.append("")
    return "\n".join(out), code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("weekly", "monthly", "register"):
        p = sub.add_parser(name)
        p.add_argument("--today", type=date.fromisoformat, default=date.today())
        p.add_argument("--validation", type=Path, default=VALIDATION)
        p.add_argument("--raise-dir", type=Path, default=RAISE)
        if name == "weekly":
            p.add_argument("--week")
            p.add_argument("--out-dir", type=Path)
        if name == "monthly":
            p.add_argument("--engine-python", default=sys.executable)
        if name == "register":
            p.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if args.cmd == "weekly":
        label = args.week or iso_label(args.today)
        text = weekly(label, args.today, args.validation, args.raise_dir)
        if args.out_dir:
            args.out_dir.mkdir(parents=True, exist_ok=True)
            (args.out_dir / f"WEEKLY_{label}.md").write_text(text, encoding="utf-8")
        else:
            print(text)
        return 0
    if args.cmd == "register":
        text = register(args.today, args.validation, args.raise_dir)
        if args.out:
            args.out.write_text(text, encoding="utf-8")
        else:
            print(text)
        return 0
    text, code = monthly(args.today, args.engine_python, args.validation, args.raise_dir)
    print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
