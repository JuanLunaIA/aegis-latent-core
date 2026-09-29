# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Evaluate the tranche gates of the SAFE round against facts the owner recorded.

    python tools/raise/tranche_gate.py [--data docs/raise] [--validation docs/commercial/validation]
                                       [--today YYYY-MM-DD] [--json]

Inputs, all owner-written: ``EVIDENCE.json`` (a dated reference per gate document),
``PILOTS.csv`` and ``PLAN.json`` (``plan_start_date``). A condition is ``MET`` only when its
evidence entry carries both a date and a non-empty ``ref`` naming where the signed
document is kept; a paid pilot counts only when it also has a countersigned order in
``EVIDENCE.json`` under ``pilot_orders``. Anything else is ``OPEN``, and ``LATE`` once the
tranche deadline (calendar months after ``plan_start_date``) has passed. The tool never
writes an input and never releases money: it reports what the investor would check.

Exit codes: 0 no tranche is late, 3 a gate deadline has passed unmet.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TERMS = Path(__file__).resolve().parent / "terms.json"
MET, OPEN, LATE = "MET", "OPEN", "LATE"


def _add_months(start: date, months: int) -> date:
    index = start.month - 1 + months
    year, month = start.year + index // 12, index % 12 + 1
    for day in (start.day, 30, 29, 28):
        try:
            return date(year, month, day)
        except ValueError:
            continue
    raise AssertionError("unreachable")


def _json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _entry_ok(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    try:
        date.fromisoformat(str(entry.get("date", "")))
    except ValueError:
        return False
    return bool(str(entry.get("ref", "")).strip())


def paid_pilots(pilots: list[dict[str, str]], evidence: dict[str, Any], floor: float) -> int:
    orders = evidence.get("pilot_orders") or {}
    customers = set()
    for row in pilots:
        try:
            fee = float(row.get("fee_usd") or 0)
        except ValueError:
            continue
        if fee >= floor and row.get("start", "").strip() and _entry_ok(orders.get(row["pilot_id"])):
            customers.add(row.get("customer", "").strip().lower() or row["pilot_id"])
    return len(customers)


def evaluate(data: Path, validation: Path, today: date) -> list[dict[str, Any]]:
    terms = json.loads(TERMS.read_text(encoding="utf-8"))
    evidence = _json(data / "EVIDENCE.json")
    plan = _json(validation / "PLAN.json")
    pilots_path = validation / "PILOTS.csv"
    pilots: list[dict[str, str]] = []
    if pilots_path.exists():
        with pilots_path.open(newline="", encoding="utf-8") as handle:
            pilots = list(csv.DictReader(handle))
    start = plan.get("plan_start_date")
    out = []
    for tranche in terms["tranches"]:
        month = tranche["deadline_month"]
        deadline = _add_months(date.fromisoformat(start), month) if start and month else None
        rows = []
        for cond in tranche["conditions"]:
            if cond["kind"] == "paid_pilots":
                have = paid_pilots(pilots, evidence, float(terms["min_pilot_fee_usd"]))
                met, detail = (
                    have >= cond["min"],
                    f"{have} of {cond['min']} paid pilots with a countersigned order",
                )
            else:
                entry = evidence.get(cond["key"])
                met = _entry_ok(entry)
                detail = (
                    f"{entry['date']}: {entry['ref']}"
                    if met and isinstance(entry, dict)
                    else "no dated reference recorded"
                )
            rows.append(
                {
                    "id": cond["id"],
                    "text": cond["text"],
                    "status": MET if met else OPEN,
                    "detail": detail,
                }
            )
        all_met = all(r["status"] == MET for r in rows)
        late = deadline is not None and today > deadline and not all_met
        out.append(
            {
                "tranche": tranche["id"],
                "amount_usd": tranche["amount_usd"],
                "post_money_cap_usd": tranche["post_money_cap_usd"],
                "deadline": deadline.isoformat() if deadline else None,
                "status": MET if all_met else (LATE if late else OPEN),
                "conditions": rows,
            }
        )
    return out


def render(results: list[dict[str, Any]]) -> str:
    lines = []
    for t in results:
        lines.append(
            f"{t['tranche']} ${t['amount_usd']:,} cap ${t['post_money_cap_usd']:,}  {t['status']}  deadline {t['deadline'] or 'n/a'}"
        )
        lines += [
            f"  [{c['status']:4}] {c['id']} {c['text']}: {c['detail']}" for c in t["conditions"]
        ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", type=Path, default=ROOT / "docs" / "raise")
    parser.add_argument(
        "--validation", type=Path, default=ROOT / "docs" / "commercial" / "validation"
    )
    parser.add_argument("--today", type=date.fromisoformat, default=date.today())
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    results = evaluate(args.data, args.validation, args.today)
    print(json.dumps(results, indent=2) if args.json else render(results))
    return 3 if any(t["status"] == LATE for t in results) else 0


if __name__ == "__main__":
    sys.exit(main())
