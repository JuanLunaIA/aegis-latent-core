# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""Draft the monthly investor update from what the owner recorded, and nothing else.

    python tools/raise/monthly_update.py --month YYYY-MM [--today YYYY-MM-DD] [--out FILE]

Every figure is read from ``VALIDATION_LOG.csv``, ``PILOTS.csv``, ``CONTRACTS.csv``,
``PLAN.json``, ``EVIDENCE.json``, ``RAISE_LEDGER.csv`` and ``docs/assurance/ASSURANCE_STATUS.json``;
an empty input is printed as zero or "not recorded", never estimated. Narrative sections are
left as ``[OWNER TO WRITE]``. The output is a draft: the agent does not send it.
The tool runs the tranche gates and the kill criteria, and puts any triggered criterion or
late gate at the top of the update, before the good news.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import sys
from datetime import date
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
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


def ledger_totals(rows: list[dict[str, str]]) -> tuple[float, float]:
    received = sum(float(r["amount_usd"]) for r in rows if r["kind"] == "tranche_received")
    spent = sum(float(r["amount_usd"]) for r in rows if r["kind"] == "spend")
    return received, spent


def build(month: str, today: date, data: Path, validation: Path) -> str:
    gate = _load("tranche_gate", HERE / "tranche_gate.py")
    kill = _load("kill_switch", ROOT / "tools" / "validation" / "kill_switch.py")
    terms = json.loads((HERE / "terms.json").read_text(encoding="utf-8"))
    tranches = gate.evaluate(data, validation, today)
    kills = kill.evaluate(validation, today)
    log = _rows(validation / "VALIDATION_LOG.csv")
    pilots = _rows(validation / "PILOTS.csv")
    contracts = _rows(validation / "CONTRACTS.csv")
    received, spent = ledger_totals(_rows(data / "RAISE_LEDGER.csv"))
    assurance = json.loads(
        (ROOT / "docs/assurance/ASSURANCE_STATUS.json").read_text(encoding="utf-8")
    )

    def count(col: str) -> int:
        return sum(1 for r in log if (r.get(col) or "").strip())

    out = [
        f"# Investor update, {month} (DRAFT, not sent)",
        "",
        f"Prepared {today.isoformat()} from recorded facts. Tags: V read back, M model, H hypothesis.",
        "",
    ]
    alerts = [t for t in tranches if t["status"] == gate.LATE]
    fired = [k for k in kills if k.status == kill.TRIGGERED]
    out += ["## 1. Bad news first", ""]
    if not alerts and not fired:
        out += ["No gate is late and no kill criterion is triggered.", ""]
    for t in alerts:
        out.append(
            f"- **{t['tranche']} gate is LATE** (deadline {t['deadline']}): open conditions "
            + ", ".join(c["id"] for c in t["conditions"] if c["status"] != gate.MET)
            + "."
        )
    for k in fired:
        out.append(f"- **{k.id} {k.name} TRIGGERED:** {k.detail}. Plan consequence: {k.action}")
    out += ["", "## 2. Gates", ""]
    for t in tranches:
        out.append(
            f"- {t['tranche']} (${t['amount_usd']:,}, cap ${t['post_money_cap_usd']:,}): **{t['status']}**, deadline {t['deadline'] or 'not set'}"
        )
        out += [
            f"  - {c['id']} {c['status']}: {c['text']} ({c['detail']})" for c in t["conditions"]
        ]
    out += [
        "",
        "## 3. Validation funnel (V, from the log)",
        "",
        "| Measure | Count |",
        "|---|---|",
        f"| First touches sent | {count('touch1_sent')} |",
        f"| Replies | {count('replied')} |",
        f"| Calls held | {count('call_date')} |",
        f"| Pilot proposals sent | {count('pilot_proposal_sent')} |",
        f"| Pilots recorded | {len(pilots)} |",
        f"| Contracts recorded | {len(contracts)} |",
        "",
        "## 4. Kill criteria",
        "",
        "| ID | Name | Status | Detail |",
        "|---|---|---|---|",
    ]
    out += [f"| {k.id} | {k.name} | {k.status} | {k.detail} |" for k in kills]
    out += [
        "",
        "## 5. Cash against released capital (V, from RAISE_LEDGER.csv)",
        "",
        f"- Received: ${received:,.2f}",
        f"- Spent: ${spent:,.2f}",
        f"- Remaining: ${received - spent:,.2f}",
    ]
    if received > 0:
        share = spent / received
        out.append(f"- Share of released capital spent: {share:.1%}")
        for level, action in sorted(terms["budget_alerts"].items()):
            if share >= float(level):
                out.append(f"- **Alert at {float(level):.0%} reached:** {action}")
    else:
        out.append("- No tranche has been recorded as received; no share is computed.")
    out += [
        "",
        "## 6. Assurance (state as recorded, none complete unless evidenced)",
        "",
        "| Item | Register | State |",
        "|---|---|---|",
    ]
    out += [f"| {i['id']} | {i['register']} | {i['state']} |" for i in assurance["items"]]
    out += [
        "",
        "## 7. Narrative",
        "",
        "Asks of investors: `[OWNER TO WRITE]`",
        "",
        "What changed this month: `[OWNER TO WRITE]`",
        "",
        "What did not work: `[OWNER TO WRITE]`",
        "",
    ]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--month", required=True)
    parser.add_argument("--today", type=date.fromisoformat, default=date.today())
    parser.add_argument("--data", type=Path, default=ROOT / "docs" / "raise")
    parser.add_argument(
        "--validation", type=Path, default=ROOT / "docs" / "commercial" / "validation"
    )
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    text = build(args.month, args.today, args.data, args.validation)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
