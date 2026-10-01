# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""Fill the paid-pilot agreement template from one JSON file of facts.

    python tools/validation/pilot_generator.py facts.json --out pilot_acme.md

The output is a **draft for counsel**: it keeps the template's counsel-review banner,
marks the fee ``[HYPOTHESIS-UNVALIDATED]``, and leaves every signature row as a
placeholder. The tool signs nothing and sends nothing. It refuses facts that break
the pilot's own rules: one workload, a fixed duration of 4 to 8 weeks, an end date
that matches that duration.

Required keys: customer, sponsor, workload, environments, deployment_shape
(``gateway`` or ``embedded``), duration_weeks, fee_usd, start, end (ISO dates).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "docs" / "legal" / "PILOT_AGREEMENT_TEMPLATE.md"
REQUIRED = (
    "customer", "sponsor", "workload", "environments", "deployment_shape",
    "duration_weeks", "fee_usd", "start", "end",
)  # fmt: skip


class FactsError(ValueError):
    """The facts cannot describe a valid pilot."""


def validate(facts: dict[str, Any]) -> None:
    missing = [k for k in REQUIRED if facts.get(k) in (None, "")]
    if missing:
        raise FactsError(f"missing: {', '.join(missing)}")
    if facts["deployment_shape"] not in {"gateway", "embedded"}:
        raise FactsError("deployment_shape must be 'gateway' or 'embedded'")
    workload = str(facts["workload"])
    if any(sep in workload for sep in (";", "\n", " and ", " + ")):
        raise FactsError("a pilot covers exactly one workload; list one")
    weeks = facts["duration_weeks"]
    if not isinstance(weeks, int) or not 4 <= weeks <= 8:
        raise FactsError("duration_weeks must be an integer from 4 to 8")
    fee = facts["fee_usd"]
    if isinstance(fee, bool) or not isinstance(fee, int | float) or fee < 0:
        raise FactsError("fee_usd must be a non-negative number")
    start, end = date.fromisoformat(str(facts["start"])), date.fromisoformat(str(facts["end"]))
    if (end - start).days != weeks * 7:
        raise FactsError(f"end must be exactly {weeks} weeks after start")


def render(facts: dict[str, Any], today: date) -> str:
    validate(facts)
    fills = {
        "| Customer |": f"| Customer | {facts['customer']} |",
        "| Sponsor |": f"| Sponsor | {facts['sponsor']}, who owns the record-keeping obligation |",
        "| Workload |": f"| Workload | **One** named workload: {facts['workload']} |",
        "| Environments |": f"| Environments | {facts['environments']} |",
        "| Deployment shape |": f"| Deployment shape | {facts['deployment_shape']} |",
        "| Duration |": f"| Duration | {facts['duration_weeks']} weeks, fixed. Extensions are a new agreement |",
        "| Fee |": f"| Fee | {facts['fee_usd']} USD, `[HYPOTHESIS-UNVALIDATED]`; payable `[before start / on milestones]` |",
        "| Dates |": f"| Dates | {facts['start']} to {facts['end']} |",
    }
    out: list[str] = []
    done: set[str] = set()
    for line in TEMPLATE.read_text(encoding="utf-8").splitlines():
        key = next((k for k in fills if line.startswith(k) and k not in done), None)
        if key:
            done.add(key)
            out.append(fills[key])
        else:
            out.append(line)
    if done != set(fills):
        raise FactsError(f"template no longer has rows: {sorted(set(fills) - done)}")
    note = (
        f"> Generated {today.isoformat()} by `tools/validation/pilot_generator.py` from the "
        "template. Counsel review is still required; nothing here is signed or sent.\n"
    )
    return note + "\n" + "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("facts", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        text = render(json.loads(args.facts.read_text(encoding="utf-8")), date.today())
    except (FactsError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    args.out.write_text(text, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
