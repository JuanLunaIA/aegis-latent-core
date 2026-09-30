# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Turn the owner's private contact sheet into a Brevo import file.

    python tools/validation/brevo_export.py contacts_private.csv --out brevo_import.csv

The contact sheet is the owner's own file and **stays outside the repository**: the
validation log holds no e-mail address on purpose, and contact data must never be
committed. The tool refuses to read or write a path inside the repository unless
``--allow-in-repo`` is given.

Input columns (header required, extra columns ignored):
``log_id, email, first_name, last_name, organisation, role, segment, lead_source,
consent_basis, consent_date, opted_out``.

A row is exported only when it has a valid address, a ``V-nn`` log id, a known
segment and lead source, a consent basis written in words and a consent date that
is a real past date. Anything else is refused and reported by row number and log id
(never by address). Rows marked ``opted_out`` are skipped, not refused. The first
occurrence of an address wins; a later duplicate is refused.

Exit 0: nothing refused. Exit 1: at least one row refused (the valid rows are still
written). Exit 2: a path or header problem, nothing written.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

INPUT_COLUMNS = (
    "log_id", "email", "first_name", "last_name", "organisation", "role",
    "segment", "lead_source", "consent_basis", "consent_date", "opted_out",
)  # fmt: skip
# Brevo attribute names, in the order the plan creates them.
BREVO_COLUMNS = (
    "EMAIL", "FIRSTNAME", "LASTNAME", "ORGANISATION", "ROLE", "SEGMENT",
    "LEAD_SOURCE", "LOG_ID", "CONSENT_BASIS", "CONSENT_DATE",
)  # fmt: skip
SEGMENTS = frozenset({"fintech", "healthtech", "insurance", "challenged"})
LEAD_SOURCES = frozenset({"oss", "partner", "event", "direct"})
LOG_ID = re.compile(r"^V-\d{2}$")
EMAIL = re.compile(r"^[^@\s,;<>()]+@[^@\s,;<>()]+\.[^@\s,;<>()]{2,}$")
TRUE_WORDS = frozenset({"1", "true", "yes", "y", "x", "si", "sí"})


@dataclass
class Result:
    exported: list[dict[str, str]] = field(default_factory=list)
    refused: list[tuple[int, str, str]] = field(default_factory=list)  # (row, log_id, reason)
    opted_out: int = 0


def _clean(row: dict[str, str | None]) -> dict[str, str]:
    return {key: (row.get(key) or "").strip() for key in INPUT_COLUMNS}


def _reason(row: dict[str, str], today: date, seen: set[str]) -> str | None:
    if not LOG_ID.match(row["log_id"]):
        return "log_id is not of the form V-nn"
    if not EMAIL.match(row["email"]):
        return "address missing or malformed"
    if row["email"].lower() in seen:
        return "duplicate address"
    if row["segment"] not in SEGMENTS:
        return f"segment is not one of {sorted(SEGMENTS)}"
    if row["lead_source"] not in LEAD_SOURCES:
        return f"lead_source is not one of {sorted(LEAD_SOURCES)}"
    if not row["consent_basis"]:
        return "no consent basis recorded"
    try:
        given = date.fromisoformat(row["consent_date"])
    except ValueError:
        return "consent_date is not an ISO date (YYYY-MM-DD)"
    if given > today:
        return "consent_date is in the future"
    return None


def convert(rows: list[dict[str, str | None]], today: date) -> Result:
    """Apply the export rules to already-parsed rows."""
    result = Result()
    seen: set[str] = set()
    for number, raw in enumerate(rows, start=2):  # row 1 is the header
        row = _clean(raw)
        if row["opted_out"].lower() in TRUE_WORDS:
            result.opted_out += 1
            continue
        reason = _reason(row, today, seen)
        if reason is not None:
            result.refused.append((number, row["log_id"], reason))
            continue
        seen.add(row["email"].lower())
        result.exported.append(
            {
                "EMAIL": row["email"],
                "FIRSTNAME": row["first_name"],
                "LASTNAME": row["last_name"],
                "ORGANISATION": row["organisation"],
                "ROLE": row["role"],
                "SEGMENT": row["segment"],
                "LEAD_SOURCE": row["lead_source"],
                "LOG_ID": row["log_id"],
                "CONSENT_BASIS": row["consent_basis"],
                "CONSENT_DATE": row["consent_date"],
            }
        )
    return result


def _inside_repo(path: Path) -> bool:
    return path.resolve().is_relative_to(ROOT)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("contacts", type=Path, help="the owner's private contact sheet (CSV)")
    parser.add_argument("--out", type=Path, required=True, help="Brevo import file to write")
    parser.add_argument(
        "--allow-in-repo",
        action="store_true",
        help="permit paths inside the repository (contact data must not be committed)",
    )
    args = parser.parse_args(argv)

    if not args.allow_in_repo and (_inside_repo(args.contacts) or _inside_repo(args.out)):
        print(
            "refused: contact data must not live inside the repository. "
            "Keep both files outside it, or pass --allow-in-repo for a throwaway test.",
            file=sys.stderr,
        )
        return 2
    if not args.contacts.is_file():
        print(f"refused: {args.contacts} is not a file", file=sys.stderr)
        return 2

    with args.contacts.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = [c for c in INPUT_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            print(f"refused: the sheet has no column(s) {missing}", file=sys.stderr)
            return 2
        rows: list[dict[str, str | None]] = list(reader)

    result = convert(rows, date.today())
    with args.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=BREVO_COLUMNS)
        writer.writeheader()
        writer.writerows(result.exported)

    for number, log_id, reason in result.refused:
        print(f"refused row {number} ({log_id or 'no log id'}): {reason}")
    print(
        f"exported {len(result.exported)}, refused {len(result.refused)}, "
        f"skipped as opted out {result.opted_out}"
    )
    return 1 if result.refused else 0


if __name__ == "__main__":
    raise SystemExit(main())
