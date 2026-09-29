# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Write the empty validation log and the two ledgers the kill switch reads.

    python tools/validation/make_log.py --out docs/commercial/validation [--force]

The log has 60 rows: rows 1 to 30 are batch 1 (the segments below), rows 31 to 60
are reserved for batch 2. Every row starts with an id, a batch and a segment and
nothing else. **Organisation, contact and every date are the owner's to enter.**
The tool refuses to overwrite a file that already holds data unless ``--force``
is given, so a rerun can never erase recorded results.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

LOG_COLUMNS = [
    "id", "batch", "segment", "organisation", "role", "lead_source",
    "touch1_sent", "touch2_sent", "touch3_sent", "replied", "call_date",
    "cites_examiner_request", "interview_notes_ref", "pilot_proposal_sent",
    "pilot_price_offered_usd", "outcome", "founder_hours", "expenses_usd",
]  # fmt: skip
PILOT_COLUMNS = ["pilot_id", "customer", "start", "end", "status", "fee_usd"]
CONTRACT_COLUMNS = ["contract_id", "customer", "type", "acv_usd", "signed_date"]

# Batch 1 segments follow docs/commercial/SALES_KIT/OUTBOUND_SEQUENCES.md "Who to target".
BATCH_1: list[tuple[str, int]] = [
    ("fintech: LLM in credit, fraud or advice", 10),
    ("healthtech: LLM in triage, summarisation or coding", 8),
    ("insurance: LLM in claims", 7),
    ("recently had an AI decision challenged", 5),
]
BATCH_SIZE = 30
LOG_SIZE = 60


def log_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for segment, count in BATCH_1:
        rows += [{"batch": "1", "segment": segment}] * count
    assert len(rows) == BATCH_SIZE
    rows += [{"batch": "2", "segment": "reserved"}] * (LOG_SIZE - BATCH_SIZE)
    return [
        {**dict.fromkeys(LOG_COLUMNS, ""), **row, "id": f"V-{i:02d}"}
        for i, row in enumerate(rows, start=1)
    ]


def _write(path: Path, columns: list[str], rows: list[dict[str, str]], force: bool) -> str:
    if path.exists() and not force:
        with path.open(newline="", encoding="utf-8") as handle:
            filled = any(
                v
                for r in csv.DictReader(handle)
                for k, v in r.items()
                if k not in ("id", "batch", "segment")
            )
        if filled:
            return f"kept {path.name} (holds data; pass --force to overwrite)"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return f"wrote {path.name}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    print(_write(args.out / "VALIDATION_LOG.csv", LOG_COLUMNS, log_rows(), args.force))
    print(_write(args.out / "PILOTS.csv", PILOT_COLUMNS, [], args.force))
    print(_write(args.out / "CONTRACTS.csv", CONTRACT_COLUMNS, [], args.force))
    return 0


if __name__ == "__main__":
    sys.exit(main())
