"""``docs/MODULE_INVENTORY.md`` is generated — these tests keep it honest.

The registry row that asked for the inventory (``REG-D29`` / ``AUD-25``) is only
closed if the artifact cannot silently go stale or silently lie about itself, so
this file does three things:

1. regenerates into a temp copy and asserts byte-equality with the committed file
   (the currency check — the same shape as the governed-manifest test);
2. asserts the inventory classifies *every* file under the six source roots
   exactly once, using the same file walk the generator uses;
3. asserts the inventory's own self-description (status counts, navigation
   coverage, open-ticket table) matches what its rows say — a generated table
   that miscounts itself is worse than no table.

Run: ``pytest tests/test_module_inventory_current.py``.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "docs" / "MODULE_INVENTORY.md"
GENERATOR = ROOT / "scripts" / "generate_module_inventory.py"

sys.path.insert(0, str(ROOT / "scripts"))
import generate_module_inventory as generator  # noqa: E402


def _rows() -> list[list[str]]:
    """The file table's data rows, split on unescaped pipes."""
    rows = []
    for line in INVENTORY.read_text(encoding="utf-8").splitlines():
        if line.startswith("| `") and line.endswith("|"):
            cells = [cell.strip() for cell in re.split(r"(?<!\\)\|", line)[1:-1]]
            if len(cells) == 6:
                rows.append(cells)
    return rows


def test_the_committed_inventory_is_what_the_generator_produces() -> None:
    # S603: the interpreter and the script are both this repository's own paths.
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 0, (
        "docs/MODULE_INVENTORY.md is stale — run `python scripts/generate_module_inventory.py`\n"
        f"{result.stdout}{result.stderr}"
    )


def test_every_file_under_the_six_roots_is_classified_exactly_once() -> None:
    listed = [row[0].strip("`") for row in _rows()]
    expected: list[str] = []
    for root in generator.SOURCE_ROOTS:
        for path in sorted((ROOT / root).rglob("*")):
            if path.is_dir() or generator.SKIP_DIR_NAMES & set(path.parts):
                continue
            expected.append(str(path.relative_to(ROOT)))

    assert sorted(listed) == sorted(expected), (
        "the inventory does not cover the tree it claims to: "
        f"missing {sorted(set(expected) - set(listed))[:5]}, "
        f"extra {sorted(set(listed) - set(expected))[:5]}"
    )
    assert len(listed) == len(set(listed)), "a file is listed more than once"


def test_the_status_vocabulary_is_closed() -> None:
    allowed = {
        "reachable",
        "roadmap-omit",
        "allowlisted",
        "referenced",
        "unreferenced",
        "orphan",
        "n/a",
    }
    observed = {row[3] for row in _rows()}
    assert observed <= allowed, f"statuses outside the vocabulary: {sorted(observed - allowed)}"


def test_the_counts_it_reports_about_itself_match_its_rows() -> None:
    text = INVENTORY.read_text(encoding="utf-8")
    rows = _rows()

    reported = dict(
        re.findall(r"`([\w/-]+)` (\d+)", text.split("**Status counts:**")[1].split("\n")[0])
    )
    actual: dict[str, int] = {}
    for row in rows:
        actual[row[3]] = actual.get(row[3], 0) + 1
    assert {k: int(v) for k, v in reported.items()} == actual

    named = len(
        [row for row in rows if Path(row[0].strip("`")).name in generator._navigation_text()]
    )
    reported_named = int(re.search(r"\*\*Navigation coverage:\*\* (\d+) of (\d+)", text).group(1))  # type: ignore[union-attr]
    total = int(re.search(r"\*\*Navigation coverage:\*\* (\d+) of (\d+)", text).group(2))  # type: ignore[union-attr]
    assert (named, len(rows)) == (reported_named, total)


def test_the_open_ticket_table_matches_the_roadmap() -> None:
    text = INVENTORY.read_text(encoding="utf-8")
    section = text.split("## Open roadmap tickets")[1].split("## Files")[0]
    listed = set(re.findall(r"^\| `([A-Z]+-\d+)`", section, re.MULTILINE))
    from_roadmap = {name for name, _priority, _solution in generator._open_tickets()}
    assert listed == from_roadmap, (
        "the open-ticket table and docs/ROADMAP.md disagree about what is open: "
        f"inventory-only {sorted(listed - from_roadmap)}, roadmap-only {sorted(from_roadmap - listed)}"
    )
