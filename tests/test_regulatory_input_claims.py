# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Gate for the MiFID II / MAR rows (AUD-20 / REG-D24).

Before this row, two compliance modules existed with corrected docstrings and no
register presence at all: `docs/CLAIMS_MATRIX.md`, `docs/ROADMAP.md` and
`docs/institutional/UNSUPPORTED_CLAIMS.md` contained no MiFID or MAR entry, so a
reader could not tell whether the modules were wired, compliant, or dead code.

These tests pin the four things that make the rows honest rather than decorative:

* both claims are *present* in the matrix and in the unsupported-claims register;
* each boundary says **not wired** and names the reason it can never be read as
  compliance on its own (hash-only records; text classification over one request);
* the citations are the right instruments — MAR Art. 12(1)(a)(ii) for spoofing,
  MiFID II Art. 16(6)/25(1) with the five-year floor for retention;
* the modules are still *unwired*, measured by the repository's own reachability
  tool's input (the allowlist), so a future wiring change fails here instead of
  silently ageing the rows.

The forbidden-phrase side is enforced by `scripts/verify_claims.py` (control
register range coverage); this file asserts the range exists and names the
MiFID/MAR language a writer must not use.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MATRIX = REPO_ROOT / "docs/CLAIMS_MATRIX.md"
UC_REGISTER = REPO_ROOT / "docs/institutional/UNSUPPORTED_CLAIMS.md"
ALLOWLIST = REPO_ROOT / "scripts/import_reachability_allowlist.txt"

MODULES = ("aegis.core.market_abuse_detector", "aegis.core.mifid_record_keeper")

# AUD-23 / REG-D27 (AF-064): the sealed-segment module was named in no document
# under docs/ while mifid_record_keeper's docstring asserted 17a-4 was "already
# addressed" by it. Both halves are pinned here.
WORM_MODULE = "aegis.core.worm_ledger"
WORM_SOURCE = REPO_ROOT / "aegis/core/worm_ledger.py"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _claim_row(ident: str) -> str:
    for line in _text(MATRIX).splitlines():
        if line.startswith(f"| `{ident}` |"):
            return line
    raise AssertionError(f"{ident} is not in the claims matrix")


def test_both_modules_have_a_claim_row() -> None:
    for ident in ("CLM-103", "CLM-104"):
        row = _claim_row(ident)
        assert "IMPLEMENTED" in row, f"{ident} lost its state"
        assert "Not wired" in row, f"{ident} no longer states that it is unwired"


def test_claim_rows_cite_the_modules_and_their_tests() -> None:
    detector = _claim_row("CLM-103")
    keeper = _claim_row("CLM-104")
    assert "aegis/core/market_abuse_detector.py" in detector
    assert "tests/test_market_abuse_detector.py" in detector
    assert "aegis/core/mifid_record_keeper.py" in keeper
    assert "tests/test_mifid_record_keeper.py" in keeper
    for row in (detector, keeper):
        cited = re.findall(r"`([A-Za-z0-9_./-]+\.py)`", row)
        for path in cited:
            assert (REPO_ROOT / path).is_file(), f"{row[:24]} cites missing {path}"


def test_citations_name_the_right_instruments() -> None:
    detector = _claim_row("CLM-103")
    keeper = _claim_row("CLM-104")
    assert "MAR (Reg. (EU) No 596/2014) Art. 12(1)(a)(ii)" in detector
    assert "MiFID II Art. 12 is" in detector, "the Art. 12 correction must stay spelled out"
    assert "five-year" in keeper
    assert "seven" in keeper, (
        "the retention statement must keep the five-year floor and the "
        "competent-authority extension distinct"
    )


def test_unsupported_claims_register_carries_uc_056() -> None:
    register = _text(UC_REGISTER)
    match = re.search(r"^\| `UC-056` \|.*$", register, re.M)
    assert match, "UC-056 is missing from the unsupported-claims register"
    row = match.group(0)
    for module in MODULES:
        assert module.replace(".", "/") + ".py" in row
    assert "MAR Art. 12(1)(a)(ii)" in row


def test_control_register_covers_the_new_claims_and_names_the_language() -> None:
    """The range widened to CLM-105 in REG-D27; it must still start at CLM-103 and
    cover every row the section added, or a new row can escape the phrases."""
    matrix = _text(MATRIX)
    match = re.search(r"^\| `CLM-103`–`CLM-105` \|.*$", matrix, re.M)
    assert match, "no control-register range covers CLM-103..CLM-105"
    row = match.group(0)
    for phrase in (
        '"MiFID II compliant"',
        '"MAR compliant"',
        '"SMCR compliant"',
        '"WORM compliant"',
        '"17a-4 compliant"',
    ):
        assert phrase in row, f"the register must forbid {phrase}"
    assert row.count("|") >= 5, "the range row must carry review date and owner"


def test_the_modules_are_still_unwired_by_the_repository_tool() -> None:
    allowlist = _text(ALLOWLIST)
    for module in MODULES:
        assert module in allowlist, (
            f"{module} left the reachability allowlist — it now has an import edge "
            "from a documented entrypoint, so CLM-103/CLM-104's 'Not wired' "
            "boundary and AUD-36 are both wrong until they are rewritten"
        )
    assert "worklist, not a verdict" in allowlist, (
        "the allowlist header must keep disclosing that it is not a classification"
    )
    for module in MODULES:
        importlib.import_module(module)


def test_no_document_asserts_the_modules_satisfy_an_obligation() -> None:
    """A cheap tripwire for the wording the register forbids."""
    forbidden = (
        r"MiFID II compliant",
        r"MAR compliant",
        r"market-abuse monitoring in place",
        r"satisfies Article 16",
        r"WORM compliant",
        r"17a-4 compliant",
        r"satisfies Rule 17a-4",
        r"immutable storage",
    )
    for path in (MATRIX, UC_REGISTER):
        body = _text(path)
        # Table rows are exempt: the control register quotes each phrase in order to
        # forbid it, and a claim row may quote it to name the statement that would
        # falsify the row. Prose is where a claim would be made, so prose is what
        # this checks.
        prose = re.sub(r"^\|.*$", "", body, flags=re.M)
        for pattern in forbidden:
            assert not re.search(pattern, prose, re.I), (
                f"{path.name} asserts {pattern!r} in prose outside the table rows"
            )


def test_worm_ledger_has_a_claim_row_with_its_own_boundary() -> None:
    """AF-064: the module was named in no document under docs/ at all, so a
    reader could not tell whether it was wired, compliant or dead code."""
    row = _claim_row("CLM-105")
    assert "IMPLEMENTED" in row, "CLM-105 lost its state"
    assert "Not wired" in row, "CLM-105 lost its unwired boundary"
    assert WORM_MODULE.replace(".", "/") + ".py" in row, "CLM-105 does not name the module"
    assert "17a-4" in row.lower(), "CLM-105 lost the 17a-4 cross-reference"
    # The module's own boundaries, which the row must not contradict.
    source = _text(WORM_SOURCE)
    assert "do not resist a privileged actor" in source
    assert (
        "do not\nestablish regulatory WORM media" in source
        or "do not establish regulatory WORM media" in source
    )


def test_nothing_claims_17a4_is_already_addressed_by_the_worm_module() -> None:
    """The claim AF-064 named, pinned where it was made."""
    body = _text(REPO_ROOT / "aegis/core/mifid_record_keeper.py")
    assert "already addressed by" not in body, (
        "mifid_record_keeper again asserts that Rule 17a-4 is already addressed by "
        "worm_ledger; nothing in this repository discharges that obligation"
    )
    assert "does not establish" in body
    assert WORM_MODULE in body or "worm_ledger" in body


def test_worm_module_is_still_unwired_by_the_repository_tool() -> None:
    allowlist = _text(ALLOWLIST)
    assert WORM_MODULE in allowlist, (
        "worm_ledger left the reachability allowlist — it now has an import edge from a "
        "documented entrypoint, so CLM-105's 'Not wired' boundary is wrong until rewritten"
    )
    importlib.import_module(WORM_MODULE)
