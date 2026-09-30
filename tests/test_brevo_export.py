# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Only people with a recorded consent basis may reach a Brevo import file.

The Brevo plan (``docs/commercial/validation/BREVO_PLAN.md``) allows a list of people
who asked to be contacted and nothing else. The exporter is the mechanical gate: it
refuses a row with no consent basis or no real past date, skips anyone who opted
out, drops duplicates, never puts an address in its report, and will not touch a
path inside the repository, where contact data could be committed by accident.
"""

from __future__ import annotations

import csv
import importlib.util
import sys
from datetime import date
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
TODAY = date(2026, 9, 30)


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "brevo_export_mod", ROOT / "tools/validation/brevo_export.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["brevo_export_mod"] = module
    spec.loader.exec_module(module)
    return module


be = _load()


def _row(**overrides: str) -> dict[str, str | None]:
    row: dict[str, str | None] = {
        "log_id": "V-01",
        "email": "reader@example.org",
        "first_name": "Ana",
        "last_name": "Rey",
        "organisation": "Example Fintech",
        "role": "CISO",
        "segment": "fintech",
        "lead_source": "direct",
        "consent_basis": "asked for the one-pager by reply on 2026-09-28",
        "consent_date": "2026-09-28",
        "opted_out": "",
    }
    row.update(overrides)
    return row


def _sheet(path: Path, rows: list[dict[str, str | None]]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=be.INPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_a_complete_row_is_exported_under_brevo_attribute_names() -> None:
    result = be.convert([_row()], TODAY)

    assert result.refused == []
    assert result.exported == [
        {
            "EMAIL": "reader@example.org",
            "NOMBRE": "Ana",
            "APELLIDOS": "Rey",
            "ORGANISATION": "Example Fintech",
            "ROLE": "CISO",
            "SEGMENT": "fintech",
            "LEAD_SOURCE": "direct",
            "LOG_ID": "V-01",
            "CONSENT_BASIS": "asked for the one-pager by reply on 2026-09-28",
            "CONSENT_DATE": "2026-09-28",
        }
    ]
    assert tuple(result.exported[0]) == be.BREVO_COLUMNS


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"consent_basis": ""}, "no consent basis"),
        ({"consent_basis": "   "}, "no consent basis"),
        ({"consent_date": ""}, "not an ISO date"),
        ({"consent_date": "28/09/2026"}, "not an ISO date"),
        ({"consent_date": "2026-10-01"}, "in the future"),
        ({"email": ""}, "address missing or malformed"),
        ({"email": "not-an-address"}, "address missing or malformed"),
        ({"email": "a@b"}, "address missing or malformed"),
        ({"log_id": "row 3"}, "V-nn"),
        ({"segment": "crypto"}, "segment"),
        ({"lead_source": "purchased"}, "lead_source"),
    ],
)
def test_a_row_missing_what_consent_needs_is_refused_not_exported(
    overrides: dict[str, str], fragment: str
) -> None:
    result = be.convert([_row(**overrides)], TODAY)

    assert result.exported == []
    assert len(result.refused) == 1
    assert fragment in result.refused[0][2]


def test_one_bad_row_does_not_hold_back_the_good_ones() -> None:
    rows = [
        _row(log_id="V-01", email="one@example.org"),
        _row(log_id="V-02", email="two@example.org", consent_basis=""),
        _row(log_id="V-03", email="three@example.org"),
    ]

    result = be.convert(rows, TODAY)

    assert [r["LOG_ID"] for r in result.exported] == ["V-01", "V-03"]
    assert result.refused == [(3, "V-02", "no consent basis recorded")]


def test_someone_who_opted_out_is_skipped_and_counted_not_refused() -> None:
    result = be.convert([_row(opted_out="yes"), _row(email="b@example.org", opted_out="Sí")], TODAY)

    assert result.exported == []
    assert result.refused == []
    assert result.opted_out == 2


def test_the_first_occurrence_of_an_address_wins_regardless_of_case() -> None:
    rows = [_row(log_id="V-01"), _row(log_id="V-02", email="READER@example.org")]

    result = be.convert(rows, TODAY)

    assert [r["LOG_ID"] for r in result.exported] == ["V-01"]
    assert result.refused == [(3, "V-02", "duplicate address")]


def test_the_cli_writes_a_brevo_file_and_exits_zero_when_nothing_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sheet = _sheet(tmp_path / "contacts.csv", [_row()])
    out = tmp_path / "import.csv"

    code = be.main([str(sheet), "--out", str(out)])

    assert code == 0
    with out.open(newline="", encoding="utf-8") as handle:
        written = list(csv.DictReader(handle))
    assert [r["EMAIL"] for r in written] == ["reader@example.org"]
    assert "exported 1, refused 0" in capsys.readouterr().out


def test_the_cli_exits_one_when_a_row_is_refused_but_still_writes_the_valid_ones(
    tmp_path: Path,
) -> None:
    sheet = _sheet(tmp_path / "contacts.csv", [_row(), _row(log_id="V-02", consent_basis="")])
    out = tmp_path / "import.csv"

    code = be.main([str(sheet), "--out", str(out)])

    assert code == 1
    with out.open(newline="", encoding="utf-8") as handle:
        assert len(list(csv.DictReader(handle))) == 1


def test_the_report_names_rows_and_log_ids_but_never_an_address(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sheet = _sheet(
        tmp_path / "contacts.csv",
        [_row(log_id="V-07", email="secret@example.org", consent_basis="")],
    )

    be.main([str(sheet), "--out", str(tmp_path / "import.csv")])

    report = capsys.readouterr().out
    assert "V-07" in report
    assert "secret@example.org" not in report


def test_a_sheet_without_the_required_columns_is_refused_and_nothing_is_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sheet = tmp_path / "contacts.csv"
    sheet.write_text("email,first_name\nreader@example.org,Ana\n", encoding="utf-8")
    out = tmp_path / "import.csv"

    code = be.main([str(sheet), "--out", str(out)])

    assert code == 2
    assert not out.exists()
    assert "no column(s)" in capsys.readouterr().err


def test_a_path_inside_the_repository_is_refused_unless_explicitly_allowed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sheet = _sheet(tmp_path / "contacts.csv", [_row()])
    inside = ROOT / "brevo_import_should_never_exist.csv"

    code = be.main([str(sheet), "--out", str(inside)])

    assert code == 2
    assert not inside.exists()
    assert "must not live inside the repository" in capsys.readouterr().err


def test_the_committed_validation_data_holds_no_address() -> None:
    """The exporter's premise: the repository carries no contact data at all."""
    for path in (ROOT / "docs/commercial/validation").glob("*.csv"):
        text = path.read_text(encoding="utf-8")
        assert "@" not in text, f"{path.name} must not hold an address"
