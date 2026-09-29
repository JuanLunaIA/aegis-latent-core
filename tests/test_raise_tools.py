# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The raise tooling must report only what the owner recorded and invent no figure.

Covers the tranche gates (evidence needs a date and a reference; a paid pilot needs a
countersigned order), deadline handling, the monthly update's refusal to estimate, the
data-room manifest, the drift check between the round's terms and the model outputs, and
the rule that the committed inputs and drafts hold no signature, name or recorded fact.
"""

from __future__ import annotations

import csv
import importlib.util
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
RAISE = ROOT / "docs" / "raise"
VALIDATION = ROOT / "docs" / "commercial" / "validation"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / "raise" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load("tranche_gate")
update = _load("monthly_update")


def _dirs(tmp_path: Path, *, evidence=None, pilots=None, plan=None) -> tuple[Path, Path]:
    data, val = tmp_path / "raise", tmp_path / "val"
    data.mkdir()
    val.mkdir()
    (data / "EVIDENCE.json").write_text(json.dumps(evidence or {}), encoding="utf-8")
    (data / "RAISE_LEDGER.csv").write_text("date,kind,amount_usd,note\n", encoding="utf-8")
    (val / "PLAN.json").write_text(json.dumps(plan or {}), encoding="utf-8")
    for name, header in (
        ("PILOTS.csv", "pilot_id,customer,start,end,status,fee_usd"),
        ("CONTRACTS.csv", "contract_id,customer,type,acv_usd,signed_date"),
        ("VALIDATION_LOG.csv", "id,touch1_sent,replied,call_date,pilot_proposal_sent"),
    ):
        with (val / name).open("w", newline="", encoding="utf-8") as handle:
            handle.write(header + "\n")
            for row in (pilots or []) if name == "PILOTS.csv" else []:
                csv.writer(handle).writerow(row)
    return data, val


def _status(results, tranche: str) -> str:
    return next(t for t in results if t["tranche"] == tranche)["status"]


def test_committed_state_is_open_everywhere_and_not_late():
    results = gate.evaluate(RAISE, VALIDATION, date(2030, 1, 1))
    assert [t["status"] for t in results] == ["OPEN", "OPEN", "OPEN"]


def test_terms_equal_the_model_outputs():
    model = json.loads(
        (ROOT / "investor_packs/aegis_investor_pack_en/data/model_outputs.json").read_text("utf-8")
    )["inputs"]
    terms = json.loads((ROOT / "tools/raise/terms.json").read_text("utf-8"))["tranches"]
    for tranche in terms:
        assert tranche["amount_usd"] == model["raise_usd"]["value"][tranche["id"]]
        assert tranche["post_money_cap_usd"] == model["post_money_caps_usd"]["value"][tranche["id"]]


def test_evidence_without_a_reference_or_a_valid_date_is_not_met(tmp_path: Path):
    bad = {
        "safe_t1_signed": {"date": "2026-10-01", "ref": ""},
        "entity_formed": {"date": "soon", "ref": "x"},
    }
    data, val = _dirs(tmp_path, evidence=bad)
    assert _status(gate.evaluate(data, val, date(2026, 10, 2)), "T1") == "OPEN"


def test_t1_is_met_with_dated_referenced_evidence(tmp_path: Path):
    ev = {
        k: {"date": "2026-10-01", "ref": "vault/doc.pdf"}
        for k in ("safe_t1_signed", "entity_formed")
    }
    data, val = _dirs(tmp_path, evidence=ev)
    assert _status(gate.evaluate(data, val, date(2026, 10, 2)), "T1") == "MET"


def test_a_pilot_counts_only_with_fee_start_and_a_countersigned_order(tmp_path: Path):
    pilots = [["P-1", "Acme", "2026-11-01", "", "active", "3000"]]
    cases = {
        "no order": {},
        "order": {"pilot_orders": {"P-1": {"date": "2026-10-30", "ref": "vault/p1.pdf"}}},
    }
    got = {}
    for name, ev in cases.items():
        sub = tmp_path / name.replace(" ", "_")
        sub.mkdir()
        data, val = _dirs(sub, evidence=ev, pilots=pilots)
        t2 = gate.evaluate(data, val, date(2026, 11, 2))[1]
        got[name] = next(c["status"] for c in t2["conditions"] if c["id"] == "T2-a")
    assert got == {"no order": "OPEN", "order": "MET"}


def test_a_pilot_below_the_fee_floor_does_not_count(tmp_path: Path):
    pilots = [["P-1", "Acme", "2026-11-01", "", "active", "1000"]]
    ev = {"pilot_orders": {"P-1": {"date": "2026-10-30", "ref": "v/p1.pdf"}}}
    data, val = _dirs(tmp_path, evidence=ev, pilots=pilots)
    assert gate.paid_pilots(list(csv.DictReader((val / "PILOTS.csv").open())), ev, 2500) == 0


def test_two_pilots_for_the_same_customer_count_once(tmp_path: Path):
    pilots = [
        ["P-1", "Acme", "2026-11-01", "", "a", "3000"],
        ["P-2", "ACME", "2026-12-01", "", "a", "3000"],
    ]
    ev = {"pilot_orders": {p[0]: {"date": "2026-10-30", "ref": "v"} for p in pilots}}
    data, val = _dirs(tmp_path, evidence=ev, pilots=pilots)
    assert gate.paid_pilots(list(csv.DictReader((val / "PILOTS.csv").open())), ev, 2500) == 1


def test_gate_two_is_late_only_after_month_eight_and_exits_three(tmp_path: Path):
    data, val = _dirs(tmp_path, plan={"plan_start_date": "2026-10-01"})
    assert _status(gate.evaluate(data, val, date(2027, 6, 1)), "T2") == "OPEN"
    assert _status(gate.evaluate(data, val, date(2027, 6, 2)), "T2") == "LATE"
    rc = gate.main(["--data", str(data), "--validation", str(val), "--today", "2027-06-02"])
    assert rc == 3


def test_monthly_update_leads_with_bad_news_and_estimates_nothing(tmp_path: Path):
    data, val = _dirs(tmp_path, plan={"plan_start_date": "2026-10-01"})
    text = update.build("2027-07", date(2027, 7, 1), data, val)
    assert text.index("Bad news first") < text.index("Gates")
    assert "T2 gate is LATE" in text
    assert "| First touches sent | 0 |" in text
    assert "no share is computed" in text
    assert "runway" not in text.lower()
    assert text.count("[OWNER TO WRITE]") == 3


def test_ledger_alerts_fire_at_documented_levels(tmp_path: Path):
    data, val = _dirs(tmp_path)
    (data / "RAISE_LEDGER.csv").write_text(
        "date,kind,amount_usd,note\n2026-10-01,tranche_received,300000,\n2026-11-01,spend,240000,\n",
        encoding="utf-8",
    )
    text = update.build("2026-11", date(2026, 11, 30), data, val)
    assert "Alert at 50% reached" in text
    assert "Alert at 80% reached" in text
    assert "Alert at 95% reached" not in text


def test_data_room_manifest_hashes_tracked_files():
    done = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, shell=False
        [sys.executable, str(ROOT / "tools/raise/data_room_manifest.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    if "not a git repository" in done.stderr:
        pytest.skip("not a git checkout")
    assert done.returncode in (0, 2)
    assert (
        re.search(r"\| docs/RELEASE_STATUS\.md \| \d+ \| [0-9a-f]{64} \|", done.stdout)
        or done.returncode == 2
    )
    assert "MISSING-HUMAN" in done.stdout


def test_committed_inputs_hold_no_recorded_fact():
    ev = json.loads((RAISE / "EVIDENCE.json").read_text("utf-8"))
    assert all(v is None for k, v in ev.items() if k != "pilot_orders")
    assert ev["pilot_orders"] == {}
    assert (RAISE / "RAISE_LEDGER.csv").read_text("utf-8").strip() == "date,kind,amount_usd,note"


@pytest.mark.parametrize(
    "name",
    ["SAFE_SHEET.md", "DOWNGRADE_MEMO_DRAFT.md", "TRANCHE_EVIDENCE_PACKS.md", "DATA_ROOM_INDEX.md"],
)
def test_legal_facing_drafts_are_marked_and_unsigned(name: str):
    text = (RAISE / name).read_text("utf-8")
    assert "[COUNSEL-REVIEW-REQUIRED]" in text
    assert not re.search(r"^\s*(/s/|Signed by|Date signed)", text, re.M | re.I)


def test_no_raise_document_claims_assurance_or_traction():
    forbidden = re.compile(
        r"\b(is|are) (SOC 2 (compliant|certified)|penetration[- ]tested|court[- ]admissible|production[- ]ready)\b",
        re.I,
    )
    for path in RAISE.glob("*.md"):
        assert not forbidden.search(path.read_text("utf-8")), path.name


def test_tools_send_nothing():
    for name in ("tranche_gate", "monthly_update", "data_room_manifest"):
        source = (ROOT / "tools" / "raise" / f"{name}.py").read_text("utf-8")
        assert not re.search(r"smtplib|urllib|requests|httpx|socket|sendmail", source), name
