# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The Phase-0 price readback, checked offline (EXEC_BASELINE G12).

``deploy/azure/phase0/00_query_prices.sh`` re-reads the Azure list prices the
investor pack tags VERIFIED. It is only useful if it compares against the same
figures the engine prints, and if a moved price or a vanished meter turns into
a non-zero exit instead of a quiet JSON file. No test here reaches the network:
``fetch`` is replaced by canned API pages.
"""

from __future__ import annotations

import ast
import datetime as dt
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
PHASE0 = ROOT / "deploy/azure/phase0"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolves annotations through sys.modules
    spec.loader.exec_module(module)
    return module


prices = _load("aegis_query_prices", PHASE0 / "query_prices.py")
NOW = dt.datetime(2026, 9, 30, 21, 0, tzinfo=dt.UTC)


def _row(meter: Any, price: float, **overrides: Any) -> dict[str, Any]:
    row = {
        "meterId": f"meter-{meter.key}",
        "armRegionName": meter.region,
        "type": "Consumption",
        "productName": meter.product,
        "skuName": meter.sku,
        "meterName": meter.meter_name,
        "tierMinimumUnits": 0.0,
        "retailPrice": price,
        "unitOfMeasure": "1 Hour",
        "currencyCode": "USD",
        "effectiveStartDate": "2021-01-01T00:00:00Z",
    }
    row.update(overrides)
    return row


def _pages(price_for: dict[str, float | None]) -> Any:
    """A stand-in for ``fetch``: one page per meter, priced by key (None = no row)."""
    by_url = {prices.query_url(m): m for m in prices.METERS}

    def fetch(url: str, **_: Any) -> list[dict[str, Any]]:
        meter = by_url[url]
        price = price_for.get(meter.key, meter.expected if meter.expected is not None else 1.0)
        if price is None:
            return []
        # Noise the API really returns for a meter: another tier, a reservation row.
        return [
            _row(meter, price * 0.9, tierMinimumUnits=51200.0),
            _row(meter, price * 5000, type="Reservation"),
            _row(meter, price),
        ]

    return fetch


def _committed_readback() -> dict[str, dict[str, Any]]:
    """The newest committed ``prices_verified_*.json``, keyed by price."""
    files = sorted((ROOT / "evidence/benchmarks/azure").glob("prices_verified_*.json"))
    assert files, "no committed price readback"
    doc = json.loads(files[-1].read_text())
    assert doc["schema"] == prices.SCHEMA
    return {entry["key"]: entry for entry in doc["prices"]}


ENGINES = (
    ROOT / "investor_packs/aegis_investor_pack_en/engine/aegis_financial_engine.py",
    ROOT / "investor_packs/paquete_inversor_aegis_es/motor/aegis_financial_engine.py",
)


def _engine_inputs(path: Path) -> dict[str, tuple[object, str, str]]:
    """Each literal ``inp(key, value, tag, note, ...)`` call, read without importing.

    The engine imports matplotlib at module level; the test environment need
    not have it, and a price check should not depend on a plotting library.
    """
    found: dict[str, tuple[object, str, str]] = {}
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "inp"):
            continue
        key, value, tag, note = node.args[:4]
        if not all(isinstance(arg, ast.Constant) for arg in (key, value, tag)):
            continue  # derived inputs (e.g. a monthly figure computed from an hourly one)
        note_text = note.value if isinstance(note, ast.Constant) else ast.unparse(note)
        found[str(key.value)] = (value.value, str(tag.value), str(note_text))
    return found


@pytest.mark.parametrize("engine", ENGINES, ids=("en", "es"))
def test_the_verified_figures_are_the_engines(engine: Path) -> None:
    """A price the pack prints and a price the readback checks must be one number."""
    inputs = _engine_inputs(engine)
    for meter in prices.METERS:
        if meter.expected is None:
            assert meter.key not in inputs, meter.key
            continue
        value, tag, note = inputs[meter.key]
        assert tag == "VERIFIED", meter.key
        assert value == meter.expected, meter.key
        # The engine cites the meter id it read; the committed readback must
        # have reached that same meter by name.
        if "meterId" in note:
            assert _committed_readback()[meter.key]["meterId"] in note, meter.key


def test_all_prices_match_exits_zero(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(prices, "fetch", _pages({}))
    code, path, doc = prices.run(tmp_path, now=NOW)
    assert code == 0
    assert path.name == "prices_verified_2026-09-30.json"
    assert json.loads(path.read_text()) == doc
    statuses = {e["key"]: e["status"] for e in doc["prices"]}
    assert set(statuses.values()) == {"MATCH", "CONTEXT"}
    assert doc["fetchedAtUtc"] == "2026-09-30T21:00:00Z"
    # The tier and reservation rows were ignored; only the first-tier price counts.
    hsm = next(e for e in doc["prices"] if e["key"] == "hsm_b1_hourly_usd")
    assert hsm["retailPrice"] == 3.20
    assert len(hsm["rowSha256"]) == 64


def test_a_moved_price_exits_three(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(prices, "fetch", _pages({"vm_d4s_v5_hourly_usd": 0.201}))
    code, _, doc = prices.run(tmp_path, now=NOW)
    assert code == 3
    moved = next(e for e in doc["prices"] if e["key"] == "vm_d4s_v5_hourly_usd")
    assert moved["status"] == "CHANGED"
    assert moved["retailPrice"] == 0.201
    assert moved["expected"] == 0.192


def test_a_context_price_that_moves_does_not_fail(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(prices, "fetch", _pages({"p4_lrs_disk_chilecentral_month_usd": 99.0}))
    code, _, _ = prices.run(tmp_path, now=NOW)
    assert code == 0


def test_a_missing_meter_exits_four(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(prices, "fetch", _pages({"hsm_b1_hourly_usd": None}))
    code, _, doc = prices.run(tmp_path, now=NOW)
    assert code == 4
    missing = next(e for e in doc["prices"] if e["key"] == "hsm_b1_hourly_usd")
    assert missing["status"] == "NOT_FOUND"
    assert "retailPrice" not in missing


def test_two_first_tier_rows_that_disagree_are_an_error() -> None:
    meter = prices.METERS[0]
    with pytest.raises(prices.PriceError, match="different prices"):
        prices.select(meter, [_row(meter, 3.20), _row(meter, 3.30)])


def test_a_next_page_off_the_api_host_is_refused(monkeypatch) -> None:
    class Response:
        def __init__(self, body: dict[str, Any]) -> None:
            self.body = json.dumps(body).encode()

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def read(self, *_: Any) -> bytes:
            return self.body

    monkeypatch.setattr(
        prices.urllib.request,
        "urlopen",
        lambda url, timeout: Response({"Items": [], "NextPageLink": "https://evil.example/x"}),
    )
    with pytest.raises(prices.PriceError, match="outside"):
        prices.fetch(prices.API + "?$filter=x")


def test_an_unreachable_api_exits_one(monkeypatch, capsys, tmp_path: Path) -> None:
    def down(url: str, timeout: float) -> None:
        raise OSError("network is unreachable")

    monkeypatch.setattr(prices.urllib.request, "urlopen", down)
    assert prices.main(["--out-dir", str(tmp_path)]) == 1
    assert "could not read" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_the_wrapper_prints_its_usage_without_network() -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv: bash and an in-repo script
        ["bash", str(PHASE0 / "00_query_prices.sh"), "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0
    assert "Read-only" in result.stdout
    assert "Copyright" not in result.stdout


def test_the_committed_readback_matched() -> None:
    """The dated file committed as G12 evidence recorded every pinned price as MATCH."""
    readback = _committed_readback()
    pinned = {m.key for m in prices.METERS if m.expected is not None}
    assert {key for key, e in readback.items() if e["status"] == "MATCH"} == pinned
