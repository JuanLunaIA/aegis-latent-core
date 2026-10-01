#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""Read back the Azure list prices the investor pack cites (EXEC_BASELINE G12).

Read-only. Each price is one public, unauthenticated HTTPS GET to the Azure
Retail Prices API. There is no Azure login and no subscription, and nothing is
created or spent.

Each entry is pinned by region, price type, product, SKU, meter name and first
tier, so exactly one row can answer it. The meter id the API returns is recorded
in the output; it is not written here, because this directory carries no GUIDs
(``tests/test_azure_kit.py`` keeps subscription and tenant ids out of it). Where the investor engine tags the figure
VERIFIED, ``expected`` holds the engine's value. A mismatch means the list price
has moved since the pack was built, and the pack must be rebuilt before it is
cited again. Entries with ``expected=None`` are recorded for context only.

What this does not establish: what any account pays. Retail list prices exclude
credits, discounts, agreements, taxes, bandwidth, and every resource not listed.

Exit codes: 0 every pinned price was found and equals the engine's value;
3 at least one price differs; 4 a meter returned no matching row;
1 the API could not be reached or answered something unreadable.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

API = "https://prices.azure.com/api/retail/prices"
MAX_PAGES = 10
SCHEMA = "aegis-azure-prices-1"


@dataclass(frozen=True)
class Meter:
    key: str
    region: str
    product: str
    sku: str
    meter_name: str
    expected: float | None
    note: str


# The four VERIFIED keys are the investor engine's
# (investor_packs/*/{engine,motor}/aegis_financial_engine.py); a test keeps them equal.
METERS: tuple[Meter, ...] = (
    Meter(
        "hsm_b1_hourly_usd",
        "eastus",
        "Key Vault HSM Pool",
        "Standard B1",
        "Standard B1 Instance",
        3.20,
        "Managed HSM pool, USD per hour; excluded from the design by cost",
    ),
    Meter(
        "vm_d4s_v5_hourly_usd",
        "eastus",
        "Virtual Machines Dsv5 Series",
        "Standard_D4s_v5",
        "D4s v5",
        0.192,
        "Linux pay-as-you-go, USD per hour, VM only",
    ),
    Meter(
        "blob_hot_lrs_gb_month_usd",
        "eastus",
        "Blob Storage",
        "Hot LRS",
        "Hot LRS Data Stored",
        0.0208,
        "data stored, first tier, USD per GB-month",
    ),
    Meter(
        "azure_b2als_v2_chilecentral_hourly_usd",
        "chilecentral",
        "Virtual Machines Basv2 Series",
        "B2als v2",
        "B2als v2",
        0.0526,
        "Linux pay-as-you-go, USD per hour, VM only (the measured pilot host)",
    ),
    Meter(
        "p4_lrs_disk_chilecentral_month_usd",
        "chilecentral",
        "Premium SSD Managed Disks",
        "P4 LRS",
        "P4 LRS Disk",
        None,
        "32 GiB Premium SSD, USD per month; the pilot host's data disk (context only)",
    ),
)


class PriceError(Exception):
    """The API could not be reached, or its answer could not be read."""


def query_url(meter: Meter) -> str:
    flt = (
        f"armRegionName eq '{meter.region}' and priceType eq 'Consumption' "
        f"and productName eq '{meter.product}' and skuName eq '{meter.sku}' "
        f"and meterName eq '{meter.meter_name}'"
    )
    return API + "?" + urllib.parse.urlencode({"$filter": flt})


def fetch(url: str, *, timeout: float = 20.0) -> list[dict[str, Any]]:
    """Every item the query returns, following NextPageLink up to ``MAX_PAGES``."""
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    for _ in range(MAX_PAGES):
        if next_url is None:
            return items
        if not next_url.startswith(API):
            raise PriceError(f"refusing a next page outside {API}: {next_url[:80]}")
        try:
            with urllib.request.urlopen(next_url, timeout=timeout) as resp:  # noqa: S310 - fixed https host, checked above
                page = json.load(resp)
        except (OSError, ValueError) as exc:
            raise PriceError(f"could not read {API}: {exc}") from exc
        if not isinstance(page, dict) or not isinstance(page.get("Items"), list):
            raise PriceError("the API answered without an Items list")
        items.extend(page["Items"])
        next_url = page.get("NextPageLink") or None
    raise PriceError(f"more than {MAX_PAGES} pages for one meter")


def select(meter: Meter, items: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The one row that answers *meter*, or None when no row matches."""
    rows = [
        item
        for item in items
        if item.get("armRegionName") == meter.region
        and item.get("type") == "Consumption"
        and item.get("productName") == meter.product
        and item.get("skuName") == meter.sku
        and item.get("meterName") == meter.meter_name
        and float(item.get("tierMinimumUnits") or 0.0) == 0.0
    ]
    if len(rows) > 1:
        prices = {float(row["retailPrice"]) for row in rows}
        if len(prices) > 1:
            raise PriceError(
                f"{meter.key}: {len(rows)} rows with different prices {sorted(prices)}"
            )
    return rows[0] if rows else None


def record(meter: Meter, url: str, row: dict[str, Any] | None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "key": meter.key,
        "note": meter.note,
        "query": url,
        "armRegionName": meter.region,
        "expected": meter.expected,
    }
    if row is None:
        entry["status"] = "NOT_FOUND"
        return entry
    price = float(row["retailPrice"])
    entry.update(
        productName=row.get("productName"),
        skuName=row.get("skuName"),
        meterId=row.get("meterId"),
        meterName=row.get("meterName"),
        unitOfMeasure=row.get("unitOfMeasure"),
        currencyCode=row.get("currencyCode"),
        effectiveStartDate=row.get("effectiveStartDate"),
        retailPrice=price,
        rowSha256=hashlib.sha256(
            json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    )
    if meter.expected is None:
        entry["status"] = "CONTEXT"
    else:
        entry["status"] = "MATCH" if abs(price - meter.expected) < 1e-9 else "CHANGED"
    return entry


def run(out_dir: Path, *, now: dt.datetime | None = None) -> tuple[int, Path, dict[str, Any]]:
    fetched = (now or dt.datetime.now(dt.UTC)).replace(microsecond=0)
    entries = []
    for meter in METERS:
        url = query_url(meter)
        entries.append(record(meter, url, select(meter, fetch(url))))
    statuses = {entry["status"] for entry in entries}
    code = 4 if "NOT_FOUND" in statuses else 3 if "CHANGED" in statuses else 0
    doc = {
        "schema": SCHEMA,
        "source": API,
        "fetchedAtUtc": fetched.isoformat().replace("+00:00", "Z"),
        "method": "one unauthenticated GET per meter; nothing created or spent",
        "scope": "retail list prices only; not what any account pays",
        "result": {0: "all pinned prices match", 3: "a price changed", 4: "a meter not found"}[
            code
        ],
        "prices": entries,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"prices_verified_{fetched.date().isoformat()}.json"
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return code, path, doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", type=Path, default=Path("."), help="where to write the JSON")
    args = parser.parse_args(argv)
    try:
        code, path, doc = run(args.out_dir)
    except PriceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for entry in doc["prices"]:
        price = entry.get("retailPrice", "-")
        print(f"{entry['status']:<9} {entry['key']:<40} {price} {entry.get('unitOfMeasure', '')}")
    print(f"{doc['result']}: {path}")
    return code


if __name__ == "__main__":
    sys.exit(main())
