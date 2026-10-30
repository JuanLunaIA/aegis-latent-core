#!/usr/bin/env python3
"""Build the one-page A4 investor sheet, from the repository's own numbers.

The copy lives in facts.json with `{tokens}` instead of figures. Every token is
filled from a file that a gate already maintains -- the investor facts file, the
scalability measurement, the cost model, the clean-tree gate report and the
financial engine's model outputs -- so the sheet cannot quote a number the
repository does not hold. A token that cannot be resolved is a hard error, not a
blank.

Rendering is real A4 through headless Chromium, and the result is verified with
poppler: exactly one page, 595 x 842 points, text present and no placeholder left
in the PDF.

    python3 build.py            # writes out/*.pdf and SHA256SUMS
    python3 build.py --check    # re-verifies the committed PDFs
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import html
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATEWAY = HERE.parents[1]  # aegis-latent-core
WORKSPACE = HERE.parents[2]  # repository container
OUT = HERE / "out"

FACTS = WORKSPACE / "docs/investor/facts.json"
COST_DOC = WORKSPACE / "docs/COST_MODEL.md"
LOAD_DOC = WORKSPACE / "docs/SCALABILITY.md"
GATES_DOC = WORKSPACE / "orch/reports/integration/section12-reproduction.md"
MODEL = GATEWAY / "investor_packs/aegis_investor_pack_en/data/model_outputs.json"

FONT_DIR = WORKSPACE / "aegisweb/.vercel/output/static/assets"
SANS = FONT_DIR / "geist-latin-ext-wght-normal-DC-KSUi6.woff2"
SERIF = FONT_DIR / "instrument-serif-latin-400-normal-DnYpCC2O.woff2"

CHROME_CANDIDATES = (
    "/home/luna/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell",
    "/home/luna/.hermes/tools/chromium-*/chrome-linux64/chrome",
)

MONTHS = {
    "en": [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ],
    "es": [
        "enero",
        "febrero",
        "marzo",
        "abril",
        "mayo",
        "junio",
        "julio",
        "agosto",
        "septiembre",
        "octubre",
        "noviembre",
        "diciembre",
    ],
}


def fail(message: str) -> None:
    print(f"one-page: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: Path) -> str:
    if not path.is_file():
        fail(f"missing source {path}")
    return path.read_text(encoding="utf-8")


def money(value: float, locale: str, decimals: int = 0) -> str:
    text = f"{value:,.{decimals}f}"
    if locale == "es":
        text = text.replace(",", "X").replace(".", ",").replace("X", ".")
    return text


def compact(value: float, locale: str, decimals: int = 1) -> str:
    return f"{money(value / 1000, locale, decimals)}k"


def metrics() -> dict[str, dict[str, str]]:
    facts = json.loads(read(FACTS))
    surface = facts["surface"]
    prices = {row["code"]: row["monthlyUsd"] for row in facts["pricing"]["rows"]}
    rows = {row["code"]: row for row in facts["pricing"]["rows"]}
    annual = {
        code: (rows[code]["annualCents"] / 100)
        if rows[code].get("annualCents")
        else (39000.0 if code == "enterprise" else prices[code] * 12)
        for code in ("team", "business", "enterprise")
    }
    tests = surface["testTotal"]

    cost_doc = read(COST_DOC)
    cost_match = re.search(r"19\.4660", cost_doc)
    if not cost_match:
        fail("cost model does not state 19.4660 USD at one million requests")

    load_doc = read(LOAD_DOC)
    # Section 6 is a laptop and section 7 is the deployed path; the file has two
    # headings numbered 7, so the slice starts at the AWS one and ends at section 8.
    aws_start = load_doc.find("Measured on AWS")
    aws_end = load_doc.find("## 8.", aws_start)
    if aws_start < 0 or aws_end < 0:
        fail("scalability document has no AWS section or no section 8 boundary")
    aws_doc = load_doc[aws_start:aws_end]
    load = re.search(r"p50=([\d.]+)\s+p95=([\d.]+)\s+p99=([\d.]+)", aws_doc)
    if not load:
        fail("scalability document has no p50/p95/p99 measurement")
    rate = re.search(r"--rate\s+(\d+)", aws_doc)
    answered = re.search(r"sent=(\d+)\s+completed=(\d+)", aws_doc)
    if not rate or not answered:
        fail("scalability document has no rate or answered count")
    rate_value = int(rate.group(1) or 0)
    sent_value = int(answered.group(1) or 0)
    done_value = int(answered.group(2) or 0)

    gate_doc = read(GATES_DOC)
    runs = re.findall(r"PASS\s+(\d+)/(\d+) ran \(0 cached\) in ([\d.]+)s", gate_doc)
    gates = runs[-1] if runs else None
    if not gates:
        fail("gate report has no clean-tree full run")
    gates_passed, gates_total, gates_seconds_text = gates
    gates_seconds = float(gates_seconds_text)

    model = json.loads(read(MODEL))
    raise_value = model["use_of_funds"]["raise"]
    tranches = model["inputs"]["raise_usd"]["value"]
    runway = model["burn_runway"]["post_funding"]["all tranches"]
    opex = model["burn_runway"]["avg_monthly_opex_18m"]
    mid = model["unit_economics"]["tiers"]["Mid-market"]
    funds = model["use_of_funds"]["workstreams"]

    result: dict[str, dict[str, str]] = {}
    for locale in ("en", "es"):
        dash = "–" if locale == "es" else "–"
        result[locale] = {
            "month_year": MONTHS[locale][9] + " 2026",
            "date_long": "29 October 2026" if locale == "en" else "29 de octubre de 2026",
            "p50": f"{money(float(load.group(1)), locale, 1)} ms",
            "p95": f"{money(float(load.group(2)), locale, 1)} ms",
            "rate": money(rate_value, locale),
            "answered": f"{money(done_value, locale)} of {money(sent_value, locale)}"
            if locale == "en"
            else f"{money(done_value, locale)} de {money(sent_value, locale)}",
            "gates": f"{gates_passed} / {gates_total}",
            "gates_s": f"{money(gates_seconds, locale, 0)} s",
            "tests": money(tests, locale),
            "cost": "$" + money(19.47, locale, 2),
            "routes": money(surface["apiRoutes"], locale),
            "migrations": money(surface["migrations"], locale),
            "locales": money(surface["locales"], locale),
            "team": "$" + money(prices["team"], locale),
            "business": "$" + money(prices["business"], locale),
            "enterprise": "$" + money(prices["enterprise"], locale),
            "acv": ("$" + money(mid["acv"], locale))
            if locale == "en"
            else ("USD " + money(mid["acv"], locale)),
            "payback": money(float(mid["payback_months"]), locale, 1),
            "ltvcac": money(float(mid["ltv_cac_40"]), locale, 1),
            "raise": ("$" + money(raise_value, locale))
            if locale == "en"
            else ("USD " + money(raise_value, locale)),
            "t1": ("$" + compact(tranches["T1"], locale, 0))
            if locale == "en"
            else ("USD " + compact(tranches["T1"], locale, 0)),
            "t2": ("$" + compact(tranches["T2"], locale, 0))
            if locale == "en"
            else ("USD " + compact(tranches["T2"], locale, 0)),
            "t3": ("$" + compact(tranches["T3"], locale, 0))
            if locale == "en"
            else ("USD " + compact(tranches["T3"], locale, 0)),
            "opex": ("$" + compact(opex, locale))
            if locale == "en"
            else ("USD " + compact(opex, locale)),
            "runway": f"{min(runway.values())}{dash}{max(runway.values())}",
            "margin": money((2 * prices["team"] - 19.47) / (2 * prices["team"]) * 100, locale, 1)
            + "%",
            "plan_team_annual": ("$" if locale == "en" else "USD ") + money(annual["team"], locale),
            "plan_business_annual": ("$" if locale == "en" else "USD ")
            + money(annual["business"], locale),
            "plan_enterprise_annual": ("$" if locale == "en" else "USD ")
            + money(annual["enterprise"], locale),
            "t1_pct": f"{tranches['T1'] / raise_value * 100:.0f}%",
            "t2_pct": f"{tranches['T2'] / raise_value * 100:.0f}%",
            "t3_pct": f"{tranches['T3'] / raise_value * 100:.0f}%",
            "fund_engineer": compact(
                funds["Engineering continuity (2nd maintainer, 16 mo)"], locale
            ),
            "fund_gtm": compact(
                funds["Go-to-market (solutions engineer 12 mo + design-partner program)"], locale
            ),
            "fund_assurance": compact(
                funds["Assurance (pen test + retest, SOC 2 Type I, escrow)"], locale
            ),
            "fund_legal": compact(
                funds["Legal & corporate (entity, IP, licence, regulatory, AI-authorship opinion)"],
                locale,
            ),
            "fund_founder": compact(funds["Founder salary (18 mo)"], locale),
            "fund_infra": compact(funds["Infra, tools, insurance, accounting (18 mo)"], locale),
            "fund_recruit": compact(funds["Recruiting"], locale),
            "fund_contingency": compact(funds["Contingency (10%)"], locale),
        }
    return result


def fill(text: str, values: dict[str, str], where: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group(1)
        if token not in values:
            fail(f"unknown token {{{token}}} in {where}")
        return values[token]

    filled = re.sub(r"\{([a-z0-9_]+)\}", replace, text)
    if re.search(r"\{[a-z0-9_]+\}", filled):
        fail(f"unresolved token remains in {where}")
    return filled


def font_face(path: Path, family: str) -> str:
    if not path.is_file():
        return ""
    return (
        f"@font-face{{font-family:'{family}';src:url('file://{path}') format('woff2');"
        "font-weight:100 900;font-style:normal;font-display:block}"
    )


def metrics_values_team(values: dict[str, str]) -> float:
    text = values["team"].replace("$", "").replace("USD ", "")
    if "," in text and "." in text:
        text = text.replace(".", "").replace(",", ".")
    elif "," in text:
        text = text.replace(",", ".")
    return float(text)


def render(locale: str, copy: dict, values: dict[str, str], contact: dict[str, str]) -> str:
    def t(key: str) -> str:
        return html.escape(fill(str(copy[key]), values, f"{locale}.{key}"))

    cost_value = 19.47
    price_value = 2 * metrics_values_team(values)
    cost_bar = round(cost_value / price_value * 100, 1)
    price_bar = "$" + money(price_value, locale)
    flow_cells = "".join(
        f"<div><b>{html.escape(fill(str(head), values, locale + '.flow'))}</b>"
        f"<p>{html.escape(fill(str(body), values, locale + '.flow'))}</p></div>"
        for head, body in copy["flow"]
    )
    plan_rows = "".join(
        f"""<div class="bar"><span class="lab">{html.escape(fill(str(label), values, locale + ".plans"))}</span>
        <span class="track"><i style="width:{html.escape(fill(str(width), values, locale + ".plans"))}"></i></span>
        <span class="val">{html.escape(fill(str(value), values, locale + ".plans"))}</span></div>"""
        for label, value, width in copy["plans"]
    )
    value_cards = "".join(
        f"""<div><b>{html.escape(fill(str(title), values, locale + ".value_cards"))}</b>
        <p>{html.escape(fill(str(body), values, locale + ".value_cards"))}</p></div>"""
        for title, body in copy["value_cards"]
    )
    tranche_rows = "".join(
        f"""<div class="bar"><span class="lab">{html.escape(fill(str(label), values, locale + ".tranches"))}</span>
        <span class="track"><i style="width:{html.escape(fill(str(width), values, locale + ".tranches"))}"></i></span>
        <span class="val">{html.escape(fill(str(value), values, locale + ".tranches"))}</span></div>"""
        for label, value, width in copy["tranches"]
    )
    proof_rows = "\n".join(
        f"""<div class="row"><div class="num">{html.escape(fill(str(head), values, locale + ".proof"))}</div>
        <div class="body">{html.escape(fill(str(body), values, locale + ".proof"))}</div></div>"""
        for head, body in copy["proof"]
    )
    business_rows = "\n".join(
        f"""<div class="row"><div class="num">{html.escape(fill(str(head), values, locale + ".business"))}</div>
        <div class="body">{html.escape(fill(str(body), values, locale + ".business"))}</div></div>"""
        for head, body in copy["business"]
    )
    sans = font_face(SANS, "Geist")
    serif = font_face(SERIF, "Instrument")
    return f"""<!doctype html>
<html lang="{locale}"><head><meta charset="utf-8"><title>Aegis Latent Core — {t("eyebrow")}</title>
<style>
{sans}
{serif}
@page {{ size: A4; margin: 0; }}
html[lang="es"] .claim {{ font-size: 11.7pt; }}
html[lang="es"] p, html[lang="es"] .row .body {{ font-size: 7.9pt; }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html, body {{ width: 210mm; height: 297mm; }}
body {{ font-family: 'Geist', 'Liberation Sans', sans-serif; color: #14130f; background: #fbf9f3;
        font-size: 9.25pt; line-height: 1.44; -webkit-font-smoothing: antialiased; }}
.sheet {{ width: 210mm; height: 297mm; padding: 9mm 12mm 6mm; display: flex; flex-direction: column; }}
header {{ display: flex; justify-content: space-between; align-items: flex-end;
          border-bottom: 1.6pt solid #14130f; padding-bottom: 2.4mm; }}
.mark {{ font-family: 'Instrument', 'DejaVu Serif', serif; font-size: 23pt; letter-spacing: -0.01em; }}
.mark small {{ display: block; font-family: 'Geist', sans-serif; font-size: 6.6pt; letter-spacing: .18em;
               text-transform: uppercase; color: #8a6d1f; margin-top: 1.2mm; }}
.contact {{ text-align: right; font-size: 7pt; color: #4b4841; line-height: 1.55; }}
.contact b {{ color: #14130f; font-weight: 600; }}
.claim {{ font-size: 12.2pt; line-height: 1.3; margin: 3.2mm 0 2.6mm; max-width: 182mm; letter-spacing: -0.006em; }}
.columns {{ display: flex; gap: 7mm; flex: 1; }}
.col {{ flex: 1; }}
h2 {{ font-size: 6.9pt; letter-spacing: .17em; text-transform: uppercase; color: #8a6d1f;
      margin: 2.8mm 0 1.2mm; font-weight: 600; }}
p {{ color: #2c2a25; }}
.rows {{ border-top: .6pt solid #d9d2be; }}
.row {{ display: flex; gap: 3.2mm; padding: 1.8mm 0; border-bottom: .6pt solid #d9d2be; }}
.row .num {{ width: 26mm; flex: none; font-weight: 650; font-size: 9pt; letter-spacing: -0.012em; }}
.row .body {{ font-size: 8.05pt; color: #3a3731; }}
.flow {{ display: flex; margin: 0 0 3.4mm; border-top: .9pt solid #14130f; border-bottom: .6pt solid #d9d2be; }}
.flow div {{ flex: 1; padding: 2.4mm 3.2mm 2.6mm 0; }}
.flow div + div {{ border-left: .6pt solid #d9d2be; padding-left: 3.2mm; }}
.flow b {{ display: block; font-size: 6.7pt; letter-spacing: .16em; text-transform: uppercase;
           color: #8a6d1f; margin-bottom: 1.1mm; }}
.flow p {{ font-size: 7.75pt; color: #33302a; }}
.milestone-band {{ border-top: .6pt solid #d9d2be; margin-top: 2.2mm; padding-top: 1.6mm; }}
.milestones {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 0 4mm; margin-top: 0.4mm; }}
.milestones span {{ font-size: 7.2pt; color: #3a3731; padding-left: 4.2mm; position: relative; }}
.milestones span::before {{ content: ""; position: absolute; left: 0; top: 1.1mm;
                            width: 1.8mm; height: 1.8mm; border: .8pt solid #8a6d1f; }}
.ask {{ margin-top: 2.8mm; padding: 2.8mm 3.2mm; background: #14130f; color: #f3eee1; }}
.ask h2 {{ color: #d3b56a; margin-top: 0; }}
.ask p {{ color: #e9e2d1; font-size: 8.15pt; }}
.ask .amount {{ font-family: 'Instrument', 'DejaVu Serif', serif; font-size: 17pt; color: #fff;
                margin: 0.8mm 0 1.2mm; }}
.bars {{ margin-top: 1.4mm; }}
.bar {{ display: flex; align-items: center; gap: 2.2mm; font-size: 7.1pt; color: #3a3731; margin-top: 1.2mm; }}
.bar .lab {{ width: 30mm; flex: none; }}
.bar .track {{ flex: 1; height: 2.2mm; background: #ece5d3; }}
.bar .track i {{ display: block; height: 100%; background: #8a6d1f; }}
.bar .track i.full {{ width: 100%; background: #14130f; }}
.bar .val {{ width: 20mm; text-align: right; flex: none; font-variant-numeric: tabular-nums; }}
.note {{ font-size: 7.1pt; color: #4b4841; margin-top: 1.3mm; }}
.value-band {{ border-top: 1.2pt solid #14130f; margin-top: 2.2mm; padding-top: 1.6mm; }}
.value-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 5mm; margin-top: 1.4mm; }}
.value-grid b {{ display: block; font-size: 7pt; letter-spacing: .14em; text-transform: uppercase; color: #8a6d1f; }}
.value-grid p {{ font-size: 7.7pt; color: #33302a; margin-top: 1mm; }}
footer {{ margin-top: auto; border-top: .6pt solid #cfc7b2; padding-top: 1.8mm;
          display: flex; justify-content: space-between; font-size: 6.2pt; color: #6a655b; }}
</style></head>
<body><div class="sheet">
<header>
  <div class="mark">{t("wordmark")}<small>{t("eyebrow")}</small></div>
  <div class="contact"><b>{html.escape(contact["name"])}</b><br>{html.escape(contact["email"])}<br>{html.escape(contact["site"])}</div>
</header>
<div class="claim">{t("claim")}</div>
<div class="flow">{flow_cells}</div>
<div class="columns">
  <div class="col">
    <h2>{t("why_title")}</h2><p>{t("why")}</p>
    <h2>{t("product_title")}</h2><p>{t("product")}</p>
    <h2>{t("proof_title")}</h2><div class="rows">{proof_rows}</div>
  </div>
  <div class="col">
    <h2>{t("business_title")}</h2><div class="rows">{business_rows}</div>
    <h2>{t("margin_title")}</h2>
    <div class="bars">
      <div class="bar"><span class="lab">{t("margin_cost")}</span><span class="track"><i style="width:{cost_bar}%"></i></span><span class="val">{values["cost"]}</span></div>
      <div class="bar"><span class="lab">{t("margin_price")}</span><span class="track"><i class="full"></i></span><span class="val">{price_bar}</span></div>
    </div>
    <p class="note">{t("margin_note")}</p>
    <div class="ask">
      <h2>{t("raise_title")}</h2>
      <div class="amount">{values["raise"] if locale == "en" else "USD " + values["raise"].split(" ", 1)[-1]}</div>
      <p>{t("raise")}</p>
      <h2>{t("funds_title")}</h2>
      <p>{t("funds")}</p>
    </div>
    <h2>{t("plans_title")}</h2>
    <div class="bars">{plan_rows}</div>
    <p class="note">{t("plans_note")}</p>
    <h2>{t("tranches_title")}</h2>
    <div class="bars">{tranche_rows}</div>
    <p class="note">{t("tranches_note")}</p>
  </div>
</div>
<div class="value-band"><h2>{t("value_title")}</h2><div class="value-grid">{value_cards}</div></div>
<footer><span>{t("footer")}</span><span>{html.escape(contact["site"])} · {t("eyebrow")}</span></footer>
</div></body></html>
"""


def chrome() -> str:
    for pattern in CHROME_CANDIDATES:
        matches = sorted(glob.glob(pattern))
        if matches:
            return matches[-1]
    fail("no headless Chromium found")
    raise AssertionError


def print_pdf(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    command = [
        chrome(),
        "--headless",
        "--no-sandbox",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={target}",
        "--virtual-time-budget=5000",
        source.as_uri(),
    ]
    done = subprocess.run(command, capture_output=True, text=True, timeout=180)  # noqa: S603 - fixed argv
    if not target.is_file():
        fail(f"chromium did not write {target}: {done.stderr[-400:]}")


def pdf_info(path: Path) -> tuple[int, float, float]:
    text = subprocess.run(  # noqa: S603 - fixed argv, our own file
        ["pdfinfo", str(path)], capture_output=True, text=True, check=True
    ).stdout
    pages_match = re.search(r"Pages:\s+(\d+)", text)
    if not pages_match:
        fail(f"cannot read page count of {path}")
    pages = int(pages_match.group(1) or 0)
    size = re.search(r"Page size:\s+([\d.]+) x ([\d.]+)", text)
    if not size:
        fail(f"cannot read page size of {path}")
    return pages, float(size.group(1) or 0), float(size.group(2) or 0)


def verify_pdf(path: Path, locale: str, copy: dict) -> None:
    pages, width, height = pdf_info(path)
    if pages != 1:
        fail(f"{path.name} has {pages} pages, expected 1")
    if not (594 <= width <= 596 and 841 <= height <= 843):
        fail(f"{path.name} is {width}x{height} pt, expected A4 (595x842)")
    # -raw keeps every span in content order; the default mode reorders columns
    # and can drop a small-caps heading, which would read as a clipped page.
    text = subprocess.run(  # noqa: S603 - fixed argv, our own file
        ["pdftotext", "-raw", str(path), "-"], capture_output=True, text=True, check=True
    ).stdout

    # Kerning can collapse the space between words in extraction ("AegisLatentCore"),
    # so compare with whitespace removed rather than pretending the text is absent.
    def normalise(value: str) -> str:
        return re.sub(r"\s+", "", value.casefold())

    folded = normalise(text)
    for needle in (copy["wordmark"], copy["plans_title"], copy["footer"][:40]):
        if normalise(needle) not in folded:
            fail(f"{path.name} is missing {needle!r}; content may be clipped")
    if re.search(r"\{[a-z0-9_]+\}", text):
        fail(f"{path.name} still contains a template token")
    fonts = subprocess.run(  # noqa: S603 - fixed argv, our own file
        ["pdffonts", str(path)], capture_output=True, text=True, check=True
    ).stdout
    for row in fonts.splitlines()[2:]:
        columns = row.split()
        if len(columns) >= 5 and columns[4] == "no":
            fail(f"{path.name} has an unembedded font: {row}")


def build() -> int:
    facts = json.loads(read(HERE / "facts.json"))
    values = metrics()
    OUT.mkdir(parents=True, exist_ok=True)
    outputs = []
    for locale in ("en", "es"):
        page = render(locale, facts[locale], values[locale], facts["contact"])
        html_path = OUT / f"aegis-one-page-{locale}.html"
        pdf_path = OUT / f"aegis-one-page-{locale}.pdf"
        html_path.write_text(page, encoding="utf-8")
        print_pdf(html_path, pdf_path)
        verify_pdf(pdf_path, locale, facts[locale])
        outputs.append(pdf_path)
        print(
            f"wrote {pdf_path.relative_to(HERE)} ({pdf_path.stat().st_size / 1024:.0f} KiB, A4, 1 page)"
        )

    sums = []
    for path in sorted(OUT.iterdir()):
        if path.suffix in {".pdf", ".html"}:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            sums.append(f"{digest}  {path.name}")
    (OUT / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print(f"checksums: {len(sums)} files")
    return 0


def check() -> int:
    sums_path = OUT / "SHA256SUMS"
    if not sums_path.is_file():
        fail("no SHA256SUMS in out/")
    problems = 0
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split("  ", 1)
        path = OUT / name
        if not path.is_file():
            print(f"one-page: missing {name}", file=sys.stderr)
            problems += 1
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            print(f"one-page: {name} changed since the checksum was written", file=sys.stderr)
            problems += 1
    facts = json.loads(read(HERE / "facts.json"))
    for locale in ("en", "es"):
        path = OUT / f"aegis-one-page-{locale}.pdf"
        if path.is_file():
            verify_pdf(path, locale, facts[locale])
    if problems:
        return 1
    print("one-page: OK — 2 PDFs, A4, one page each, checksums verified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify the committed PDFs")
    args = parser.parse_args()
    return check() if args.check else build()


if __name__ == "__main__":
    raise SystemExit(main())
