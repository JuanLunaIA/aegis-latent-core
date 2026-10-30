#!/usr/bin/env python3
"""Build the AWS edition of the investor HTML, in English and Spanish.

Every figure comes from a repository file or from the 2026-10-30 readback in
aws_facts.json. The generator writes one self-contained HTML per locale; fonts
are embedded so the file can be opened offline and printed to A4.
"""

from __future__ import annotations

import base64
import html
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATEWAY = HERE.parents[1]
FACTS = HERE / "data/investor_facts.json"
MODEL = GATEWAY / "investor_packs/aegis_investor_pack_en/data/model_outputs.json"
AWS = HERE / "aws_facts.json"
OUT = HERE / "out"

SANS = HERE / "assets/geist-latin-ext-wght-normal-DC-KSUi6.woff2"
SERIF = HERE / "assets/instrument-serif-latin-400-normal-DnYpCC2O.woff2"


def fail(msg: str) -> None:
    raise SystemExit(f"aws-edition: {msg}")


def read(path: Path) -> str:
    if not path.is_file():
        fail(f"missing {path}")
    return path.read_text(encoding="utf-8")


def money(value: float, locale: str, decimals: int = 0) -> str:
    text = f"{value:,.{decimals}f}"
    if locale == "es":
        text = text.replace(",", "X").replace(".", ",").replace("X", ".")
    return text


def esc(value: str) -> str:
    return html.escape(str(value), quote=True)


def font_face(path: Path, family: str, weight: str = "100 900") -> str:
    data = base64.b64encode(path.read_bytes()).decode("ascii")
    return (
        f"@font-face{{font-family:'{family}';src:url(data:font/woff2;base64,{data}) format('woff2');"
        f"font-weight:{weight};font-style:normal;font-display:block}}"
    )


def load_facts() -> dict:
    facts = json.loads(read(FACTS))
    model = json.loads(read(MODEL))
    aws = json.loads(read(AWS))
    throughput = aws["throughput"]
    gates = aws["gates"]
    return {
        "facts": facts,
        "model": model,
        "aws": aws,
        "p50": float(throughput["p50_ms"]),
        "p95": float(throughput["p95_ms"]),
        "rate": int(throughput["rate"]),
        "sent": int(throughput["sent"]),
        "done": int(throughput["completed"]),
        "gate_pass": str(gates["pass"]),
        "gate_total": str(gates["total"]),
        "gate_seconds": float(gates["seconds"]),
    }


def values(data: dict, locale: str) -> dict[str, str]:
    facts, model, aws = data["facts"], data["model"], data["aws"]["aws"]
    release = data["aws"]["release"]
    surface = facts["surface"]
    prices = {r["code"]: r["monthlyUsd"] for r in facts["pricing"]["rows"]}
    annual = {
        "team": 2490.0,
        "business": 8990.0,
        "enterprise": 39000.0,
    }
    raise_usd = model["use_of_funds"]["raise"]
    tranches = model["inputs"]["raise_usd"]["value"]
    runway = model["burn_runway"]["post_funding"]["all tranches"]
    opex = model["burn_runway"]["avg_monthly_opex_18m"]
    mid = model["unit_economics"]["tiers"]["Mid-market"]
    funds = model["use_of_funds"]["workstreams"]
    fund_total = sum(funds.values())
    return {
        "version": release["version"],
        "published": release["published_at"][:10],
        "assets": str(release["assets"]),
        "sha": release["sha256sums"],
        "pypi_core": release["pypi_core"],
        "pypi_sdk": release["pypi_sdk"],
        "npm_sdk": release["npm_sdk"],
        "oci_gateway": release["oci_gateway"],
        "tag": release["tag"],
        "commit": release["commit"][:12],
        "p50": f"{money(data['p50'], locale, 1)} ms",
        "p95": f"{money(data['p95'], locale, 1)} ms",
        "rate": money(data["rate"], locale),
        "done": money(data["done"], locale),
        "sent": money(data["sent"], locale),
        "gates": f"{data['gate_pass']} / {data['gate_total']}",
        "gate_s": f"{money(data['gate_seconds'], locale, 0)} s",
        "tests": money(surface["testTotal"], locale),
        "routes": money(surface["apiRoutes"], locale),
        "migrations": money(surface["migrations"], locale),
        "locales": money(surface["locales"], locale),
        "cost": money(19.47, locale, 2),
        "team": money(prices["team"], locale),
        "business": money(prices["business"], locale),
        "enterprise": money(prices["enterprise"], locale),
        "team_year": money(annual["team"], locale),
        "business_year": money(annual["business"], locale),
        "enterprise_year": money(annual["enterprise"], locale),
        "acv": money(mid["acv"], locale),
        "payback": money(float(mid["payback_months"]), locale, 1),
        "ltvcac": money(float(mid["ltv_cac_40"]), locale, 1),
        "raise": money(raise_usd, locale),
        "t1": money(tranches["T1"], locale),
        "t2": money(tranches["T2"], locale),
        "t3": money(tranches["T3"], locale),
        "opex": money(opex, locale),
        "runway": f"{min(runway.values())}–{max(runway.values())}",
        "fund_engineer": money(funds["Engineering continuity (2nd maintainer, 16 mo)"], locale),
        "fund_gtm": money(
            funds["Go-to-market (solutions engineer 12 mo + design-partner program)"], locale
        ),
        "fund_assurance": money(
            funds["Assurance (pen test + retest, SOC 2 Type I, escrow)"], locale
        ),
        "fund_legal": money(
            funds["Legal & corporate (entity, IP, licence, regulatory, AI-authorship opinion)"],
            locale,
        ),
        "fund_founder": money(funds["Founder salary (18 mo)"], locale),
        "fund_infra": money(funds["Infra, tools, insurance, accounting (18 mo)"], locale),
        "fund_recruit": money(funds["Recruiting"], locale),
        "fund_contingency": money(funds["Contingency (10%)"], locale),
        "fund_total": money(fund_total, locale),
        "aws_cost": money(aws["month_to_date_usd"], locale, 2),
        "aws_budget": money(aws["budget_usd"], locale),
        "aws_health": aws["health_version"],
        "aws_ready": aws["ready"],
        "aws_audit": aws["audit_status"],
        "aws_updated": aws["last_code_update"][:10],
        "region": aws["region"],
        "runtime": aws["runtime"],
        "memory": money(aws["memory_mb"], locale),
        "timeout": money(aws["timeout_s"], locale),
        "fund_pct_eng": f"{(funds['Engineering continuity (2nd maintainer, 16 mo)'] + funds['Founder salary (18 mo)'] + funds['Recruiting']) / fund_total * 100:.1f}",
        "fund_pct_gtm": f"{funds['Go-to-market (solutions engineer 12 mo + design-partner program)'] / fund_total * 100:.1f}",
        "fund_pct_assurance": f"{(funds['Assurance (pen test + retest, SOC 2 Type I, escrow)'] + funds['Legal & corporate (entity, IP, licence, regulatory, AI-authorship opinion)']) / fund_total * 100:.1f}",
        "fund_pct_infra": f"{(funds['Infra, tools, insurance, accounting (18 mo)'] + funds['Contingency (10%)']) / fund_total * 100:.1f}",
        "plan_team_pct": f"{annual['team'] / annual['enterprise'] * 100:.1f}",
        "plan_business_pct": f"{annual['business'] / annual['enterprise'] * 100:.1f}",
        "currency": "$" if locale == "en" else "USD ",
    }


COPY = {
    "en": {
        "lang": "en",
        "eyebrow": "SEED · AWS EDITION · OCTOBER 2026",
        "title": "Aegis Latent Core",
        "claim": "A control point for AI traffic that writes every governed call to an append-only ledger and gives the buyer a proof a third party can verify offline.",
        "metrics_title": "What the system already does",
        "metrics": [
            ("5.0.3", "published release"),
            ("{rate}/s", "measured on the AWS Function URL"),
            ("{p50}", "p50, {p95} p95"),
            ("{gates}", "gates on a clean tree, {gate_s}"),
            ("{tests}", "declared control-plane and SDK tests"),
            ("{cost}", "unit cost per million requests"),
        ],
        "product_title": "The product",
        "product_lead": "A gateway, a ledger and an offline verifier. It sits between the application and the model, so the team changes nothing in the assistant it already uses.",
        "product_cards": [
            (
                "01 · Request",
                "A key names the tenant, the quota and the route. The gateway enforces all three before the upstream call.",
            ),
            (
                "02 · Ledger",
                "The request and the response digest enter an append-only log; each entry carries the previous hash.",
            ),
            (
                "03 · Proof",
                "The customer exports a signed pack and verifies inclusion offline. Our credentials are not part of the proof.",
            ),
        ],
        "aws_title": "Running on AWS",
        "aws_lead": "The control plane is deployed, not planned. These values were read back from the public Function URL on 30 October 2026.",
        "aws_rows": [
            ("Region", "{region}"),
            ("GET /health", "200 · version {aws_health}"),
            ("GET /readyz", "200 · {aws_ready}"),
            ("GET /v1/audit", "{aws_audit} — the endpoint exists and requires a session"),
            ("Runtime", "{runtime} · {memory} MB · {timeout} s"),
            ("Last code update", "{aws_updated}"),
            (
                "October run-rate",
                "US$ {aws_cost} month-to-date, estimated; planning budget US$ {aws_budget}/month",
            ),
        ],
        "arch_title": "How a call moves",
        "arch": [
            ("Application", "Your service keeps its current SDK or HTTP client."),
            ("Gateway", "Keys, quotas, policy and the ledger commit."),
            ("Model", "A compatible provider or a model in your own infrastructure."),
            ("Proof", "A signed export the buyer verifies offline."),
        ],
        "release_title": "Release 5.0.3",
        "release_lead": "Published on GitHub Release, PyPI SDK, npm SDK and GHCR on {published}. The SDKs ship at {pypi_sdk}; the gateway distribution keeps its own release cadence at {pypi_core}.",
        "release_rows": [
            ("Git tag", "{tag} · commit {commit}"),
            ("GitHub Release", "{assets} assets · SHA-256 manifest {sha}"),
            ("PyPI SDK", "{pypi_sdk}"),
            ("npm SDK", "{npm_sdk}"),
            ("OCI gateway", "{oci_gateway}"),
        ],
        "business_title": "Business, as a model",
        "business_lead": "Reference values, not a booking. The annual plan ladder and the unit-cost bar come from the same files the repository publishes.",
        "plans_title": "Annual plan ladder",
        "plans_note": "Annual reference values; final scope and terms are confirmed in a proposal.",
        "plans": [
            ("Team", "{team_year}"),
            ("Business", "{business_year}"),
            ("Enterprise", "{enterprise_year}"),
        ],
        "unit_title": "Unit cost per million requests",
        "unit_note": "{cost} at one million requests, computed from list prices. Team lists at ${team}/month; two blocks minus the unit cost is the gross-margin model.",
        "raise_title": "The raise",
        "raise_body": "US$ {raise} in three tranches tied to milestones, against an 18-month plan, US$ {opex} monthly operating cost and a {runway}-month runway after closing.",
        "tranches": [("T1", "{t1}"), ("T2", "{t2}"), ("T3", "{t3}")],
        "funds_title": "Use of funds",
        "funds_note": "Engineering continuity {fund_engineer} · go-to-market {fund_gtm} · assurance {fund_assurance} · legal {fund_legal} · founder {fund_founder} · infrastructure {fund_infra} · recruiting {fund_recruit} · contingency {fund_contingency}. Total US$ {fund_total}.",
        "data_title": "Data room",
        "data_lead": "Every figure is reproducible from the repository or from a public registry.",
        "data_links": [
            (
                "GitHub Release",
                "https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v5.0.3",
            ),
            (
                "Release status",
                "https://github.com/JuanLunaIA/aegis-latent-core/blob/main/docs/RELEASE_STATUS.md",
            ),
            ("Public site", "https://aegislatent.com"),
            ("One-page A4", "aegis-one-page-en.pdf"),
        ],
        "footer": "Aegis Latent Core · AWS edition · October 2026 · figures produced by commands, not typed.",
    },
    "es": {
        "lang": "es",
        "eyebrow": "SEED · EDICIÓN AWS · OCTUBRE 2026",
        "title": "Aegis Latent Core",
        "claim": "Un punto de control para el tráfico de IA que escribe cada llamada gobernada en un libro append-only y entrega al comprador una prueba que un tercero verifica sin conexión.",
        "metrics_title": "Lo que el sistema ya hace",
        "metrics": [
            ("5.0.3", "release publicada"),
            ("{rate}/s", "medido en la Function URL de AWS"),
            ("{p50}", "p50, {p95} p95"),
            ("{gates}", "gates sobre árbol limpio, {gate_s}"),
            ("{tests}", "pruebas declaradas del plano de control y SDK"),
            ("{cost}", "costo unitario por millón de peticiones"),
        ],
        "product_title": "El producto",
        "product_lead": "Un gateway, un libro y un verificador sin conexión. Se coloca entre la aplicación y el modelo, así que el equipo no cambia el asistente que ya usa.",
        "product_cards": [
            (
                "01 · Petición",
                "Una clave nombra el tenant, la cuota y la ruta. El gateway aplica las tres antes de llamar al proveedor.",
            ),
            (
                "02 · Libro",
                "La petición y el digest de la respuesta entran en un registro append-only; cada entrada lleva el hash anterior.",
            ),
            (
                "03 · Prueba",
                "El cliente exporta un paquete firmado y verifica la inclusión sin conexión. Nuestras credenciales no forman parte de la prueba.",
            ),
        ],
        "aws_title": "Funcionando en AWS",
        "aws_lead": "El plano de control está desplegado, no proyectado. Estos valores se leyeron de la Function URL pública el 30 de octubre de 2026.",
        "aws_rows": [
            ("Región", "{region}"),
            ("GET /health", "200 · versión {aws_health}"),
            ("GET /readyz", "200 · {aws_ready}"),
            ("GET /v1/audit", "{aws_audit} — el endpoint existe y exige sesión"),
            ("Runtime", "{runtime} · {memory} MB · {timeout} s"),
            ("Última actualización de código", "{aws_updated}"),
            (
                "Consumo de octubre",
                "USD {aws_cost} acumulado estimado; presupuesto de planificación USD {aws_budget}/mes",
            ),
        ],
        "arch_title": "Cómo viaja una llamada",
        "arch": [
            ("Aplicación", "Su servicio conserva el SDK o el cliente HTTP actual."),
            ("Gateway", "Claves, cuotas, política y confirmación en el libro."),
            ("Modelo", "Un proveedor compatible o un modelo en su infraestructura."),
            ("Prueba", "Una exportación firmada que el comprador verifica sin conexión."),
        ],
        "release_title": "Release 5.0.3",
        "release_lead": "Publicada en GitHub Release, PyPI SDK, npm SDK y GHCR el {published}. Los SDK salen en {pypi_sdk}; la distribución del gateway mantiene su propio ritmo en {pypi_core}.",
        "release_rows": [
            ("Etiqueta Git", "{tag} · commit {commit}"),
            ("GitHub Release", "{assets} assets · manifiesto SHA-256 {sha}"),
            ("PyPI SDK", "{pypi_sdk}"),
            ("npm SDK", "{npm_sdk}"),
            ("OCI gateway", "{oci_gateway}"),
        ],
        "business_title": "Negocio, como modelo",
        "business_lead": "Valores de referencia, no una reserva. La escalera anual y la barra de costo unitario salen de los mismos archivos que publica el repositorio.",
        "plans_title": "Escalera anual de planes",
        "plans_note": "Valores anuales de referencia; el alcance y las condiciones finales se confirman en una propuesta.",
        "plans": [
            ("Team", "{team_year}"),
            ("Business", "{business_year}"),
            ("Enterprise", "{enterprise_year}"),
        ],
        "unit_title": "Costo unitario por millón de peticiones",
        "unit_note": "{cost} a un millón de peticiones, calculado con precios de lista. Team lista USD {team}/mes; dos bloques menos el costo unitario dan el modelo de margen bruto.",
        "raise_title": "La ronda",
        "raise_body": "USD {raise} en tres tramos atados a hitos, contra un plan de 18 meses, un costo operativo de USD {opex} por mes y una pista de {runway} meses después del cierre.",
        "tranches": [("T1", "{t1}"), ("T2", "{t2}"), ("T3", "{t3}")],
        "funds_title": "Uso de fondos",
        "funds_note": "Continuidad de ingeniería {fund_engineer} · go-to-market {fund_gtm} · assurance {fund_assurance} · legal {fund_legal} · fundador {fund_founder} · infraestructura {fund_infra} · recruiting {fund_recruit} · contingencia {fund_contingency}. Total USD {fund_total}.",
        "data_title": "Data room",
        "data_lead": "Cada cifra se reproduce desde el repositorio o desde un registro público.",
        "data_links": [
            (
                "GitHub Release",
                "https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v5.0.3",
            ),
            (
                "Estado del release",
                "https://github.com/JuanLunaIA/aegis-latent-core/blob/main/docs/RELEASE_STATUS.md",
            ),
            ("Sitio público", "https://aegislatent.com"),
            ("Hoja A4", "aegis-one-page-es.pdf"),
        ],
        "footer": "Aegis Latent Core · edición AWS · octubre de 2026 · cifras producidas por comandos, no escritas a mano.",
    },
}


def fmt(template: str, vals: dict[str, str]) -> str:
    out = re.sub(r"\{([a-z0-9_]+)\}", lambda m: vals.get(m.group(1), m.group(0)), template)
    if re.search(r"\{[a-z0-9_]+\}", out):
        fail(f"unresolved token in {template!r}")
    return out


def render(locale: str, data: dict) -> str:
    c = COPY[locale]
    v = values(data, locale)

    def t(text: str) -> str:
        return fmt(esc(text), {k: esc(x) for k, x in v.items()})

    metrics = "".join(
        f"<div class='metric'><b>{t(a)}</b><span>{t(b)}</span></div>" for a, b in c["metrics"]
    )
    cards = "".join(
        f"<article class='step'><h3>{t(a)}</h3><p>{t(b)}</p></article>"
        for a, b in c["product_cards"]
    )
    aws_rows = "".join(f"<tr><th>{t(a)}</th><td>{t(b)}</td></tr>" for a, b in c["aws_rows"])
    arch = "".join(f"<div class='node'><b>{t(a)}</b><p>{t(b)}</p></div>" for a, b in c["arch"])
    release_rows = "".join(
        f"<tr><th>{t(a)}</th><td class='mono'>{t(b)}</td></tr>" for a, b in c["release_rows"]
    )
    plans = "".join(
        f"<div class='bar'><span class='lab'>{t(a)}</span><span class='track'><i style='width:{pct}%'></i></span><span class='val'>{v['currency']}{t(b)}</span></div>"
        for (a, b), pct in zip(
            c["plans"], (v["plan_team_pct"], v["plan_business_pct"], "100"), strict=True
        )
    )
    tranches = "".join(
        f"<div class='tranche'><b>{t(a)}</b><span>{v['currency']}{t(b)}</span></div>"
        for a, b in c["tranches"]
    )
    funds = [
        ("Engineering", v["fund_pct_eng"]),
        ("GTM", v["fund_pct_gtm"]),
        ("Assurance & legal", v["fund_pct_assurance"]),
        ("Infra & contingency", v["fund_pct_infra"]),
    ]
    fund_bar = "".join(
        f"<i style='width:{pct}%' title='{esc(name)} {pct}%'></i>" for name, pct in funds
    )
    fund_legend = "".join(f"<span><i></i>{esc(name)} {pct}%</span>" for name, pct in funds)
    links = "".join(
        f"<li><a href='{esc(href)}'>{t(label)}</a></li>" for label, href in c["data_links"]
    )
    sans = font_face(SANS, "Geist")
    serif = font_face(SERIF, "Instrument", "400")

    return f"""<!doctype html>
<html lang="{locale}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis Latent Core — {t(c["eyebrow"])}</title>
<style>
{sans}
{serif}
:root{{--ink:#14130f;--muted:#5b564b;--line:#d9d2be;--paper:#fbf9f3;--brand:#145c44;--gold:#8a6d1f}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 'Geist','Liberation Sans',sans-serif;-webkit-font-smoothing:antialiased}}
.page{{max-width:1080px;margin:0 auto;padding:38px 32px 48px}}
header{{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:2px solid var(--ink);padding-bottom:14px;gap:24px}}
.mark{{font-family:'Instrument','DejaVu Serif',serif;font-size:42px;letter-spacing:-.015em;line-height:1}}
.mark small{{display:block;font-family:'Geist',sans-serif;font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--gold);margin-top:8px}}
.contact{{text-align:right;font-size:12px;color:var(--muted);line-height:1.6}}
.claim{{font-family:'Instrument','DejaVu Serif',serif;font-size:28px;line-height:1.22;max-width:900px;margin:26px 0 22px;letter-spacing:-.012em}}
.metrics{{display:grid;grid-template-columns:repeat(6,1fr);border-top:1px solid var(--ink);border-bottom:1px solid var(--line)}}
.metric{{padding:12px 10px 13px;border-right:1px solid var(--line)}}
.metric:last-child{{border-right:0}}
.metric b{{display:block;font-size:15px;font-variant-numeric:tabular-nums}}
.metric span{{display:block;font-size:10px;line-height:1.3;color:var(--muted);margin-top:3px}}
section{{margin-top:34px}}
h2{{font:600 10px/1.2 'Geist',sans-serif;letter-spacing:.18em;text-transform:uppercase;color:var(--gold);margin:0 0 10px}}
h3{{font-size:15px;margin:0 0 6px}}
p{{margin:0 0 12px;color:#2c2a25}}
.lede{{max-width:760px;font-size:16px;line-height:1.55}}
.grid3{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}
.step{{border-top:1px solid var(--ink);padding-top:10px}}
.step p{{font-size:13px;color:var(--muted)}}
.split{{display:grid;grid-template-columns:1.2fr .8fr;gap:28px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line)}}
th{{width:31%;font-weight:500;color:var(--muted)}}
.mono{{font-family:'Geist Mono','DejaVu Sans Mono',monospace;font-size:11px;overflow-wrap:anywhere}}
.arch{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;border-top:1px solid var(--ink);padding-top:14px}}
.node{{position:relative;padding:13px 12px;background:#fff;border:1px solid var(--line)}}
.node:not(:last-child)::after{{content:'→';position:absolute;right:-11px;top:50%;transform:translateY(-50%);color:var(--gold);font-size:16px}}
.node b{{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:var(--brand)}}
.node p{{font-size:12px;color:var(--muted);margin:5px 0 0}}
.chart{{background:#fff;border:1px solid var(--line);padding:16px}}
.bar{{display:flex;align-items:center;gap:10px;font-size:12px;margin-top:9px}}
.bar .lab{{width:80px;flex:none}}
.bar .track{{flex:1;height:8px;background:#ece5d3}}
.bar .track i{{display:block;height:100%;background:var(--brand)}}
.bar .val{{width:76px;text-align:right;flex:none;font-variant-numeric:tabular-nums}}
.note{{font-size:12px;color:var(--muted);margin-top:8px}}
.tranches{{display:flex;border:1px solid var(--line);background:#fff}}
.tranche{{padding:16px;border-right:1px solid var(--line);flex:1}}
.tranche:last-child{{border-right:0}}
.tranche b{{display:block;font-size:10px;letter-spacing:.16em;color:var(--gold)}}
.tranche span{{display:block;font-family:'Instrument',serif;font-size:26px;margin-top:6px}}
.fundbar{{display:flex;height:22px;margin:10px 0 8px}}
.fundbar i{{display:block;height:100%}}
.fundbar i:nth-child(1){{background:#145c44}}.fundbar i:nth-child(2){{background:#8a6d1f}}.fundbar i:nth-child(3){{background:#b9a46a}}.fundbar i:nth-child(4){{background:#d9d2be}}
.fundlegend{{display:flex;flex-wrap:wrap;gap:8px 16px;font-size:11px;color:var(--muted)}}
.fundlegend i{{display:inline-block;width:8px;height:8px;margin-right:5px;background:var(--brand)}}
.fundlegend span:nth-child(2) i{{background:var(--gold)}}.fundlegend span:nth-child(3) i{{background:#b9a46a}}.fundlegend span:nth-child(4) i{{background:#d9d2be}}
ul{{margin:0;padding-left:18px}} li{{margin:4px 0}} a{{color:var(--brand)}}
footer{{margin-top:40px;border-top:1px solid var(--line);padding-top:12px;display:flex;justify-content:space-between;font-size:11px;color:var(--muted)}}
@media(max-width:760px){{.page{{padding:22px 16px 30px}}.metrics{{grid-template-columns:repeat(2,1fr)}}.metric:nth-child(2n){{border-right:0}}.grid3,.split,.arch{{grid-template-columns:1fr}}.claim{{font-size:23px}}.mark{{font-size:34px}}.node:not(:last-child)::after{{display:none}}}}
@media print{{@page{{size:A4;margin:12mm}}body{{font-size:9.5pt}}.page{{max-width:none;padding:0}}section{{break-inside:avoid}}}}
</style></head>
<body><main class="page">
<header><div class="mark">{t(c["title"])}<small>{t(c["eyebrow"])}</small></div><div class="contact"><b>Juan Luna</b><br>juan.c.luna04@gmail.com<br>aegislatent.com</div></header>
<p class="claim">{t(c["claim"])}</p>
<h2>{t(c["metrics_title"])}</h2>
<div class="metrics">{metrics}</div>
<section><h2>{t(c["product_title"])}</h2><p class="lede">{t(c["product_lead"])}</p><div class="grid3">{cards}</div></section>
<section><h2>{t(c["aws_title"])}</h2><p class="lede">{t(c["aws_lead"])}</p><div class="split"><table>{aws_rows}</table><div class="arch">{arch}</div></div></section>
<section><h2>{t(c["release_title"])}</h2><p class="lede">{t(c["release_lead"])}</p><table>{release_rows}</table></section>
<section><h2>{t(c["business_title"])}</h2><p class="lede">{t(c["business_lead"])}</p><div class="split"><div><h3>{t(c["plans_title"])}</h3><div class="chart">{plans}<p class="note">{t(c["plans_note"])}</p></div></div><div><h3>{t(c["unit_title"])}</h3><div class="chart"><p style="font-family:'Instrument',serif;font-size:34px;margin:0">${t(c["unit_note"]).split(" ")[0]}</p><div class="bar"><span class="lab">Unit cost</span><span class="track"><i style="width:4%"></i></span><span class="val">${esc(v["cost"])}</span></div><p class="note">{t(c["unit_note"])}</p></div></div></div></section>
<section><h2>{t(c["raise_title"])}</h2><p class="lede">{t(c["raise_body"])}</p><div class="tranches">{tranches}</div><h3 style="margin-top:20px">{t(c["funds_title"])}</h3><div class="fundbar">{fund_bar}</div><div class="fundlegend">{fund_legend}</div><p class="note">{t(c["funds_note"])}</p></section>
<section><h2>{t(c["data_title"])}</h2><p class="lede">{t(c["data_lead"])}</p><ul>{links}</ul></section>
<footer><span>{t(c["footer"])}</span><span>aegislatent.com · v{esc(v["version"])}</span></footer>
</main></body></html>"""


def main() -> int:
    check = "--check" in __import__("sys").argv
    OUT.mkdir(exist_ok=True)
    data = load_facts()
    stale = 0
    for locale in ("en", "es"):
        path = OUT / f"aegis-aws-edition-{locale}.html"
        rendered = render(locale, data)
        if check:
            current = path.read_text(encoding="utf-8") if path.is_file() else ""
            if current != rendered:
                print(f"stale {path.name}")
                stale += 1
        else:
            path.write_text(rendered, encoding="utf-8")
            print(f"wrote {path.name} ({path.stat().st_size} bytes)")
    if check:
        if stale:
            return 1
        print("aws edition: up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
