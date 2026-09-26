#!/usr/bin/env python3
"""Aegis Latent Core — investor financial engine (Mission Order XV).

One deterministic script produces every number in deliverables D3-D7 and all
six charts. Nothing is typed into the memo by hand: the memo quotes
``model_outputs.json`` and ``model_tables.md``, which this script writes.

    python aegis_financial_engine.py --out ./out
    python aegis_financial_engine.py --out ./out_es --lang es

Determinism: seed=42 (numpy Generator), matplotlib Agg backend (headless),
no network, no wall-clock values in the outputs.

Languages: ``--lang es`` renders the charts and tables in Rioplatense Spanish,
with Argentine number format and every US-dollar amount followed by its peso
equivalent at the VERIFIED BCRA rate (``fx_ars_per_usd``). The model itself
runs in USD in both languages, so ``model_outputs.json`` is byte-identical.

Tags on every input:
  VERIFIED    read back from a primary source or a retained repo artifact
  MODEL       an assumption stated inline, derived or owner-supplied
  HYPOTHESIS  untested; the experiment that would validate it is stated
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.patches import Rectangle, Wedge  # noqa: E402

SEED = 42
YEARS = [1, 2, 3, 4, 5]  # FY1 = Oct 2026 - Sep 2027
SCEN = ["bear", "base", "bull"]

# ---------------------------------------------------------------------------
# 0. Tagged inputs
# ---------------------------------------------------------------------------
INPUTS: dict[str, dict] = {}
LANG = "en"  # set by --lang; changes presentation only, never a number


def inp(key: str, value, tag: str, note: str, note_es: str):
    INPUTS[key] = {"value": value, "tag": tag, "note": note, "note_es": note_es}
    return value


# VERIFIED -------------------------------------------------------------------
HSM_B1_HOURLY = inp(
    "hsm_b1_hourly_usd",
    3.20,
    "VERIFIED",
    "Azure Retail Prices API, 'Key Vault HSM Pool' Standard B1, eastus, "
    "meterId 74a72b91-1389-578c-b534-d4c204e6e37d, read 2026-09-25",
    "API Azure Retail Prices, 'Key Vault HSM Pool' Standard B1, eastus, "
    "meterId 74a72b91-1389-578c-b534-d4c204e6e37d, consultada el 25/09/2026",
)
HSM_B1_MONTH = inp(
    "hsm_b1_month_usd",
    round(HSM_B1_HOURLY * 732, 2),
    "VERIFIED",
    "3.20 USD/h x 732 h (30.5-day month) = 2,342.40; excluded by design",
    "3,20 USD/h x 732 h (mes de 30,5 días) = 2.342,40; excluido por diseño",
)
VM_D4_HOURLY = inp(
    "vm_d4s_v5_hourly_usd",
    0.192,
    "VERIFIED",
    "Azure Retail Prices API, Standard_D4s_v5 Linux, eastus, "
    "meterId db8c0962-f3f8-5b44-99aa-f3c7c1e668c8, read 2026-09-25",
    "API Azure Retail Prices, Standard_D4s_v5 Linux, eastus, "
    "meterId db8c0962-f3f8-5b44-99aa-f3c7c1e668c8, consultada el 25/09/2026",
)
BLOB_GB_MONTH = inp(
    "blob_hot_lrs_gb_month_usd",
    0.0208,
    "VERIFIED",
    "Azure Retail Prices API, Blob Hot LRS data stored, first tier, eastus, "
    "meterId 272492b3-1c92-4a5f-bee9-52a8e10ca514, read 2026-09-25",
    "API Azure Retail Prices, Blob Hot LRS, datos almacenados, primer tramo, eastus, "
    "meterId 272492b3-1c92-4a5f-bee9-52a8e10ca514, consultada el 25/09/2026",
)
FX_ARS = inp(
    "fx_ars_per_usd",
    1519.50,
    "VERIFIED",
    "BCRA API Estadisticas Cambiarias v1.0, Cotizaciones/USD, date 2026-09-24 (tipoCotizacion), "
    "read 2026-09-25; used only by the Spanish edition to show pesos in parentheses",
    "API del BCRA Estadísticas Cambiarias v1.0, Cotizaciones/USD, fecha 24/09/2026 (tipoCotizacion), "
    "consultada el 25/09/2026; solo la usa la edición en castellano para mostrar pesos entre paréntesis",
)
AZURE_VM_HOURLY = inp(
    "azure_b2als_v2_chilecentral_hourly_usd",
    0.0526,
    "VERIFIED",
    "evidence/benchmarks/azure/azure_Standard_B2als_v2_chilecentral_2026-09-26.json "
    "(SHA-256 762016d9...); retail list price fetched via aegis_azure_kit.py estimate, "
    "2026-09-26; VM only, excludes the attached disk",
    "evidence/benchmarks/azure/azure_Standard_B2als_v2_chilecentral_2026-09-26.json "
    "(SHA-256 762016d9...); precio de lista obtenido con aegis_azure_kit.py estimate, "
    "26/09/2026; solo la VM, sin el disco adjunto",
)
THROUGHPUT_100T = inp(
    "commits_per_s_100_threads",
    1482.37,
    "VERIFIED",
    "evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json, 4 vCPU shared VM, "
    "commit_forensic incl. MMR append + HMAC + WAL fsync",
    "evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json, VM compartida de 4 vCPU, "
    "commit_forensic con append al MMR + HMAC + fsync del WAL",
)
COMMIT_P50_MS = inp(
    "commit_p50_ms", 0.617, "VERIFIED", "same artifact, n=1000", "mismo artefacto, n=1000"
)
COMMIT_P99_MS = inp(
    "commit_p99_ms", 1.216, "VERIFIED", "same artifact, n=1000", "mismo artefacto, n=1000"
)
TESTS_PASSED = inp(
    "tests_passed",
    7550,
    "VERIFIED",
    "pytest -n auto on the 5.0.1 tree, 2026-09-24: 7,550 passed, 41 skipped, 0 failed",
    "pytest -n auto sobre el árbol 5.0.1, 24/09/2026: 7.550 aprobadas, 41 omitidas, 0 fallidas",
)
CLAIMS = inp(
    "claims_registered",
    112,
    "VERIFIED",
    "scripts/verify_claims.py, 2026-09-25: 0 findings",
    "scripts/verify_claims.py, 25/09/2026: 0 hallazgos",
)
UNSUPPORTED = inp(
    "claims_refused",
    70,
    "VERIFIED",
    "docs/institutional/UNSUPPORTED_CLAIMS.md rows",
    "filas de docs/institutional/UNSUPPORTED_CLAIMS.md",
)
TEST_SRC = inp(
    "test_to_source_loc",
    1.24,
    "VERIFIED",
    "87,557 test LOC / 70,672 Python source LOC (aegis + aegis_server), 2026-09-25",
    "87.557 líneas de prueba / 70.672 líneas de código Python (aegis + aegis_server), 25/09/2026",
)
ORPHANS = inp(
    "orphan_modules_disclosed",
    77,
    "VERIFIED",
    "scripts/import_reachability_allowlist.txt entries, of ~207 aegis modules",
    "entradas de scripts/import_reachability_allowlist.txt, sobre ~207 módulos de aegis",
)

# MODEL ----------------------------------------------------------------------
AZ_TYPICAL = inp(
    "azure_typical_month_usd",
    17.54,
    "MODEL",
    "owner-supplied planning input; cited evidence file is absent from the repo "
    "(docs/REGISTRY_HUMAN_PACK.md) -> downgraded from VERIFIED",
    "dato de planificación del fundador; el archivo de evidencia citado no está en el repositorio "
    "(docs/REGISTRY_HUMAN_PACK.md) -> baja de VERIFIED a MODEL",
)
AZ_WORST = inp(
    "azure_worst_month_usd",
    44.77,
    "MODEL",
    "owner-supplied, same status",
    "dato del fundador, mismo estado",
)
CREDIT = inp(
    "azure_credit_usd",
    200.0,
    "MODEL",
    "Founders Hub credit, owner-stated",
    "crédito de Founders Hub, según el fundador",
)
HUMAN_FIXED = inp(
    "human_fixed_cash_month_usd", 100.0, "MODEL", "owner prior", "supuesto previo del fundador"
)
CAC_FOUNDER = inp(
    "cac_founder_led_usd",
    6400.0,
    "MODEL",
    "prior: founder-led, per paying customer",
    "supuesto previo: venta liderada por el fundador, por cliente que paga",
)
CHURN_PRIOR = inp(
    "churn_prior",
    0.40,
    "MODEL",
    "annual logo churn prior",
    "supuesto previo de churn anual de clientes",
)
CM_PRIOR = inp("contribution_margin_prior", 0.90, "MODEL", "prior", "supuesto previo")
LTV_PRIOR = inp(
    "ltv_prior_usd", 33750.0, "MODEL", "prior at 40% churn", "supuesto previo con churn del 40%"
)
ACV_IMPLIED = inp(
    "acv_implied_by_prior_usd",
    LTV_PRIOR * CHURN_PRIOR / CM_PRIOR,
    "MODEL",
    "LTV x churn / CM = 15,000 (derived)",
    "LTV x churn / MC = 15.000 (derivado)",
)
PAYBACK_PRIOR = inp(
    "payback_prior_months", 6.3, "MODEL", "prior as supplied", "supuesto previo tal como se recibió"
)
SUPPORT_PER_CUST = inp(
    "support_cost_per_customer_year",
    4000.0,
    "MODEL",
    "0.05 FTE of an 80k senior; self-hosted product",
    "0,05 FTE de un senior de 80 mil; producto autoalojado",
)
HOSTING_PER_CUST = inp(
    "hosting_per_customer_year",
    round(AZ_WORST * 12, 2),
    "MODEL",
    "one staging/demo environment at the worst-case Azure month",
    "un entorno de staging/demo al costo mensual de Azure del peor caso",
)
PILOT_DELIVERY = inp(
    "pilot_delivery_cost_share",
    0.25,
    "MODEL",
    "founder/SE time + travel",
    "tiempo del fundador/ingeniero de soluciones + viajes",
)
PAYMENT_FEES = inp(
    "payment_fee_share",
    0.03,
    "MODEL",
    "cards/wires/FX spread",
    "tarjetas/transferencias/diferencial cambiario",
)
RECORD_BYTES = inp(
    "evidence_record_bytes",
    1500,
    "MODEL",
    "WAL JSONL line incl. MMR and signature",
    "línea JSONL del WAL con MMR y firma",
)
RETENTION_MONTHS = inp(
    "retention_months",
    60,
    "MODEL",
    "MiFID II Art 16(7) five-year horizon",
    "horizonte de cinco años de MiFID II art. 16(7)",
)
HOSTED_UTIL = inp(
    "hosted_vm_utilisation",
    0.30,
    "MODEL",
    "average utilisation of a hosted node",
    "utilización promedio de un nodo alojado",
)
DSO_DAYS = inp(
    "dso_days", 45, "MODEL", "enterprise net-30/45 terms", "plazos empresariales de 30/45 días"
)
DEFERRED_SHARE = inp(
    "deferred_revenue_share_of_arr",
    0.50,
    "MODEL",
    "annual upfront billing, mid-term",
    "facturación anual por adelantado, a mitad de período",
)
TAX_RATE = inp(
    "tax_rate",
    0.25,
    "MODEL",
    "applied only once cumulative EBT > 0",
    "se aplica solo cuando el resultado antes de impuestos acumulado es > 0",
)
COMMISSION = inp("commission_share_of_new_acv", 0.08, "MODEL", "", "")
CONTINGENCY = inp("opex_contingency", 0.10, "MODEL", "", "")
ENG_WEEK = inp(
    "engineering_week_usd",
    2300.0,
    "MODEL",
    "110k loaded / 48 weeks",
    "110 mil con cargas / 48 semanas",
)
SCORECARD_REF = inp(
    "scorecard_reference_usd",
    10.0e6,
    "MODEL",
    "pre-seed post-money SAFE-cap reference (press-reported US medians); range 8-12M",
    "referencia de tope post-money de SAFE pre-semilla (medianas de EE. UU. informadas por la prensa); rango 8-12 M",
)
EXIT_MULT = inp(
    "exit_arr_multiple",
    {"bear": 4.0, "base": 8.0, "bull": 12.0},
    "MODEL",
    "private security-software M&A range (not strategic-premium comps)",
    "rango de M&A privado de software de seguridad (sin comparables con prima estratégica)",
)
VC_TARGET = inp("vc_target_multiple", 10.0, "MODEL", "mission spec", "especificación de la misión")
VC_STAGE = inp(
    "vc_stage_discount",
    0.60,
    "MODEL",
    "mission spec: applied as a 0.40 retention factor",
    "especificación de la misión: se aplica como factor de retención de 0,40",
)
DCF_RATE = inp("dcf_discount_rate", 0.25, "MODEL", "mission spec", "especificación de la misión")
SCEN_P = inp(
    "scenario_probabilities",
    {"bear": 0.45, "base": 0.40, "bull": 0.15},
    "MODEL",
    "audit 51/100 ~ P(base or better)=0.55; bull capped at 0.15 with zero buyer interviews",
    "auditoría 51/100 ~ P(base o mejor)=0,55; el optimista se limita a 0,15 sin entrevistas con compradores",
)
AUDIT = inp(
    "audit_bands",
    {
        "replacement": (1.8e6, 11.0e6),
        "asset_floor": (0.65e6, 3.1e6),
        "seed_today": (8.0e6, 15.0e6),
        "post_conditions": (18.0e6, 28.0e6),
        "series_a": (30.0e6, 60.0e6),
        "score": 51,
    },
    "MODEL",
    "[AUDIT] executed independent audit, as supplied",
    "[AUDIT] auditoría independiente realizada, tal como se recibió",
)
RAISE = inp(
    "raise_usd",
    {"T1": 300_000, "T2": 250_000, "T3": 200_000},
    "MODEL",
    "tranche-gated SAFE, sized to the 18-month plan + contingency",
    "SAFE por tramos atados a hitos, dimensionado al plan de 18 meses + contingencia",
)
CAPS = inp(
    "post_money_caps_usd",
    {"T1": 6.0e6, "T2": 8.0e6, "T3": 10.0e6},
    "MODEL",
    "milestone step-up: T1 at the haircut-now value, T2 at the [AUDIT] floor, T3 above it",
    "escalonado por hitos: T1 al valor con descuentos de hoy, T2 en el piso [AUDIT], T3 por encima",
)

# HYPOTHESIS -------------------------------------------------------------------
PRICING = inp(
    "pricing",
    {
        "pilot": (2500, 30000),
        "mid": (25000, 75000),
        "ent": (95000, 175000),
        "mgt": {"10-50M": 1500, "50-250M": 950, "250M+": 500},
    },
    "HYPOTHESIS",
    "zero buyer interviews; validate with 3 interviews + 1 paid pilot (REG-H06)",
    "cero entrevistas con compradores; se valida con 3 entrevistas + 1 piloto pago (REG-H06)",
)
CHANNEL_CAC = inp(
    "channel_cac_usd",
    {"founder_outbound": 6400, "oss_inbound": 2000, "partner_si": 9000, "events_paid": 18000},
    "HYPOTHESIS",
    "founder-led is the MODEL prior; the rest untested",
    "la venta del fundador es el supuesto previo MODEL; el resto no se probó",
)
CHANNEL_MIX = inp(
    "channel_mix",
    {"founder_outbound": 0.50, "oss_inbound": 0.30, "partner_si": 0.15, "events_paid": 0.05},
    "HYPOTHESIS",
    "",
    "",
)
SCN = inp(
    "scenarios",
    {
        "bear": {
            "pilots": [2, 4, 6, 8, 10],
            "pilot_price": 5000,
            "conv": 0.30,
            "acv": [20e3, 25e3, 30e3, 35e3, 40e3],
            "churn": 0.55,
            "exp": 0.00,
        },
        "base": {
            "pilots": [4, 8, 12, 16, 20],
            "pilot_price": 10000,
            "conv": 0.50,
            "acv": [30e3, 40e3, 50e3, 60e3, 70e3],
            "churn": 0.40,
            "exp": 0.10,
        },
        "bull": {
            "pilots": [6, 12, 18, 24, 30],
            "pilot_price": 15000,
            "conv": 0.65,
            "acv": [40e3, 60e3, 80e3, 100e3, 120e3],
            "churn": 0.25,
            "exp": 0.20,
        },
    },
    "HYPOTHESIS",
    "pilots, conversion, ACV path, churn, expansion per scenario",
    "pilotos, conversión, trayectoria del ACV, churn y expansión por escenario",
)

# ---------------------------------------------------------------------------
# 0b. Presentation language (numbers are identical in both languages)
# ---------------------------------------------------------------------------
SCN_ES = {"bear": "pesimista", "base": "base", "bull": "optimista"}


def _swap(s: str) -> str:
    """English digit grouping to Argentine: '1,234.5' -> '1.234,5'."""
    return s.translate(str.maketrans({",": ".", ".": ","}))


def nfmt(v: float, spec: str) -> str:
    """A number in the active language's format."""
    s = format(v, spec)
    return _swap(s) if LANG == "es" else s


def _ars_parts(x: float, ref: float) -> tuple[str, str]:
    a = abs(ref)
    if a >= 1e8:
        return f"{x / 1e6:,.0f}", " M"
    if a >= 1e6:
        return f"{x / 1e6:,.1f}", " M"
    if a >= 1e3:
        return f"{x:,.0f}", ""
    return f"{x:,.2f}", ""


def ars_num(x: float) -> str:
    """A non-negative peso amount, Argentine format ('M' = millones)."""
    n, u = _ars_parts(x, x)
    return _swap(n) + u


def ars_rng(lo_usd: float, hi_usd: float) -> str:
    """Peso range for a dollar range, one unit for both ends."""
    lo, hi = lo_usd * FX_ARS, hi_usd * FX_ARS
    n1, _ = _ars_parts(lo, hi)
    n2, u = _ars_parts(hi, hi)
    return f"{_swap(n1)}–{_swap(n2)}{u}"


def dol(v: float, spec: str = ",.2f") -> str:
    """Plain-dollar table cell: EN '$1,500'; ES 'US$ 1.500 (ARS 2,3 M)'."""
    if LANG == "en":
        return "$" + format(v, spec)
    sign = "−" if v < 0 else ""
    return f"{sign}US$ {nfmt(abs(v), spec)} ({sign}ARS {ars_num(abs(v) * FX_ARS)})"


ES = {
    # charts
    "Monte Carlo P10-P90 (seed 42, n=5,000)": "Monte Carlo P10-P90 (semilla 42, n=5.000)",
    "probability-weighted": "ponderado por probabilidad",
    "ARR by fiscal year — scenario fan [MODEL/HYPOTHESIS]": "ARR por año fiscal — abanico de escenarios [MODEL/HYPOTHESIS]",
    "Fiscal year (FY1 = Oct 2026 – Sep 2027)": "Año fiscal (AF1 = oct 2026 – sep 2027)",
    "ARR, $M": "ARR, millones de US\\$",
    "2nd maintainer": "2.º mantenedor",
    "Go-to-market": "Salida al mercado",
    "Assurance": "Aseguramiento",
    "Legal & corporate": "Legal y societario",
    "Founder salary": "Sueldo del fundador",
    "Infra & G&A": "Infra y G&A",
    "Recruiting": "Reclutamiento",
    "Contingency": "Contingencia",
    "Raise (T1+T2+T3)": "Ronda (T1+T2+T3)",
    "Buffer at M18": "Colchón al mes 18",
    "18-month use of funds — burn waterfall [MODEL]": "Uso de fondos a 18 meses — cascada de consumo [MODEL]",
    "USD": "US\\$",
    "ACV (mid-market)": "ACV\n(mercado medio)",
    "COGS": "COGS",
    "Gross profit / yr": "Ganancia\nbruta por año",
    "x 2.5-yr life\n(40% churn)": "x 2,5 años de vida\n(churn 40%)",
    "LTV": "LTV",
    "CAC": "CAC",
    "Net value / customer": "Valor neto\npor cliente",
    "EU Horizon TRL (filled = achieved with cited evidence; hatched = 12-month target)": "TRL de EU Horizon (lleno = alcanzado con evidencia citada; rayado = meta a 12 meses)",
    "Technology readiness by component [VERIFIED evidence, MODEL levels]": "Madurez tecnológica por componente [evidencia VERIFIED, niveles MODEL]",
    "VC method (bear–bull)": "Método VC (pesimista–optimista)",
    "DCF, base FCF @25% (6–10x exit)": "DCF, FCF base al 25% (salida 6–10x)",
    "Berkus, audit-adjusted": "Berkus, ajustado por auditoría",
    "Scorecard, audit-adjusted": "Scorecard, ajustado por auditoría",
    "Asset-sale floor [AUDIT]": "Piso de venta de activos [AUDIT]",
    "Replacement cost + corpus premium": "Costo de reposición + prima del corpus",
    "Haircut table (now → after gates)": "Tabla de descuentos (hoy → tras los hitos)",
    "Valuation football field — pre-money, $M": "Football field de valuación — pre-money, millones de US\\$",
    "$M": "millones de US\\$",
    "fx_note": "ARS entre paréntesis = US\\$ × 1.519,50 (cotización del BCRA, 24/09/2026) [VERIFIED]; "
    "no proyecta inflación ni devaluación.",
    # tables
    "Tier": "Nivel",
    "CM": "MC",
    "Payback (mo)": "Payback (meses)",
    "Blended prior": "Base combinada (supuesto previo §0)",
    "Mid-market": "Mercado medio",
    "Enterprise": "Gran empresa",
    "Pilot (one-off)": "Piloto (único)",
    "n/a": "n/d",
    "Channel": "Canal",
    "Mix": "Mezcla",
    "Blended": "Combinado",
    "Churn": "Churn",
    "Band": "Banda",
    "Price/MGT": "Precio/MGT",
    "Marginal cost/MGT": "Costo marginal/MGT",
    "Margin": "Margen",
    "Churn \\ ACV": "Churn \\ ACV",
    "Line": "Línea",
    "New customers": "Clientes nuevos",
    "Customers (end)": "Clientes (cierre)",
    "ARR (end)": "ARR (cierre)",
    "Revenue": "Ingresos",
    "Gross margin": "Margen bruto",
    "OpEx": "OpEx",
    "EBITDA": "EBITDA",
    "Net income": "Resultado neto",
    "CFO": "Flujo operativo (CFO)",
    "CFF (SAFE tranches)": "Flujo de financiación (tramos SAFE)",
    "Cash / (unfunded gap), close": "Caja / (brecha sin financiar), cierre",
    "AR": "Cuentas por cobrar",
    "Deferred revenue": "Ingresos diferidos",
    "Equity (paid-in + retained)": "Patrimonio (aportes + resultados)",
    "Balance check (A−L−E)": "Control de balance (A−P−PN)",
    "Headcount": "Dotación",
    "Burn multiple": "Burn multiple",
    "Magic number (proxy)": "Magic number (proxy)",
    "Item": "Ítem",
    "Typical": "Típico",
    "Worst": "Peor caso",
    "Azure / month": "Azure / mes",
    "Credit runway (months)": "Autonomía del crédito (meses)",
    "Cash burn while credit lasts": "Consumo de caja mientras dura el crédito",
    "Cash burn after credit": "Consumo de caja después del crédito",
    "Managed HSM B1 (excluded)": "Managed HSM B1 (excluido)",
    "Alert": "Alerta",
    "Spend": "Gasto",
    "Month @typical": "Mes @típico",
    "Month @worst": "Mes @peor caso",
    "Capital": "Capital",
    "0 clients": "0 clientes",
    "1 client": "1 cliente",
    "3 clients": "3 clientes",
    "all tranches": "todos los tramos",
    "T1 only": "solo T1",
    "Workstream": "Frente de trabajo",
    "Share": "Participación",
    "Engineering continuity (2nd maintainer, 16 mo)": "Continuidad de ingeniería (2.º mantenedor, 16 meses)",
    "Go-to-market (solutions engineer 12 mo + design-partner program)": "Salida al mercado (ingeniero de soluciones 12 meses + programa de clientes de diseño)",
    "Assurance (pen test + retest, SOC 2 Type I, escrow)": "Aseguramiento (pentest + retest, SOC 2 Tipo I, escrow)",
    "Legal & corporate (entity, IP, licence, regulatory, AI-authorship opinion)": "Legal y societario (sociedad, PI, licencia, regulatorio, dictamen de autoría con IA)",
    "Founder salary (18 mo)": "Sueldo del fundador (18 meses)",
    "Infra, tools, insurance, accounting (18 mo)": "Infraestructura, herramientas, seguros, contabilidad (18 meses)",
    "Contingency (10%)": "Contingencia (10%)",
    "Total 18 months": "Total 18 meses",
    "Raise": "Ronda",
    "Scenario": "Escenario",
    "ARR FY5": "ARR AF5",
    "Exit multiple": "Múltiplo de salida",
    "Exit EV": "EV de salida",
    "Post-money": "Post-money",
    "Pre-money": "Pre-money",
    "Probability-weighted": "Ponderado por probabilidad",
    "Factor": "Factor",
    "Weight": "Peso",
    "Score vs average": "Puntaje vs. promedio",
    "Contribution": "Contribución",
    "Team": "Equipo",
    "Opportunity size": "Tamaño de la oportunidad",
    "Product/technology": "Producto/tecnología",
    "Competitive environment": "Entorno competitivo",
    "Sales channels/partnerships": "Canales de venta/alianzas",
    "Need for more capital": "Necesidad de más capital",
    "Other (jurisdiction, licence)": "Otros (jurisdicción, licencia)",
    "Factor total": "Factor total",
    "Element": "Elemento",
    "Score (0–1)": "Puntaje (0–1)",
    "Sound idea": "Idea sólida",
    "Prototype (audit 51/100)": "Prototipo (auditoría 51/100)",
    "Quality team": "Calidad del equipo",
    "Strategic relationships": "Relaciones estratégicas",
    "Product rollout/sales": "Lanzamiento/ventas",
    "Exit multiple on FY5 ARR": "Múltiplo de salida sobre ARR AF5",
    "PV(FCF FY1–5)": "VP(FCF AF1–5)",
    "Enterprise value": "Valor de empresa",
    "Haircut": "Descuento",
    "Now": "Hoy",
    "After gates": "Tras los hitos",
    "Gate that removes it": "Hito que lo elimina",
    "Bus factor 1": "Bus factor 1",
    "AGPL friction": "Fricción por AGPL",
    "Zero revenue": "Cero ingresos",
    "No third-party audit": "Sin auditoría de terceros",
    "Single geography": "Una sola geografía",
    "FX / Argentina jurisdiction": "Cambio / jurisdicción Argentina",
    "second maintainer hired + escrow executed": "segundo mantenedor contratado + escrow firmado",
    "commercial licence counsel + one executed commercial licence": "abogado de licencias + una licencia comercial firmada",
    "two paid design partners": "dos clientes de diseño pagos",
    "pen test report with criticals remediated": "informe de pentest con los críticos corregidos",
    "one EU or US design partner": "un cliente de diseño en la UE o EE. UU.",
    "Delaware parent + USD contracts": "sociedad controlante en Delaware + contratos en dólares",
    "Resulting value": "Valor resultante",
    "Component": "Componente",
    "TRL now": "TRL hoy",
    "Evidence": "Evidencia",
    "Gap to TRL+1": "Brecha a TRL+1",
    "Eng weeks": "Semanas de ingeniería",
    "External $": "Externo",
    "Cost to close": "Costo de cierre",
    "Percentile": "Percentil",
}


def tr(s: str) -> str:
    """Strict: in Spanish a missing string is an error, never a silent English leak."""
    return ES[s] if LANG == "es" else s


# ---------------------------------------------------------------------------
# 1. Unit economics (D3)
# ---------------------------------------------------------------------------


def ltv(acv: float, cm: float, churn: float) -> float:
    return acv * cm / churn


def unit_economics() -> dict:
    tiers = {
        "Blended prior": {
            "acv": ACV_IMPLIED,
            "cogs": ACV_IMPLIED * (1 - CM_PRIOR),
            "cac": CAC_FOUNDER,
        },
        "Mid-market": {
            "acv": 50_000.0,
            "cogs": SUPPORT_PER_CUST + HOSTING_PER_CUST,
            "cac": 12_500.0,
        },
        "Enterprise": {
            "acv": 135_000.0 + 15_000.0,  # 10 MGT above the included 10M at $1,500
            "cogs": 12_000.0 + HOSTING_PER_CUST + 2_000.0,
            "cac": 33_750.0,
        },
        "Pilot (one-off)": {"acv": 10_000.0, "cogs": 10_000.0 * PILOT_DELIVERY, "cac": 0.0},
    }
    out = {}
    for name, t in tiers.items():
        cm = 1 - t["cogs"] / t["acv"]
        row = {"acv": t["acv"], "cm": cm, "cac": t["cac"]}
        for c in (0.25, 0.40, 0.55):
            row[f"ltv_{int(c * 100)}"] = (
                ltv(t["acv"], cm, c) if name != "Pilot (one-off)" else t["acv"] * cm
            )
        row["payback_months"] = (t["cac"] / (t["acv"] * cm / 12)) if t["cac"] else 0.0
        row["ltv_cac_40"] = row["ltv_40"] / t["cac"] if t["cac"] else None
        out[name] = row
    blended_cac = sum(CHANNEL_CAC[k] * CHANNEL_MIX[k] for k in CHANNEL_CAC)
    # MGT overage economics, Aegis-hosted marginal cost per million governed transactions
    secs = 1e6 / THROUGHPUT_100T
    compute = secs / 3600 * VM_D4_HOURLY / HOSTED_UTIL
    storage = 1e6 * RECORD_BYTES / 1e9 * BLOB_GB_MONTH * RETENTION_MONTHS
    mgt_cost = compute + storage
    mgt = {
        band: {"price": p, "marginal_cost_hosted": mgt_cost, "margin": 1 - mgt_cost / p}
        for band, p in PRICING["mgt"].items()
    }
    # sensitivity grid churn x ACV, CAC = max(founder prior, 25% of ACV)
    grid = {}
    for c in (0.25, 0.40, 0.55):
        grid[c] = {}
        for a in (15e3, 25e3, 50e3, 75e3, 135e3):
            cac = max(CAC_FOUNDER, 0.25 * a)
            lv = ltv(a, CM_PRIOR, c)
            grid[c][a] = {"ltv": lv, "ltv_cac": lv / cac, "cac": cac}
    payback_recomputed = CAC_FOUNDER / (ACV_IMPLIED * CM_PRIOR / 12)
    # stress: enterprise-style CAC equal to first-year ACV
    stress = {c: ltv(1.0, CM_PRIOR, c) / 1.0 for c in (0.25, 0.40, 0.55)}
    return {
        "tiers": out,
        "blended_cac": blended_cac,
        "mgt": mgt,
        "mgt_compute": compute,
        "mgt_storage": storage,
        "grid": grid,
        "payback_recomputed": payback_recomputed,
        "cac_stress_ltv_cac": stress,
    }


# ---------------------------------------------------------------------------
# 2. Five-year three-statement model (D4)
# ---------------------------------------------------------------------------
HIRES = {  # role: (annual loaded cost, {scenario: (start_year, fraction_of_start_year)})
    "Founder": (None, None),
    "Senior security engineer (2nd maintainer)": (
        110_000,
        {"bear": (1, 10 / 12), "base": (1, 10 / 12), "bull": (1, 10 / 12)},
    ),
    "Solutions engineer": (
        100_000,
        {"bear": (1, 6 / 12), "base": (1, 6 / 12), "bull": (1, 6 / 12)},
    ),
    "Engineer #2": (110_000, {"base": (3, 1.0), "bull": (2, 1.0)}),
    "Account executive #1": (120_000, {"base": (3, 1.0), "bull": (2, 1.0)}),
    "Customer success": (70_000, {"base": (4, 1.0), "bull": (3, 1.0)}),
    "Engineer #3": (115_000, {"base": (4, 1.0), "bull": (3, 1.0)}),
    "Account executive #2": (125_000, {"base": (5, 1.0), "bull": (4, 1.0)}),
    "Engineer #4": (115_000, {"base": (5, 1.0), "bull": (4, 1.0)}),
    "Engineer #5": (120_000, {"bull": (5, 1.0)}),
    "Account executive #3": (130_000, {"bull": (5, 1.0)}),
}
FOUNDER_PAY = [36_000, 60_000, 90_000, 95_000, 100_000]
BEAR_SE_END_YEAR = 2  # bear cuts the solutions engineer after FY2


SALES_ROLES = {
    "Solutions engineer",
    "Account executive #1",
    "Account executive #2",
    "Account executive #3",
    "Customer success",
}


def headcount_cost(s: str, y: int, sales_only: bool = False) -> tuple[float, int]:
    cost = 0.0 if sales_only else FOUNDER_PAY[y - 1]
    heads = 0 if sales_only else 1
    for role, (annual, plan) in HIRES.items():
        if annual is None or s not in plan or (sales_only and role not in SALES_ROLES):
            continue
        start, frac = plan[s]
        if role == "Solutions engineer" and s == "bear" and y > BEAR_SE_END_YEAR:
            continue
        if y < start:
            continue
        raise_factor = 1.04 ** (y - start)
        cost += annual * raise_factor * (frac if y == start else 1.0)
        heads += 1
    return cost, heads


def opex_lines(s: str, y: int, new_acv: float, new_hires: int) -> dict:
    hc, heads = headcount_cost(s, y)
    travel_scale = {"bear": 0.6, "base": 1.0, "bull": 1.5}[s]
    lines = {
        "Headcount": hc,
        "Commissions": COMMISSION * new_acv,
        "Penetration testing": 22_000 if y == 1 else 18_000,  # REG-H01 15-25k
        "SOC 2 (Type I Y1, Type II after)": 35_000 if y == 1 else 50_000,  # REG-H02 20-80k/yr
        "Escrow": 7_500 + 3_000 if y == 1 else 3_000,  # REG-H03 5-10k setup
        "Legal & corporate": 32_000 if y == 1 else 15_000,  # entity/IP/licence/regulatory counsel
        "Insurance (cyber/E&O)": 6_000,
        "Accounting & tax (AR + US)": 9_000,
        "Tools & SaaS": 4_800,
        "Cloud (company)": (AZ_WORST * 12 + 250 * 12) * (1.10 ** (y - 1)),
        "Travel & design-partner program": travel_scale
        * [18_000, 30_000, 45_000, 60_000, 75_000][y - 1],
        "Recruiting": 8_000 * new_hires,
    }
    lines["Contingency"] = CONTINGENCY * sum(lines.values())
    return lines, heads


def three_statement(s: str) -> dict:
    p = SCN[s]
    arr_prev = cust_prev = 0.0
    heads_prev = 1
    cash = 0.0
    cum_ebt = 0.0
    paid_in = 0.0
    ar_prev = def_prev = 0.0
    tranche_by_year = {
        "bear": [RAISE["T1"] + RAISE["T2"], 0, 0, 0, 0],
        "base": [RAISE["T1"] + RAISE["T2"], RAISE["T3"], 0, 0, 0],
        "bull": [RAISE["T1"] + RAISE["T2"] + RAISE["T3"], 0, 0, 0, 0],
    }[s]
    rows = []
    min_cash, min_cash_year = 0.0, 0
    for y in YEARS:
        i = y - 1
        new_cust = p["pilots"][i] * p["conv"]
        new_acv = new_cust * p["acv"][i]
        arr = arr_prev * (1 - p["churn"]) * (1 + p["exp"]) + new_acv
        cust = cust_prev * (1 - p["churn"]) + new_cust
        rec_rev = arr_prev * (1 - p["churn"] / 2) * (1 + p["exp"] / 2) + new_acv * 0.5
        pilot_rev = p["pilots"][i] * p["pilot_price"]
        revenue = rec_rev + pilot_rev
        avg_cust = (cust_prev + cust) / 2
        cogs = (
            avg_cust * (SUPPORT_PER_CUST + HOSTING_PER_CUST)
            + pilot_rev * PILOT_DELIVERY
            + revenue * PAYMENT_FEES
        )
        gp = revenue - cogs
        _, heads_now = headcount_cost(s, y)
        new_hires = max(0, heads_now - heads_prev) if y > 1 else heads_now - 1
        ox, heads = opex_lines(s, y, new_acv, new_hires)
        opex = sum(ox.values())
        sm = (
            ox["Commissions"]
            + ox["Travel & design-partner program"]
            + headcount_cost(s, y, sales_only=True)[0]
        )
        ebitda = gp - opex
        cum_ebt += ebitda
        tax = TAX_RATE * ebitda if cum_ebt > 0 and ebitda > 0 else 0.0
        ni = ebitda - tax
        ar = revenue * DSO_DAYS / 365
        deferred = DEFERRED_SHARE * arr
        cfo = ni - (ar - ar_prev) + (deferred - def_prev)
        cff = tranche_by_year[i]
        paid_in += cff
        cash_open = cash
        cash = cash + cfo + cff
        if cash < min_cash:
            min_cash, min_cash_year = cash, y
        equity = paid_in + (cum_ebt - (0 if tax == 0 else 0)) - sum(r["tax"] for r in rows) - tax
        assets = cash + ar
        liabilities = deferred
        rows.append(
            {
                "year": y,
                "new_customers": new_cust,
                "customers_end": cust,
                "arr_end": arr,
                "new_arr": new_acv,
                "net_new_arr": arr - arr_prev,
                "recurring_revenue": rec_rev,
                "pilot_revenue": pilot_rev,
                "revenue": revenue,
                "cogs": cogs,
                "gross_profit": gp,
                "gross_margin": gp / revenue if revenue else 0.0,
                "opex": opex,
                "opex_lines": ox,
                "s_and_m": sm,
                "ebitda": ebitda,
                "tax": tax,
                "net_income": ni,
                "cfo": cfo,
                "cfi": 0.0,
                "cff": cff,
                "cash_open": cash_open,
                "cash_close": cash,
                "ar": ar,
                "deferred_revenue": deferred,
                "paid_in": paid_in,
                "equity": equity,
                "assets": assets,
                "liabilities": liabilities,
                "headcount": heads,
                "balance_check": round(assets - liabilities - equity, 2),
                "burn_multiple": (-(cfo) / (arr - arr_prev))
                if (arr - arr_prev) > 0 and cfo < 0
                else None,
                "magic_number": ((arr - arr_prev) / sm) if sm else None,
            }
        )
        arr_prev, cust_prev, ar_prev, def_prev, heads_prev = arr, cust, ar, deferred, heads
    return {
        "rows": rows,
        "min_cash": min_cash,
        "min_cash_year": min_cash_year,
        "funding_gap": -min_cash if min_cash < 0 else 0.0,
    }


# ---------------------------------------------------------------------------
# 3. Monte Carlo fan (seed=42) over the scenario hypotheses
# ---------------------------------------------------------------------------


def monte_carlo_arr(n: int = 5000) -> dict:
    rng = np.random.default_rng(SEED)
    b, m, u = SCN["bear"], SCN["base"], SCN["bull"]
    conv = rng.triangular(b["conv"], m["conv"], u["conv"], n)
    churn = rng.triangular(u["churn"], m["churn"], b["churn"], n)
    exp = rng.triangular(b["exp"], m["exp"], u["exp"], n)
    acv_scale = rng.triangular(0.67, 1.0, 1.6, n)
    pil_scale = rng.triangular(0.5, 1.0, 1.5, n)
    arr = np.zeros((n, len(YEARS) + 1))
    for y in YEARS:
        new = m["pilots"][y - 1] * pil_scale * conv * m["acv"][y - 1] * acv_scale
        arr[:, y] = arr[:, y - 1] * (1 - churn) * (1 + exp) + new
    return {
        "p10": np.percentile(arr, 10, axis=0).tolist(),
        "p50": np.percentile(arr, 50, axis=0).tolist(),
        "p90": np.percentile(arr, 90, axis=0).tolist(),
    }


# ---------------------------------------------------------------------------
# 4. Burn and runway (D5)
# ---------------------------------------------------------------------------


def burn_runway(models: dict) -> dict:
    pre = {
        "credit_runway_typical_months": CREDIT / AZ_TYPICAL,
        "credit_runway_worst_months": CREDIT / AZ_WORST,
        "cash_burn_while_credit_lasts": HUMAN_FIXED,
        "cash_burn_after_credit_typical": HUMAN_FIXED + AZ_TYPICAL,
        "cash_burn_after_credit_worst": HUMAN_FIXED + AZ_WORST,
        "alerts": {},
    }
    for pct in (0.50, 0.80, 0.95):
        pre["alerts"][f"{int(pct * 100)}%"] = {
            "usd": CREDIT * pct,
            "month_typical": CREDIT * pct / AZ_TYPICAL,
            "month_worst": CREDIT * pct / AZ_WORST,
        }
    base_rows = models["base"]["rows"]
    opex_m = (
        [base_rows[0]["opex"] / 12] * 12
        + [base_rows[1]["opex"] / 12] * 12
        + [base_rows[2]["opex"] / 12] * 24
    )
    contrib_per_client_m = 50_000 * (1 - (SUPPORT_PER_CUST + HOSTING_PER_CUST) / 50_000) / 12
    runway = {}
    for label, cash0 in (("all tranches", sum(RAISE.values())), ("T1 only", RAISE["T1"])):
        runway[label] = {}
        for clients in (0, 1, 3):
            cash, month = float(cash0), 0
            while cash > 0 and month < len(opex_m):
                cash -= opex_m[month] - clients * contrib_per_client_m
                month += 1
            runway[label][clients] = month if cash <= 0 else float(len(opex_m))
    avg18 = sum(opex_m[:18]) / 18
    return {
        "pre_funding": pre,
        "post_funding": runway,
        "avg_monthly_opex_18m": avg18,
        "contribution_per_client_month": contrib_per_client_m,
        "opex_monthly": opex_m[:36],
    }


# ---------------------------------------------------------------------------
# 5. Use of funds, 18 months (D7)
# ---------------------------------------------------------------------------


def use_of_funds() -> dict:
    ws = {
        "Engineering continuity (2nd maintainer, 16 mo)": 110_000 / 12 * 16,
        "Go-to-market (solutions engineer 12 mo + design-partner program)": 100_000 + 30_000,
        "Assurance (pen test + retest, SOC 2 Type I, escrow)": 22_000
        + 9_000
        + 35_000
        + 7_500
        + 3_000,
        "Legal & corporate (entity, IP, licence, regulatory, AI-authorship opinion)": 32_000
        + 7_500,
        "Founder salary (18 mo)": 36_000 + 30_000,
        "Infra, tools, insurance, accounting (18 mo)": (AZ_WORST + 250) * 18
        + 4_800 * 1.5
        + 6_000 * 1.5
        + 9_000 * 1.5,
        "Recruiting": 16_000,
    }
    sub = sum(ws.values())
    ws["Contingency (10%)"] = CONTINGENCY * sub
    total = sum(ws.values())
    return {
        "workstreams": ws,
        "total_18m": total,
        "raise": sum(RAISE.values()),
        "buffer": sum(RAISE.values()) - total,
    }


# ---------------------------------------------------------------------------
# 6. Valuation (D6)
# ---------------------------------------------------------------------------


def valuation(models: dict) -> dict:
    inv = sum(RAISE.values())
    vc = {}
    for s in SCEN:
        arr5 = models[s]["rows"][-1]["arr_end"]
        ev = arr5 * EXIT_MULT[s]
        post = ev / VC_TARGET * (1 - VC_STAGE)
        vc[s] = {"arr5": arr5, "exit_ev": ev, "post": post, "pre": max(0.0, post - inv)}
    vc_w = sum(SCEN_P[s] * vc[s]["pre"] for s in SCEN)
    weights = {
        "Team": 0.30,
        "Opportunity size": 0.25,
        "Product/technology": 0.15,
        "Competitive environment": 0.10,
        "Sales channels/partnerships": 0.10,
        "Need for more capital": 0.05,
        "Other (jurisdiction, licence)": 0.05,
    }
    scores = {
        "Team": 0.60,
        "Opportunity size": 1.40,
        "Product/technology": AUDIT["score"] / 50,
        "Competitive environment": 0.80,
        "Sales channels/partnerships": 0.40,
        "Need for more capital": 1.10,
        "Other (jurisdiction, licence)": 0.80,
    }
    factor = sum(weights[k] * scores[k] for k in weights)
    scorecard = {
        "factor": factor,
        "low": factor * 8.0e6,
        "mid": factor * SCORECARD_REF,
        "high": factor * 12.0e6,
        "weights": weights,
        "scores": scores,
    }
    berkus_elems = {
        "Sound idea": 0.70,
        "Prototype (audit 51/100)": AUDIT["score"] / 100,
        "Quality team": 0.30,
        "Strategic relationships": 0.10,
        "Product rollout/sales": 0.20,
    }
    bsum = sum(berkus_elems.values())
    berkus = {"elements": berkus_elems, "low": bsum * 0.5e6, "high": bsum * 1.0e6}
    repl = {"low": AUDIT["replacement"][0] * 1.10, "high": AUDIT["replacement"][1] * 1.25}
    base = models["base"]["rows"]
    fcf = [r["cfo"] + r["cfi"] for r in base]
    pv_fcf = sum(f / (1 + DCF_RATE) ** r["year"] for f, r in zip(fcf, base, strict=True))
    dcf = {}
    for mult in (6.0, 8.0, 10.0):
        tv = base[-1]["arr_end"] * mult
        dcf[mult] = pv_fcf + tv / (1 + DCF_RATE) ** 5
    haircuts = {
        "Bus factor 1": (0.20, 0.08, "second maintainer hired + escrow executed"),
        "AGPL friction": (
            0.07,
            0.04,
            "commercial licence counsel + one executed commercial licence",
        ),
        "Zero revenue": (0.25, 0.10, "two paid design partners"),
        "No third-party audit": (0.12, 0.03, "pen test report with criticals remediated"),
        "Single geography": (0.05, 0.03, "one EU or US design partner"),
        "FX / Argentina jurisdiction": (0.12, 0.04, "Delaware parent + USD contracts"),
    }
    ref = AUDIT["seed_today"][1]
    now = ref
    after = ref
    for _h, (a, b, _) in haircuts.items():
        now *= 1 - a
        after *= 1 - b
    return {
        "vc": vc,
        "vc_weighted_pre": vc_w,
        "scorecard": scorecard,
        "berkus": berkus,
        "replacement_premium": repl,
        "asset_floor": {"low": AUDIT["asset_floor"][0], "high": AUDIT["asset_floor"][1]},
        "dcf": dcf,
        "dcf_pv_fcf": pv_fcf,
        "haircuts": haircuts,
        "haircut_reference": ref,
        "haircut_now": now,
        "haircut_after_gates": after,
    }


# ---------------------------------------------------------------------------
# 7. TRL matrix (D2) — anchors from the mission, adjusted only with evidence
# ---------------------------------------------------------------------------
TRL = [
    # component, now, target (12 mo), evidence, gap, eng weeks, external USD
    (
        "Gateway core",
        6,
        7,
        "7,550 tests; shipped image smoke-tested in hardened posture (CLM-109); signed 5.0.1 release",
        "operational pilot at a design partner",
        8,
        0,
    ),
    (
        "WAL + group commit",
        6,
        7,
        "commit p50 0.62 ms / p99 1.22 ms incl. fsync; 1,482 commits/s @100 threads on 4 vCPU",
        "30-day soak + power-loss test on target storage",
        3,
        1_000,
    ),
    (
        "MMR v2 proofs",
        6,
        7,
        "Rust/Python root agreement; portable inclusion proofs (CLM-064)",
        "third-party verification in a pilot",
        2,
        0,
    ),
    (
        "SDK verifiers",
        6,
        7,
        "PyPI/npm 5.0.1 byte-identical to Release assets; provenance verified",
        "external auditor runs aegis-sdk verify in a pilot",
        2,
        0,
    ),
    (
        "WAF L1/L2",
        5,
        6,
        "corpus-tested normalisation; finite pattern set (UC-042)",
        "published adversarial eval + pen test coverage",
        4,
        0,
    ),
    (
        "Crypto-shredding",
        5,
        6,
        "wired into commit path; keyed digests (CLM-098)",
        "counsel review of erasure semantics + pilot",
        3,
        3_000,
    ),
    (
        "HA lease + global sequence",
        5,
        6,
        "CI vs real Redis/PostgreSQL; SIGKILL failover 4.2-5.2 s (CLM-108)",
        "partition/failover chaos tests + pilot",
        6,
        2_000,
    ),
    (
        "ZK circuit",
        4,
        4,
        "preview guard; not on the request path",
        "proving-system audit; deferred",
        12,
        40_000,
    ),
    (
        "Raft / consensus",
        2,
        2,
        "orphan module; superseded by AD-17 lease design",
        "not on roadmap",
        0,
        0,
    ),
    (
        "HSM / PQC signing",
        4,
        5,
        "PKCS#11 path; ML-DSA-65 sign 173 us / verify 62 us; Managed HSM excluded ($2,342/mo)",
        "Key Vault Premium HSM-backed key integration test",
        4,
        500,
    ),
    (
        "OTel / metrics",
        6,
        7,
        "/metrics verified in the shipped image by the evidence collector (REG-D86)",
        "pilot dashboards + alert runbook exercised",
        1,
        0,
    ),
    (
        "Azure deployment kit",
        4,
        6,
        "VM kit deployed and measured once (Standard_B2als_v2, Chile Central, 2026-09-26): "
        "strict mode started, verify.sh passed, one signed record committed (REG-H07)",
        "run phase0_guardrails.sh end to end, observe a budget alert fire, repeat on a second size/region",
        1,
        200,
    ),
]
TRL_ES = {  # component: (name, evidence, gap); {hsm} is filled at render time
    "Gateway core": (
        "Núcleo del gateway",
        "7.550 pruebas; la imagen publicada se probó con la postura endurecida (CLM-109); release 5.0.1 firmado",
        "piloto operativo en un cliente de diseño",
    ),
    "WAL + group commit": (
        "WAL + commit agrupado",
        "commit p50 0,62 ms / p99 1,22 ms con fsync; 1.482 commits/s @100 hilos en 4 vCPU",
        "prueba de resistencia de 30 días + prueba de corte de energía en el almacenamiento destino",
    ),
    "MMR v2 proofs": (
        "Pruebas MMR v2",
        "raíces Rust/Python coincidentes; pruebas de inclusión portables (CLM-064)",
        "verificación por un tercero en un piloto",
    ),
    "SDK verifiers": (
        "Verificadores del SDK",
        "PyPI/npm 5.0.1 idénticos byte a byte a los archivos del release; procedencia verificada",
        "un auditor externo ejecuta aegis-sdk verify en un piloto",
    ),
    "WAF L1/L2": (
        "WAF L1/L2",
        "normalización probada contra un corpus; conjunto finito de patrones (UC-042)",
        "evaluación adversarial publicada + cobertura del pentest",
    ),
    "Crypto-shredding": (
        "Borrado criptográfico",
        "integrado al camino de commit; digests con clave (CLM-098)",
        "revisión legal de la semántica de borrado + piloto",
    ),
    "HA lease + global sequence": (
        "Lease de HA + secuencia global",
        "CI contra Redis/PostgreSQL reales; failover por SIGKILL en 4,2-5,2 s (CLM-108)",
        "pruebas de caos de partición y failover + piloto",
    ),
    "ZK circuit": (
        "Circuito ZK",
        "protección de vista previa; fuera del camino de las solicitudes",
        "auditoría del sistema de pruebas; diferida",
    ),
    "Raft / consensus": (
        "Raft / consenso",
        "módulo huérfano; reemplazado por el diseño de lease AD-17",
        "fuera de la hoja de ruta",
    ),
    "HSM / PQC signing": (
        "Firma HSM / PQC",
        "camino PKCS#11; ML-DSA-65 firma en 173 us y verifica en 62 us; Managed HSM excluido: {hsm} por mes",
        "prueba de integración con una clave respaldada por HSM en Key Vault Premium",
    ),
    "OTel / metrics": (
        "OTel / métricas",
        "/metrics verificado en la imagen publicada por el recolector de evidencia (REG-D86)",
        "tableros del piloto + runbook de alertas ejercitado",
    ),
    "Azure deployment kit": (
        "Kit de despliegue en Azure",
        "kit de VM desplegado y medido una vez (Standard_B2als_v2, Chile Central, 26/09/2026): "
        "modo estricto activo, verify.sh aprobado, un registro firmado confirmado (REG-H07)",
        "correr phase0_guardrails.sh de punta a punta, observar una alerta de presupuesto disparada, "
        "repetir en un segundo tamaño/región",
    ),
}


def trl_text(name: str, evidence: str, gap: str) -> tuple[str, str, str]:
    if LANG == "en":
        return name, evidence, gap
    n, e, g = TRL_ES[name]
    return n, e.format(hsm=dol(round(HSM_B1_MONTH), ",.0f")), g


# ---------------------------------------------------------------------------
# 8. Charts
# ---------------------------------------------------------------------------
C = {
    "surface": "#fcfcfb",
    "ink": "#0b0b0b",
    "ink2": "#52514e",
    "grid": "#e4e3df",
    "blue": "#2a78d6",
    "orange": "#eb6834",
    "aqua": "#1baf7a",
    "seq": ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"],
    "good": "#0ca30c",
    "warning": "#fab219",
    "critical": "#d03b3b",
}


def style(ax, title: str):
    ax.set_facecolor(C["surface"])
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    for sp in ("left", "bottom"):
        ax.spines[sp].set_color(C["grid"])
    ax.tick_params(colors=C["ink2"], labelsize=9)
    ax.grid(True, color=C["grid"], linewidth=0.8, axis="y")
    ax.set_axisbelow(True)
    ax.set_title(title, loc="left", color=C["ink"], fontsize=12, fontweight="bold", pad=12)


def fig():
    f, ax = plt.subplots(figsize=(10, 5.6), dpi=150)
    f.patch.set_facecolor(C["surface"])
    return f, ax


def usd(v: float, ars_line: bool = False) -> str:
    """Chart money label; '\\$' stops matplotlib reading a pair of $ as mathtext.

    In Spanish the dollar sign alone reads as pesos, so dollars print as 'US$',
    and ``ars_line`` adds the peso equivalent on a second line.
    """
    sign = "\u2212" if v < 0 else ""
    a = abs(v)
    if LANG == "en":
        if a == 0:
            return "\\$0"
        return f"{sign}\\${a / 1e6:.2f}M" if a >= 1e6 else f"{sign}\\${a / 1e3:.0f}k"
    if a == 0:
        return "US\\$ 0"
    body = _swap(f"{a / 1e6:.2f} M") if a >= 1e6 else f"{a / 1e3:.0f} mil"
    s = f"{sign}US\\$ {body}"
    if ars_line:
        s += f"\n({sign}ARS {ars_num(a * FX_ARS)})"
    return s


def fx_footnote(f):
    """Spanish charts state the peso conversion under the plot."""
    if LANG == "es":
        f.text(0.01, 0.012, tr("fx_note"), fontsize=7.5, color=C["ink2"], ha="left", va="bottom")


def layout(f, rect=(0, 0, 1, 1)):
    if LANG == "es":
        rect = (rect[0], max(rect[1], 0.04), rect[2], rect[3])
    f.tight_layout(rect=rect)


def chart_fan(models, mc, out):
    f, ax = fig()
    x = [0] + YEARS
    ax.fill_between(
        x,
        np.array(mc["p10"]) / 1e6,
        np.array(mc["p90"]) / 1e6,
        color=C["seq"][0],
        linewidth=0,
        label=tr("Monte Carlo P10-P90 (seed 42, n=5,000)"),
    )
    cols = {"bear": C["orange"], "base": C["blue"], "bull": C["aqua"]}
    for s in SCEN:
        name = s if LANG == "en" else SCN_ES[s]
        y = [0] + [r["arr_end"] / 1e6 for r in models[s]["rows"]]
        ax.plot(
            x,
            y,
            color=cols[s],
            linewidth=2,
            marker="o",
            markersize=5,
            label=f"{name} (p={nfmt(SCEN_P[s], '.2f')})",
        )
        ax.annotate(
            f"{name} {usd(y[-1] * 1e6, ars_line=True)}",
            (x[-1], y[-1]),
            xytext=(6, 0),
            textcoords="offset points",
            va="center",
            color=C["ink"],
            fontsize=9,
        )
    exp = [
        sum(SCEN_P[s] * ([0] + [r["arr_end"] for r in models[s]["rows"]])[i] for s in SCEN) / 1e6
        for i in range(6)
    ]
    ax.plot(x, exp, color=C["ink"], linewidth=2, linestyle="--", label=tr("probability-weighted"))
    style(ax, tr("ARR by fiscal year — scenario fan [MODEL/HYPOTHESIS]"))
    ax.set_xlabel(tr("Fiscal year (FY1 = Oct 2026 – Sep 2027)"), color=C["ink2"])
    ax.set_ylabel(tr("ARR, $M"), color=C["ink2"])
    if LANG == "es":
        ax.set_xticks(x)
        ax.set_xticklabels(["0"] + [f"AF{y}" for y in YEARS])
        ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: nfmt(v, ".0f")))
    ax.set_xlim(0, 5.9 if LANG == "en" else 6.6)
    ax.legend(frameon=False, fontsize=8, loc="upper left", labelcolor=C["ink"])
    fx_footnote(f)
    layout(f)
    f.savefig(out / "01_scenario_fan.png", facecolor=C["surface"])
    plt.close(f)


def waterfall(ax, labels, vals, start_color, step_color, end_color):
    cum = 0.0
    for i, (_lab, v) in enumerate(zip(labels, vals, strict=True)):
        if i == 0:
            ax.bar(i, v, color=start_color, width=0.6, edgecolor=C["surface"], linewidth=2)
            cum = v
            top = v
        elif i == len(vals) - 1:
            ax.bar(i, v, color=end_color, width=0.6, edgecolor=C["surface"], linewidth=2)
            top = v
        else:
            bottom = cum + v if v < 0 else cum
            ax.bar(
                i,
                abs(v),
                bottom=bottom,
                color=step_color,
                width=0.6,
                edgecolor=C["surface"],
                linewidth=2,
            )
            cum += v
            top = max(bottom + abs(v), bottom)
        ax.text(
            i,
            top,
            usd(v, ars_line=True),
            ha="center",
            va="bottom",
            fontsize=8 if LANG == "en" else 7.5,
            color=C["ink"],
        )
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=25, ha="right", fontsize=8, color=C["ink2"])


def chart_burn(uof, out):
    f, ax = fig()
    short = {
        "Engineering continuity (2nd maintainer, 16 mo)": "2nd maintainer",
        "Go-to-market (solutions engineer 12 mo + design-partner program)": "Go-to-market",
        "Assurance (pen test + retest, SOC 2 Type I, escrow)": "Assurance",
        "Legal & corporate (entity, IP, licence, regulatory, AI-authorship opinion)": "Legal & corporate",
        "Founder salary (18 mo)": "Founder salary",
        "Infra, tools, insurance, accounting (18 mo)": "Infra & G&A",
        "Recruiting": "Recruiting",
        "Contingency (10%)": "Contingency",
    }
    labels = (
        [tr("Raise (T1+T2+T3)")]
        + [tr(short[k]) for k in uof["workstreams"]]
        + [tr("Buffer at M18")]
    )
    vals = [uof["raise"]] + [-v for v in uof["workstreams"].values()] + [uof["buffer"]]
    waterfall(ax, labels, vals, C["blue"], C["orange"], C["aqua"])
    style(ax, tr("18-month use of funds — burn waterfall [MODEL]"))
    ax.set_ylabel(tr("USD"), color=C["ink2"])
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: usd(v)))
    if LANG == "es":
        ax.set_ylim(0, uof["raise"] * 1.14)
    fx_footnote(f)
    layout(f)
    f.savefig(out / "02_burn_waterfall.png", facecolor=C["surface"])
    plt.close(f)


def chart_bridge(ue, out):
    f, ax = fig()
    t = ue["tiers"]["Mid-market"]
    acv, cm, cac = t["acv"], t["cm"], t["cac"]
    gp = acv * cm
    lt = gp / 0.40
    labels = [
        tr(s)
        for s in (
            "ACV (mid-market)",
            "COGS",
            "Gross profit / yr",
            "x 2.5-yr life\n(40% churn)",
            "LTV",
            "CAC",
            "Net value / customer",
        )
    ]
    cum = 0
    steps = [
        (acv, "total"),
        (-(acv - gp), "step"),
        (gp, "total"),
        (lt - gp, "step"),
        (lt, "total"),
        (-cac, "step"),
        (lt - cac, "end"),
    ]
    for i, (v, kind) in enumerate(steps):
        if kind in ("total", "end"):
            ax.bar(
                i,
                v,
                color=C["blue"] if kind == "total" else C["aqua"],
                width=0.6,
                edgecolor=C["surface"],
                linewidth=2,
            )
            cum = v
            ax.text(
                i, v, usd(v, ars_line=True), ha="center", va="bottom", fontsize=8, color=C["ink"]
            )
        else:
            bottom = cum + v if v < 0 else cum
            ax.bar(
                i,
                abs(v),
                bottom=bottom,
                color=C["orange"] if v < 0 else C["seq"][2],
                width=0.6,
                edgecolor=C["surface"],
                linewidth=2,
            )
            ax.text(
                i,
                bottom + abs(v),
                usd(v, ars_line=True),
                ha="center",
                va="bottom",
                fontsize=8,
                color=C["ink"],
            )
            cum += v
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=8, color=C["ink2"])
    if LANG == "en":
        style(
            ax,
            f"Unit-economics bridge — mid-market, LTV/CAC {lt / cac:.1f}x, payback {cac / (gp / 12):.1f} mo [HYPOTHESIS]",
        )
    else:
        style(
            ax,
            f"Economía unitaria, mercado medio: LTV/CAC {nfmt(lt / cac, '.1f')}x, "
            f"payback {nfmt(cac / (gp / 12), '.1f')} meses [HYPOTHESIS]",
        )
        ax.set_ylim(0, lt * 1.12)
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: usd(v)))
    fx_footnote(f)
    layout(f)
    f.savefig(out / "03_unit_economics_bridge.png", facecolor=C["surface"])
    plt.close(f)


def chart_trl(out):
    f, ax = plt.subplots(figsize=(10, 6.4), dpi=150)
    f.patch.set_facecolor(C["surface"])
    ax.set_facecolor(C["surface"])
    n = len(TRL)
    for r, (_name, now, target, *_rest) in enumerate(TRL):
        yy = n - 1 - r
        for lvl in range(1, 10):
            if lvl <= now:
                col = C["seq"][min(6, 1 + lvl // 2)]
                ax.add_patch(
                    Rectangle(
                        (lvl - 0.5, yy - 0.42),
                        0.96,
                        0.84,
                        facecolor=col,
                        edgecolor=C["surface"],
                        linewidth=2,
                    )
                )
            elif lvl <= target:
                ax.add_patch(
                    Rectangle(
                        (lvl - 0.5, yy - 0.42),
                        0.96,
                        0.84,
                        facecolor=C["surface"],
                        edgecolor=C["seq"][3],
                        linewidth=1.2,
                        hatch="////",
                    )
                )
            else:
                ax.add_patch(
                    Rectangle(
                        (lvl - 0.5, yy - 0.42),
                        0.96,
                        0.84,
                        facecolor="#f0efec",
                        edgecolor=C["surface"],
                        linewidth=2,
                    )
                )
        ax.text(
            9.8,
            yy,
            f"TRL {now}" + (f" → {target}" if target > now else ""),
            va="center",
            fontsize=8.5,
            color=C["ink"],
        )
    ax.set_xlim(0.4, 11.2)
    ax.set_ylim(-0.7, n - 0.3)
    ax.set_yticks(range(n))
    ax.set_yticklabels(
        [trl_text(*t[:1], "", "")[0] for t in reversed(TRL)], fontsize=9, color=C["ink"]
    )
    ax.set_xticks(range(1, 10))
    ax.set_xticklabels([str(i) for i in range(1, 10)], fontsize=9, color=C["ink2"])
    ax.set_xlabel(
        tr("EU Horizon TRL (filled = achieved with cited evidence; hatched = 12-month target)"),
        color=C["ink2"],
        fontsize=9,
    )
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.tick_params(length=0)
    ax.set_title(
        tr("Technology readiness by component [VERIFIED evidence, MODEL levels]"),
        loc="left",
        color=C["ink"],
        fontsize=12,
        fontweight="bold",
        pad=12,
    )
    f.tight_layout()
    f.savefig(out / "04_trl_heatmap.png", facecolor=C["surface"])
    plt.close(f)


def chart_football(val, out, caps: dict):
    f, ax = fig()
    vc = val["vc"]
    bars = [
        (
            "VC method (bear–bull)",
            min(v["pre"] for v in vc.values()),
            max(v["pre"] for v in vc.values()),
        ),
        ("DCF, base FCF @25% (6–10x exit)", min(val["dcf"].values()), max(val["dcf"].values())),
        ("Berkus, audit-adjusted", val["berkus"]["low"], val["berkus"]["high"]),
        ("Scorecard, audit-adjusted", val["scorecard"]["low"], val["scorecard"]["high"]),
        ("Asset-sale floor [AUDIT]", val["asset_floor"]["low"], val["asset_floor"]["high"]),
        (
            "Replacement cost + corpus premium",
            val["replacement_premium"]["low"],
            val["replacement_premium"]["high"],
        ),
        ("Haircut table (now → after gates)", val["haircut_now"], val["haircut_after_gates"]),
    ]
    band_lo, band_hi = AUDIT["seed_today"]
    band_label = (
        "[AUDIT] seed band today \\$8–15M"
        if LANG == "en"
        else f"[AUDIT] banda semilla hoy US\\$ 8–15 M (ARS {ars_rng(band_lo, band_hi)})"
    )
    ax.axvspan(band_lo / 1e6, band_hi / 1e6, color="#fbe3d6", zorder=0, label=band_label)
    for i, (_lab, lo, hi) in enumerate(bars):
        yy = len(bars) - 1 - i
        ax.barh(
            yy,
            (hi - lo) / 1e6,
            left=lo / 1e6,
            height=0.5,
            color=C["blue"],
            edgecolor=C["surface"],
            linewidth=2,
        )
        text = f"{usd(lo)} – {usd(hi)}"
        if LANG == "es":
            text += f"\n(ARS {ars_rng(lo, hi)})"
        box = (
            None
            if LANG == "en"
            else {"facecolor": C["surface"], "edgecolor": "none", "alpha": 0.9, "pad": 1.5}
        )
        ax.text(
            hi / 1e6 + 0.15,
            yy,
            text,
            va="center",
            fontsize=8.5 if LANG == "en" else 8,
            color=C["ink"],
            bbox=box,
        )
    for (tranche, cap), ls in zip(caps.items(), ("--", "-.", ":"), strict=True):
        cap_label = (
            f"{tranche} post-money cap {usd(cap)}"
            if LANG == "en"
            else f"{tranche}: tope post-money {usd(cap)} (ARS {ars_num(cap * FX_ARS)})"
        )
        ax.axvline(cap / 1e6, color=C["ink"], linewidth=1.8, linestyle=ls, label=cap_label)
    ax.set_yticks(range(len(bars)))
    ax.set_yticklabels([tr(b[0]) for b in reversed(bars)], fontsize=9, color=C["ink"])
    style(ax, tr("Valuation football field — pre-money, $M"))
    ax.grid(True, axis="x", color=C["grid"])
    ax.grid(False, axis="y")
    ax.set_xlim(0, 17.5 if LANG == "en" else 20.5)
    ax.set_xlabel(tr("$M"), color=C["ink2"])
    if LANG == "es":
        ax.xaxis.set_major_locator(matplotlib.ticker.MultipleLocator(2))
        ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: nfmt(v, ".0f")))
    ax.legend(
        frameon=True,
        facecolor=C["surface"],
        edgecolor=C["grid"],
        fontsize=8,
        loc="upper right",
        labelcolor=C["ink"],
    )
    fx_footnote(f)
    layout(f)
    f.savefig(out / "05_valuation_football_field.png", facecolor=C["surface"])
    plt.close(f)


def chart_gauge(br, out):
    f, axes = plt.subplots(1, 3, figsize=(10, 3.9), dpi=150)
    f.patch.set_facecolor(C["surface"])
    vmax = 36.0
    zones = [
        (0, 12, C["critical"], "< 12 mo"),
        (12, 18, C["warning"], "12–18 mo"),
        (18, vmax, C["good"], "≥ 18 mo"),
    ]
    mo = "mo" if LANG == "en" else "meses"
    for ax, clients in zip(axes, (0, 1, 3), strict=True):
        ax.set_facecolor(C["surface"])
        ax.set_aspect("equal")
        ax.axis("off")
        for lo, hi, col, _ in zones:
            a0 = 180 - 180 * hi / vmax
            a1 = 180 - 180 * lo / vmax
            ax.add_patch(
                Wedge(
                    (0, 0),
                    1.0,
                    a0,
                    a1,
                    width=0.22,
                    facecolor=col,
                    edgecolor=C["surface"],
                    linewidth=2,
                )
            )
        months = min(br["post_funding"]["all tranches"][clients], vmax)
        ang = np.deg2rad(180 - 180 * months / vmax)
        ax.plot([0, 0.78 * np.cos(ang)], [0, 0.78 * np.sin(ang)], color=C["ink"], linewidth=2.5)
        ax.add_patch(plt.Circle((0, 0), 0.05, color=C["ink"]))
        label = (
            f"{br['post_funding']['all tranches'][clients]:.0f} {mo}"
            if br["post_funding"]["all tranches"][clients] < vmax
            else f"≥ 36 {mo}"
        )
        ax.text(0, -0.22, label, ha="center", fontsize=14, fontweight="bold", color=C["ink"])
        t1 = br["post_funding"]["T1 only"][clients]
        t1_label = f"T1 only: {t1:.0f} mo" if LANG == "en" else f"Solo T1: {t1:.0f} meses"
        ax.text(0, -0.42, t1_label, ha="center", fontsize=9, color=C["ink2"])
        if LANG == "en":
            head = f"{clients} paying client{'s' if clients != 1 else ''}"
        else:
            head = f"{clients} cliente{'s' if clients != 1 else ''} que paga{'n' if clients != 1 else ''}"
        ax.text(0, 1.12, head, ha="center", fontsize=10, color=C["ink"])
        ax.set_xlim(-1.15, 1.15)
        ax.set_ylim(-0.55, 1.25)
    title = (
        "Runway after the full raise — status zones labelled: red < 12 mo, amber 12–18 mo, green ≥ 18 mo [MODEL]"
        if LANG == "en"
        else "Autonomía con la ronda completa — zonas: rojo < 12 meses, ámbar 12–18 meses, verde ≥ 18 meses [MODEL]"
    )
    f.suptitle(title, x=0.01, ha="left", fontsize=10.5, fontweight="bold", color=C["ink"])
    f.tight_layout(rect=(0, 0, 1, 0.92))
    f.savefig(out / "06_runway_gauge.png", facecolor=C["surface"])
    plt.close(f)


# ---------------------------------------------------------------------------
# 9. Markdown tables
# ---------------------------------------------------------------------------


def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def k(v):
    """Table money cell: EN '15.0k' / '1.62M'; ES 'US$ 15,0 mil (ARS 22,8 M)'."""
    if LANG == "en":
        return f"{v / 1e3:,.1f}k" if abs(v) < 1e6 else f"{v / 1e6:,.2f}M"
    if v == 0:
        return "US$ 0"
    sign = "−" if v < 0 else ""
    a = abs(v)
    body = f"{a / 1e3:,.1f} mil" if a < 1e6 else f"{a / 1e6:,.2f} M"
    return f"{sign}US$ {_swap(body)} ({sign}ARS {ars_num(a * FX_ARS)})"


def pick(en: str, es: str) -> str:
    return en if LANG == "en" else es


def build_tables(ue, models, br, uof, val, mc) -> str:
    parts = []
    xx = lambda v, spec=".1f": nfmt(v, spec) + "x"  # noqa: E731
    fy = "FY" if LANG == "en" else "AF"
    parts.append(
        pick("### D3.1 Tiers [MODEL/HYPOTHESIS]\n", "### D3.1 Niveles [MODEL/HYPOTHESIS]\n")
        + md_table(
            [
                tr("Tier"),
                "ACV",
                tr("CM"),
                "CAC",
                "LTV @25%",
                "LTV @40%",
                "LTV @55%",
                tr("Payback (mo)"),
                "LTV/CAC @40%",
            ],
            [
                [
                    tr(n),
                    k(t["acv"]),
                    nfmt(t["cm"], ".1%"),
                    k(t["cac"]),
                    k(t["ltv_25"]),
                    k(t["ltv_40"]),
                    k(t["ltv_55"]),
                    nfmt(t["payback_months"], ".1f"),
                    tr("n/a") if not t["cac"] else xx(t["ltv_cac_40"]),
                ]
                for n, t in ue["tiers"].items()
            ],
        )
    )
    parts.append(
        pick(
            "### D3.2 CAC by channel [HYPOTHESIS except founder-led MODEL]\n",
            "### D3.2 CAC por canal [HYPOTHESIS, salvo la venta del fundador: MODEL]\n",
        )
        + md_table(
            [tr("Channel"), "CAC", tr("Mix")],
            [[c, k(v), nfmt(CHANNEL_MIX[c], ".0%")] for c, v in CHANNEL_CAC.items()]
            + [[tr("Blended"), k(ue["blended_cac"]), "100%"]],
        )
    )
    parts.append(
        pick(
            "### D3.5 CAC stress: LTV/CAC when CAC = first-year ACV (CM 90%)\n",
            "### D3.5 Estrés de CAC: LTV/CAC cuando el CAC = ACV del primer año (MC 90%)\n",
        )
        + md_table(
            [tr("Churn"), "LTV/CAC"],
            [[nfmt(c, ".0%"), xx(v, ".2f")] for c, v in ue["cac_stress_ltv_cac"].items()],
        )
    )
    band = {"10-50M": "10-50 M", "50-250M": "50-250 M", "250M+": "250 M+"}
    parts.append(
        pick(
            "### D3.3 MGT overage (Aegis-hosted marginal cost) [VERIFIED prices, MODEL volumes]\n",
            "### D3.3 Excedente por MGT (costo marginal con hosting de Aegis) [precios VERIFIED, volúmenes MODEL]\n",
        )
        + md_table(
            [tr("Band"), tr("Price/MGT"), tr("Marginal cost/MGT"), tr("Margin")],
            [
                [
                    b if LANG == "en" else band[b],
                    dol(m["price"], ","),
                    dol(m["marginal_cost_hosted"], ".2f"),
                    nfmt(m["margin"], ".2%"),
                ]
                for b, m in ue["mgt"].items()
            ],
        )
    )
    ch = [0.25, 0.40, 0.55]
    acvs = [15e3, 25e3, 50e3, 75e3, 135e3]
    cell = (
        (lambda g: f"{g['ltv_cac']:.1f}x (LTV {k(g['ltv'])})")
        if LANG == "en"
        else (lambda g: f"{xx(g['ltv_cac'])} · LTV {k(g['ltv'])}")
    )
    parts.append(
        pick(
            "### D3.4 Sensitivity: LTV/CAC by churn x ACV (CM 90%, CAC = max($6.4k, 25% ACV))\n",
            f"### D3.4 Sensibilidad: LTV/CAC por churn x ACV (MC 90%, CAC = máx({k(CAC_FOUNDER)}; 25% del ACV))\n",
        )
        + md_table(
            [tr("Churn \\ ACV")] + [k(a) for a in acvs],
            [[nfmt(c, ".0%")] + [cell(ue["grid"][c][a]) for a in acvs] for c in ch],
        )
    )
    for s in SCEN:
        rows = models[s]["rows"]
        title = (
            f"### D4 {s.upper()} — P&L / cash flow / balance sheet (p={SCEN_P[s]:.2f})\n"
            if LANG == "en"
            else f"### D4 {SCN_ES[s].upper()} — P&L / flujo de caja / balance (p={nfmt(SCEN_P[s], '.2f')})\n"
        )
        dash = lambda v, spec: "—" if v is None else nfmt(v, spec)  # noqa: E731
        parts.append(
            title
            + md_table(
                [tr("Line")] + [f"{fy}{r['year']}" for r in rows],
                [
                    [tr("New customers")] + [nfmt(r["new_customers"], ".1f") for r in rows],
                    [tr("Customers (end)")] + [nfmt(r["customers_end"], ".1f") for r in rows],
                    [tr("ARR (end)")] + [k(r["arr_end"]) for r in rows],
                    [tr("Revenue")] + [k(r["revenue"]) for r in rows],
                    [tr("Gross margin")] + [nfmt(r["gross_margin"], ".0%") for r in rows],
                    [tr("OpEx")] + [k(r["opex"]) for r in rows],
                    [tr("EBITDA")] + [k(r["ebitda"]) for r in rows],
                    [tr("Net income")] + [k(r["net_income"]) for r in rows],
                    [tr("CFO")] + [k(r["cfo"]) for r in rows],
                    [tr("CFF (SAFE tranches)")] + [k(r["cff"]) for r in rows],
                    [tr("Cash / (unfunded gap), close")] + [k(r["cash_close"]) for r in rows],
                    [tr("AR")] + [k(r["ar"]) for r in rows],
                    [tr("Deferred revenue")] + [k(r["deferred_revenue"]) for r in rows],
                    [tr("Equity (paid-in + retained)")] + [k(r["equity"]) for r in rows],
                    [tr("Balance check (A−L−E)")] + [nfmt(r["balance_check"], ".2f") for r in rows],
                    [tr("Headcount")] + [str(r["headcount"]) for r in rows],
                    [tr("Burn multiple")] + [dash(r["burn_multiple"], ".1f") for r in rows],
                    [tr("Magic number (proxy)")] + [dash(r["magic_number"], ".2f") for r in rows],
                ],
            )
        )
    pre = br["pre_funding"]
    parts.append(
        pick(
            "### D5.1 Pre-funding burn [MODEL: owner-supplied Azure figures]\n",
            "### D5.1 Consumo antes del financiamiento [MODEL: cifras de Azure provistas por el fundador]\n",
        )
        + md_table(
            [tr("Item"), tr("Typical"), tr("Worst")],
            [
                [tr("Azure / month"), dol(AZ_TYPICAL, ".2f"), dol(AZ_WORST, ".2f")],
                [
                    tr("Credit runway (months)"),
                    nfmt(pre["credit_runway_typical_months"], ".1f"),
                    nfmt(pre["credit_runway_worst_months"], ".1f"),
                ],
                [
                    tr("Cash burn while credit lasts"),
                    dol(HUMAN_FIXED, ".0f"),
                    dol(HUMAN_FIXED, ".0f"),
                ],
                [
                    tr("Cash burn after credit"),
                    dol(pre["cash_burn_after_credit_typical"], ".2f"),
                    dol(pre["cash_burn_after_credit_worst"], ".2f"),
                ],
                [tr("Managed HSM B1 (excluded)"), dol(HSM_B1_MONTH, ",.2f") + " [VERIFIED]", "—"],
            ],
        )
    )
    parts.append(
        pick("### D5.2 Credit alert thresholds\n", "### D5.2 Umbrales de alerta del crédito\n")
        + md_table(
            [tr("Alert"), tr("Spend"), tr("Month @typical"), tr("Month @worst")],
            [
                [
                    a,
                    dol(v["usd"], ".0f"),
                    nfmt(v["month_typical"], ".1f"),
                    nfmt(v["month_worst"], ".1f"),
                ]
                for a, v in pre["alerts"].items()
            ],
        )
    )
    pf = br["post_funding"]
    parts.append(
        pick(
            "### D5.3 Post-funding runway (months) [MODEL]\n",
            "### D5.3 Autonomía después del financiamiento (meses) [MODEL]\n",
        )
        + md_table(
            [tr("Capital"), tr("0 clients"), tr("1 client"), tr("3 clients")],
            [
                [
                    tr(lab),
                    *[("≥36" if pf[lab][c] >= 36 else f"{pf[lab][c]:.0f}") for c in (0, 1, 3)],
                ]
                for lab in pf
            ],
        )
    )
    parts.append(
        pick(
            "### D7.1 Use of funds, 18 months [MODEL]\n",
            "### D7.1 Uso de fondos, 18 meses [MODEL]\n",
        )
        + md_table(
            [tr("Workstream"), pick("USD", "Monto"), tr("Share")],
            [
                [tr(w), k(v), nfmt(v / uof["total_18m"], ".0%")]
                for w, v in uof["workstreams"].items()
            ]
            + [
                [tr("Total 18 months"), k(uof["total_18m"]), "100%"],
                [tr("Raise"), k(uof["raise"]), ""],
                [tr("Buffer at M18"), k(uof["buffer"]), ""],
            ],
        )
    )
    vc = val["vc"]
    parts.append(
        pick(
            "### D6.1 VC method (10x target, 5-yr exit, 60% stage discount) [MODEL]\n",
            "### D6.1 Método VC (objetivo 10x, salida a 5 años, descuento por etapa del 60%) [MODEL]\n",
        )
        + md_table(
            [
                tr("Scenario"),
                tr("ARR FY5"),
                tr("Exit multiple"),
                tr("Exit EV"),
                tr("Post-money"),
                tr("Pre-money"),
            ],
            [
                [
                    s if LANG == "en" else SCN_ES[s],
                    k(vc[s]["arr5"]),
                    f"{EXIT_MULT[s]:.0f}x",
                    k(vc[s]["exit_ev"]),
                    k(vc[s]["post"]),
                    k(vc[s]["pre"]),
                ]
                for s in SCEN
            ]
            + [[tr("Probability-weighted"), "", "", "", "", k(val["vc_weighted_pre"])]],
        )
    )
    sc = val["scorecard"]
    parts.append(
        pick(
            "### D6.2 Scorecard (audit-adjusted) [MODEL]\n",
            "### D6.2 Scorecard (ajustado por auditoría) [MODEL]\n",
        )
        + md_table(
            [tr("Factor"), tr("Weight"), tr("Score vs average"), tr("Contribution")],
            [
                [
                    tr(f),
                    nfmt(sc["weights"][f], ".0%"),
                    nfmt(sc["scores"][f], ".2f"),
                    nfmt(sc["weights"][f] * sc["scores"][f], ".3f"),
                ]
                for f in sc["weights"]
            ]
            + [
                [tr("Factor total"), "", "", nfmt(sc["factor"], ".3f")],
                [
                    pick(
                        "Pre-money (ref $8–12M)",
                        f"Pre-money (ref. US$ 8–12 M; ARS {ars_rng(8e6, 12e6)})",
                    ),
                    "",
                    "",
                    f"{k(sc['low'])} – {k(sc['high'])}",
                ],
            ],
        )
    )
    bk = val["berkus"]
    parts.append(
        pick(
            "### D6.3 Berkus (audit-adjusted) [MODEL]\n",
            "### D6.3 Berkus (ajustado por auditoría) [MODEL]\n",
        )
        + md_table(
            [tr("Element"), tr("Score (0–1)")],
            [[tr(e), nfmt(v, ".2f")] for e, v in bk["elements"].items()]
            + [
                [
                    pick(
                        "Value at $0.5M / $1.0M per element",
                        f"Valor a US$ 0,5 M / 1,0 M por elemento (ARS {ars_num(0.5e6 * FX_ARS)} / {ars_num(1e6 * FX_ARS)})",
                    ),
                    f"{k(bk['low'])} / {k(bk['high'])}",
                ]
            ],
        )
    )
    parts.append(
        pick(
            "### D6.4 DCF of base FCF @25% [MODEL]\n", "### D6.4 DCF del FCF base al 25% [MODEL]\n"
        )
        + md_table(
            [tr("Exit multiple on FY5 ARR"), tr("PV(FCF FY1–5)"), tr("Enterprise value")],
            [[f"{m:.0f}x", k(val["dcf_pv_fcf"]), k(v)] for m, v in val["dcf"].items()],
        )
    )
    parts.append(
        pick(
            "### D6.5 Haircut table (reference = [AUDIT] $15M top of seed band) [MODEL]\n",
            "### D6.5 Tabla de descuentos (referencia = techo [AUDIT] de la banda semilla, "
            f"{k(AUDIT['seed_today'][1])}) [MODEL]\n",
        )
        + md_table(
            [tr("Haircut"), tr("Now"), tr("After gates"), tr("Gate that removes it")],
            [
                [tr(h), "−" + nfmt(a, ".0%"), "−" + nfmt(b, ".0%"), tr(g)]
                for h, (a, b, g) in val["haircuts"].items()
            ]
            + [[tr("Resulting value"), k(val["haircut_now"]), k(val["haircut_after_gates"]), ""]],
        )
    )
    parts.append(
        pick("### D2 TRL matrix\n", "### D2 Matriz TRL\n")
        + md_table(
            [
                tr("Component"),
                tr("TRL now"),
                tr("Evidence"),
                tr("Gap to TRL+1"),
                tr("Eng weeks"),
                tr("External $"),
                tr("Cost to close"),
            ],
            [
                [
                    *trl_text(n, ev, gap)[:1],
                    str(now),
                    *trl_text(n, ev, gap)[1:],
                    str(w),
                    dol(x, ","),
                    dol(w * ENG_WEEK + x, ",.0f"),
                ]
                for n, now, _t, ev, gap, w, x in TRL
            ],
        )
    )
    parts.append(
        pick(
            "### Monte Carlo ARR percentiles (seed 42, n=5,000)\n",
            "### Monte Carlo: percentiles de ARR (semilla 42, n=5.000)\n",
        )
        + md_table(
            [tr("Percentile")] + [f"{fy}{y}" for y in YEARS],
            [[p.upper()] + [k(v) for v in mc[p][1:]] for p in ("p10", "p50", "p90")],
        )
    )
    return "\n\n".join(parts) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=Path("out"))
    ap.add_argument(
        "--lang",
        choices=("en", "es"),
        default="en",
        help="chart and table language; es adds pesos in parentheses (numbers unchanged)",
    )
    a = ap.parse_args()
    global LANG
    LANG = a.lang
    a.out.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "svg.hashsalt": str(SEED)})
    np.random.seed(SEED)

    ue = unit_economics()
    models = {s: three_statement(s) for s in SCEN}
    mc = monte_carlo_arr()
    br = burn_runway(models)
    uof = use_of_funds()
    val = valuation(models)
    cap_t1 = CAPS["T1"]

    chart_fan(models, mc, a.out)
    chart_burn(uof, a.out)
    chart_bridge(ue, a.out)
    chart_trl(a.out)
    chart_football(val, a.out, CAPS)
    chart_gauge(br, a.out)

    (a.out / "model_tables.md").write_text(
        build_tables(ue, models, br, uof, val, mc), encoding="utf-8"
    )

    def clean(o):
        if isinstance(o, dict):
            return {str(kk): clean(v) for kk, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [clean(v) for v in o]
        if isinstance(o, float):
            return round(o, 4)
        return o

    payload = {
        "inputs": INPUTS,
        "unit_economics": ue,
        "models": models,
        "monte_carlo": mc,
        "burn_runway": br,
        "use_of_funds": uof,
        "valuation": val,
        "cap_t1": cap_t1,
        "trl": [
            dict(
                zip(
                    ["component", "now", "target", "evidence", "gap", "eng_weeks", "external_usd"],
                    t,
                    strict=True,
                )
            )
            for t in TRL
        ],
    }
    (a.out / "model_outputs.json").write_text(
        json.dumps(clean(payload), indent=1, ensure_ascii=False), encoding="utf-8"
    )
    for p in sorted(a.out.glob("*.png")):
        print("wrote", p.name)
    print("wrote model_tables.md, model_outputs.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
