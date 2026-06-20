#!/usr/bin/env python3
"""
Generate the `Samples/` gallery: copies of the live dashboard (static/index.html)
pre-populated with realistic mock data so the project can be screenshotted as if
it were running against a busy production deployment.

Each sample is the EXACT same UI as the live dashboard — it simply boots from an
embedded ``window.__AEGIS_BOOTSTRAP__`` dataset instead of fetching the live API,
so what you see is faithful to the real program.

Usage:
    python tools/visualizer/generate_samples.py
Output:
    Samples/index.html            full dashboard (Overview)
    Samples/<NN>-<page>.html       one deep-linked file per page (clean screenshots)
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
import math
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TEMPLATE = HERE / "static" / "index.html"
OUT_DIR = ROOT / "Samples"

PAGES = [
    "overview", "performance", "audit", "forensics", "waf",
    "providers", "compliance", "architecture", "code", "health",
]


def _series(n: int, base: float, amp: float, noise: float, rnd: random.Random, lo: float, hi: float, nd: int = 0):
    out = []
    cur = base
    for i in range(n):
        cur += (rnd.random() - 0.5) * noise
        v = cur + math.sin(i / 6.0) * amp
        v = max(lo, min(hi, v))
        out.append(round(v, nd) if nd else int(round(v)))
    return out


def build_bootstrap() -> dict:
    # Deterministic seed → stable, reproducible screenshots. Not cryptographic;
    # this only fabricates illustrative numbers for the sample gallery.
    rnd = random.Random(4242)  # noqa: S311

    throughput = _series(60, 11200, 900, 700, rnd, 6500, 13800)
    added = _series(60, 0.82, 0.10, 0.06, rnd, 0.55, 1.15, 3)
    p99 = _series(60, 0.95, 0.12, 0.08, rnd, 0.62, 1.45, 3)
    entropy = _series(60, 3.6, 0.5, 0.25, rnd, 2.6, 4.6, 3)

    models = ["gpt-4o", "claude-opus-4-5", "gemini-1.5-pro", "llama-3.1-70b"]
    node_base = 1_842_553_017
    nodes = []
    for i in range(14):
        nodes.append({
            "seq": node_base - i,
            "ts": f"2026-06-20T15:{(40 - i) % 60:02d}:{(59 - (i * 7) % 60):02d}Z",
            "model": models[i % len(models)],
            "entropy": round(3.0 + (i % 7) * 0.21 + rnd.random() * 0.2, 3),
            "scheme": "hmac-sha256" if i % 9 == 4 else "pqc-ml-dsa",
            "node_hash": "sha256:" + "".join(rnd.choice("0123456789abcdef") for _ in range(16)),
            "prev_hash": "sha256:" + "".join(rnd.choice("0123456789abcdef") for _ in range(16)),
        })
    growth = [int(node_base - (29 - i) * 23000 + math.sin(i) * 4000) for i in range(30)]

    waf_recent = []
    pats = ["ignore previous instructions", "DAN jailbreak", "system prompt exfiltration", "zero-width evasion", "{{template}} injection"]
    for i in range(10):
        waf_recent.append({
            "ts": f"2026-06-20T15:{(40 - i) % 60:02d}:{(55 - (i * 5) % 60):02d}Z",
            "ip": f"203.0.113.{17 + (i * 11) % 220}",
            "pattern": pats[i % len(pats)],
            "action": "BLOCK",
            "score": round(0.90 + (i % 6) * 0.015, 2),
        })

    bootstrap = {
        "project": "aegis-latent-core",
        "git_head": "1aed8ea",
        "version": "2.4.0",
        "code": {
            "python_files": 97,
            "rust_files": 11,
            "py_functions": 1284,
            "py_classes": 213,
            "rust_functions": 187,
            "top_modules": [
                {"path": "aegis/proxy/app.py", "functions": 41, "classes": 7},
                {"path": "aegis/providers/anthropic_provider.py", "functions": 33, "classes": 4},
                {"path": "aegis/core/crypto_audit.py", "functions": 28, "classes": 5},
                {"path": "aegis/proxy/forwarder.py", "functions": 24, "classes": 3},
                {"path": "aegis/core/mmr.py", "functions": 19, "classes": 2},
                {"path": "aegis/core/observability.py", "functions": 18, "classes": 3},
                {"path": "aegis/proxy/schemas.py", "functions": 9, "classes": 18},
                {"path": "aegis/core/ratelimiter.py", "functions": 14, "classes": 4},
                {"path": "aegis/proxy/analyzer.py", "functions": 16, "classes": 2},
                {"path": "aegis_server/compliance/exporter.py", "functions": 15, "classes": 3},
                {"path": "aegis/core/session_manager.py", "functions": 13, "classes": 2},
                {"path": "aegis/proxy/waf.py", "functions": 11, "classes": 2},
            ],
        },
        "forensics": {
            "patterns": {
                "todo": ["aegis/core/observability.py", "aegis/proxy/analyzer.py", "docs/RUST_BUILD.md"],
                "fixme": ["aegis/core/mmr.py"],
                "api_key_upper": [".env.example", "README.md", "DEPLOYMENT_GUIDE.md"],
                "secret_word": ["SECURITY.md", "aegis/core/secrets.py", "tests/test_secrets.py"],
                "subprocess_popen": ["tools/forensic/forensic_checks.py"],
            },
            "python_syntax": [],
            "rust_build": {"status": "done"},
            "notes": ["snapshot"],
        },
        "tests": {
            "pytest": {"status": "ok", "tests_run": 1050, "passed": 1050, "warnings": 1},
            "rust_tests": {"status": "ok", "summary": "23/23 unit tests passed"},
        },
        "health": {
            "components": [
                {"name": "Proxy core (FastAPI)", "status": "ok", "detail": "12 replicas · serving 11.2k req/s"},
                {"name": "Audit ledger", "status": "ok", "detail": "1.84B nodes · chain VALID"},
                {"name": "WAF (Aho-Corasick)", "status": "ok", "detail": "34 patterns · SIMD automata"},
                {"name": "Rate limiter", "status": "ok", "detail": "lock-free token bucket · 41.2k buckets"},
                {"name": "Rust extension", "status": "ok", "detail": "v3.0.0 · PQC / MMR / forwarder"},
                {"name": "PQC signing (ML-DSA-65)", "status": "ok", "detail": "FIPS 204 · 99.2% of nodes"},
                {"name": "Redis (rate-limit cluster)", "status": "warn", "detail": "1 replica lagging 40ms"},
                {"name": "Storage (Postgres)", "status": "ok", "detail": "primary + 2 read replicas"},
            ],
        },
        "runtime": {
            "kpis": {
                "requests_per_min": throughput[-1] * 60,
                "requests_total": node_base,
                "p50_ms": 0.41, "p95_ms": 0.83, "p99_ms": p99[-1],
                "added_latency_ms": added[-1],
                "blocked_waf": 14732, "rate_limited": 88214,
                "audit_nodes": node_base, "chain_integrity": "VALID",
                "error_rate": 0.014, "uptime_s": 1_398_540, "throughput_rps": throughput[-1],
            },
            "series": {"throughput": throughput, "p99": p99, "entropy": entropy, "added": added},
            "providers": [
                {"name": "OpenAI", "requests": 924_102_223, "p95_ms": 0.79, "tokens_in": 5_204_881_004, "tokens_out": 1_980_557_120, "errors": 120_440, "share": 50.1},
                {"name": "Anthropic", "requests": 518_821_119, "p95_ms": 0.91, "tokens_in": 3_122_004_551, "tokens_out": 1_244_119_882, "errors": 77_400, "share": 28.1},
                {"name": "Gemini", "requests": 241_175_400, "p95_ms": 0.88, "tokens_in": 1_402_551_223, "tokens_out": 612_004_117, "errors": 51_200, "share": 13.1},
                {"name": "OpenRouter", "requests": 158_454_275, "p95_ms": 1.04, "tokens_in": 905_117_004, "tokens_out": 388_240_660, "errors": 66_100, "share": 8.7},
            ],
            "waf": {
                "blocked_total": 14732,
                "by_pattern": [
                    {"pattern": "ignore previous instructions", "count": 6121, "severity": "crit"},
                    {"pattern": "system prompt exfiltration", "count": 3180, "severity": "crit"},
                    {"pattern": "DAN / jailbreak", "count": 2050, "severity": "crit"},
                    {"pattern": "role override", "count": 1422, "severity": "warn"},
                    {"pattern": "template injection {{}}", "count": 1210, "severity": "warn"},
                    {"pattern": "base64 obfuscation", "count": 749, "severity": "warn"},
                ],
                "recent": waf_recent,
            },
            "ratelimit": {
                "limited": 88214, "buckets_active": 41207,
                "top": [
                    {"key": "tenant:acme-prod", "used": 5980, "limit": 6000},
                    {"key": "tenant:globex", "used": 4120, "limit": 6000},
                    {"key": "ip:198.51.100.23", "used": 600, "limit": 600},
                    {"key": "tenant:initech", "used": 3110, "limit": 6000},
                    {"key": "tenant:umbrella", "used": 1450, "limit": 6000},
                ],
            },
            "audit": {
                "node_count": node_base, "scheme": "pqc-ml-dsa",
                "last_root": "b3:9f4c1a2e7d6b88f0c5a1e2d3b4c5f6a7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3",
                "nodes": nodes, "growth": growth,
            },
            "compliance": {
                "bundles": [
                    {"id": "8750666c", "format": "SOC2", "nodes": 40_021_550, "chain_hash": "239c3a4aeb96…", "signer": "pqc-ml-dsa", "integrity": "VALID", "ts": "2026-06-19T22:14:00Z"},
                    {"id": "a1f23be2", "format": "HIPAA", "nodes": 19_904_220, "chain_hash": "71b9e4c0a2d1…", "signer": "hmac-sha256", "integrity": "VALID", "ts": "2026-06-15T09:02:00Z"},
                    {"id": "cf90a7d4", "format": "SOC2", "nodes": 85_500_119, "chain_hash": "0ea4477122ab…", "signer": "pqc-ml-dsa", "integrity": "VALID", "ts": "2026-06-01T00:00:00Z"},
                    {"id": "5b2e1097", "format": "HIPAA", "nodes": 12_004_900, "chain_hash": "c41a9be07f23…", "signer": "pqc-ml-dsa", "integrity": "VALID", "ts": "2026-05-20T11:40:00Z"},
                ],
            },
            "performance": {
                "rust_mmr_speedup": 2.87, "hotpath_p50_us": 77, "hotpath_p99_us": 132, "added_p99_ms": 1.06,
                "bench": [
                    {"n": "100", "py": 210610, "rs": 604450},
                    {"n": "1,000", "py": 177630, "rs": 510120},
                    {"n": "10,000", "py": 159750, "rs": 458800},
                    {"n": "100,000", "py": 143500, "rs": 411270},
                ],
            },
        },
    }
    return bootstrap


def inject(template: str, bootstrap: dict, page: str) -> str:
    payload = json.dumps(bootstrap, separators=(",", ":"))
    script = (
        "  <script>\n"
        f"    window.__AEGIS_BOOTSTRAP__ = {payload};\n"
        f"    window.__AEGIS_INITIAL_PAGE__ = {json.dumps(page)};\n"
        "  </script>\n"
    )
    anchor = '  <script>\n  "use strict";'
    if anchor not in template:
        raise SystemExit("Template anchor not found — did static/index.html change its main <script> header?")
    html = template.replace(anchor, script + anchor, 1)
    html = html.replace(
        "<title>Aegis Latent Core — Mission Control</title>",
        f"<title>Aegis Mission Control — {page.title()} (Sample)</title>",
        1,
    )
    return html


def main() -> None:
    template = TEMPLATE.read_text(encoding="utf-8")
    bootstrap = build_bootstrap()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Full dashboard (lands on Overview).
    (OUT_DIR / "index.html").write_text(inject(template, bootstrap, "overview"), encoding="utf-8")

    # One deep-linked file per page for clean per-tab screenshots.
    for i, page in enumerate(PAGES, start=1):
        (OUT_DIR / f"{i:02d}-{page}.html").write_text(inject(template, bootstrap, page), encoding="utf-8")

    readme = """# Aegis Mission Control — Sample Gallery

These are **screenshot-ready** snapshots of the live dashboard
(`tools/visualizer/static/index.html`), pre-populated with realistic mock data
so the project can be shown as if it were running against a busy production
deployment (>1B audit nodes, multi-provider traffic, live WAF blocks, sealed
compliance bundles).

Every file is the *exact same UI* as the live dashboard — it just boots from an
embedded dataset instead of calling the API, so what you see is faithful to the
real program. Open any file directly in a browser (no server required; an
internet connection is used only to load the Chart.js / Mermaid CDNs).

| File | Page |
|------|------|
| `index.html` | Full dashboard (Overview) |
| `01-overview.html` | Overview — KPIs, live throughput & latency |
| `02-performance.html` | Performance — percentiles, Rust vs Python, budgets |
| `03-audit.html` | Audit Chain — Merkle root, node explorer, growth |
| `04-forensics.html` | Forensics — entropy / KL, static security scan |
| `05-waf.html` | WAF & Limits — injection blocks, rate-limit pressure |
| `06-providers.html` | Providers — routing share, token economics |
| `07-compliance.html` | Compliance — SOC2 / HIPAA sealed bundles |
| `08-architecture.html` | Architecture — topology, lifecycle, data flow |
| `09-code.html` | Code Map — Python / Rust symbol explorer |
| `10-health.html` | System Health — components & security posture |

Regenerate with:

    python tools/visualizer/generate_samples.py

> The numbers here are illustrative mock data for presentation only. The live
> dashboard reports real code/forensic metrics and renders honest "connect
> telemetry" states until a running proxy's metrics are wired in.
"""
    (OUT_DIR / "README.md").write_text(readme, encoding="utf-8")
    print(f"Wrote sample gallery to {OUT_DIR} ({len(PAGES) + 1} HTML files).")


if __name__ == "__main__":
    main()
