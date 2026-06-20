# Aegis Mission Control — Sample Gallery

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
