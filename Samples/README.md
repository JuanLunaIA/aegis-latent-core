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
| `03-providers.html` | Providers — routing share, token economics |
| `04-health.html` | System Health — components & security posture |
| `05-threatlab.html` | **Threat Lab** — paste a payload (EICAR virus, injection, leaked key…) and watch every engine flag it |
| `06-detectors.html` | **Detectors** — detection-engine catalog & coverage radar |
| `07-waf.html` | WAF & Limits — injection blocks, rate-limit pressure |
| `08-audit.html` | Audit Chain — Merkle root, node explorer, growth |
| `09-forensics.html` | Forensics — entropy / KL, static security scan |
| `10-compliance.html` | Compliance — SOC2 / HIPAA sealed bundles |
| `11-architecture.html` | Architecture — topology, lifecycle, data flow |
| `12-code.html` | Code Map — Python / Rust symbol explorer |

Regenerate with:

```bash
# Run from the repository root, not from Samples/.
python tools/visualizer/generate_samples.py
```

The root working directory ensures the generator writes to the tracked
`Samples/` directory and resolves visualizer assets correctly. For the live
local tool and its clean-checkout environment, see the
[visualizer README](../tools/visualizer/README.md). Canonical project navigation
is in the [repository overview](../README.md) and
[developer quickstart](../docs/DEVELOPER_QUICKSTART.md).

> The numbers here are illustrative mock data for presentation only. The live
> dashboard reports real code/forensic metrics and renders honest "connect
> telemetry" states until a running proxy's metrics are wired in.
