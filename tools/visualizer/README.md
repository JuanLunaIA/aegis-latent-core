# Aegis Mission Control — Visualizer

An enterprise-grade, single-file control-plane dashboard for Aegis Latent Core.
It presents the whole product across ten navigable pages, updates in real time,
and degrades honestly when runtime telemetry is not connected.

> **Local dev tool only — never expose publicly.** It reads repository metadata
> and (optionally) a running proxy's metrics.

## Pages

| Page | What it shows |
|------|---------------|
| **Overview** | Live KPIs, throughput & added-latency sparklines, system health, activity feed |
| **Performance** | p50/p95/p99 latency, Rust-vs-Python MMR throughput, hot-path overhead, budget meters, real control-plane latency |
| **Audit Chain** | Merkle root, signature-scheme distribution, chain-growth chart, searchable node explorer |
| **Forensics** | Token-level Shannon entropy, KL divergence, and the static security scan (`tools/forensic/report.json`) |
| **WAF & Limits** | Top injection patterns, recent blocked requests, rate-limit pressure per tenant |
| **Providers** | Traffic share, per-provider latency/tokens/errors, token economics |
| **Compliance** | SOC2 / HIPAA sealed export bundles with offline re-verification status |
| **Architecture** | Topology, request lifecycle, and data-flow Mermaid diagrams + signed-node layout |
| **Code Map** | Python / Rust symbol explorer derived live from the working tree |
| **System Health** | Component status grid and security posture |

## Features

- **Real-time** — auto-refreshes live data every 15 s, animates live series, shows
  the real control-plane (dashboard ↔ API) latency, and a live clock.
- **Honest by default** — runtime panels show explicit "connect telemetry" empty
  states rather than fabricating numbers. A clearly-badged **demo telemetry**
  toggle lets you preview the full experience.
- **Themeable** — dark / light, collapsible sidebar, fully responsive (desktop → mobile).
- **Accessible** — keyboard navigation (`j`/`k` to switch pages, `r` to refresh),
  ARIA roles, visible focus, reduced-motion support.
- **Exportable** — one-click JSON snapshot of the current model.

## Run (dev)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r tools/visualizer/requirements.txt
uvicorn tools.visualizer.app:app --reload --port 8081
# open http://localhost:8081/
```

### API

| Endpoint | Purpose |
|----------|---------|
| `GET /` | the dashboard |
| `GET /api/metrics` | repo-derived KPIs (code symbols, providers, tests, git/version) — **real, honest data** |
| `GET /api/summary` | full Python/Rust symbol index |
| `GET /api/forensic_report` | static security scan results |

`/api/metrics` intentionally returns `runtime: null` — this lightweight tool does
not invent inference telemetry. Wire it to a running proxy's metrics to light up
the runtime panels, or use the demo toggle / the sample gallery below.

## Sample gallery (screenshots)

`Samples/` contains screenshot-ready snapshots of the dashboard pre-populated with
realistic production-scale mock data. They are the *exact same UI* (they boot from
an embedded dataset instead of the API), so they faithfully represent the program.

```bash
python tools/visualizer/generate_samples.py   # regenerate Samples/
```

Open any `Samples/*.html` directly in a browser (no server needed; the Chart.js /
Mermaid CDNs are the only network dependency).
