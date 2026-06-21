# Aegis Mission Control — Visualizer

An enterprise-grade, single-file control-plane dashboard for Aegis Latent Core.
It presents the whole product across twelve navigable pages, updates in real time,
lets you **scan live payloads through every real detection engine**, and degrades
honestly when runtime telemetry is not connected.

> **Local dev tool only — never expose publicly.** It reads repository metadata
> and (optionally) a running proxy's metrics, and runs the detection engines on
> text you submit in the Threat Lab.

## Pages

| Page | What it shows |
|------|---------------|
| **Overview** | Live KPIs, throughput & added-latency sparklines, system health, activity feed |
| **Performance** | p50/p95/p99 latency, Rust-vs-Python MMR throughput, hot-path overhead, budget meters, real control-plane latency |
| **Providers** | Traffic share, per-provider latency/tokens/errors, token economics |
| **System Health** | Component status grid and security posture |
| **🛡 Threat Lab** | **Paste a payload — a prompt injection, the EICAR test virus, a leaked key, a classified marker, a SCADA command — and watch every Aegis engine flag it live, with verdict, severity, matched signatures and timing.** Ships a one-click test-payload library. |
| **Detectors** | Catalog of all 10 detection engines with a coverage radar and per-engine severity ceiling |
| **WAF & Limits** | Top injection patterns, recent blocked requests, rate-limit pressure per tenant |
| **Audit Chain** | Merkle root, signature-scheme distribution, chain-growth chart, searchable node explorer |
| **Forensics** | Token-level Shannon entropy, KL divergence, and the static security scan (`tools/forensic/report.json`) |
| **Compliance** | SOC2 / HIPAA sealed export bundles with offline re-verification status |
| **Architecture** | Topology, request lifecycle, and data-flow Mermaid diagrams + signed-node layout |
| **Code Map** | Python / Rust symbol explorer derived live from the working tree |

## Threat Lab — live detection testing

The Threat Lab is the answer to *"does it actually catch things?"* — it runs your
input through **the real production detection classes** (not mocks) and returns a
single normalized verdict:

| Engine | Catches |
|--------|---------|
| `AegisWAF` (Aho-Corasick + regex) | prompt injection / jailbreak |
| `YARAEngine` | jailbreak / obfuscation rule hits |
| Malware-signature pass | EICAR test virus, Log4Shell, pipe-to-shell droppers, XSS, SQLi |
| Secret-leak pass | private keys, OpenAI/AWS/GitHub/Slack tokens, hard-coded creds |
| `ClassifiedMarkerDetector` | DoD/IC SCI/SAP classification banners |
| `AdversarialSuffixDetector` | GCG / AutoDAN gradient suffixes |
| `RAGInjectionScanner` | indirect injection in retrieved content |
| `ManyShotDetector` | many-shot example flooding |
| `OTProtocolScanner` | MODBUS / DNP3 / OPC-UA command injection |
| `IOCCorrelator` | SimHash correlation to known threat-actor TTPs |

Verdict policy: **BLOCK** on any high/critical hit, **FLAG** on medium/low, **ALLOW**
when clean. Backed by `tools/visualizer/threat_lab.py` and proven by
`tests/test_threat_lab.py` (30 tests). In the static sample gallery the lab uses a
transparent client-side simulator; the live dashboard scans through the real engines.

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
| `POST /api/scan` | `{"text": "..."}` → runs the text through every real detection engine and returns the unified verdict (powers the Threat Lab) |
| `GET /api/threat_samples` | curated, safe one-click test payloads for the Threat Lab |

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
