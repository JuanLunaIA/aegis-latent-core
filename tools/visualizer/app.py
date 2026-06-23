# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from tools.visualizer.generate_summary import generate_summary_dict

if getattr(sys, "frozen", False):
    APP_DIR = Path(sys._MEIPASS)  # type: ignore[attr-defined]
else:
    APP_DIR = Path(__file__).resolve().parents[2]

PROJECT_DIR = Path.cwd()
VIS_DIR = APP_DIR / "tools" / "visualizer"

app = FastAPI(title="Aegis Visualizer")
app.mount("/static", StaticFiles(directory=str(VIS_DIR / "static")), name="static")


@app.get("/api/summary")
async def summary():
    try:
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as pool:
            data = await loop.run_in_executor(pool, generate_summary_dict)
        return JSONResponse(content=data)
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"error": "failed to generate summary", "exception": str(e)}
        )


@app.get("/api/forensic_report")
async def forensic_report():
    path = PROJECT_DIR / "tools" / "forensic" / "report.json"
    if not path.exists():
        return JSONResponse(status_code=404, content={"error": "forensic report not found"})
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"error": "failed to read report", "exception": str(e)}
        )
    return JSONResponse(content=data)


def _build_metrics() -> dict:
    """Repo-derived, honest metrics for the dashboard control plane.

    This endpoint reports only what can be measured from the working tree
    (code symbol counts, providers, test snapshot, git/version). Runtime
    inference telemetry (throughput, latency, audit nodes) is intentionally
    absent here — the dashboard renders explicit "connect telemetry" states
    or a clearly-badged demo stream rather than fabricating numbers.
    """
    summary = generate_summary_dict()

    def _is_src(rel: str) -> bool:
        return (
            (rel.startswith("aegis/") or rel.startswith("aegis_server/"))
            and ".venv" not in rel
            and "site-packages" not in rel
        )

    py = summary.get("python", {})
    rs = summary.get("rust", {})

    py_fn = py_cls = 0
    top_modules = []
    for rel, info in py.items():
        if not _is_src(rel) or not isinstance(info, dict):
            continue
        f = len(info.get("functions", []) or [])
        c = len(info.get("classes", []) or [])
        py_fn += f
        py_cls += c
        if f or c:
            top_modules.append({"path": rel, "functions": f, "classes": c})

    rust_fn = 0
    for rel, info in rs.items():
        if ".venv" in rel or "/target/" in rel or not isinstance(info, dict):
            continue
        rust_fn += len(info.get("functions", []) or [])

    top_modules.sort(key=lambda m: m["functions"] + m["classes"], reverse=True)

    # Read project version from pyproject if available.
    version = "unknown"
    pp = PROJECT_DIR / "pyproject.toml"
    if pp.exists():
        try:
            for line in pp.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s.startswith("version") and "=" in s:
                    version = s.split("=", 1)[1].strip().strip('"').strip("'")
                    break
        except Exception:
            pass

    # Discover configured provider adapters from the providers package.
    providers = []
    prov_dir = PROJECT_DIR / "aegis" / "providers"
    if prov_dir.exists():
        for p in sorted(prov_dir.glob("*_provider.py")):
            providers.append(p.stem.replace("_provider", ""))
    if not providers:
        providers = ["openai", "anthropic", "gemini", "openrouter"]

    forensic = {}
    fpath = PROJECT_DIR / "tools" / "forensic" / "report.json"
    if fpath.exists():
        try:
            forensic = json.loads(fpath.read_text(encoding="utf-8"))
        except Exception:
            forensic = {}

    return {
        "meta": {
            "project": summary.get("project"),
            "git_head": summary.get("git_head"),
            "version": version,
        },
        "code": {
            "python_files": sum(1 for r in py if _is_src(r)),
            "rust_files": sum(1 for r in rs if ".venv" not in r and "/target/" not in r),
            "py_functions": py_fn,
            "py_classes": py_cls,
            "rust_functions": rust_fn,
            "top_modules": top_modules[:40],
        },
        "providers": providers,
        "tests": summary.get("test_results", {}),
        "forensics": {
            "rust_build": forensic.get("rust_build", {}),
            "python_syntax": forensic.get("python_syntax", []),
        },
        "runtime": None,
    }


@app.get("/api/metrics")
async def metrics():
    try:
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as pool:
            data = await loop.run_in_executor(pool, _build_metrics)
        return JSONResponse(content=data)
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"error": "failed to build metrics", "exception": str(e)}
        )


_MAX_SCAN_CHARS = 20000


@app.post("/api/scan")
async def scan(request: Request):
    """Run submitted text through every real Aegis detection engine.

    This powers the Threat Lab page: paste a prompt injection, an EICAR test
    virus, a leaked key, a classified marker or a SCADA command and see exactly
    which engines flag it and why. Input is bounded and never executed.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid JSON body"})
    text = (body or {}).get("text", "")
    if not isinstance(text, str):
        return JSONResponse(status_code=400, content={"error": "'text' must be a string"})
    if len(text) > _MAX_SCAN_CHARS:
        text = text[:_MAX_SCAN_CHARS]
    try:
        from tools.visualizer.threat_lab import scan_text

        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as pool:
            data = await loop.run_in_executor(pool, scan_text, text)
        return JSONResponse(content=data)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "scan failed", "exception": str(e)})


@app.get("/api/threat_samples")
async def threat_samples():
    """Curated, safe one-click test payloads for the Threat Lab."""
    try:
        from tools.visualizer.threat_lab import sample_payloads

        return JSONResponse(content={"samples": sample_payloads()})
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"error": "failed to load samples", "exception": str(e)}
        )


@app.get("/")
async def index():
    return FileResponse(str(VIS_DIR / "static" / "index.html"))
