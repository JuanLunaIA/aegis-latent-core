# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from tools.visualizer.generate_summary import generate_summary_dict

if getattr(sys, "frozen", False):
    APP_DIR = Path(sys._MEIPASS)  # type: ignore[attr-defined]
else:
    APP_DIR = Path(__file__).resolve().parents[2]

PROJECT_DIR = Path.cwd()
VIS_DIR = APP_DIR / "tools" / "visualizer"

app = FastAPI(title="Aegis Visualizer")

# ── SSE event bus ─────────────────────────────────────────────────────────────
# A module-level asyncio.Queue that POST /api/scan publishes scan events to.
# GET /api/events subscribers consume from their own per-connection copy via a
# broadcast list so every connected dashboard tab receives every event.
_SSE_SUBSCRIBERS: list[asyncio.Queue[str]] = []
_SSE_LOCK = asyncio.Lock()


async def _broadcast_event(event_type: str, data: dict) -> None:
    """Publish a JSON event to all active SSE subscribers."""
    payload = json.dumps({"type": event_type, "ts": time.time(), **data})
    msg = f"data: {payload}\n\n"
    async with _SSE_LOCK:
        dead: list[asyncio.Queue[str]] = []
        for q in _SSE_SUBSCRIBERS:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            _SSE_SUBSCRIBERS.remove(q)


async def _sse_generator(queue: asyncio.Queue[str]) -> AsyncGenerator[str, None]:
    """Yield SSE frames from the subscriber queue until the client disconnects."""
    yield ": aegis-stream-connected\n\n"  # Initial ping so the browser opens the connection
    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=25.0)
                yield msg
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"  # Prevent proxy/load-balancer idle disconnects
    except asyncio.CancelledError:
        pass
    finally:
        async with _SSE_LOCK:
            try:
                _SSE_SUBSCRIBERS.remove(queue)
            except ValueError:
                pass
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
        t0 = time.perf_counter()
        with ThreadPoolExecutor() as pool:
            data = await loop.run_in_executor(pool, scan_text, text)
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        data["latency_ms"] = latency_ms
        # Broadcast to all SSE subscribers so every open dashboard tab updates live
        await _broadcast_event(
            "scan_result",
            {
                "verdict": data.get("verdict"),
                "severity": data.get("severity"),
                "latency_ms": latency_ms,
                "engine_count": len(data.get("engines", [])),
                "flagged_engines": [
                    e["engine"] for e in data.get("engines", []) if e.get("flagged")
                ],
                "text_preview": text[:80],
            },
        )
        return JSONResponse(content=data)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "scan failed", "exception": str(e)})


@app.get("/api/events")
async def events(request: Request) -> StreamingResponse:
    """Server-Sent Events stream for live dashboard updates.

    Every POST /api/scan result is broadcast here so all 12 dashboard tabs
    can update in real time without polling.

    Connect from JavaScript:
        const es = new EventSource('/api/events');
        es.onmessage = e => { const ev = JSON.parse(e.data); ... };

    Event types:
        scan_result  — a completed Threat Lab scan (verdict, engines, latency_ms)
        keepalive    — 25-second heartbeat comment (no event dispatched by browser)
    """
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=64)
    async with _SSE_LOCK:
        _SSE_SUBSCRIBERS.append(queue)
    return StreamingResponse(
        _sse_generator(queue),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering for SSE
            "Connection": "keep-alive",
        },
    )


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
