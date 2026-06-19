# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import json
import subprocess
from pathlib import Path

import sys

if getattr(sys, 'frozen', False):
    APP_DIR = Path(sys._MEIPASS)
else:
    APP_DIR = Path(__file__).resolve().parents[2]

PROJECT_DIR = Path.cwd()
VIS_DIR = APP_DIR / "tools" / "visualizer"

app = FastAPI(title="Aegis Visualizer")
app.mount("/static", StaticFiles(directory=str(VIS_DIR / "static")), name="static")


import asyncio
from concurrent.futures import ThreadPoolExecutor
from tools.visualizer.generate_summary import generate_summary_dict

@app.get("/api/summary")
async def summary():
    try:
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as pool:
            data = await loop.run_in_executor(pool, generate_summary_dict)
        return JSONResponse(content=data)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "failed to generate summary", "exception": str(e)})


@app.get("/api/forensic_report")
async def forensic_report():
    path = PROJECT_DIR / "tools" / "forensic" / "report.json"
    if not path.exists():
        return JSONResponse(status_code=404, content={"error": "forensic report not found"})
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "failed to read report", "exception": str(e)})
    return JSONResponse(content=data)


@app.get("/")
async def index():
    return FileResponse(str(VIS_DIR / "static" / "index.html"))
