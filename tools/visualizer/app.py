from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VIS_DIR = ROOT / "tools" / "visualizer"

app = FastAPI(title="Aegis Visualizer")
app.mount("/static", StaticFiles(directory=str(VIS_DIR / "static")), name="static")


@app.get("/api/summary")
async def summary():
    # Run the local summary generator (lightweight, no deps)
    gen = VIS_DIR / "generate_summary.py"
    try:
        proc = subprocess.run(["python", str(gen)], capture_output=True, text=True, cwd=str(ROOT), timeout=30)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"failed to run generator: {e}"})
    if proc.returncode != 0:
        return JSONResponse(status_code=500, content={"error": "generator failed", "stderr": proc.stderr})
    try:
        data = json.loads(proc.stdout)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "invalid json from generator", "exception": str(e), "raw": proc.stdout})
    return JSONResponse(content=data)


@app.get("/api/forensic_report")
async def forensic_report():
    path = ROOT / "tools" / "forensic" / "report.json"
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
