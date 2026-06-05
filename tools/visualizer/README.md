Aegis Visualizer (light)

This is a small, optional dashboard to inspect repository structure and a quick summary of test results.

How to run (dev):

1. Create virtualenv and install dependencies:

   python -m venv .venv && source .venv/bin/activate
   pip install -r tools/visualizer/requirements.txt

2. Start the dashboard:

   uvicorn tools.visualizer.app:app --reload --port 8081

3. Open http://localhost:8081/ in your browser.

Notes:
- The visualizer is intentionally lightweight (no DB). It runs a small generator script to summarize Python and Rust symbols.
- For production dashboards, integrate with Prometheus/Grafana or a React UI and persist audit data to a secure storage backend.
