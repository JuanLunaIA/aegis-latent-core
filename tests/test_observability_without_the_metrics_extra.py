# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The no-op stub path in aegis.core.observability.

``CLM-013``'s boundary reads: "It requires the optional ``metrics`` extra and a
working scrape; without ``prometheus-client`` no ``/metrics`` endpoint is
registered and every metric is a no-op." The module implements that with a
``try: import prometheus_client`` plus a ``_NoopMetric`` fallback, so which half
executes is a property of the *environment*, not of the code.

Now that the ``metrics`` extra is installed for the suite (``REG-D40``), the real
branch is the one this process executes and the fallback would never run
anywhere. The fallback is exercised here by importing the module a second time,
under a private name, with the import of ``prometheus_client`` halted — which is
what ``sys.modules[name] = None`` does, without touching the already-imported
real module or the default registry every other test reads. A fresh interpreter
is used for the real half so the pair does not depend on this process's imports.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "aegis" / "core" / "observability.py"
PROBE_NAME = "aegis.core._observability_fallback_probe"

REAL_PROGRAM = """
import json

import aegis.core.observability as obs

obs.REQUEST_TOTAL.labels(method="GET", endpoint="/v1", status_class="2xx").inc()
print(json.dumps({
    "prom": obs._PROM,
    "available": obs.prometheus_available(),
    "metric_type": type(obs.REQUEST_TOTAL).__name__,
}))
"""


def _load_with_the_import_halted(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the module fresh, with ``import prometheus_client`` refused."""
    monkeypatch.setitem(sys.modules, "prometheus_client", None)
    spec = importlib.util.spec_from_file_location(PROBE_NAME, MODULE_PATH)
    assert spec is not None, f"no import spec for {MODULE_PATH}"
    assert spec.loader is not None, "the module path has no loader"
    module = importlib.util.module_from_spec(spec)
    sys.modules[PROBE_NAME] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(PROBE_NAME, None)
    return module


def test_the_fallback_is_taken_when_the_import_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`prometheus_client` unimportable -> no-op stubs, and every call is silent."""
    module = _load_with_the_import_halted(monkeypatch)

    assert module._PROM is False
    assert module.prometheus_available() is False
    assert type(module.REQUEST_TOTAL).__name__ == "_NoopMetric"

    exercised = 0
    for name in dir(module):
        if not name.isupper():
            continue
        metric = getattr(module, name)
        if not hasattr(metric, "labels"):
            continue
        # The full method surface, so no caller ever has to branch on _PROM.
        metric.labels(method="GET", endpoint="/v1", stage="total", layer="layer1")
        metric.inc()
        metric.observe(0.001)
        metric.set(2.0)
        metric.set_function(lambda: 1.0)
        exercised += 1
    assert exercised > 10, f"only {exercised} stub metrics were exercised"


def test_the_real_metrics_are_constructed_when_the_import_succeeds() -> None:
    """The same question in a fresh interpreter: the real classes, or a skip."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "PYTHONHOME", "LD_LIBRARY_PATH")
    }
    env["AEGIS_SECURITY_ENFORCEMENT_MODE"] = "development"
    env["HERMES_SANDBOX"] = "true"
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    # No untrusted input reaches this command: it is this file's own constant.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", textwrap.dedent(REAL_PROGRAM)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(PROJECT_ROOT),
        timeout=180,
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout.strip().splitlines()[-1])

    if not summary["available"]:
        pytest.skip("prometheus_client is not installed in this environment")
    assert summary["prom"] is True
    assert summary["metric_type"] != "_NoopMetric"
