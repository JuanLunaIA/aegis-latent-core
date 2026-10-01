# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""The shipped alert rules and dashboard may only reference metrics the gateway exports."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "deploy" / "observability"
EXPORTED = set(re.findall(r'"(aegis_[a-z_]+)"', (ROOT / "aegis/core/observability.py").read_text()))
SUFFIXES = ("_bucket", "_count", "_sum")


def _metrics(expression: str) -> set[str]:
    names = set(re.findall(r"\baegis_[a-z_]+", expression))
    return {next((n[: -len(s)] for s in SUFFIXES if n.endswith(s)), n) for n in names}


def _rules() -> list[dict[str, object]]:
    doc = yaml.safe_load((ASSETS / "prometheus-alerts.yml").read_text(encoding="utf-8"))
    return [rule for group in doc["groups"] for rule in group["rules"]]


def test_every_alert_references_an_exported_metric():
    for rule in _rules():
        used = _metrics(str(rule["expr"]))
        assert used, rule["alert"]
        assert used <= EXPORTED, f"{rule['alert']} uses {sorted(used - EXPORTED)}"


def test_every_alert_has_a_known_severity():
    for rule in _rules():
        assert rule["labels"]["severity"] in {"critical", "warning", "info"}, rule["alert"]  # type: ignore[index]


def test_the_documented_alerts_are_all_shipped():
    documented = set(
        re.findall(
            r"- alert: (\w+)",
            (ROOT / "docs/operations/MONITORING_ALERTING.md").read_text(encoding="utf-8"),
        )
    )
    assert documented <= {str(r["alert"]) for r in _rules()}


def test_every_dashboard_expression_references_an_exported_metric():
    dashboard = json.loads((ASSETS / "grafana-aegis-dashboard.json").read_text(encoding="utf-8"))
    assert len(dashboard["panels"]) >= 10
    for panel in dashboard["panels"]:
        for target in panel["targets"]:
            used = _metrics(target["expr"])
            assert used, panel["title"]
            assert used <= EXPORTED, f"{panel['title']} uses {sorted(used - EXPORTED)}"
