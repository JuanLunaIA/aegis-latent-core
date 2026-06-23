# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.slo_alerting — SLO burn-rate alert rule generation.

Implements the multi-window, multi-burn-rate alerting pattern from the
Google SRE Workbook (Chapter 5) for Aegis proxy SLOs.

Two SLOs are modelled:

Availability SLO
    99.9% of requests return a non-5xx status class.
    Error budget = 0.1% of requests.

Latency SLO
    99% of requests complete in < 500ms (end-to-end, stage=total).
    Error budget = 1% of requests.

For each SLO, four burn-rate windows are generated following the
standard page/ticket severity mapping:

  1h  / 5m  window → burn ≥ 14.4× → severity: critical  (2% budget in 1h)
  6h  / 30m window → burn ≥ 6×    → severity: critical  (5% budget in 6h)
  24h / 2h  window → burn ≥ 3×    → severity: warning   (10% budget in 24h)
  72h / 6h  window → burn ≥ 1×    → severity: warning   (100% in 72h)

Usage::

    from aegis.core.slo_alerting import (
        default_burn_rate_windows,
        generate_prometheus_rule,
        SLOConfig,
        AVAILABILITY_SLO,
        LATENCY_SLO,
    )

    rule = generate_prometheus_rule([AVAILABILITY_SLO, LATENCY_SLO])
    import yaml
    print(yaml.dump(rule))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ── Dataclasses ───────────────────────────────────────────────────────────────


@dataclass
class SLOBurnRateWindow:
    """One multi-window burn-rate alert pair.

    Attributes
    ----------
    short_window:
        Short evaluation window (e.g. ``"5m"``). Used for fast confirmation.
    long_window:
        Long evaluation window (e.g. ``"1h"``). Sets overall burn rate.
    burn_rate_threshold:
        Minimum burn rate multiplier above which the alert fires.
        E.g. ``14.4`` means the error budget is being consumed 14.4× faster
        than allowed.
    severity:
        Alert severity label (``"critical"`` or ``"warning"``).
    page:
        If ``True``, this window should trigger an on-call page.
    """

    short_window: str
    long_window: str
    burn_rate_threshold: float
    severity: str
    page: bool = True


@dataclass
class SLOConfig:
    """Configuration for one Service Level Objective.

    Attributes
    ----------
    name:
        Short identifier used in alert names (e.g. ``"availability"``).
    slo_target:
        Fractional SLO target (e.g. ``0.999`` for 99.9%).
    error_budget_fraction:
        ``1.0 - slo_target``.
    expr_error_rate:
        PromQL expression returning the *instantaneous error fraction*
        (values in [0, 1]).  Must accept a ``{window}`` placeholder that
        will be substituted with the evaluation window string.
    description:
        Human-readable SLO description.
    alert_labels:
        Additional labels attached to every alert (e.g. team, service).
    alert_annotations:
        Additional annotations attached to every alert.
    """

    name: str
    slo_target: float
    error_budget_fraction: float
    expr_error_rate: str
    description: str
    alert_labels: dict[str, str] = field(default_factory=dict)
    alert_annotations: dict[str, str] = field(default_factory=dict)

    def burn_rate_for_window(self, window_seconds: int) -> float:
        """Return the exact burn rate at which the budget is exhausted in *window_seconds*."""
        budget_seconds = (1 - self.slo_target) * 30 * 24 * 3600  # 30-day budget
        return budget_seconds / window_seconds


# ── Standard window set ───────────────────────────────────────────────────────

_WINDOW_SECONDS = {
    "5m": 5 * 60,
    "30m": 30 * 60,
    "1h": 3600,
    "2h": 2 * 3600,
    "6h": 6 * 3600,
    "72h": 72 * 3600,
}


def default_burn_rate_windows() -> list[SLOBurnRateWindow]:
    """Return the four standard multi-window burn-rate alert pairs.

    Based on the Google SRE Workbook Chapter 5 multi-burn-rate algorithm
    for a 30-day error budget:

    +-----------+-----------+------------+----------+
    | Long win  | Short win | Burn rate  | Severity |
    +===========+===========+============+==========+
    | 1h        | 5m        | 14.4       | critical |
    +-----------+-----------+------------+----------+
    | 6h        | 30m       | 6          | critical |
    +-----------+-----------+------------+----------+
    | 24h       | 2h        | 3          | warning  |
    +-----------+-----------+------------+----------+
    | 72h       | 6h        | 1          | warning  |
    +-----------+-----------+------------+----------+
    """
    return [
        SLOBurnRateWindow(
            long_window="1h",
            short_window="5m",
            burn_rate_threshold=14.4,
            severity="critical",
            page=True,
        ),
        SLOBurnRateWindow(
            long_window="6h",
            short_window="30m",
            burn_rate_threshold=6.0,
            severity="critical",
            page=True,
        ),
        SLOBurnRateWindow(
            long_window="24h",
            short_window="2h",
            burn_rate_threshold=3.0,
            severity="warning",
            page=False,
        ),
        SLOBurnRateWindow(
            long_window="72h",
            short_window="6h",
            burn_rate_threshold=1.0,
            severity="warning",
            page=False,
        ),
    ]


# ── Preconfigured SLOs ────────────────────────────────────────────────────────

AVAILABILITY_SLO = SLOConfig(
    name="availability",
    slo_target=0.999,
    error_budget_fraction=0.001,
    expr_error_rate=(
        "sum(rate(aegis_requests_total{{status_class=~'4xx|5xx'}}[{window}])) "
        "/ sum(rate(aegis_requests_total[{window}]))"
    ),
    description="99.9% of proxy requests return a non-error status class",
    alert_labels={"slo": "availability", "service": "aegis-proxy"},
    alert_annotations={
        "runbook_url": "https://github.com/JuanLunaIA/aegis-latent-core/blob/main/docs/runbooks/availability.md",
        "summary": "Aegis proxy availability SLO burn rate is too high",
    },
)

LATENCY_SLO = SLOConfig(
    name="latency",
    slo_target=0.990,
    error_budget_fraction=0.010,
    expr_error_rate=(
        "1 - ("
        "sum(rate(aegis_request_duration_seconds_bucket{{stage='total',le='0.5'}}[{window}])) "
        "/ sum(rate(aegis_request_duration_seconds_count{{stage='total'}}[{window}]))"
        ")"
    ),
    description="99% of end-to-end proxy requests complete in < 500ms",
    alert_labels={"slo": "latency", "service": "aegis-proxy"},
    alert_annotations={
        "runbook_url": "https://github.com/JuanLunaIA/aegis-latent-core/blob/main/docs/runbooks/latency.md",
        "summary": "Aegis proxy latency SLO burn rate is too high",
    },
)


# ── PrometheusRule generator ──────────────────────────────────────────────────


def _alert_name(slo: SLOConfig, win: SLOBurnRateWindow) -> str:
    return f"AegisSLO{slo.name.capitalize()}BurnRate{win.long_window.upper()}"


def _build_alert(slo: SLOConfig, win: SLOBurnRateWindow) -> dict[str, Any]:
    long_expr = slo.expr_error_rate.format(window=win.long_window)
    short_expr = slo.expr_error_rate.format(window=win.short_window)
    burn = win.burn_rate_threshold
    threshold = slo.error_budget_fraction * burn

    labels = {
        "severity": win.severity,
        "long_window": win.long_window,
        "short_window": win.short_window,
        **slo.alert_labels,
    }
    annotations = {
        "description": (
            f"{slo.description}. "
            f"Burn rate is ≥{burn}× over {win.long_window} "
            f"(consuming budget {burn}× faster than allowed)."
        ),
        **slo.alert_annotations,
    }

    return {
        "alert": _alert_name(slo, win),
        "expr": (f"(\n  {long_expr}\n  > {threshold}\n) and (\n  {short_expr}\n  > {threshold}\n)"),
        "for": win.short_window,
        "labels": labels,
        "annotations": annotations,
    }


def generate_prometheus_rule(
    slos: list[SLOConfig] | None = None,
    windows: list[SLOBurnRateWindow] | None = None,
    namespace: str = "monitoring",
    name: str = "aegis-slo-burn-rate",
    additional_labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Generate a Kubernetes PrometheusRule manifest for SLO burn-rate alerting.

    Parameters
    ----------
    slos:
        List of :class:`SLOConfig` to generate rules for.
        Defaults to ``[AVAILABILITY_SLO, LATENCY_SLO]``.
    windows:
        List of :class:`SLOBurnRateWindow` pairs.
        Defaults to :func:`default_burn_rate_windows`.
    namespace:
        Kubernetes namespace for the PrometheusRule resource.
    name:
        ``metadata.name`` of the PrometheusRule resource.
    additional_labels:
        Extra labels added to ``metadata.labels`` (e.g. for label selectors).

    Returns
    -------
    dict
        A Python dict representing the PrometheusRule CRD, serializable to YAML.
    """
    if slos is None:
        slos = [AVAILABILITY_SLO, LATENCY_SLO]
    if windows is None:
        windows = default_burn_rate_windows()

    labels: dict[str, str] = {
        "app": "aegis-proxy",
        "release": "aegis",
        **(additional_labels or {}),
    }

    alerts = []
    for slo in slos:
        for win in windows:
            alerts.append(_build_alert(slo, win))

    return {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "PrometheusRule",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": labels,
        },
        "spec": {
            "groups": [
                {
                    "name": "aegis.slo.burn-rate",
                    "interval": "30s",
                    "rules": alerts,
                }
            ]
        },
    }


# ── Validation helpers ────────────────────────────────────────────────────────


def validate_burn_rate_threshold(
    window_seconds: int,
    burn_rate_threshold: float,
    slo_target: float,
    budget_days: int = 30,
) -> tuple[bool, float]:
    """Validate that a burn rate threshold is non-trivial for the given window.

    A threshold is valid when the consumed budget fraction at that burn rate
    over the window is > 0 and ≤ 1 (i.e. the window can actually exhaust
    the budget at the given rate).

    Returns
    -------
    (valid, budget_fraction_consumed)
        ``valid`` is True when 0 < budget_fraction < 1.
        ``budget_fraction_consumed`` is the fraction of the 30-day budget
        that would be consumed if the system burns at *burn_rate_threshold*
        for the entire *window_seconds*.
    """
    error_budget_fraction = 1.0 - slo_target
    budget_seconds = error_budget_fraction * budget_days * 24 * 3600
    consumed = burn_rate_threshold * window_seconds / (budget_days * 24 * 3600)
    valid = 0 < consumed <= 1.0
    return valid, consumed


def alert_names(
    slos: list[SLOConfig] | None = None,
    windows: list[SLOBurnRateWindow] | None = None,
) -> list[str]:
    """Return all alert names that would be generated for the given SLOs and windows."""
    if slos is None:
        slos = [AVAILABILITY_SLO, LATENCY_SLO]
    if windows is None:
        windows = default_burn_rate_windows()
    return [_alert_name(slo, win) for slo in slos for win in windows]
