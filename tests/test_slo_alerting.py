# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.slo_alerting — SLO burn-rate alert rule generation."""

from __future__ import annotations

from aegis.core.slo_alerting import (
    AVAILABILITY_SLO,
    LATENCY_SLO,
    SLOBurnRateWindow,
    SLOConfig,
    alert_names,
    default_burn_rate_windows,
    generate_prometheus_rule,
    validate_burn_rate_threshold,
)

# ── SLOBurnRateWindow ─────────────────────────────────────────────────────────


class TestSLOBurnRateWindow:
    def test_construction(self):
        w = SLOBurnRateWindow(
            long_window="1h",
            short_window="5m",
            burn_rate_threshold=14.4,
            severity="critical",
        )
        assert w.long_window == "1h"
        assert w.short_window == "5m"
        assert w.burn_rate_threshold == 14.4
        assert w.severity == "critical"
        assert w.page is True

    def test_page_defaults_true(self):
        w = SLOBurnRateWindow("24h", "2h", 3.0, "warning")
        assert w.page is True

    def test_page_can_be_set_false(self):
        w = SLOBurnRateWindow("72h", "6h", 1.0, "warning", page=False)
        assert w.page is False


# ── default_burn_rate_windows ─────────────────────────────────────────────────


class TestDefaultBurnRateWindows:
    def test_returns_four_windows(self):
        windows = default_burn_rate_windows()
        assert len(windows) == 4

    def test_first_window_is_1h_5m(self):
        w = default_burn_rate_windows()[0]
        assert w.long_window == "1h"
        assert w.short_window == "5m"

    def test_second_window_is_6h_30m(self):
        w = default_burn_rate_windows()[1]
        assert w.long_window == "6h"
        assert w.short_window == "30m"

    def test_third_window_is_24h_2h(self):
        w = default_burn_rate_windows()[2]
        assert w.long_window == "24h"
        assert w.short_window == "2h"

    def test_fourth_window_is_72h_6h(self):
        w = default_burn_rate_windows()[3]
        assert w.long_window == "72h"
        assert w.short_window == "6h"

    def test_burn_rate_1h_is_14_4(self):
        assert default_burn_rate_windows()[0].burn_rate_threshold == 14.4

    def test_burn_rate_6h_is_6(self):
        assert default_burn_rate_windows()[1].burn_rate_threshold == 6.0

    def test_burn_rate_24h_is_3(self):
        assert default_burn_rate_windows()[2].burn_rate_threshold == 3.0

    def test_burn_rate_72h_is_1(self):
        assert default_burn_rate_windows()[3].burn_rate_threshold == 1.0

    def test_1h_severity_is_critical(self):
        assert default_burn_rate_windows()[0].severity == "critical"

    def test_6h_severity_is_critical(self):
        assert default_burn_rate_windows()[1].severity == "critical"

    def test_24h_severity_is_warning(self):
        assert default_burn_rate_windows()[2].severity == "warning"

    def test_72h_severity_is_warning(self):
        assert default_burn_rate_windows()[3].severity == "warning"

    def test_burn_rates_descend(self):
        rates = [w.burn_rate_threshold for w in default_burn_rate_windows()]
        assert rates == sorted(rates, reverse=True)


# ── Preconfigured SLOs ────────────────────────────────────────────────────────


class TestPreconfiguredSLOs:
    def test_availability_slo_target(self):
        assert AVAILABILITY_SLO.slo_target == 0.999

    def test_availability_error_budget(self):
        assert AVAILABILITY_SLO.error_budget_fraction == 0.001

    def test_availability_name(self):
        assert AVAILABILITY_SLO.name == "availability"

    def test_latency_slo_target(self):
        assert LATENCY_SLO.slo_target == 0.990

    def test_latency_error_budget(self):
        assert LATENCY_SLO.error_budget_fraction == 0.010

    def test_latency_name(self):
        assert LATENCY_SLO.name == "latency"

    def test_availability_expr_contains_metric(self):
        assert "aegis_requests_total" in AVAILABILITY_SLO.expr_error_rate

    def test_latency_expr_contains_metric(self):
        assert "aegis_request_duration_seconds" in LATENCY_SLO.expr_error_rate

    def test_availability_has_alert_labels(self):
        assert "slo" in AVAILABILITY_SLO.alert_labels
        assert AVAILABILITY_SLO.alert_labels["slo"] == "availability"

    def test_latency_has_alert_labels(self):
        assert LATENCY_SLO.alert_labels["slo"] == "latency"

    def test_slo_budget_and_target_consistent(self):
        assert (
            abs(AVAILABILITY_SLO.slo_target + AVAILABILITY_SLO.error_budget_fraction - 1.0) < 1e-9
        )
        assert abs(LATENCY_SLO.slo_target + LATENCY_SLO.error_budget_fraction - 1.0) < 1e-9


# ── validate_burn_rate_threshold ──────────────────────────────────────────────


class TestValidateBurnRateThreshold:
    def test_1h_14_4x_valid_for_999_slo(self):
        valid, fraction = validate_burn_rate_threshold(3600, 14.4, 0.999)
        assert valid is True
        # 14.4 × 1h / (30 × 24h) ≈ 0.02 (2% of monthly budget in 1h)
        assert abs(fraction - 14.4 / (30 * 24)) < 0.001

    def test_6h_6x_valid_for_999_slo(self):
        valid, fraction = validate_burn_rate_threshold(6 * 3600, 6.0, 0.999)
        assert valid is True
        assert abs(fraction - 6.0 * 6 / (30 * 24)) < 0.001

    def test_24h_3x_valid_for_999_slo(self):
        valid, fraction = validate_burn_rate_threshold(24 * 3600, 3.0, 0.999)
        assert valid is True
        assert abs(fraction - 3.0 / 30) < 0.001

    def test_72h_1x_valid_for_999_slo(self):
        valid, fraction = validate_burn_rate_threshold(72 * 3600, 1.0, 0.999)
        assert valid is True
        assert abs(fraction - 72 / (30 * 24)) < 0.001

    def test_burn_rate_zero_invalid(self):
        valid, fraction = validate_burn_rate_threshold(3600, 0.0, 0.999)
        assert valid is False
        assert fraction == 0.0

    def test_excessive_burn_rate_invalid(self):
        # 1000× burn rate over 24h would consume >100% of 30-day budget
        valid, _ = validate_burn_rate_threshold(24 * 3600, 1000.0, 0.999)
        assert valid is False

    def test_all_default_windows_valid(self):
        windows = default_burn_rate_windows()
        window_seconds = {"1h": 3600, "6h": 6 * 3600, "24h": 24 * 3600, "72h": 72 * 3600}
        for win in windows:
            sec = window_seconds[win.long_window]
            valid, _ = validate_burn_rate_threshold(sec, win.burn_rate_threshold, 0.999)
            assert valid, f"Window {win.long_window} at {win.burn_rate_threshold}× is invalid"


# ── generate_prometheus_rule ──────────────────────────────────────────────────


class TestGeneratePrometheusRule:
    def test_returns_dict(self):
        rule = generate_prometheus_rule()
        assert isinstance(rule, dict)

    def test_api_version(self):
        rule = generate_prometheus_rule()
        assert rule["apiVersion"] == "monitoring.coreos.com/v1"

    def test_kind(self):
        rule = generate_prometheus_rule()
        assert rule["kind"] == "PrometheusRule"

    def test_metadata_name(self):
        rule = generate_prometheus_rule(name="my-slo-rules")
        assert rule["metadata"]["name"] == "my-slo-rules"

    def test_metadata_namespace(self):
        rule = generate_prometheus_rule(namespace="production")
        assert rule["metadata"]["namespace"] == "production"

    def test_metadata_has_labels(self):
        rule = generate_prometheus_rule()
        assert "labels" in rule["metadata"]
        assert "app" in rule["metadata"]["labels"]

    def test_additional_labels(self):
        rule = generate_prometheus_rule(additional_labels={"team": "platform"})
        assert rule["metadata"]["labels"]["team"] == "platform"

    def test_spec_groups_is_list(self):
        rule = generate_prometheus_rule()
        assert isinstance(rule["spec"]["groups"], list)
        assert len(rule["spec"]["groups"]) == 1

    def test_group_name(self):
        rule = generate_prometheus_rule()
        assert rule["spec"]["groups"][0]["name"] == "aegis.slo.burn-rate"

    def test_group_interval(self):
        rule = generate_prometheus_rule()
        assert rule["spec"]["groups"][0]["interval"] == "30s"

    def test_rules_count_default(self):
        # 2 SLOs × 4 windows = 8 alerts
        rule = generate_prometheus_rule()
        rules = rule["spec"]["groups"][0]["rules"]
        assert len(rules) == 8

    def test_rules_single_slo(self):
        rule = generate_prometheus_rule(slos=[AVAILABILITY_SLO])
        rules = rule["spec"]["groups"][0]["rules"]
        assert len(rules) == 4

    def test_each_rule_has_alert_field(self):
        rule = generate_prometheus_rule()
        for r in rule["spec"]["groups"][0]["rules"]:
            assert "alert" in r

    def test_each_rule_has_expr(self):
        rule = generate_prometheus_rule()
        for r in rule["spec"]["groups"][0]["rules"]:
            assert "expr" in r
            assert len(r["expr"]) > 0

    def test_each_rule_has_for(self):
        rule = generate_prometheus_rule()
        for r in rule["spec"]["groups"][0]["rules"]:
            assert "for" in r

    def test_each_rule_has_labels(self):
        rule = generate_prometheus_rule()
        for r in rule["spec"]["groups"][0]["rules"]:
            assert "labels" in r
            assert "severity" in r["labels"]

    def test_each_rule_has_annotations(self):
        rule = generate_prometheus_rule()
        for r in rule["spec"]["groups"][0]["rules"]:
            assert "annotations" in r
            assert "summary" in r["annotations"]

    def test_critical_alerts_for_1h_window(self):
        rule = generate_prometheus_rule()
        for r in rule["spec"]["groups"][0]["rules"]:
            if "1H" in r["alert"]:
                assert r["labels"]["severity"] == "critical"

    def test_warning_alerts_for_72h_window(self):
        rule = generate_prometheus_rule()
        for r in rule["spec"]["groups"][0]["rules"]:
            if "72H" in r["alert"]:
                assert r["labels"]["severity"] == "warning"

    def test_alert_names_contain_slo_name(self):
        rule = generate_prometheus_rule()
        names = [r["alert"] for r in rule["spec"]["groups"][0]["rules"]]
        availability_alerts = [n for n in names if "Availability" in n]
        latency_alerts = [n for n in names if "Latency" in n]
        assert len(availability_alerts) == 4
        assert len(latency_alerts) == 4

    def test_for_field_matches_short_window(self):
        """The `for` duration must equal the short confirmation window."""
        rule = generate_prometheus_rule()
        for r in rule["spec"]["groups"][0]["rules"]:
            assert r["for"] in {"5m", "30m", "2h", "6h"}

    def test_custom_slo_single_window(self):
        custom_slo = SLOConfig(
            name="custom",
            slo_target=0.99,
            error_budget_fraction=0.01,
            expr_error_rate="sum(rate(my_errors[{window}])) / sum(rate(my_total[{window}]))",
            description="Custom SLO",
        )
        custom_window = [SLOBurnRateWindow("1h", "5m", 14.4, "critical")]
        rule = generate_prometheus_rule(slos=[custom_slo], windows=custom_window)
        rules = rule["spec"]["groups"][0]["rules"]
        assert len(rules) == 1
        assert "Custom" in rules[0]["alert"]

    def test_json_serializable(self):
        import json

        rule = generate_prometheus_rule()
        serialized = json.dumps(rule)
        assert len(serialized) > 0


# ── alert_names ───────────────────────────────────────────────────────────────


class TestAlertNames:
    def test_returns_8_names_for_defaults(self):
        names = alert_names()
        assert len(names) == 8

    def test_all_strings(self):
        for name in alert_names():
            assert isinstance(name, str)

    def test_names_are_unique(self):
        names = alert_names()
        assert len(set(names)) == len(names)

    def test_availability_names_present(self):
        names = alert_names()
        assert any("Availability" in n for n in names)

    def test_latency_names_present(self):
        names = alert_names()
        assert any("Latency" in n for n in names)

    def test_all_four_windows_in_availability(self):
        names = [n for n in alert_names() if "Availability" in n]
        windows = {"1H", "6H", "24H", "72H"}
        for w in windows:
            assert any(w in n for n in names), f"Missing window {w} in availability alerts"

    def test_single_slo_returns_4_names(self):
        names = alert_names(slos=[AVAILABILITY_SLO])
        assert len(names) == 4
