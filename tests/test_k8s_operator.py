# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for the AegisProxy Kubernetes operator controller scaffold."""

from __future__ import annotations

import pytest

# ── Import guard ─────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def operator():
    """Import the operator module, injecting it into sys.path if needed."""
    import importlib.util
    import os

    spec_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "deploy",
        "k8s",
        "aegis-operator",
        "operator.py",
    )
    spec = importlib.util.spec_from_file_location("aegis_operator", spec_path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# ── Import / module-level tests ───────────────────────────────────────────────


class TestModuleImport:
    def test_operator_imports_without_error(self, operator) -> None:
        assert operator is not None

    def test_has_kopf_is_bool(self, operator) -> None:
        assert isinstance(operator.HAS_KOPF, bool)

    def test_build_deployment_callable(self, operator) -> None:
        assert callable(operator._build_deployment)

    def test_build_hpa_callable(self, operator) -> None:
        assert callable(operator._build_hpa)


# ── _build_deployment() ───────────────────────────────────────────────────────


class TestBuildDeployment:
    @pytest.fixture
    def basic_spec(self) -> dict:
        return {
            "replicas": 3,
            "upstreamProvider": "anthropic",
            "signingKeySecret": "my-signing-secret",
            "apiKeysSecret": "my-api-keys-secret",
            "resources": {
                "requests": {"cpu": "200m", "memory": "512Mi"},
                "limits": {"cpu": "1000m", "memory": "1Gi"},
            },
        }

    def test_returns_dict(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("proxy-1", "aegis-system", basic_spec)
        assert isinstance(result, dict)

    def test_api_version_apps_v1(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("proxy-1", "aegis-system", basic_spec)
        assert result["apiVersion"] == "apps/v1"

    def test_kind_is_deployment(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("proxy-1", "aegis-system", basic_spec)
        assert result["kind"] == "Deployment"

    def test_replicas_from_spec(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("proxy-1", "aegis-system", basic_spec)
        assert result["spec"]["replicas"] == 3

    def test_default_replicas_is_one(self, operator) -> None:
        result = operator._build_deployment(
            "proxy-1", "aegis-system", {"upstreamProvider": "openai"}
        )
        assert result["spec"]["replicas"] == 1

    def test_name_in_metadata(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("my-proxy", "default", basic_spec)
        assert result["metadata"]["name"] == "my-proxy"

    def test_namespace_in_metadata(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("proxy-1", "my-ns", basic_spec)
        assert result["metadata"]["namespace"] == "my-ns"

    def test_env_vars_reference_secrets_not_plaintext(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("proxy-1", "aegis-system", basic_spec)
        containers = result["spec"]["template"]["spec"]["containers"]
        assert len(containers) == 1
        env = containers[0]["env"]
        for var in env:
            if var["name"] in ("AEGIS_SIGNING_KEY", "AEGIS_API_KEYS"):
                # Must come from a secretKeyRef, never a literal value=
                assert "valueFrom" in var, f"{var['name']} must use secretKeyRef"
                assert "secretKeyRef" in var["valueFrom"]
                assert "value" not in var, f"{var['name']} must not have a literal value"

    def test_signing_key_secret_name_from_spec(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("proxy-1", "aegis-system", basic_spec)
        containers = result["spec"]["template"]["spec"]["containers"]
        env_map = {e["name"]: e for e in containers[0]["env"]}
        ref = env_map["AEGIS_SIGNING_KEY"]["valueFrom"]["secretKeyRef"]
        assert ref["name"] == "my-signing-secret"

    def test_api_keys_secret_name_from_spec(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("proxy-1", "aegis-system", basic_spec)
        containers = result["spec"]["template"]["spec"]["containers"]
        env_map = {e["name"]: e for e in containers[0]["env"]}
        ref = env_map["AEGIS_API_KEYS"]["valueFrom"]["secretKeyRef"]
        assert ref["name"] == "my-api-keys-secret"

    def test_default_secret_names_use_cr_name(self, operator) -> None:
        result = operator._build_deployment("myproxy", "ns", {"upstreamProvider": "openai"})
        containers = result["spec"]["template"]["spec"]["containers"]
        env_map = {e["name"]: e for e in containers[0]["env"]}
        assert (
            env_map["AEGIS_SIGNING_KEY"]["valueFrom"]["secretKeyRef"]["name"]
            == "myproxy-signing-key"
        )
        assert env_map["AEGIS_API_KEYS"]["valueFrom"]["secretKeyRef"]["name"] == "myproxy-api-keys"

    def test_has_readiness_probe(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("proxy-1", "aegis-system", basic_spec)
        container = result["spec"]["template"]["spec"]["containers"][0]
        assert "readinessProbe" in container
        assert container["readinessProbe"]["httpGet"]["path"] == "/ready"

    def test_has_liveness_probe(self, operator, basic_spec: dict) -> None:
        result = operator._build_deployment("proxy-1", "aegis-system", basic_spec)
        container = result["spec"]["template"]["spec"]["containers"][0]
        assert "livenessProbe" in container
        assert container["livenessProbe"]["httpGet"]["path"] == "/health"


# ── _build_hpa() ─────────────────────────────────────────────────────────────


class TestBuildHpa:
    def test_returns_none_when_disabled(self, operator) -> None:
        spec = {"hpa": {"enabled": False}}
        result = operator._build_hpa("proxy-1", "aegis-system", spec)
        assert result is None

    def test_returns_dict_when_enabled(self, operator) -> None:
        spec = {
            "hpa": {"enabled": True, "minReplicas": 2, "maxReplicas": 8, "targetCpuPercent": 60}
        }
        result = operator._build_hpa("proxy-1", "aegis-system", spec)
        assert isinstance(result, dict)

    def test_default_enabled_returns_hpa(self, operator) -> None:
        # No hpa key at all — default is enabled
        result = operator._build_hpa("proxy-1", "aegis-system", {})
        assert result is not None

    def test_hpa_kind(self, operator) -> None:
        result = operator._build_hpa("proxy-1", "aegis-system", {})
        assert result["kind"] == "HorizontalPodAutoscaler"

    def test_hpa_min_replicas_from_spec(self, operator) -> None:
        spec = {"hpa": {"enabled": True, "minReplicas": 3}}
        result = operator._build_hpa("proxy-1", "aegis-system", spec)
        assert result["spec"]["minReplicas"] == 3

    def test_hpa_max_replicas_from_spec(self, operator) -> None:
        spec = {"hpa": {"enabled": True, "maxReplicas": 20}}
        result = operator._build_hpa("proxy-1", "aegis-system", spec)
        assert result["spec"]["maxReplicas"] == 20

    def test_hpa_target_cpu_from_spec(self, operator) -> None:
        spec = {"hpa": {"enabled": True, "targetCpuPercent": 50}}
        result = operator._build_hpa("proxy-1", "aegis-system", spec)
        metrics = result["spec"]["metrics"]
        assert metrics[0]["resource"]["target"]["averageUtilization"] == 50

    def test_hpa_scale_target_ref_points_to_deployment(self, operator) -> None:
        result = operator._build_hpa("my-proxy", "ns", {})
        ref = result["spec"]["scaleTargetRef"]
        assert ref["kind"] == "Deployment"
        assert ref["name"] == "my-proxy"
