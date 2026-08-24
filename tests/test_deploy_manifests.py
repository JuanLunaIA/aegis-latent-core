# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Deterministic checks for Kubernetes deployment sources."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
HELM = ROOT / "deploy/helm"
OPERATOR = ROOT / "deploy/k8s/aegis-operator"


def _documents(name: str) -> list[dict]:
    return [doc for doc in yaml.safe_load_all((OPERATOR / name).read_text()) if doc]


def test_all_static_operator_yaml_parses() -> None:
    for path in sorted(OPERATOR.glob("*.yaml")):
        assert list(yaml.safe_load_all(path.read_text())), path


def test_helm_values_are_hardened_and_external_dependencies_are_caller_supplied() -> None:
    values = yaml.safe_load((HELM / "values.yaml").read_text())
    assert values["image"]["repository"] == "ghcr.io/juanlunaia/aegis-latent-core"
    assert values["image"]["tag"] != "latest"
    assert values["aegis"]["existingSecret"] == "aegis-keys"
    assert values["aegis"]["rateLimitBackend"] == "redis"
    assert values["aegis"]["redisUrl"] == "redis://redis:6379"
    assert values["podSecurityContext"]["runAsNonRoot"] is True
    assert values["podSecurityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    assert values["containerSecurityContext"]["readOnlyRootFilesystem"] is True
    assert values["containerSecurityContext"]["capabilities"]["drop"] == ["ALL"]


def test_helm_values_schema_is_valid_json_and_rejects_latest() -> None:
    schema = json.loads((HELM / "values.schema.json").read_text())
    pattern = schema["properties"]["image"]["properties"]["tag"]["pattern"]
    assert re.fullmatch(pattern, "3.1.0")
    for mutable_tag in ("latest", "Latest", "LATEST", "lAtEsT"):
        assert re.fullmatch(pattern, mutable_tag) is None


def test_operator_crd_requires_explicit_tag_or_sha256_digest_shape() -> None:
    crd = _documents("crd.yaml")[0]
    image_schema = crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"][
        "properties"
    ]["image"]
    pattern = image_schema["pattern"]
    assert re.fullmatch(pattern, "registry.example/aegis:3.1.0")
    assert re.fullmatch(pattern, "registry.example/aegis@sha256:" + "a" * 64)
    for invalid in ("registry.example/aegis", "registry.example/aegis@garbage", "repo@sha256:abc"):
        assert re.fullmatch(pattern, invalid) is None


def test_operator_install_is_namespaced_and_least_privilege() -> None:
    role, binding = _documents("rbac.yaml")
    assert role["kind"] == "Role"
    assert binding["roleRef"]["kind"] == "Role"
    all_resources = {resource for rule in role["rules"] for resource in rule["resources"]}
    assert "secrets" not in all_resources
    assert "pods" not in all_resources
    assert all("*" not in rule["verbs"] and "*" not in rule["resources"] for rule in role["rules"])


def test_operator_install_deployment_is_restricted_and_requires_reviewed_image() -> None:
    deployment = _documents("deployment.yaml")[0]
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert deployment["metadata"]["annotations"]["aegis.io/status"] == (
        "source-template-unreleased"
    )
    assert container["image"].startswith("example.invalid/")
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]


def test_kustomization_references_complete_install_set() -> None:
    kustomization = _documents("kustomization.yaml")[0]
    assert kustomization["resources"] == [
        "crd.yaml",
        "serviceaccount.yaml",
        "rbac.yaml",
        "deployment.yaml",
    ]
