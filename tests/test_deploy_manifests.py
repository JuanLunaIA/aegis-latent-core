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


def test_helm_gives_every_replica_its_own_wal_volume() -> None:
    """One WAL path per writer. A Deployment over a shared PVC violated that.

    Two processes appending to one WAL produce divergent ``prev_hash``
    relationships that the loader cannot reconstruct as a single verified
    chain, so replicas must not share a claim.
    """
    templates = HELM / "templates"
    assert not (templates / "deployment.yaml").exists(), (
        "a Deployment gives every replica the same WAL path"
    )
    assert not (templates / "pvc.yaml").exists(), (
        "a standalone PVC is shared by all replicas; use volumeClaimTemplates"
    )

    statefulset = (templates / "statefulset.yaml").read_text()
    assert "kind: StatefulSet" in statefulset
    assert "volumeClaimTemplates:" in statefulset
    assert "serviceName:" in statefulset

    # The governing Service the StatefulSet names must actually exist, or the
    # replicas never get the stable identity that pins them to their volume.
    assert (templates / "service-headless.yaml").exists()
    assert "clusterIP: None" in (templates / "service-headless.yaml").read_text()

    # An HPA still pointed at a Deployment would silently scale nothing.
    assert "kind: StatefulSet" in (templates / "hpa.yaml").read_text()
    assert "kind: Deployment" not in (templates / "hpa.yaml").read_text()


def test_helm_pins_one_uvicorn_worker_per_pod() -> None:
    """AEGIS_WORKERS forks processes that all share the pod's WAL path."""
    values = yaml.safe_load((HELM / "values.yaml").read_text())
    assert values["aegis"]["workers"] == "1"

    schema = json.loads((HELM / "values.schema.json").read_text())
    assert schema["properties"]["aegis"]["properties"]["workers"]["const"] == "1", (
        "an operator must not be able to raise workers past the single-writer limit"
    )

    access_mode = schema["properties"]["persistence"]["properties"]["accessMode"]
    assert "ReadWriteMany" not in access_mode["enum"], (
        "a shared-write volume reintroduces the multi-writer fork"
    )
    assert values["persistence"]["accessMode"] in access_mode["enum"]


def test_helm_ships_a_default_deny_network_policy() -> None:
    """Gateway pods must not be reachable by, or able to reach, the whole cluster."""
    values = yaml.safe_load((HELM / "values.yaml").read_text())
    policy = values["networkPolicy"]
    assert policy["enabled"] is True

    # Caller-supplied peers stay empty: a guessed default would silently widen
    # the policy, and an empty list denies rather than permits.
    assert policy["ingressFrom"] == []
    assert policy["egressTo"] == []
    assert policy["dnsTo"], "DNS egress must name a resolver, not be unrestricted"
    for peer in policy["dnsTo"]:
        # namespaceSelector and podSelector in one peer AND together. A peer
        # carrying only a namespaceSelector opens port 53 to every pod in that
        # namespace, which is broader than "the cluster resolver".
        assert "podSelector" in peer, (
            f"DNS egress peer {peer} selects a whole namespace; add a podSelector "
            "so the rule reaches resolver pods only"
        )

    template = (HELM / "templates/networkpolicy.yaml").read_text()
    assert "kind: NetworkPolicy" in template
    for direction in ("- Ingress", "- Egress"):
        assert direction in template, f"policyTypes must include {direction.strip('- ')}"


def test_helm_values_schema_is_valid_json_and_rejects_latest() -> None:
    schema = json.loads((HELM / "values.schema.json").read_text())
    tag_schema = schema["properties"]["image"]["properties"]["tag"]
    assert tag_schema["minLength"] == 1
    forbidden_pattern = tag_schema["not"]["pattern"]
    assert re.fullmatch(forbidden_pattern, "3.1.0") is None
    for mutable_tag in ("latest", "Latest", "LATEST", "lAtEsT"):
        assert re.fullmatch(forbidden_pattern, mutable_tag)


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
