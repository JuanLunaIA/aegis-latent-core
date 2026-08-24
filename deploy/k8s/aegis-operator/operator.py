# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
AegisProxy Kubernetes operator controller.

Uses the kopf framework (https://kopf.readthedocs.io/) for event-driven reconciliation.
Install: pip install kopf kubernetes

Run: kopf run deploy/k8s/aegis-operator/operator.py --namespace=aegis-system
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_AEGIS_IMAGE = "ghcr.io/juanlunaia/aegis-latent-core:3.1.0"
WRITABLE_TMP_PATH = "/tmp"  # noqa: S108 -- mounted emptyDir, not host temporary storage
_OCI_DIGEST_REFERENCE = re.compile(r"^.+@sha256:[0-9a-fA-F]{64}$")
_OCI_TAG_REFERENCE = re.compile(r"^.+:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")

# ── kopf soft dependency ──────────────────────────────────────────────────────

try:
    import kopf  # type: ignore[import]
    import kubernetes  # type: ignore[import]

    HAS_KOPF = True
except ImportError:
    kopf = None  # type: ignore[assignment]
    kubernetes = None
    HAS_KOPF = False
    logger.warning(
        "kopf/kubernetes not installed — operator cannot run. pip install kopf kubernetes"
    )

# ── Reconciler ────────────────────────────────────────────────────────────────


def _validated_image(spec: dict[str, Any]) -> str:
    """Return an explicit image reference, rejecting mutable latest by default."""
    image = spec.get("image", DEFAULT_AEGIS_IMAGE)
    if not isinstance(image, str) or not image.strip():
        raise ValueError("spec.image must be a non-empty string")
    image = image.strip()
    if "@" in image:
        if _OCI_DIGEST_REFERENCE.fullmatch(image) is None:
            raise ValueError(
                "spec.image digest must be sha256 followed by 64 hexadecimal characters"
            )
        return image
    if _OCI_TAG_REFERENCE.fullmatch(image) is None:
        raise ValueError("spec.image must include an explicit valid tag or sha256 digest")
    final_component = image.split("@", 1)[0].rsplit("/", 1)[-1]
    tag = final_component.rsplit(":", 1)[1] if ":" in final_component else None
    uses_latest = tag is None or tag.lower() == "latest"
    if uses_latest and not spec.get("allowLatestImage", False):
        raise ValueError("spec.image must be pinned by tag or digest; latest is disabled")
    return image


def _build_deployment(name: str, namespace: str, spec: dict[str, Any]) -> dict[str, Any]:
    """Build a Deployment manifest from AegisProxy spec."""
    replicas = spec.get("replicas", 1)
    provider = spec.get("upstreamProvider", "openai")
    resources = spec.get("resources", {})
    signing_secret = spec.get("signingKeySecret", f"{name}-signing-key")
    api_keys_secret = spec.get("apiKeysSecret", f"{name}-api-keys")
    image = _validated_image(spec)

    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app": "aegis", "aegis-cr": name},
        },
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": "aegis", "aegis-cr": name}},
            "template": {
                "metadata": {"labels": {"app": "aegis", "aegis-cr": name}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "aegis",
                            "image": image,
                            "imagePullPolicy": "IfNotPresent",
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "ports": [{"containerPort": 8080}],
                            "env": [
                                {
                                    "name": "AEGIS_UPSTREAM_PROVIDER",
                                    "value": provider,
                                },
                                {
                                    "name": "AEGIS_SIGNING_KEY",
                                    "valueFrom": {
                                        "secretKeyRef": {
                                            "name": signing_secret,
                                            "key": "signing-key",
                                        }
                                    },
                                },
                                {
                                    "name": "AEGIS_API_KEYS",
                                    "valueFrom": {
                                        "secretKeyRef": {
                                            "name": api_keys_secret,
                                            "key": "api-keys",
                                        }
                                    },
                                },
                            ],
                            "resources": resources,
                            "readinessProbe": {
                                "httpGet": {"path": "/ready", "port": 8080},
                                "periodSeconds": 10,
                            },
                            "livenessProbe": {
                                "httpGet": {"path": "/health", "port": 8080},
                                "periodSeconds": 30,
                            },
                            "volumeMounts": [
                                {"name": "data", "mountPath": "/data"},
                                {"name": "tmp", "mountPath": WRITABLE_TMP_PATH},
                            ],
                        }
                    ],
                    "volumes": [
                        {"name": "data", "emptyDir": {}},
                        {"name": "tmp", "emptyDir": {}},
                    ],
                },
            },
        },
    }


def _build_hpa(name: str, namespace: str, spec: dict[str, Any]) -> dict[str, Any] | None:
    """Build HPA if enabled in spec."""
    hpa_spec = spec.get("hpa", {})
    if not hpa_spec.get("enabled", True):
        return None
    return {
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "scaleTargetRef": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": name,
            },
            "minReplicas": hpa_spec.get("minReplicas", 1),
            "maxReplicas": hpa_spec.get("maxReplicas", 10),
            "metrics": [
                {
                    "type": "Resource",
                    "resource": {
                        "name": "cpu",
                        "target": {
                            "type": "Utilization",
                            "averageUtilization": hpa_spec.get("targetCpuPercent", 70),
                        },
                    },
                }
            ],
        },
    }


if HAS_KOPF:

    @kopf.on.create("aegis.io", "v1alpha1", "aegisproxies")
    def on_create(name: str, namespace: str, spec: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        logger.info("Creating AegisProxy %s/%s", namespace, name)
        api = kubernetes.client.AppsV1Api()

        deployment = _build_deployment(name, namespace, spec)
        kopf.adopt(deployment)
        api.create_namespaced_deployment(namespace=namespace, body=deployment)

        hpa = _build_hpa(name, namespace, spec)
        if hpa is not None:
            kopf.adopt(hpa)
            kubernetes.client.AutoscalingV2Api().create_namespaced_horizontal_pod_autoscaler(
                namespace=namespace, body=hpa
            )

        return {"phase": "Pending", "replicas": spec.get("replicas", 1), "readyReplicas": 0}

    @kopf.on.update("aegis.io", "v1alpha1", "aegisproxies")
    def on_update(name: str, namespace: str, spec: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        logger.info("Updating AegisProxy %s/%s", namespace, name)
        api = kubernetes.client.AppsV1Api()
        deployment = _build_deployment(name, namespace, spec)
        kopf.adopt(deployment)
        api.patch_namespaced_deployment(name=name, namespace=namespace, body=deployment)
        return {"phase": "Pending"}

    @kopf.on.delete("aegis.io", "v1alpha1", "aegisproxies")
    def on_delete(name: str, namespace: str, **kwargs: Any) -> None:
        logger.info(
            "Deleting AegisProxy %s/%s — owned resources will be garbage collected",
            namespace,
            name,
        )
