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
from typing import Any

logger = logging.getLogger(__name__)

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


def _build_deployment(name: str, namespace: str, spec: dict[str, Any]) -> dict[str, Any]:
    """Build a Deployment manifest from AegisProxy spec."""
    replicas = spec.get("replicas", 1)
    provider = spec.get("upstreamProvider", "openai")
    resources = spec.get("resources", {})
    signing_secret = spec.get("signingKeySecret", f"{name}-signing-key")
    api_keys_secret = spec.get("apiKeysSecret", f"{name}-api-keys")

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
                    "containers": [
                        {
                            "name": "aegis",
                            "image": "ghcr.io/juanlunaia/aegis-latent-core:latest",
                            "ports": [{"containerPort": 8000}],
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
                                "httpGet": {"path": "/ready", "port": 8000},
                                "periodSeconds": 10,
                            },
                            "livenessProbe": {
                                "httpGet": {"path": "/health", "port": 8000},
                                "periodSeconds": 30,
                            },
                        }
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

        return {"phase": "Running", "replicas": spec.get("replicas", 1), "readyReplicas": 0}

    @kopf.on.update("aegis.io", "v1alpha1", "aegisproxies")
    def on_update(name: str, namespace: str, spec: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        logger.info("Updating AegisProxy %s/%s", namespace, name)
        api = kubernetes.client.AppsV1Api()
        deployment = _build_deployment(name, namespace, spec)
        kopf.adopt(deployment)
        api.patch_namespaced_deployment(name=name, namespace=namespace, body=deployment)
        return {"phase": "Running"}

    @kopf.on.delete("aegis.io", "v1alpha1", "aegisproxies")
    def on_delete(name: str, namespace: str, **kwargs: Any) -> None:
        logger.info(
            "Deleting AegisProxy %s/%s — owned resources will be garbage collected",
            namespace,
            name,
        )
