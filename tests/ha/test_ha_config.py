# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The multi-replica configuration refuses the shapes that would fork evidence.

Settings: a mode must be one of three; HA means one writer process per replica
(workers=1); active_passive names its shared chain; active_active has a
sequence store; strict mode accepts only PostgreSQL for it (SQLite locking is
unsafe on the network filesystems replicas share). The Helm chart enforces the
same at render time, and does not strand an active_passive rollout behind a
standby that is never Ready.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from aegis.config import AegisSettings

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy/helm"
BASE = {"backend_api_key": "sk-test", "backend_url": "http://upstream"}


def _cfg(**overrides: object) -> AegisSettings:
    return AegisSettings(**{**BASE, **overrides})


def test_single_mode_needs_nothing() -> None:
    _cfg().validate_ha()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"ha_mode": "active-active"}, "must be 'single'"),
        (
            {"ha_mode": "active_active", "ha_sequencer_url": "sqlite:////x", "workers": 2},
            "workers=1",
        ),
        ({"ha_mode": "active_passive"}, "ha_chain_id"),
        ({"ha_mode": "active_active"}, "ha_sequencer_url"),
        (
            {"ha_mode": "active_active", "ha_sequencer_url": "mysql://db/x"},
            "postgresql://",
        ),
        (
            {
                "ha_mode": "active_active",
                "ha_sequencer_url": "sqlite:////var/lib/aegis/seq.db",
                "security_enforcement_mode": "strict",
            },
            "strict runtime requires a postgresql://",
        ),
    ],
)
def test_shapes_that_could_fork_evidence_are_refused(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _cfg(**overrides).validate_ha()


def test_valid_shapes_pass() -> None:
    _cfg(ha_mode="active_passive", ha_chain_id="prod").validate_ha()
    _cfg(ha_mode="active_active", ha_sequencer_url="postgresql://db/aegis").validate_ha()
    _cfg(
        ha_mode="active_active",
        ha_sequencer_url="postgresql://db/aegis",
        security_enforcement_mode="strict",
    ).validate_ha()


def test_the_chart_defaults_to_single_and_constrains_the_mode() -> None:
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["ha"]["mode"] == "single"
    schema = json.loads((CHART / "values.schema.json").read_text())
    assert schema["properties"]["ha"]["properties"]["mode"]["enum"] == [
        "single",
        "active_active",
        "active_passive",
    ]


def test_the_chart_template_guards_each_mode() -> None:
    template = (CHART / "templates/statefulset.yaml").read_text()
    assert "ha.mode=active_passive needs ha.sharedClaim" in template
    assert "ha.mode=active_passive needs ha.chainId" in template
    assert "ha.mode=active_active needs ha.sequencerUrlSecret" in template
    assert "type: OnDelete" in template, "a standby is never Ready; ordered updates would stall"
    assert "fieldPath: metadata.name" in template


HELM = shutil.which("helm")


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
@pytest.mark.parametrize(
    ("args", "expect"),
    [
        (["--set", "ha.mode=active_passive"], "needs ha.sharedClaim"),
        (["--set", "ha.mode=active_active"], "needs ha.sequencerUrlSecret"),
        # helm 3.x: "must be one of the following"; newer: "value must be one of 'single', …"
        (["--set", "ha.mode=bogus"], "must be one of"),
    ],
)
def test_helm_refuses_to_render_an_unsafe_shape(args: list[str], expect: str) -> None:
    assert HELM is not None
    out = subprocess.run(  # noqa: S603 - fixed argv
        [HELM, "template", "t", str(CHART), *args], capture_output=True, text=True, check=False
    )
    assert out.returncode != 0
    assert expect in out.stderr


@pytest.mark.skipif(HELM is None, reason="helm is not installed")
def test_helm_renders_active_passive_on_one_shared_claim() -> None:
    assert HELM is not None
    out = subprocess.run(  # noqa: S603 - fixed argv
        [
            HELM, "template", "t", str(CHART),
            "--set", "ha.mode=active_passive",
            "--set", "ha.sharedClaim=wal-rwx",
            "--set", "ha.chainId=prod",
        ],
        capture_output=True,
        text=True,
        check=True,
    )  # fmt: skip
    statefulset = next(
        doc for doc in yaml.safe_load_all(out.stdout) if doc and doc.get("kind") == "StatefulSet"
    )
    spec = statefulset["spec"]
    assert spec["podManagementPolicy"] == "Parallel"
    assert spec["updateStrategy"]["type"] == "OnDelete"
    assert "volumeClaimTemplates" not in spec
    volumes = {v["name"]: v for v in spec["template"]["spec"]["volumes"]}
    assert volumes["wal-data"]["persistentVolumeClaim"]["claimName"] == "wal-rwx"
