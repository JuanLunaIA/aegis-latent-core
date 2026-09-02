# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Every workflow must pin ``GITHUB_TOKEN`` to least privilege.

Threat SUP-01: a workflow with no ``permissions:`` block inherits the
repository default, which may be read/write across every scope. These
workflows check out untrusted pull-request content, install dependencies and
invoke third-party actions, so an over-scoped token is reachable by anything
that achieves execution inside a job.

The floor is asserted structurally rather than by grep so a reordering or a
reformat cannot silently satisfy it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github/workflows"

# Scopes that let a job mutate the repository, its releases, or its supply
# chain. A job may hold one only where it is the job's actual purpose.
_WRITE_SCOPES = {
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "issues",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
}


def _workflows() -> list[Path]:
    paths = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    assert paths, "no workflows found; the test is pointed at the wrong directory"
    return paths


def _load(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path.name} is not a mapping"
    return data


def _write_scopes(block: object) -> set[str]:
    """Return the write-capable scopes granted by one ``permissions:`` value."""
    if block == "write-all":
        return set(_WRITE_SCOPES)
    if not isinstance(block, dict):
        return set()
    return {
        scope for scope, level in block.items() if scope in _WRITE_SCOPES and str(level) == "write"
    }


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_workflow_declares_a_top_level_permissions_floor(path: Path) -> None:
    """No workflow may inherit the repository-wide default token scope."""
    workflow = _load(path)
    assert "permissions" in workflow, (
        f"{path.name} has no top-level 'permissions:' block, so GITHUB_TOKEN "
        "inherits the repository default. Declare an explicit floor."
    )


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_top_level_permissions_are_not_write_all(path: Path) -> None:
    """A blanket write grant defeats the point of declaring the block."""
    workflow = _load(path)
    assert workflow.get("permissions") != "write-all", (
        f"{path.name} grants 'write-all' at workflow level"
    )


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_top_level_permissions_grant_no_write_scope(path: Path) -> None:
    """The floor is read-only; a job that needs to write says so in its own block.

    GitHub replaces — not merges — the workflow block when a job declares one,
    so keeping the floor read-only makes every privilege escalation local and
    reviewable in the diff that introduces it.
    """
    workflow = _load(path)
    granted = _write_scopes(workflow.get("permissions"))
    assert not granted, (
        f"{path.name} grants write scopes {sorted(granted)} to every job. "
        "Move the grant to the job that needs it."
    )


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_job_level_write_grants_are_scoped_not_blanket(path: Path) -> None:
    """Jobs that do need to write must enumerate scopes, never 'write-all'."""
    workflow = _load(path)
    for name, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, dict) or "permissions" not in job:
            continue
        assert job["permissions"] != "write-all", f"{path.name}: job '{name}' grants 'write-all'"


def _job_uses_sarif_upload(job: dict) -> bool:
    """True when a job publishes findings to GitHub code scanning."""
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        uses = str(step.get("uses", ""))
        if "codeql-action/upload-sarif" in uses or "codeql-action/analyze" in uses:
            return True
    return False


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_security_events_write_is_granted_only_where_sarif_is_uploaded(path: Path) -> None:
    """The code-scanning write scope must follow the jobs that actually publish.

    A scanner job runs third-party analysis over checked-out source; granting
    every job in the workflow the ability to write code-scanning results widens
    that blast radius for no functional gain.
    """
    workflow = _load(path)
    workflow_grants = "security-events" in _write_scopes(workflow.get("permissions"))

    for name, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        declared = job.get("permissions")
        effective = (
            "security-events" in _write_scopes(declared)
            if declared is not None
            else workflow_grants
        )
        if _job_uses_sarif_upload(job):
            assert effective, (
                f"{path.name}: job '{name}' uploads SARIF but has no 'security-events: write'"
            )
        else:
            assert not effective, (
                f"{path.name}: job '{name}' holds 'security-events: write' but uploads no SARIF"
            )


def test_ci_and_forensic_keep_the_read_only_floor() -> None:
    """Pin the two workflows that previously inherited the repository default."""
    for name in ("ci.yml", "forensic.yml"):
        workflow = _load(WORKFLOW_DIR / name)
        assert workflow["permissions"] == {"contents": "read"}, (
            f"{name} no longer declares a read-only workflow-level floor"
        )
