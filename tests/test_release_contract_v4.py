# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.verify_release_contract import assess_repository

ROOT = Path(__file__).resolve().parents[1]


def test_release_source_contract_is_complete_without_claiming_external_readiness() -> None:
    assessment = assess_repository(ROOT)

    assert len(assessment.versions) == 6
    assert len(set(assessment.versions.values())) == 1
    assert assessment.ready
    assert assessment.diagnostics == ()


def test_release_contract_cli_reports_source_contract_as_json() -> None:
    completed = subprocess.run(  # noqa: S603 - fixed local executable and arguments
        [sys.executable, "scripts/verify_release_contract.py", "--root", str(ROOT), "--json"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    report = json.loads(completed.stdout)
    assert report["ready"] is True
    assert report["diagnostics"] == []


def test_publish_workflows_are_tag_only_and_publish_downloaded_artifacts() -> None:
    pypi = (ROOT / ".github/workflows/publish_pypi.yml").read_text()
    npm = (ROOT / ".github/workflows/publish_npm.yml").read_text()

    for workflow in (pypi, npm):
        assert "workflow_dispatch" not in workflow
        assert '      - "v*"' in workflow
        assert "environment:" in workflow
        assert "id-token: write" in workflow
        assert "${{ github.sha }}" in workflow
        assert "git verify-tag" in workflow
        assert "git merge-base --is-ancestor" in workflow
        assert "AEGIS_TRUSTED_PUBLISHING_ENABLED" in workflow
    assert "packages-dir: release-artifact" in pypi
    assert "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33" in pypi
    assert "npm publish release-artifact/*.tgz --access public --provenance" in npm


def test_oci_workflow_is_multiarch_digest_signed_and_externally_gated() -> None:
    workflow = (ROOT / ".github/workflows/publish_oci.yml").read_text()
    assert "linux/amd64,linux/arm64" in workflow
    assert "component: gateway" in workflow
    assert "component: dashboard" in workflow
    assert "AEGIS_OCI_PUBLISHING_ENABLED" in workflow
    assert "git verify-tag" in workflow
    assert "git merge-base --is-ancestor" in workflow
    assert "provenance: mode=max" in workflow
    assert "sbom: true" in workflow
    assert "cosign sign --yes" in workflow


def test_dashboard_container_is_pinned_standalone_and_non_root() -> None:
    dockerfile = (ROOT / "dashboard/Dockerfile").read_text()

    assert "@sha256:" in dockerfile
    assert " AS builder" in dockerfile
    assert " AS runtime" in dockerfile
    assert "/.next/standalone" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert 'CMD ["node", "dashboard/server.js"]' in dockerfile
    assert ":latest" not in dockerfile
