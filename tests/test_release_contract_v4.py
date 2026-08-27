# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.create_github_release import build_create_command
from scripts.extract_release_notes import extract_release_notes
from scripts.prepare_release_assets import prepare_release_assets
from scripts.verify_release_contract import assess_repository

ROOT = Path(__file__).resolve().parents[1]
VERSION_LABELS = {
    "core",
    "core-runtime",
    "python-sdk",
    "python-sdk-runtime",
    "typescript-sdk",
    "typescript-lock",
    "dashboard",
    "dashboard-lock",
    "rust-cargo",
    "rust-pyproject",
    "rust-lock",
    "helm-chart",
    "helm-app",
    "helm-image",
}


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed git executable
        ["git", *arguments], cwd=ROOT, check=False, capture_output=True, text=True
    )


def _copy_contract_repository(destination: Path) -> Path:
    for relative_path in (
        ".github/workflows",
        "aegis/__init__.py",
        "aegis/core/forensic_pdf_report.py",
        "aegis_server/__init__.py",
        "aegis_rust_v2/Cargo.lock",
        "aegis_rust_v2/Cargo.toml",
        "aegis_rust_v2/pyproject.toml",
        "aegis_rust_v2/src/lib.rs",
        "dashboard/Dockerfile",
        "dashboard/package-lock.json",
        "dashboard/package.json",
        "deploy/docker/Dockerfile",
        "deploy/docker/Dockerfile.airgap",
        "deploy/docker/docker-compose.enterprise.yml",
        "deploy/docker/docker-compose.yml",
        "deploy/helm/Chart.yaml",
        "deploy/helm/values.yaml",
        "deploy/k8s/aegis-operator/crd.yaml",
        "deploy/k8s/aegis-operator/operator.py",
        "pyproject.toml",
        "sdk/python/pyproject.toml",
        "sdk/python/src/aegis_sdk/__init__.py",
        "sdk/typescript/package-lock.json",
        "sdk/typescript/package.json",
        "scripts/create_github_release.py",
        "scripts/extract_release_notes.py",
        "scripts/install_aegis.sh",
        "scripts/install_gitsign.sh",
        "scripts/prepare_release_assets.py",
        "scripts/verify_release_tag.sh",
        "scripts/vendor_wheels.sh",
    ):
        source = ROOT / relative_path
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
    return destination


def test_release_source_contract_is_complete_without_external_claims() -> None:
    assessment = assess_repository(ROOT)
    assert set(assessment.versions) == VERSION_LABELS
    assert len(set(assessment.versions.values())) == 1
    assert assessment.ready
    assert assessment.diagnostics == ()
    assert set(assessment.versions.values()) == {"4.0.2"}
    assert _git("tag", "--list", "v4.0.2").stdout.strip() == ""
    assert "published" not in assessment.to_dict()
    assert "released" not in assessment.to_dict()


def test_release_contract_cli_reports_source_contract_as_json() -> None:
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and local script
        [
            sys.executable,
            "scripts/verify_release_contract.py",
            "--root",
            str(ROOT),
            "--tag",
            "v4.0.2",
            "--json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )  # noqa: S603
    assert completed.returncode == 0
    report = json.loads(completed.stdout)
    assert report["ready"] is True
    assert report["diagnostics"] == []


@pytest.mark.parametrize("tag", ["v4.0.1", "4.0.2", "v04.0.2", "v4.0.2-rc1"])
def test_release_contract_rejects_mismatched_or_noncanonical_tag(tag: str) -> None:
    assessment = assess_repository(ROOT, release_tag=tag)
    assert "metadata.tag-version-mismatch" in {item.code for item in assessment.diagnostics}
    assert not assessment.ready


def test_release_notes_require_one_exact_nonempty_stable_section() -> None:
    changelog = "# Changes\n\n## [3.1.0] — 2026-08-18\n\nShipped.\n\n## [3.0.0]\nOld.\n"
    assert extract_release_notes(changelog, "3.1.0") == "Shipped.\n"
    with pytest.raises(ValueError, match="exactly one"):
        extract_release_notes(changelog, "4.0.2")
    with pytest.raises(ValueError, match="empty"):
        extract_release_notes("## [3.1.0]\n\n## [3.0.0]\nOld.\n", "3.1.0")
    with pytest.raises(ValueError, match="invalid stable"):
        extract_release_notes(changelog, "3.1.0-rc1")


def test_release_creator_builds_only_create_command_with_hashed_assets(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    wheel = source / "aegis-4.0.2-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    assets = tmp_path / "assets"
    prepare_release_assets(source, assets)
    notes = tmp_path / "notes.md"
    notes.write_text("Release notes\n", encoding="utf-8")
    command = build_create_command(
        tag="v4.0.2", version="4.0.2", notes_file=notes, asset_directory=assets
    )
    assert command[:4] == ("gh", "release", "create", "v4.0.2")
    assert any(str(item).endswith("release-asset-manifest.json") for item in command)
    assert any(str(item).endswith("SHA256SUMS") for item in command)
    assert "--verify-tag" in command
    assert "upload" not in command
    assert "edit" not in command
    assert "--clobber" not in command
    with pytest.raises(ValueError, match="exactly equal"):
        build_create_command(
            tag="v4.0.1", version="4.0.2", notes_file=notes, asset_directory=assets
        )


def test_release_asset_preparation_is_deterministic_and_rejects_duplicates(tmp_path: Path) -> None:
    source = tmp_path / "input"
    (source / "one").mkdir(parents=True)
    (source / "one/aegis.whl").write_bytes(b"one")
    outputs = prepare_release_assets(source, tmp_path / "output")
    assert [path.name for path in outputs] == [
        "aegis.whl",
        "aegis.whl.sha256",
        "release-asset-manifest.json",
        "release-asset-manifest.json.sha256",
        "SHA256SUMS",
    ]
    assert (
        (tmp_path / "output/aegis.whl.sha256").read_text(encoding="ascii").endswith("  aegis.whl\n")
    )

    duplicate_source = tmp_path / "duplicates"
    (duplicate_source / "one").mkdir(parents=True)
    (duplicate_source / "two").mkdir()
    (duplicate_source / "one/aegis.whl").write_bytes(b"one")
    (duplicate_source / "two/aegis.whl").write_bytes(b"two")
    with pytest.raises(ValueError, match="duplicate release asset"):
        prepare_release_assets(duplicate_source, tmp_path / "duplicate-output")


def test_release_creator_rejects_payload_tampering(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "aegis-latent-sdk-4.0.2.tgz").write_bytes(b"package")
    assets = tmp_path / "assets"
    prepare_release_assets(source, assets)
    (assets / "aegis-latent-sdk-4.0.2.tgz").write_bytes(b"tampered")
    notes = tmp_path / "notes.md"
    notes.write_text("Release notes\n", encoding="utf-8")
    with pytest.raises(ValueError, match="sidecar mismatch"):
        build_create_command(
            tag="v4.0.2", version="4.0.2", notes_file=notes, asset_directory=assets
        )


def test_publish_workflows_are_tag_only_and_publish_downloaded_artifacts() -> None:
    pypi = (ROOT / ".github/workflows/publish_pypi.yml").read_text()
    npm = (ROOT / ".github/workflows/publish_npm.yml").read_text()
    for workflow in (pypi, npm):
        assert "workflow_dispatch" in workflow
        assert '      - "v*"' in workflow
        assert "environment:" in workflow
        assert "id-token: write" in workflow
        assert 'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${GITHUB_SHA}"' in workflow
        assert "AEGIS_TRUSTED_PUBLISHING_ENABLED" in workflow
    assert "packages-dir: release-artifact" in pypi
    assert "npm publish release-artifact/*.tgz --access public --provenance" in npm


def test_oci_workflow_publishes_multiarch_by_digest_with_keyless_signature() -> None:
    workflow = (ROOT / ".github/workflows/publish_oci.yml").read_text()
    assert "linux/amd64,linux/arm64" in workflow
    assert "component: gateway" in workflow
    assert "component: dashboard" in workflow
    assert "workflow_dispatch" in workflow
    assert 'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${GITHUB_SHA}"' in workflow
    assert "dockerfile: deploy/docker/Dockerfile" in workflow
    assert "dockerfile: dashboard/Dockerfile" in workflow
    assert "push: true" in workflow
    assert "packages: write" in workflow
    assert "attestations: write" in workflow
    assert "docker/login-action@" in workflow
    assert 'cosign sign --yes "${IMAGE}@${IMAGE_DIGEST}"' in workflow
    assert "push-to-registry: true" in workflow
    assert ":latest" not in workflow


def test_release_workflow_is_tag_bound_create_only_and_protected() -> None:
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert "workflow_dispatch" in workflow
    assert '      - "v[0-9]*"' in workflow
    assert 'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${GITHUB_SHA}"' in workflow
    assert 'python scripts/verify_release_contract.py --root . --tag "${RELEASE_TAG}"' in workflow
    assert "python scripts/extract_release_notes.py" in workflow
    assert "python scripts/create_github_release.py" in workflow
    assert "python scripts/prepare_release_assets.py" in workflow
    assert "name: release" in workflow
    assert "sdk/python/dist/*.whl" in workflow
    assert "sdk/typescript/dist/*.tgz" in workflow
    assert ".spdx.json" in workflow
    assert "syft-version: v1.51.0" in workflow
    assert "--clobber" not in workflow
    assert "gh release upload" not in workflow
    assert "gh release edit" not in workflow
    assert "softprops/action-gh-release@" not in workflow


def test_legacy_package_workflow_is_build_validation_only() -> None:
    workflow = (ROOT / ".github/workflows/publish.yml").read_text()
    assert "workflow_dispatch" not in workflow
    assert "refs/tags" not in workflow
    assert "pypa/gh-action-pypi-publish@" not in workflow
    assert "twine upload" not in workflow
    assert "id-token: write" not in workflow
    assert "pip install build==1.3.0 twine==6.2.0" in workflow


def test_release_contract_detects_version_drift_missing_dockerfile_and_backend(
    tmp_path: Path,
) -> None:
    cases = [
        ("aegis/__init__.py", '"4.0.2"', '"4.0.3"', "metadata.version-drift"),
        ("pyproject.toml", "hatchling==1.28.0", "hatchling>=1.24", "build.backend-unpinned"),
        (
            "pyproject.toml",
            'packages = ["aegis", "aegis_server", "integrations"]',
            'packages = ["aegis", "integrations"]',
            "metadata.core-wheel-packages",
        ),
        (
            "deploy/k8s/aegis-operator/operator.py",
            "aegis-latent-core:4.0.2",
            "aegis-latent-core:3.1.0",
            "deployment.version-drift",
        ),
        (
            "scripts/install_aegis.sh",
            'verify_sha256 "${WHEEL_PATH}" "${SIDECAR_PATH}"',
            'test -s "${WHEEL_PATH}"',
            "deployment.version-drift",
        ),
    ]
    for index, (relative, old, new, code) in enumerate(cases):
        repository = _copy_contract_repository(tmp_path / f"case-{index}")
        path = repository / relative
        path.write_text(path.read_text().replace(old, new))
        assessment = assess_repository(repository)
        assert code in {item.code for item in assessment.diagnostics}
        assert not assessment.ready
    repository = _copy_contract_repository(tmp_path / "missing-dockerfile")
    (repository / "deploy/docker/Dockerfile").unlink()
    assessment = assess_repository(repository)
    assert "oci.dockerfile-missing" in {item.code for item in assessment.diagnostics}


@pytest.mark.parametrize(
    ("relative_path", "old", "new", "diagnostic_code"),
    [
        (
            "sdk/python/pyproject.toml",
            'name = "aegis-latent-sdk"',
            'name = "aegis-sdk"',
            "metadata.python-package-name",
        ),
        (
            "sdk/typescript/package.json",
            '"name": "aegis-latent-sdk"',
            '"name": "@aegis-latent/sdk"',
            "metadata.typescript-package-name",
        ),
        (
            "aegis_rust_v2/src/lib.rs",
            'm.add("__version__", env!("CARGO_PKG_VERSION"))?;',
            'm.add("__version__", "4.0.0")?;',
            "metadata.rust-runtime-version-unbound",
        ),
        (
            "aegis_server/__init__.py",
            "from aegis import __version__",
            '__version__ = "4.0.2"',
            "metadata.server-runtime-version-unbound",
        ),
        (
            "aegis/core/forensic_pdf_report.py",
            "tool_version: str = aegis_version",
            'tool_version: str = "4.0.2"',
            "metadata.forensic-report-version-unbound",
        ),
    ],
)
def test_release_contract_binds_package_identity_and_rust_runtime_version(
    tmp_path: Path, relative_path: str, old: str, new: str, diagnostic_code: str
) -> None:
    repository = _copy_contract_repository(tmp_path / "repository")
    path = repository / relative_path
    contents = path.read_text(encoding="utf-8")
    assert contents.count(old) == 1
    path.write_text(contents.replace(old, new), encoding="utf-8")
    assessment = assess_repository(repository)
    assert diagnostic_code in {item.code for item in assessment.diagnostics}
    assert not assessment.ready


@pytest.mark.parametrize(
    ("workflow_name", "required", "replacement", "diagnostic_code"),
    [
        (
            "release.yml",
            'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${GITHUB_SHA}"',
            'exit 0\n          scripts/verify_release_tag.sh "${RELEASE_TAG}" "${GITHUB_SHA}"',
            "release.validation-executable",
        ),
        (
            "release.yml",
            "python scripts/create_github_release.py",
            ": # python scripts/create_github_release.py",
            "release.create-only",
        ),
        (
            "release.yml",
            "python scripts/create_github_release.py",
            "exit 0\n          python scripts/create_github_release.py",
            "release.create-only",
        ),
        (
            "release.yml",
            "python scripts/create_github_release.py",
            "gh api --method PATCH /repos/x/y/releases/1\n          python scripts/create_github_release.py",
            "release.create-only",
        ),
        (
            "publish_oci.yml",
            'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${GITHUB_SHA}"',
            'exit 0\n          scripts/verify_release_tag.sh "${RELEASE_TAG}" "${GITHUB_SHA}"',
            "oci.provenance-executable",
        ),
        (
            "publish_oci.yml",
            "push: true",
            "push: false",
            "oci.publish-by-action",
        ),
        (
            "publish_oci.yml",
            "      - name: Build and publish exact multi-architecture image",
            "      - name: Forbidden registry shell\n        run: docker push ghcr.io/example/image:v4.0.2\n      - name: Build and publish exact multi-architecture image",
            "oci.publish-by-action",
        ),
        (
            "publish_oci.yml",
            'cosign sign --yes "${IMAGE}@${IMAGE_DIGEST}"',
            'cosign verify "${IMAGE}@${IMAGE_DIGEST}"',
            "oci.keyless-signature",
        ),
        (
            "publish_oci.yml",
            'echo "tags=${IMAGE}:${VERSION},${IMAGE}:sha-${GITHUB_SHA}"',
            'echo "tags=${IMAGE}:${VERSION},${IMAGE}:sha-${GITHUB_SHA},${IMAGE}:latest"',
            "oci.immutable-tags",
        ),
    ],
)
def test_contract_rejects_unreachable_or_alternate_publication_paths(
    tmp_path: Path, workflow_name: str, required: str, replacement: str, diagnostic_code: str
) -> None:
    repository = _copy_contract_repository(tmp_path / "repository")
    workflow_path = repository / ".github/workflows" / workflow_name
    workflow = workflow_path.read_text()
    assert required in workflow
    workflow_path.write_text(workflow.replace(required, replacement, 1))
    assessment = assess_repository(repository)
    assert diagnostic_code in {item.code for item in assessment.diagnostics}
    assert not assessment.ready


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
