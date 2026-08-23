#!/usr/bin/env python3
"""Validate release metadata and immutable publication workflow contracts."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SHA_PIN = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)")
PERMISSION = re.compile(r"^([A-Za-z-]+):\s*([^#\s]+)")


@dataclass(frozen=True)
class Diagnostic:
    """A release-contract violation that must be handled before release."""

    code: str
    message: str
    path: str
    severity: str = "blocking"


@dataclass(frozen=True)
class Assessment:
    """Structured release readiness result."""

    root: str
    versions: dict[str, str]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def ready(self) -> bool:
        return not any(item.severity == "blocking" for item in self.diagnostics)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "root": self.root,
            "versions": self.versions,
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _permission_blocks(workflow: str) -> list[tuple[int, dict[str, str]]]:
    """Return permission maps and their indentation without a YAML dependency."""

    lines = workflow.splitlines()
    blocks: list[tuple[int, dict[str, str]]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^( *)permissions:\s*$", line)
        if match is None:
            continue
        indentation = len(match.group(1))
        values: dict[str, str] = {}
        for candidate in lines[index + 1 :]:
            if not candidate.strip() or candidate.lstrip().startswith("#"):
                continue
            child_indent = len(candidate) - len(candidate.lstrip())
            if child_indent <= indentation:
                break
            if child_indent == indentation + 2:
                permission = PERMISSION.match(candidate.strip())
                if permission:
                    values[permission.group(1)] = permission.group(2)
        blocks.append((indentation, values))
    return blocks


def _add_if_false(
    diagnostics: list[Diagnostic], condition: bool, code: str, message: str, path: str
) -> None:
    if not condition:
        diagnostics.append(Diagnostic(code=code, message=message, path=path))


def _validate_action_pins(root: Path, diagnostics: list[Diagnostic]) -> None:
    workflows = root / ".github" / "workflows"
    for path in sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml"))):
        for reference in USES.findall(path.read_text(encoding="utf-8")):
            if reference.startswith("./"):
                continue
            action, separator, revision = reference.rpartition("@")
            _add_if_false(
                diagnostics,
                bool(action and separator and SHA_PIN.fullmatch(revision)),
                "actions.unpinned",
                f"action reference must use a full 40-character commit SHA: {reference}",
                str(path.relative_to(root)),
            )


def _validate_publish_permissions(
    relative_path: str, workflow: str, diagnostics: list[Diagnostic]
) -> None:
    blocks = _permission_blocks(workflow)
    top_level = [values for indentation, values in blocks if indentation == 0]
    job_level = [values for indentation, values in blocks if indentation == 4]
    _add_if_false(
        diagnostics,
        top_level == [{"contents": "read"}],
        "permissions.workflow",
        "publishing workflow must default to only contents: read",
        relative_path,
    )
    _add_if_false(
        diagnostics,
        job_level == [{"contents": "read", "id-token": "write"}],
        "permissions.publish-job",
        "only the environment-gated publish job may add id-token: write",
        relative_path,
    )


def _load_versions(root: Path, diagnostics: list[Diagnostic]) -> dict[str, str]:
    sources: dict[str, tuple[str, tuple[str, ...]]] = {
        "core": ("pyproject.toml", ("project", "version")),
        "python-sdk": ("sdk/python/pyproject.toml", ("project", "version")),
        "typescript-sdk": ("sdk/typescript/package.json", ("version",)),
        "typescript-lock": ("sdk/typescript/package-lock.json", ("version",)),
        "dashboard": ("dashboard/package.json", ("version",)),
        "dashboard-lock": ("dashboard/package-lock.json", ("version",)),
    }
    versions: dict[str, str] = {}
    for label, (relative_path, keys) in sources.items():
        path = root / relative_path
        try:
            value: Any = _read_toml(path) if path.suffix == ".toml" else _read_json(path)
            for key in keys:
                value = value[key]
            versions[label] = str(value)
        except (OSError, ValueError, KeyError, TypeError) as error:
            diagnostics.append(
                Diagnostic(
                    code="metadata.unreadable",
                    message=f"cannot read release version: {error}",
                    path=relative_path,
                )
            )
    if versions:
        expected = versions.get("core", next(iter(versions.values())))
        _add_if_false(
            diagnostics,
            all(version == expected for version in versions.values()),
            "metadata.version-drift",
            f"release versions must be synchronized before tagging: {versions}",
            "repository metadata",
        )
    return versions


def _validate_pypi_workflow(root: Path, diagnostics: list[Diagnostic]) -> None:
    relative_path = ".github/workflows/publish_pypi.yml"
    path = root / relative_path
    if not path.is_file():
        diagnostics.append(Diagnostic("pypi.missing", "PyPI workflow is missing", relative_path))
        return
    workflow = path.read_text(encoding="utf-8")
    _validate_publish_permissions(relative_path, workflow, diagnostics)
    requirements = {
        "pypi.tag-only": "tags:" in workflow
        and '"v*"' in workflow
        and "workflow_dispatch" not in workflow,
        "pypi.version-gate": "github.ref_name" in workflow
        and "sdk/python" in workflow
        and "pyproject.toml" in workflow,
        "pypi.tests": all(token in workflow for token in ("ruff check", "mypy", "pytest -q")),
        "pypi.build": "python -m build" in workflow and "twine check" in workflow,
        "pypi.artifact-upload": "sdk/python/dist/*.whl" in workflow
        and "sdk/python/dist/*.tar.gz" in workflow,
        "pypi.exact-artifact": "python-sdk-dist-${{ github.sha }}" in workflow
        and "packages-dir: release-artifact" in workflow,
        "pypi.environment": re.search(r"(?m)^\s{4}environment:\s*$", workflow) is not None
        and "name: pypi" in workflow,
        "pypi.oidc": "pypa/gh-action-pypi-publish@" in workflow and "id-token: write" in workflow,
        "pypi.main-ancestry": "git merge-base --is-ancestor" in workflow
        and "origin/main" in workflow,
        "pypi.signed-tag": "git verify-tag" in workflow and "git cat-file -t" in workflow,
        "pypi.external-enable": "vars.AEGIS_TRUSTED_PUBLISHING_ENABLED == 'true'" in workflow,
    }
    for code, condition in requirements.items():
        _add_if_false(
            diagnostics, condition, code, f"required PyPI contract is absent: {code}", relative_path
        )


def _validate_npm_workflow(root: Path, diagnostics: list[Diagnostic]) -> None:
    relative_path = ".github/workflows/publish_npm.yml"
    path = root / relative_path
    if not path.is_file():
        diagnostics.append(Diagnostic("npm.missing", "npm workflow is missing", relative_path))
        return
    workflow = path.read_text(encoding="utf-8")
    _validate_publish_permissions(relative_path, workflow, diagnostics)
    requirements = {
        "npm.tag-only": "tags:" in workflow
        and '"v*"' in workflow
        and "workflow_dispatch" not in workflow,
        "npm.version-gate": "github.ref_name" in workflow
        and "sdk/typescript" in workflow
        and "package.json" in workflow,
        "npm.tests": "npm run check" in workflow,
        "npm.pack": "npm pack --json" in workflow,
        "npm.artifact-upload": "sdk/typescript/*.tgz" in workflow,
        "npm.exact-artifact": "typescript-sdk-package-${{ github.sha }}" in workflow
        and "release-artifact/*.tgz" in workflow,
        "npm.environment": re.search(r"(?m)^\s{4}environment:\s*$", workflow) is not None
        and "name: npm" in workflow,
        "npm.oidc": "id-token: write" in workflow
        and any(
            line.strip() == "registry-url: https://registry.npmjs.org"
            for line in workflow.splitlines()
        ),
        "npm.provenance": re.search(
            r"npm publish\s+release-artifact/\*\.tgz[^\n]*--provenance", workflow
        )
        is not None,
        "npm.main-ancestry": "git merge-base --is-ancestor" in workflow
        and "origin/main" in workflow,
        "npm.signed-tag": "git verify-tag" in workflow and "git cat-file -t" in workflow,
        "npm.external-enable": "vars.AEGIS_TRUSTED_PUBLISHING_ENABLED == 'true'" in workflow,
    }
    for code, condition in requirements.items():
        _add_if_false(
            diagnostics, condition, code, f"required npm contract is absent: {code}", relative_path
        )


def _validate_release_architectures(root: Path, diagnostics: list[Diagnostic]) -> None:
    """Require an isolated, externally gated multi-architecture OCI workflow."""

    relative_path = ".github/workflows/publish_oci.yml"
    path = root / relative_path
    if not path.is_file():
        diagnostics.append(
            Diagnostic("oci.missing", "multi-architecture OCI workflow is missing", relative_path)
        )
        return
    workflow = path.read_text(encoding="utf-8")
    requirements = {
        "oci.multiarch": "linux/amd64,linux/arm64" in workflow,
        "oci.components": "component: gateway" in workflow and "component: dashboard" in workflow,
        "oci.signed-tag": "git verify-tag" in workflow and "git cat-file -t" in workflow,
        "oci.main-ancestry": "git merge-base --is-ancestor" in workflow,
        "oci.external-enable": "vars.AEGIS_OCI_PUBLISHING_ENABLED == 'true'" in workflow,
        "oci.digest-signing": "cosign sign --yes" in workflow and "outputs.digest" in workflow,
        "oci.provenance": "provenance: mode=max" in workflow and "sbom: true" in workflow,
        "oci.environment": "name: oci-release" in workflow,
    }
    for code, condition in requirements.items():
        _add_if_false(
            diagnostics,
            condition,
            code,
            f"required OCI publication contract is absent: {code}",
            relative_path,
        )


def assess_repository(root: Path) -> Assessment:
    """Assess repository release readiness and return every blocking diagnostic."""

    root = root.resolve()
    diagnostics: list[Diagnostic] = []
    versions = _load_versions(root, diagnostics)
    _validate_action_pins(root, diagnostics)
    _validate_pypi_workflow(root, diagnostics)
    _validate_npm_workflow(root, diagnostics)
    _validate_release_architectures(root, diagnostics)
    return Assessment(str(root), versions, tuple(diagnostics))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    arguments = parser.parse_args(argv)
    assessment = assess_repository(arguments.root)
    if arguments.json:
        print(json.dumps(assessment.to_dict(), indent=2, sort_keys=True))
    else:
        status = "READY" if assessment.ready else "BLOCKED"
        print(f"release contract: {status}")
        print(f"synchronized versions: {assessment.versions}")
        for diagnostic in assessment.diagnostics:
            print(
                f"[{diagnostic.severity}] {diagnostic.code}: {diagnostic.message} ({diagnostic.path})"
            )
    return 0 if assessment.ready else 1


if __name__ == "__main__":
    sys.exit(main())
