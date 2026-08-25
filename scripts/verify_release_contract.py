#!/usr/bin/env python3
"""Validate source-only release metadata and workflow contracts."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

SHA_PIN = re.compile(r"^[0-9a-f]{40}$")
RELEASE_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
USES = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)")
PERMISSION = re.compile(r"^([A-Za-z-]+):\s*([^#\s]+)")
PYTHON_VERSION = re.compile(r'(?m)^__version__\s*=\s*["\'](?P<version>[^"\']+)["\']\s*(?:#.*)?$')
YAML_SCALAR = re.compile(r"^[ \t]*(?P<key>[A-Za-z][A-Za-z0-9_-]*):[ \t]*(?P<value>[^#]+?)\s*$")
PINNED_BACKEND = "hatchling==1.28.0"


@dataclass(frozen=True)
class Diagnostic:
    """A release-contract violation that blocks source readiness."""

    code: str
    message: str
    path: str
    severity: str = "blocking"


@dataclass(frozen=True)
class Assessment:
    """Structured source-contract result; not publication evidence."""

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
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return cast(dict[str, Any], value)


def _read_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _nested_string(value: dict[str, Any], *keys: str) -> str:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            raise KeyError(".".join(keys))
        current = current[key]
    if not isinstance(current, str):
        raise TypeError(f"{'.'.join(keys)} must be a string")
    return current


def _read_python_version(path: Path) -> str:
    matches = list(PYTHON_VERSION.finditer(path.read_text(encoding="utf-8")))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one __version__ assignment, found {len(matches)}")
    return matches[0].group("version")


def _yaml_scalar(path: Path, key: str, *, section: str | None = None) -> str:
    matches: list[str] = []
    active_section = section is None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = len(line) - len(line.lstrip(" "))
        parsed = YAML_SCALAR.fullmatch(line)
        if section is not None and indentation == 0:
            top_level_key = line.partition(":")[0].strip() if ":" in line else ""
            active_section = top_level_key == section
            continue
        if not active_section or parsed is None:
            continue
        expected_indentation = 0 if section is None else 2
        if indentation == expected_indentation and parsed.group("key") == key:
            matches.append(parsed.group("value").strip().strip("\"'"))
    if len(matches) != 1:
        location = f"{section}.{key}" if section else key
        raise ValueError(f"expected exactly one {location} scalar, found {len(matches)}")
    return matches[0]


def _cargo_lock_version(path: Path, package_name: str) -> str:
    packages = _read_toml(path).get("package")
    if not isinstance(packages, list):
        raise ValueError("Cargo.lock does not contain package entries")
    matches = [
        package.get("version") for package in packages if package.get("name") == package_name
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise ValueError(f"expected exactly one string version for package {package_name!r}")
    return matches[0]


def _job_block(workflow: str, job_name: str) -> str:
    lines = workflow.splitlines()
    start = next((i for i, line in enumerate(lines) if line == f"  {job_name}:"), None)
    if start is None:
        return ""
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def _step_block(job_block: str, step_name: str) -> str:
    lines = job_block.splitlines()
    marker = f"      - name: {step_name}"
    matches = [i for i, line in enumerate(lines) if line == marker]
    if len(matches) != 1:
        return ""
    start = matches[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.match(r"^      - (?:name|uses):", lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def _run_blocks(block: str) -> tuple[tuple[str, ...], ...]:
    lines = block.splitlines()
    blocks: list[tuple[str, ...]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(?P<indent> +)run:\s*\|\s*$", line)
        if match is None:
            continue
        indentation = len(match.group("indent"))
        commands: list[str] = []
        for candidate in lines[index + 1 :]:
            if not candidate.strip():
                continue
            child_indent = len(candidate) - len(candidate.lstrip(" "))
            if child_indent <= indentation:
                break
            command = candidate.strip()
            if not command.startswith("#"):
                commands.append(command)
        blocks.append(tuple(commands))
    return tuple(blocks)


def _run_commands(block: str) -> tuple[str, ...]:
    return tuple(command for run_block in _run_blocks(block) for command in run_block)


def _uses_references(block: str) -> tuple[str, ...]:
    return tuple(match.group(1) for match in USES.finditer(block))


def _is_unconditional_step(block: str) -> bool:
    return bool(block) and re.search(r"(?m)^\s+(?:if|continue-on-error):", block) is None


def _has_tag_only_trigger(workflow: str, pattern: str) -> bool:
    lines = workflow.splitlines()
    try:
        start = lines.index("on:")
    except ValueError:
        return False
    block: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line.startswith(" "):
            break
        if line.strip() and not line.lstrip().startswith("#"):
            block.append(line)
    trigger = "\n".join(block)
    return (
        "  push:" in trigger
        and "    tags:" in trigger
        and f'      - "{pattern}"' in trigger
        and "workflow_dispatch:" not in trigger
        and "schedule:" not in trigger
        and "pull_request:" not in trigger
    )


def _permission_blocks(workflow: str) -> list[tuple[int, dict[str, str]]]:
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
    workflows = root / ".github/workflows"
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


def _load_versions(root: Path, diagnostics: list[Diagnostic]) -> dict[str, str]:
    def json_value(path: Path, *keys: str) -> str:
        return _nested_string(_read_json(path), *keys)

    def toml_value(path: Path, *keys: str) -> str:
        return _nested_string(_read_toml(path), *keys)

    sources: dict[str, tuple[str, Callable[[Path], str]]] = {
        "core": ("pyproject.toml", lambda p: toml_value(p, "project", "version")),
        "core-runtime": ("aegis/__init__.py", _read_python_version),
        "python-sdk": ("sdk/python/pyproject.toml", lambda p: toml_value(p, "project", "version")),
        "python-sdk-runtime": ("sdk/python/src/aegis_sdk/__init__.py", _read_python_version),
        "typescript-sdk": ("sdk/typescript/package.json", lambda p: json_value(p, "version")),
        "typescript-lock": (
            "sdk/typescript/package-lock.json",
            lambda p: json_value(p, "packages", "", "version"),
        ),
        "dashboard": ("dashboard/package.json", lambda p: json_value(p, "version")),
        "dashboard-lock": (
            "dashboard/package-lock.json",
            lambda p: json_value(p, "packages", "", "version"),
        ),
        "rust-cargo": ("aegis_rust_v2/Cargo.toml", lambda p: toml_value(p, "package", "version")),
        "rust-pyproject": (
            "aegis_rust_v2/pyproject.toml",
            lambda p: toml_value(p, "project", "version"),
        ),
        "rust-lock": ("aegis_rust_v2/Cargo.lock", lambda p: _cargo_lock_version(p, "aegis_rust")),
        "helm-chart": ("deploy/helm/Chart.yaml", lambda p: _yaml_scalar(p, "version")),
        "helm-app": ("deploy/helm/Chart.yaml", lambda p: _yaml_scalar(p, "appVersion")),
        "helm-image": (
            "deploy/helm/values.yaml",
            lambda p: _yaml_scalar(p, "tag", section="image").removeprefix("v"),
        ),
    }
    versions: dict[str, str] = {}
    for label, (relative_path, loader) in sources.items():
        try:
            versions[label] = loader(root / relative_path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            diagnostics.append(
                Diagnostic(
                    "metadata.unreadable", f"cannot read release version: {exc}", relative_path
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


def _validate_build_backends(root: Path, diagnostics: list[Diagnostic]) -> None:
    for relative_path in ("pyproject.toml", "sdk/python/pyproject.toml"):
        try:
            requires = _read_toml(root / relative_path)["build-system"]["requires"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            diagnostics.append(
                Diagnostic(
                    "build.backend-unreadable", f"cannot read build backend: {exc}", relative_path
                )
            )
            continue
        _add_if_false(
            diagnostics,
            requires == [PINNED_BACKEND],
            "build.backend-unpinned",
            f"build backend must be exactly {PINNED_BACKEND}",
            relative_path,
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
        "pypi.environment": "name: pypi" in workflow,
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
        "npm.environment": "name: npm" in workflow,
        "npm.oidc": "id-token: write" in workflow
        and "registry-url: https://registry.npmjs.org" in workflow,
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
    relative_path = ".github/workflows/publish_oci.yml"
    path = root / relative_path
    if not path.is_file():
        diagnostics.append(
            Diagnostic("oci.missing", "multi-architecture OCI workflow is missing", relative_path)
        )
        return
    workflow = path.read_text(encoding="utf-8")
    provenance_job = _job_block(workflow, "provenance")
    validation_job = _job_block(workflow, "validate-images")
    provenance_step = _step_block(
        provenance_job, "Verify immutable release provenance and synchronized versions"
    )
    expected_provenance = (
        "git fetch --no-tags origin main",
        'test "$(git cat-file -t "refs/tags/${RELEASE_TAG}")" = tag',
        'git verify-tag "${RELEASE_TAG}"',
        'git merge-base --is-ancestor "${GITHUB_SHA}" origin/main',
        'python scripts/verify_release_contract.py --root . --tag "${RELEASE_TAG}"',
    )
    expected_actions = (
        "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
        "docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130",
        "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
        "docker/build-push-action@ca052bb54ab0790a636c9b5f226502c73d547a25",
    )
    forbidden = re.compile(
        r"(?im)(?:packages:\s*write|id-token:\s*write|push:\s*true|docker/login-action@|cosign(?:\s|/)|\bdocker\s+(?:login|push)\b|\b(?:oras|skopeo)\b|\bgh\s+api\b|\bcurl\b|type=registry|ghcr\.io)"
    )
    requirements = {
        "oci.tag-only": _has_tag_only_trigger(workflow, "v[0-9]*"),
        "oci.multiarch": "linux/amd64,linux/arm64" in validation_job,
        "oci.components": "component: gateway" in validation_job
        and "component: dashboard" in validation_job,
        "oci.provenance-executable": _is_unconditional_step(provenance_step)
        and _run_blocks(provenance_step) == (expected_provenance,),
        "oci.publication-disabled": forbidden.search(workflow) is None
        and len(re.findall(r"(?m)^\s+push:\s*false\s*$", validation_job)) == 1,
        "oci.action-allowlist": _uses_references(validation_job) == expected_actions
        and _run_blocks(validation_job) == ()
        and re.search(r"(?m)^\s+(?:if|continue-on-error|container|services|shell):", validation_job)
        is None
        and re.search(r"(?m)^\s+(?:outputs|tags|cache-to|secrets|secret-envs|ssh):", validation_job)
        is None,
        "oci.provenance": "provenance: mode=max" in validation_job
        and "sbom: true" in validation_job,
    }
    for code, condition in requirements.items():
        _add_if_false(
            diagnostics,
            condition,
            code,
            f"required OCI validation contract is absent: {code}",
            relative_path,
        )
    dockerfiles = re.findall(r"(?m)^\s+dockerfile:\s*([^#\s]+)\s*(?:#.*)?$", validation_job)
    _add_if_false(
        diagnostics,
        bool(dockerfiles),
        "oci.dockerfiles",
        "OCI workflow must declare component Dockerfiles",
        relative_path,
    )
    for dockerfile in dockerfiles:
        candidate = Path(dockerfile.strip("\"'"))
        exists = (
            not candidate.is_absolute()
            and ".." not in candidate.parts
            and (root / candidate).is_file()
        )
        _add_if_false(
            diagnostics,
            exists,
            "oci.dockerfile-missing",
            f"OCI workflow Dockerfile does not exist: {dockerfile}",
            relative_path,
        )


def _validate_release_workflow(root: Path, diagnostics: list[Diagnostic]) -> None:
    relative_path = ".github/workflows/release.yml"
    path = root / relative_path
    if not path.is_file():
        diagnostics.append(
            Diagnostic("release.missing", "GitHub Release workflow is missing", relative_path)
        )
        return
    workflow = path.read_text(encoding="utf-8")
    validate_job = _job_block(workflow, "validate")
    release_job = _job_block(workflow, "github-release")
    signed_step = _step_block(
        validate_job, "Verify annotated signed tag and protected-branch ancestry"
    )
    contract_step = _step_block(validate_job, "Verify full release contract")
    prepare_step = _step_block(release_job, "Flatten artifact directories")
    changelog_step = _step_block(release_job, "Extract CHANGELOG excerpt for this release")
    create_step = _step_block(release_job, "Create a new GitHub Release without an update path")
    expected_signed = (
        "git fetch --no-tags origin main",
        'test "$(git cat-file -t "refs/tags/${RELEASE_TAG}")" = tag',
        'git verify-tag "${RELEASE_TAG}"',
        'git merge-base --is-ancestor "${GITHUB_SHA}" origin/main',
    )
    expected_contract = (
        'python scripts/verify_release_contract.py --root . --tag "${RELEASE_TAG}"',
    )
    expected_prepare = (
        "python scripts/prepare_release_assets.py --input release-assets --output release",
    )
    expected_changelog = (
        'python scripts/extract_release_notes.py --changelog CHANGELOG.md --version "${VERSION}" --output release_body.md',
    )
    expected_create = (
        'python scripts/create_github_release.py --tag "${RELEASE_TAG}" --version "${VERSION}" --notes-file release_body.md --asset-directory release',
    )
    expected_actions = (
        "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "actions/attest-build-provenance@ef244123eb79f2f7a7e75d99086184180e6d0018",
    )
    permission_blocks = _permission_blocks(workflow)
    top_permissions = [v for indent, v in permission_blocks if indent == 0]
    release_permissions = [v for indent, v in _permission_blocks(release_job) if indent == 4]
    requirements = {
        "release.tag-only": _has_tag_only_trigger(workflow, "v[0-9]*"),
        "release.validation-executable": _is_unconditional_step(signed_step)
        and _run_blocks(signed_step) == (expected_signed,)
        and _is_unconditional_step(contract_step)
        and _run_blocks(contract_step) == (expected_contract,),
        "release.exact-changelog": _is_unconditional_step(changelog_step)
        and _run_blocks(changelog_step) == (expected_changelog,),
        "release.create-only": _is_unconditional_step(prepare_step)
        and _run_blocks(prepare_step) == (expected_prepare,)
        and _is_unconditional_step(create_step)
        and _run_blocks(create_step) == (expected_create,)
        and _run_blocks(release_job) == (expected_prepare, expected_changelog, expected_create)
        and _uses_references(release_job) == expected_actions
        and re.search(r"(?m)^\s+(?:if|continue-on-error|container|services|shell):", release_job)
        is None
        and re.search(
            r"(?im)(?:\bgh\s+(?:api|release\s+(?:upload|edit))\b|--clobber|softprops/action-gh-release@|\bcurl\b)",
            workflow,
        )
        is None,
        "release.environment": re.search(r"(?m)^\s{4}environment:\s*$", release_job) is not None
        and re.search(r"(?m)^\s{6}name:\s*release\s*$", release_job) is not None,
        "release.permissions": top_permissions == [{"contents": "read"}]
        and release_permissions
        == [{"contents": "write", "id-token": "write", "attestations": "write"}],
        "release.helpers": all(
            (root / path).is_file()
            for path in (
                "scripts/extract_release_notes.py",
                "scripts/create_github_release.py",
                "scripts/prepare_release_assets.py",
            )
        ),
        "release.build-tools-pinned": "pip install build==1.3.0 twine==6.2.0" in workflow,
    }
    for code, condition in requirements.items():
        _add_if_false(
            diagnostics,
            condition,
            code,
            f"required GitHub Release contract is absent: {code}",
            relative_path,
        )


def _validate_legacy_build_workflow(root: Path, diagnostics: list[Diagnostic]) -> None:
    relative_path = ".github/workflows/publish.yml"
    path = root / relative_path
    if not path.is_file():
        diagnostics.append(
            Diagnostic("legacy-build.missing", "package build workflow is missing", relative_path)
        )
        return
    workflow = path.read_text(encoding="utf-8")
    forbidden = re.compile(
        r"(?im)(?:workflow_dispatch:|refs/tags|pypa/gh-action-pypi-publish@|\bpip\s+upload\b|\btwine\s+upload\b|\bgh\s+release\b|id-token:\s*write)"
    )
    _add_if_false(
        diagnostics,
        forbidden.search(workflow) is None,
        "legacy-build.publication-disabled",
        "legacy package workflow must remain build-validation-only",
        relative_path,
    )
    _add_if_false(
        diagnostics,
        "pip install build==1.3.0 twine==6.2.0" in workflow,
        "legacy-build.tools-unpinned",
        "legacy package workflow must pin build and twine",
        relative_path,
    )


def assess_repository(root: Path, *, release_tag: str | None = None) -> Assessment:
    root = root.resolve()
    diagnostics: list[Diagnostic] = []
    versions = _load_versions(root, diagnostics)
    _validate_build_backends(root, diagnostics)
    if release_tag is not None:
        expected = versions.get("core")
        tag_version = release_tag.removeprefix("v")
        _add_if_false(
            diagnostics,
            release_tag.startswith("v")
            and RELEASE_VERSION.fullmatch(tag_version) is not None
            and expected is not None
            and tag_version == expected,
            "metadata.tag-version-mismatch",
            f"release tag {release_tag!r} must equal synchronized version v{expected}",
            "release tag",
        )
    _validate_action_pins(root, diagnostics)
    _validate_pypi_workflow(root, diagnostics)
    _validate_npm_workflow(root, diagnostics)
    _validate_release_architectures(root, diagnostics)
    _validate_release_workflow(root, diagnostics)
    _validate_legacy_build_workflow(root, diagnostics)
    return Assessment(str(root), versions, tuple(diagnostics))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--tag")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    arguments = parser.parse_args(argv)
    assessment = assess_repository(arguments.root, release_tag=arguments.tag)
    if arguments.json:
        print(json.dumps(assessment.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"release source contract: {'READY' if assessment.ready else 'BLOCKED'}")
        print(f"synchronized versions: {assessment.versions}")
        for diagnostic in assessment.diagnostics:
            print(
                f"[{diagnostic.severity}] {diagnostic.code}: {diagnostic.message} ({diagnostic.path})"
            )
    return 0 if assessment.ready else 1


if __name__ == "__main__":
    sys.exit(main())
