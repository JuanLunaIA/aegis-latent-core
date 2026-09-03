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


def _has_verified_dispatch_trigger(workflow: str) -> bool:
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
        "  workflow_dispatch:" in trigger
        and "    inputs:" in trigger
        and "      release_tag:" in trigger
        and "      expected_target:" in trigger
        and trigger.count("        required: true") == 2
        and trigger.count("        type: string") == 2
        and "  push:" not in trigger
        and "schedule:" not in trigger
        and "pull_request:" not in trigger
    )


def _has_dispatch_only_trigger(workflow: str) -> bool:
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
        "  workflow_dispatch:" in trigger
        and "  push:" not in trigger
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
        "pypi.release-trigger": _has_verified_dispatch_trigger(workflow),
        "pypi.version-gate": "RELEASE_TAG" in workflow
        and "sdk/python" in workflow
        and "pyproject.toml" in workflow,
        "pypi.tests": all(token in workflow for token in ("ruff check", "mypy", "pytest -q")),
        "pypi.build": "python -m build" in workflow and "twine check" in workflow,
        "pypi.artifact-upload": "sdk/python/dist/*.whl" in workflow
        and "sdk/python/dist/*.tar.gz" in workflow,
        "pypi.exact-artifact": "python-sdk-dist-${{ inputs.expected_target }}" in workflow
        and "packages-dir: release-artifact" in workflow,
        "pypi.environment": "name: pypi" in workflow,
        "pypi.oidc": "pypa/gh-action-pypi-publish@" in workflow and "id-token: write" in workflow,
        "pypi.main-ancestry": 'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${EXPECTED_TAG_TARGET}"'
        in workflow,
        "pypi.signed-tag": 'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${EXPECTED_TAG_TARGET}"'
        in workflow,
        "pypi.exact-source": "ref: main" in workflow
        and "ref: ${{ env.EXPECTED_TAG_TARGET }}" in workflow,
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
        "npm.release-trigger": _has_verified_dispatch_trigger(workflow),
        "npm.version-gate": "RELEASE_TAG" in workflow
        and "sdk/typescript" in workflow
        and "package.json" in workflow,
        "npm.tests": "npm run check" in workflow,
        "npm.pack": "npm pack --json" in workflow,
        "npm.artifact-upload": "sdk/typescript/*.tgz" in workflow,
        "npm.exact-artifact": "typescript-sdk-package-${{ inputs.expected_target }}" in workflow
        and "release-artifact/*.tgz" in workflow,
        "npm.environment": "name: npm" in workflow,
        "npm.oidc": "id-token: write" in workflow
        and "registry-url: https://registry.npmjs.org" in workflow,
        # This required the literal `npm publish release-artifact/*.tgz`, which
        # pinned a command that cannot work: `npm publish` reads its argument as
        # a package spec, and a bare `a/b` is npm's GitHub `owner/repo`
        # shorthand, so npm tried to clone a repository instead of reading the
        # tarball. The v4.1.1 dispatch failed there while PyPI published. The
        # check now asserts the properties the release needs — provenance,
        # public access, and a path npm resolves as a file — rather than one
        # spelling of the command.
        "npm.provenance": "--provenance" in workflow and "--access public" in workflow,
        # Matched against the workflow with comment lines removed: the comment
        # above the publish step has to name the broken form in order to
        # explain it, exactly as the documentation gates must name a phrase to
        # prohibit it.
        "npm.publish-path": "./release-artifact/*.tgz" in workflow
        and re.search(r"npm publish\s+release-artifact/", _without_yaml_comments(workflow)) is None,
        "npm.main-ancestry": 'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${EXPECTED_TAG_TARGET}"'
        in workflow,
        "npm.signed-tag": 'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${EXPECTED_TAG_TARGET}"'
        in workflow,
        "npm.exact-source": "ref: main" in workflow
        and "ref: ${{ env.EXPECTED_TAG_TARGET }}" in workflow,
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
    publish_job = _job_block(workflow, "publish-images")
    provenance_step = _step_block(
        provenance_job, "Verify immutable release provenance and synchronized versions"
    )
    contract_step = _step_block(provenance_job, "Verify synchronized source contract")
    expected_provenance = (
        'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${EXPECTED_TAG_TARGET}"',
    )
    expected_contract = (
        'python scripts/verify_release_contract.py --root . --tag "${RELEASE_TAG}"',
    )
    expected_actions = (
        "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
        "docker/setup-qemu-action@1f40c72289eff860ee54a304f1438e3cff362e0a",
        "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e",
        "docker/login-action@dbcb813823bdd20940b903addbd779551569679f",
        "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        "sigstore/cosign-installer@398d4b0eeef1380460a10c8013a76f728fb906ac",
    )
    permission_blocks = _permission_blocks(workflow)
    top_permissions = [values for indent, values in permission_blocks if indent == 0]
    publish_permissions = [
        values for indent, values in _permission_blocks(publish_job) if indent == 4
    ]
    requirements = {
        "oci.release-trigger": _has_verified_dispatch_trigger(workflow),
        "oci.multiarch": "linux/amd64,linux/arm64" in publish_job,
        "oci.components": "component: gateway" in publish_job
        and "component: dashboard" in publish_job
        and "ghcr.io/juanlunaia/aegis-latent-core" in publish_job
        and "ghcr.io/juanlunaia/aegis-latent-core-dashboard" in publish_job,
        "oci.provenance-executable": _is_unconditional_step(provenance_step)
        and _run_blocks(provenance_step) == (expected_provenance,)
        and _is_unconditional_step(contract_step)
        and _run_blocks(contract_step) == (expected_contract,),
        "oci.exact-source": "ref: main" in provenance_job
        and "ref: ${{ env.EXPECTED_TAG_TARGET }}" in provenance_job
        and "ref: ${{ env.EXPECTED_TAG_TARGET }}" in publish_job
        and "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1" in provenance_job
        and 'python-version: "3.12"' in provenance_job,
        "oci.permissions": top_permissions == [{"contents": "read"}]
        and publish_permissions
        == [
            {
                "attestations": "write",
                "contents": "read",
                "id-token": "write",
                "packages": "write",
            }
        ],
        "oci.environment": re.search(r"(?m)^    environment:\s*$", publish_job) is not None
        and re.search(r"(?m)^      name:\s*release\s*$", publish_job) is not None,
        "oci.publish-by-action": "push: true" in publish_job
        and re.search(r"(?im)\bdocker\s+(?:login|push)\b", publish_job) is None,
        "oci.action-allowlist": _uses_references(publish_job) == expected_actions
        and re.search(r"(?m)^\s+(?:continue-on-error|container|services):", publish_job) is None,
        "oci.provenance": "provenance: mode=max" in publish_job
        and "sbom: true" in publish_job
        and "push-to-registry: true" in publish_job,
        "oci.keyless-signature": 'cosign sign --yes "${IMAGE}@${IMAGE_DIGEST}"' in publish_job,
        "oci.immutable-tags": 'echo "tags=${IMAGE}:${VERSION},${IMAGE}:sha-${EXPECTED_TAG_TARGET}"'
        in publish_job
        and "latest" not in publish_job,
    }
    for code, condition in requirements.items():
        _add_if_false(
            diagnostics,
            condition,
            code,
            f"required OCI publication contract is absent: {code}",
            relative_path,
        )
    dockerfiles = re.findall(r"(?m)^\s+dockerfile:\s*([^#\s]+)\s*(?:#.*)?$", publish_job)
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
        validate_job, "Verify Sigstore-signed annotated tag and protected-branch ancestry"
    )
    contract_step = _step_block(validate_job, "Verify full release contract")
    prepare_step = _step_block(
        release_job, "Flatten artifact directories and build integrity manifests"
    )
    changelog_step = _step_block(release_job, "Extract CHANGELOG excerpt for this release")
    create_step = _step_block(release_job, "Create a new GitHub Release without an update path")
    expected_signed = ('scripts/verify_release_tag.sh "${RELEASE_TAG}" "${EXPECTED_TAG_TARGET}"',)
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
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
    )
    permission_blocks = _permission_blocks(workflow)
    top_permissions = [v for indent, v in permission_blocks if indent == 0]
    release_permissions = [v for indent, v in _permission_blocks(release_job) if indent == 4]
    prepare_helper = (root / "scripts/prepare_release_assets.py").read_text(encoding="utf-8")
    requirements = {
        "release.release-trigger": _has_verified_dispatch_trigger(workflow),
        "release.validation-executable": _is_unconditional_step(signed_step)
        and _run_blocks(signed_step) == (expected_signed,)
        and _is_unconditional_step(contract_step)
        and _run_blocks(contract_step) == (expected_contract,),
        "release.exact-source": "ref: main" in validate_job
        and validate_job.count("ref: ${{ env.EXPECTED_TAG_TARGET }}") == 1
        and workflow.count("ref: ${{ env.EXPECTED_TAG_TARGET }}") == 6,
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
                "scripts/install_gitsign.sh",
                "scripts/prepare_release_assets.py",
                "scripts/verify_release_tag.sh",
            )
        ),
        "release.build-tools-pinned": "pip install build==1.3.0 twine==6.2.0" in workflow
        and "syft-version: v1.51.0" in workflow
        and workflow.count("python-version: ${{ env.PYTHON_BUILD_VERSION }}") >= 5,
        "release.complete-assets": all(
            token in workflow + prepare_helper
            for token in (
                "sdk/python/dist/*.whl",
                "sdk/python/dist/*.tar.gz",
                "sdk/typescript/dist/*.tgz",
                ".spdx.json",
                "release-asset-manifest.json",
                "SHA256SUMS",
            )
        ),
    }
    for code, condition in requirements.items():
        _add_if_false(
            diagnostics,
            condition,
            code,
            f"required GitHub Release contract is absent: {code}",
            relative_path,
        )


def _validate_release_tag_workflow(root: Path, diagnostics: list[Diagnostic]) -> None:
    relative_path = ".github/workflows/create_release_tag.yml"
    path = root / relative_path
    if not path.is_file():
        diagnostics.append(
            Diagnostic("tag-workflow.missing", "signed tag workflow is missing", relative_path)
        )
        return
    workflow = path.read_text(encoding="utf-8")
    job = _job_block(workflow, "create-tag")
    top_permissions = [v for indent, v in _permission_blocks(workflow) if indent == 0]
    job_permissions = [v for indent, v in _permission_blocks(job) if indent == 4]
    requirements = {
        "tag-workflow.dispatch-only": _has_dispatch_only_trigger(workflow),
        "tag-workflow.environment": re.search(r"(?m)^    environment:\s*$", job) is not None
        and re.search(r"(?m)^      name:\s*release\s*$", job) is not None,
        "tag-workflow.python-runtime": "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
        in job
        and 'python-version: "3.12"' in job,
        "tag-workflow.permissions": top_permissions == [{"contents": "read"}]
        and job_permissions == [{"actions": "write", "contents": "write", "id-token": "write"}],
        "tag-workflow.exact-main": "ref: main" in job
        and 'test "${GITHUB_SHA}" = "$(git rev-parse origin/main)"' in job,
        "tag-workflow.signing": all(
            token in job
            for token in (
                "scripts/install_gitsign.sh",
                "git tag --sign --annotate",
                'scripts/verify_release_tag.sh "${RELEASE_TAG}" "${GITHUB_SHA}"',
                'git push origin "refs/tags/${RELEASE_TAG}"',
            )
        ),
        "tag-workflow.no-rewrite": not re.search(
            r"(?im)(?:git\s+tag\s+.*(?:--force|-f\b)|git\s+push\s+.*(?:--force|-f\b)|git\s+tag\s+-d)",
            job,
        ),
        "tag-workflow.dispatches": all(
            name in job
            for name in ("release.yml", "publish_pypi.yml", "publish_npm.yml", "publish_oci.yml")
        )
        and 'gh workflow run "${workflow}" --ref main' in job
        and '-f release_tag="${RELEASE_TAG}"' in job
        and '-f expected_target="${GITHUB_SHA}"' in job,
    }
    for code, condition in requirements.items():
        _add_if_false(
            diagnostics,
            condition,
            code,
            f"required signed-tag workflow contract is absent: {code}",
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


def _validate_package_identity(root: Path, diagnostics: list[Diagnostic]) -> None:
    """Bind public distribution names and runtime versions to canonical metadata."""
    try:
        root_metadata = _read_toml(root / "pyproject.toml")
        python_name = _nested_string(
            _read_toml(root / "sdk/python/pyproject.toml"), "project", "name"
        )
        typescript_name = _nested_string(_read_json(root / "sdk/typescript/package.json"), "name")
        rust_source = (root / "aegis_rust_v2/src/lib.rs").read_text(encoding="utf-8")
        server_source = (root / "aegis_server/__init__.py").read_text(encoding="utf-8")
        report_source = (root / "aegis/core/forensic_pdf_report.py").read_text(encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        diagnostics.append(
            Diagnostic(
                "metadata.identity-unreadable",
                f"cannot read release package identity: {exc}",
                "package metadata",
            )
        )
        return
    _add_if_false(
        diagnostics,
        _nested_string(root_metadata, "project", "name") == "aegis-latent-core"
        and root_metadata.get("tool", {})
        .get("hatch", {})
        .get("build", {})
        .get("targets", {})
        .get("wheel", {})
        .get("packages")
        == ["aegis", "aegis_server", "integrations"],
        "metadata.core-wheel-packages",
        "core wheel must include aegis, aegis_server, and integrations",
        "pyproject.toml",
    )
    _add_if_false(
        diagnostics,
        python_name == "aegis-latent-sdk",
        "metadata.python-package-name",
        "Python SDK distribution name must be aegis-latent-sdk",
        "sdk/python/pyproject.toml",
    )
    _add_if_false(
        diagnostics,
        typescript_name == "aegis-latent-sdk",
        "metadata.typescript-package-name",
        "TypeScript SDK package name must be aegis-latent-sdk",
        "sdk/typescript/package.json",
    )
    _add_if_false(
        diagnostics,
        'm.add("__version__", env!("CARGO_PKG_VERSION"))?;' in rust_source,
        "metadata.rust-runtime-version-unbound",
        "Rust Python runtime version must derive from CARGO_PKG_VERSION",
        "aegis_rust_v2/src/lib.rs",
    )
    _add_if_false(
        diagnostics,
        "from aegis import __version__" in server_source
        and re.search(r"(?m)^__version__\s*=", server_source) is None,
        "metadata.server-runtime-version-unbound",
        "server runtime version must derive from aegis.__version__",
        "aegis_server/__init__.py",
    )
    _add_if_false(
        diagnostics,
        "from aegis import __version__ as aegis_version" in report_source
        and "tool_version: str = aegis_version" in report_source,
        "metadata.forensic-report-version-unbound",
        "forensic report default version must derive from aegis.__version__",
        "aegis/core/forensic_pdf_report.py",
    )


def _without_yaml_comments(text: str) -> str:
    """Drop whole-line YAML comments so a check cannot match its own rationale.

    A comment that explains why a form is forbidden necessarily contains that
    form. Without this, documenting the reason would trip the check.
    """
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _validate_active_deployment_versions(
    root: Path, diagnostics: list[Diagnostic], version: str
) -> None:
    """Reject stale active image owners, tags, labels, and air-gap package pins.

    ``version`` is the synchronized core version, not a literal. Hard-coding the
    expected version here made this check assert that the deployment surface
    matched a constant rather than the release being cut: after the 14 metadata
    anchors moved to a new version, every literal below still named the old one,
    so the contract reported READY while the Dockerfiles, operator, CRD, compose
    files and installer stayed behind. Deriving the expectation from
    ``_load_versions`` is what makes this a drift check.
    """
    expectations = {
        "deploy/docker/Dockerfile": (
            "ARG PYTHON_IMAGE=python:3.12-slim@sha256:7a8b475003c4fe15a2cd4e55e5cfc2f3560bdc9333d624f24cdd6d4340fd7a17",
            f'org.opencontainers.image.version="{version}"',
        ),
        "deploy/k8s/aegis-operator/operator.py": (
            f'DEFAULT_AEGIS_IMAGE = "ghcr.io/juanlunaia/aegis-latent-core:{version}"',
        ),
        "deploy/k8s/aegis-operator/crd.yaml": (
            f'default: "ghcr.io/juanlunaia/aegis-latent-core:{version}"',
        ),
        "deploy/docker/docker-compose.yml": (
            f"image: ghcr.io/juanlunaia/aegis-latent-core:{version}",
        ),
        "deploy/docker/docker-compose.enterprise.yml": (
            f"image: ghcr.io/juanlunaia/aegis-latent-core:{version}",
            f'com.aegis.version:             "{version}"',
        ),
        "deploy/docker/Dockerfile.airgap": (
            "ARG PYTHON_BASE_DIGEST=sha256:be1575ed968de893bd54f4c56315ff7c4736ce522c1bca08fd521731aafc0d76",
            f'org.opencontainers.image.version="{version}"',
            f"-t aegis-latent-core:{version}-airgap",
        ),
        "scripts/vendor_wheels.sh": (
            f'"aegis-latent-core[storage-sqlite]=={version}"',
            f"-t aegis-latent-core:{version}-airgap",
        ),
        "scripts/install_aegis.sh": (
            f'AEGIS_VERSION="{version}"',
            'AEGIS_WHEEL_SHA256_URL="${AEGIS_WHEEL_URL}.sha256"',
            'verify_sha256 "${WHEEL_PATH}" "${SIDECAR_PATH}"',
            'pip install "${WHEEL_PATH}"',
        ),
    }
    for relative_path, required_literals in expectations.items():
        path = root / relative_path
        try:
            contents = path.read_text(encoding="utf-8")
        except OSError as exc:
            diagnostics.append(
                Diagnostic(
                    "deployment.version-unreadable",
                    f"cannot read active deployment version contract: {exc}",
                    relative_path,
                )
            )
            continue
        _add_if_false(
            diagnostics,
            all(literal in contents for literal in required_literals),
            "deployment.version-drift",
            f"active deployment reference is not synchronized to v{version}",
            relative_path,
        )
        _add_if_false(
            diagnostics,
            "3.1.0" not in contents and "juanlunia" not in contents,
            "deployment.stale-reference",
            "active deployment file retains a stale release or registry owner",
            relative_path,
        )


def _validate_ci_lock_gate(root: Path, diagnostics: list[Diagnostic]) -> None:
    relative_path = ".github/workflows/ci.yml"
    workflow_path = root / relative_path
    if not workflow_path.is_file():
        diagnostics.append(Diagnostic("ci.missing", "CI workflow is missing", relative_path))
        return
    workflow = workflow_path.read_text(encoding="utf-8")
    _add_if_false(
        diagnostics,
        "cp requirements.lock requirements.lock.new" in workflow
        and "pip-compile --generate-hashes --output-file=requirements.lock.new requirements.txt"
        in workflow,
        "ci.lock-seeded",
        "lock verification must seed pip-compile from the reviewed requirements.lock",
        relative_path,
    )


def assess_repository(root: Path, *, release_tag: str | None = None) -> Assessment:
    root = root.resolve()
    diagnostics: list[Diagnostic] = []
    versions = _load_versions(root, diagnostics)
    _validate_build_backends(root, diagnostics)
    _validate_package_identity(root, diagnostics)
    _validate_active_deployment_versions(root, diagnostics, versions.get("core", ""))
    _validate_ci_lock_gate(root, diagnostics)
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
    _validate_release_tag_workflow(root, diagnostics)
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
