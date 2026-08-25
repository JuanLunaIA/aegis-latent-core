"""Source-derived freshness checks for the advisory AI context pack."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / ".aegis_ai_context"
SOURCE_ANCHOR = "2050a310ec295afc61d033ff842c9a535a4f3105"
EXISTING_CONTEXT = tuple(
    CONTEXT / f"{number:02d}_{name}"
    for number, name in (
        (0, "CORE_ONTOLOGY_AND_BOUNDARIES.xml"),
        (1, "CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv"),
        (2, "OPERATIONAL_INVARIANTS_MATRIX.md"),
        (3, "STATE_MACHINES_AND_DAGS.mermaid"),
        (4, "FORMAL_SPECIFICATIONS_MAPPING.md"),
        (5, "DETERMINISTIC_RECIPES_PLAYBOOK.md"),
        (6, "SECURITY_AND_SUPPLY_CHAIN_MANIFEST.xml"),
        (7, "SYSTEM_COMPACT_KERNEL.xml"),
    )
)
CONTEXT_FILES = (
    CONTEXT / "README.md",
    *EXISTING_CONTEXT,
    CONTEXT / "08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md",
    CONTEXT / "09_COMMAND_AND_CI_MATRIX.md",
    CONTEXT / "10_TOOL_ADAPTER_COMPATIBILITY.md",
)
XML_FILES = (EXISTING_CONTEXT[0], EXISTING_CONTEXT[6], EXISTING_CONTEXT[7])
MARKDOWN_FILES = (
    CONTEXT / "README.md",
    EXISTING_CONTEXT[2],
    EXISTING_CONTEXT[4],
    EXISTING_CONTEXT[5],
    CONTEXT / "08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md",
    CONTEXT / "09_COMMAND_AND_CI_MATRIX.md",
    CONTEXT / "10_TOOL_ADAPTER_COMPATIBILITY.md",
)
TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)
MARKDOWN_LINK_RE = re.compile(r"\[[^]]+\]\(([^)]+)\)")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _corpus(paths: tuple[Path, ...] = CONTEXT_FILES) -> str:
    return "\n".join(_text(path) for path in paths).lower()


def _load_module(name: str, relative_path: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _json(path: str) -> dict[str, Any]:
    value = json.loads(_text(ROOT / path))
    assert isinstance(value, dict)
    return value


def _toml(path: str) -> dict[str, Any]:
    return tomllib.loads(_text(ROOT / path))


def test_context_inventory_is_complete_and_nonempty() -> None:
    expected = {
        "README.md",
        *(p.name for p in EXISTING_CONTEXT),
        "08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md",
        "09_COMMAND_AND_CI_MATRIX.md",
        "10_TOOL_ADAPTER_COMPATIBILITY.md",
        "MANIFEST.json",
    }
    assert {p.name for p in CONTEXT.iterdir() if p.is_file()} == expected
    assert all(p.stat().st_size for p in CONTEXT.iterdir())


def test_xml_and_markdown_are_structurally_valid() -> None:
    for path in XML_FILES:
        document = _text(path)
        assert len(document.encode()) <= 128 * 1024
        assert "<!DOCTYPE" not in document.upper()
        assert "<!ENTITY" not in document.upper()
        assert ET.fromstring(document).attrib.get("role") == "advisory"  # noqa: S314
    for source in MARKDOWN_FILES:
        for target in MARKDOWN_LINK_RE.findall(_text(source)):
            target = target.split("#", 1)[0]
            if target and "://" not in target:
                resolved = (source.parent / target).resolve()
                assert resolved.exists(), f"{source.relative_to(ROOT)} -> {target}"
                assert resolved.is_relative_to(ROOT.resolve())


def test_all_eight_refreshed_files_state_the_two_baselines() -> None:
    for path in EXISTING_CONTEXT:
        text = _text(path).lower()
        assert "v3.1.0" in text, path.name
        assert SOURCE_ANCHOR in text, path.name
        assert "published" in text, path.name
        assert "unpublished" in text or "no v4" in text, path.name
        assert "current-main" not in text, path.name
    for boundary in ("no v4 tag", "github release", "registry publication", "mutable working tree"):
        assert boundary in _corpus()


def test_release_contract_derives_fourteen_synchronized_anchors() -> None:
    contract = _load_module("release_contract_context_test", "scripts/verify_release_contract.py")
    assessment = contract.assess_repository(ROOT)
    assert assessment.ready, assessment.diagnostics
    assert len(assessment.versions) == 14
    assert set(assessment.versions.values()) == {_toml("pyproject.toml")["project"]["version"]}
    matrix = _text(CONTEXT / "08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md")
    for label, version in assessment.versions.items():
        assert f"`{label}`" in matrix
        assert version in matrix


def test_package_identities_are_source_derived_and_mapped() -> None:
    identities = {
        _toml("pyproject.toml")["project"]["name"],
        _toml("sdk/python/pyproject.toml")["project"]["name"],
        _json("sdk/typescript/package.json")["name"],
        _json("dashboard/package.json")["name"],
        _toml("aegis_rust_v2/Cargo.toml")["package"]["name"],
        _toml("aegis_rust_v2/pyproject.toml")["project"]["name"],
    }
    matrix = _text(CONTEXT / "08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md")
    assert all(identity in matrix for identity in identities)
    dashboard = _json("dashboard/package.json")
    sdk_name = _json("sdk/typescript/package.json")["name"]
    assert dashboard["private"] is True
    assert dashboard["dependencies"][sdk_name] == "file:../sdk/typescript"
    assert "private application package" in matrix.lower()
    assert "file:../sdk/typescript" in matrix


def test_provider_registry_and_sdk_adapter_links_match_source() -> None:
    tree = ast.parse(_text(ROOT / "aegis/providers/__init__.py"))
    registry: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "_PROVIDER_REGISTRY"
        ):
            assert isinstance(node.value, ast.Dict)
            for key, value in zip(node.value.keys, node.value.values, strict=True):
                assert isinstance(key, ast.Constant)
                assert isinstance(key.value, str)
                assert isinstance(value, ast.Name)
                registry[key.value] = value.id
    matrix = _text(CONTEXT / "08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md")
    assert registry
    assert all(f"`{provider} → {adapter}`" in matrix for provider, adapter in registry.items())
    for path in (
        "sdk/python/src/aegis_sdk/openai.py",
        "sdk/python/src/aegis_sdk/anthropic.py",
        "sdk/typescript/src/openai.ts",
        "sdk/typescript/src/anthropic.ts",
        "sdk/typescript/src/index.ts",
    ):
        assert path in matrix
        assert (ROOT / path).is_file()


def test_workflow_roles_and_no_publish_boundaries_match_source() -> None:
    workflows = {p.name: _text(p) for p in (ROOT / ".github/workflows").glob("*.yml")}
    matrix = _text(CONTEXT / "08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md")
    assert set(workflows) == {
        "ci.yml",
        "forensic.yml",
        "pqc-timing.yml",
        "publish.yml",
        "publish_npm.yml",
        "publish_oci.yml",
        "publish_pypi.yml",
        "release.yml",
        "security.yml",
    }
    assert all(f"[`{name}`]" in matrix for name in workflows)
    assert "twine upload" not in workflows["publish.yml"]
    assert "id-token: write" not in workflows["publish.yml"]
    oci = workflows["publish_oci.yml"]
    assert "push: false" in oci
    assert all(
        token not in oci for token in ("docker/login-action@", "push: true", "packages: write")
    )
    for name in ("publish_pypi.yml", "publish_npm.yml"):
        workflow = workflows[name]
        assert "vars.AEGIS_TRUSTED_PUBLISHING_ENABLED == 'true'" in workflow
        assert "id-token: write" in workflow
        assert "git verify-tag" in workflow
    assert "scripts/create_github_release.py" in workflows["release.yml"]
    assert "gh release edit" not in workflows["release.yml"]
    assert "build-validation-only" in matrix
    assert "source presence does not prove" in matrix


def test_manifest_is_deterministic_explicit_and_non_circular() -> None:
    generator = _load_module(
        "context_manifest_generator_test", "scripts/generate_ai_context_manifest.py"
    )
    manifest_path = ROOT / generator.MANIFEST_PATH
    actual = json.loads(_text(manifest_path))
    expected = generator.build_manifest(ROOT)
    assert actual == expected
    assert _text(manifest_path) == generator.serialize(expected)
    assert actual["source_baseline"]["commit"] == SOURCE_ANCHOR
    assert actual["source_baseline"]["kind"] == "immutable_git_commit"
    assert actual["working_tree"]["kind"] == "mutable_checkout"
    paths = [entry["path"] for entry in actual["files"]]
    assert paths == [*generator.CONTEXT_FILES, *generator.GOVERNED_INPUTS]
    assert len(paths) == len(set(paths))
    assert generator.MANIFEST_PATH not in paths
    assert actual["manifest_self_hash"] == "excluded_to_avoid_circularity"


def test_router_commands_stop_conditions_and_release_language() -> None:
    router = _text(CONTEXT / "README.md")
    commands = _text(CONTEXT / "09_COMMAND_AND_CI_MATRIX.md")
    assert all(path.name in router for path in CONTEXT_FILES[1:])
    command_corpus = (router + commands).lower()
    for command in (
        "python scripts/generate_ai_context_manifest.py",
        "python scripts/verify_ai_context_manifest.py",
        "pytest -q tests/test_ai_context.py",
        "python scripts/verify_release_contract.py --root .",
    ):
        assert command in command_corpus
    assert "stop condition" in router.lower()
    assert "stop" in commands.lower()
    corpus = _corpus()
    for forbidden in (
        "current-main",
        "v4.0.0 is released",
        "v4 is released",
        "v4.0.0 published",
        "zero-knowledge mmr",
        "is production-ready",
        "is fully compliant",
        "todo",
        "chain-of-thought",
        "hidden model instruction",
    ):
        assert forbidden not in corpus
    for phrase in (
        "merged unpublished v4 source",
        "no v4 tag",
        "no v4 tag, github release",
        "source readiness",
        "not publication evidence",
    ):
        assert phrase in corpus


def test_tool_adapters_are_thin_and_route_to_canonical_guidance() -> None:
    agents = _text(ROOT / "AGENTS.md")
    claude = _text(ROOT / "CLAUDE.md").strip()
    gemini = _text(ROOT / "GEMINI.md").strip()
    copilot = _text(ROOT / ".github/copilot-instructions.md")
    assert ".aegis_ai_context/README.md" in agents
    assert "hidden" in agents.lower()
    assert claude == "@AGENTS.md"
    assert gemini == "@./AGENTS.md"
    assert "AGENTS.md" in copilot
    assert "v3.1.0" in copilot
    assert SOURCE_ANCHOR in copilot
    assert len(claude.splitlines()) == 1
    assert len(gemini.splitlines()) == 1
    assert len(copilot.splitlines()) <= 20
    assert not (ROOT / ".cursorrules").exists()


def test_compact_kernel_remains_under_declared_budget() -> None:
    kernel = _text(EXISTING_CONTEXT[7])
    assert len(TOKEN_RE.findall(kernel)) < 5000
    assert ET.fromstring(kernel).attrib["token-budget"] == "under-5000"  # noqa: S314
