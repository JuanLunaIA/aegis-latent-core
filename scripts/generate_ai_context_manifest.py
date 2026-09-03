#!/usr/bin/env python3
"""Generate the deterministic manifest for the advisory AI context pack."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SOURCE_BASELINE_COMMIT = "fdace8844568eb788216740b2cb5daf187d99d3b"
# Backward-compatible name used by the manifest verifier; not an active-release link.
SOURCE_ANCHOR = SOURCE_BASELINE_COMMIT
SOURCE_BASELINE_VERSION = "4.0.0"
PUBLISHED_GITHUB_RELEASE = "v4.0.1"
PUBLISHED_GITHUB_RELEASE_TARGET = "6469904380218584ae0b5221334bc9a46500f5ba"
SOURCE_RELEASE_TARGET_VERSION = "4.1.2"
SYNCHRONIZED_VERSION_ANCHORS = 14
MANIFEST_PATH = ".aegis_ai_context/MANIFEST.json"
CONTEXT_FILES = (
    ".aegis_ai_context/README.md",
    ".aegis_ai_context/00_CORE_ONTOLOGY_AND_BOUNDARIES.xml",
    ".aegis_ai_context/01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv",
    ".aegis_ai_context/02_OPERATIONAL_INVARIANTS_MATRIX.md",
    ".aegis_ai_context/03_STATE_MACHINES_AND_DAGS.mermaid",
    ".aegis_ai_context/04_FORMAL_SPECIFICATIONS_MAPPING.md",
    ".aegis_ai_context/05_DETERMINISTIC_RECIPES_PLAYBOOK.md",
    ".aegis_ai_context/06_SECURITY_AND_SUPPLY_CHAIN_MANIFEST.xml",
    ".aegis_ai_context/07_SYSTEM_COMPACT_KERNEL.xml",
    ".aegis_ai_context/08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md",
    ".aegis_ai_context/09_COMMAND_AND_CI_MATRIX.md",
    ".aegis_ai_context/10_TOOL_ADAPTER_COMPATIBILITY.md",
)
GOVERNED_INPUTS = (
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".github/copilot-instructions.md",
    "README.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "DEPLOYMENT_GUIDE.md",
    "CONTRIBUTING.md",
    "Makefile",
    "docs/CLAIMS_MATRIX.md",
    "docs/DEVELOPER_INTEGRATIONS_GUIDE.md",
    "docs/DEVELOPER_QUICKSTART.md",
    "docs/DEVELOPER_SDK_GUIDE.md",
    "docs/FAQ_SECURITY.md",
    "docs/FAQ_TECHNICAL.md",
    "docs/PLATFORM_OPERATOR_GUIDE.md",
    "docs/REPOSITORY_MAP.md",
    "evidence/INDEX.md",
    "pyproject.toml",
    "requirements.txt",
    "requirements.lock",
    "aegis/__init__.py",
    "sdk/python/pyproject.toml",
    "sdk/python/src/aegis_sdk/__init__.py",
    "sdk/typescript/package.json",
    "sdk/typescript/package-lock.json",
    "dashboard/package.json",
    "dashboard/package-lock.json",
    "aegis_rust_v2/Cargo.toml",
    "aegis_rust_v2/pyproject.toml",
    "aegis_rust_v2/Cargo.lock",
    "aegis_rust_v2/src/lib.rs",
    "deploy/helm/Chart.yaml",
    "deploy/helm/values.yaml",
    "deploy/docker/Dockerfile",
    "deploy/docker/Dockerfile.airgap",
    "deploy/docker/docker-compose.yml",
    "deploy/docker/docker-compose.enterprise.yml",
    "deploy/k8s/aegis-operator/crd.yaml",
    "deploy/k8s/aegis-operator/operator.py",
    ".github/workflows/ci.yml",
    ".github/workflows/create_release_tag.yml",
    ".github/workflows/forensic.yml",
    ".github/workflows/pqc-timing.yml",
    ".github/workflows/publish.yml",
    ".github/workflows/publish_npm.yml",
    ".github/workflows/publish_oci.yml",
    ".github/workflows/publish_pypi.yml",
    ".github/workflows/release.yml",
    ".github/workflows/security.yml",
    "aegis/providers/__init__.py",
    "aegis/providers/base.py",
    "aegis/providers/openai_provider.py",
    "aegis/providers/anthropic_provider.py",
    "aegis/providers/gemini_provider.py",
    "sdk/python/src/aegis_sdk/openai.py",
    "sdk/python/src/aegis_sdk/anthropic.py",
    "sdk/typescript/src/index.ts",
    "sdk/typescript/src/openai.ts",
    "sdk/typescript/src/anthropic.ts",
    "scripts/create_github_release.py",
    "scripts/extract_release_notes.py",
    "scripts/install_gitsign.sh",
    "scripts/prepare_release_assets.py",
    "scripts/verify_release_contract.py",
    "scripts/verify_release_tag.sh",
    "scripts/vendor_wheels.sh",
    "scripts/generate_ai_context_manifest.py",
    "scripts/verify_ai_context_manifest.py",
    "tests/test_ai_context.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_manifest(root: Path) -> dict[str, Any]:
    """Return a stable manifest of explicit working-tree bytes."""
    root = root.resolve()
    entries = []
    for category, paths in (
        ("context", CONTEXT_FILES),
        ("governed_input", GOVERNED_INPUTS),
    ):
        for relative_path in paths:
            path = root / relative_path
            if not path.is_file():
                raise FileNotFoundError(relative_path)
            entries.append(
                {
                    "category": category,
                    "path": relative_path,
                    "sha256": _sha256(path),
                    "size": path.stat().st_size,
                }
            )
    return {
        "schema_version": 3,
        "source_baseline": {
            "commit": SOURCE_BASELINE_COMMIT,
            "kind": "immutable_git_commit",
            "synchronized_version_anchors": SYNCHRONIZED_VERSION_ANCHORS,
            "version": SOURCE_BASELINE_VERSION,
        },
        "published_github_release": {
            "release": PUBLISHED_GITHUB_RELEASE,
            "state": "published",
            "tag_kind": "lightweight",
            "target_commit": PUBLISHED_GITHUB_RELEASE_TARGET,
        },
        "registry_observation": {
            "observed_version": SOURCE_BASELINE_VERSION,
            "packages": [
                {"name": "aegis-latent-sdk", "registry": "pypi"},
                {"name": "aegis-latent-sdk", "registry": "npm"},
            ],
            "provenance": "not_attributed_to_workflow_runs",
        },
        "source_release_target": {
            "kind": "checked_out_source",
            "state": "external_lifecycle_requires_readback",
            "synchronized_version_anchors": SYNCHRONIZED_VERSION_ANCHORS,
            "version": SOURCE_RELEASE_TARGET_VERSION,
            "meaning": "Hashes describe source file bytes at generation time. Source metadata does not establish the external tag, GitHub Release, registry, OCI, signature, or attestation state; read back each surface independently.",
        },
        "hash_algorithm": "sha256",
        "manifest_self_hash": "excluded_to_avoid_circularity",
        "files": entries,
    }


def serialize(manifest: dict[str, Any]) -> str:
    """Serialize with stable ordering, indentation, Unicode, and final newline."""
    return json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    output = arguments.root / MANIFEST_PATH
    rendered = serialize(build_manifest(arguments.root))
    if arguments.check:
        if not output.is_file() or output.read_text(encoding="utf-8") != rendered:
            print(f"AI context manifest is stale: {output}")
            return 1
        print(f"AI context manifest is current: {output}")
        return 0
    output.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
