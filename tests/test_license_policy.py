# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""The licence boundary must be one answer, in every place that states it.

v5.0.3 moves the gateway, the control plane and the dashboard to the Aegis
Commercial License 1.0. The client SDKs stay Apache-2.0 so a customer can
integrate them without a licence review, and everything published before
v5.0.3 keeps the terms it shipped with. A stale Apache header, a classifier
that names the old terms, or a NOTICE copied into the SDK would each tell a
downstream user something different from ``LICENSE``. These tests pin the
repository's own statements to one answer per surface.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMERCIAL = "LicenseRef-Aegis-Commercial-1.0"
APACHE = "Apache-2.0"
SDK_DIRS = ("sdk/python", "sdk/typescript")
OWN_TREES = ("aegis", "scripts", "dashboard", "connectors", "aegis_rust_v2", "tests", "deploy")
EXCLUDED_PARTS = {".venv", "__pycache__", "node_modules", "target", "dist", ".next"}
HISTORICAL = (
    "evidence/",
    "investor_packs/",
    "CHANGELOG.md",
    "docs/RELEASE_STATUS.md",
    "docs/legal/LICENSE_TRANSITION_5.0.2.md",
    "docs/legal/LICENSE_TRANSITION_5.0.3.md",
    "sdk/",
    "examples/",
)

#: Documents whose Apache-2.0 mentions are the boundary itself (what 5.0.2 was,
#: what the SDKs remain) or a third-party dependency's licence.  They are not a
#: claim about the current product licence; every other surface must be clean.
BOUNDARY_OR_THIRD_PARTY = {
    "CLA.md",
    "COMMERCIAL.md",
    "README.md",
    "LICENSE-THIRD-PARTY.md",
    "docs/REGISTRY.md",
    "docs/CLAIMS_MATRIX.md",
    "docs/PROSPECTUS.md",
    "docs/PROSPECTUS_ES.md",
    "docs/compliance/LICENSE_AUDIT.md",
    "docs/legal/COUNSEL_QUESTIONS.md",
    "docs/security/DEPENDENCY_RISK_REGISTER.md",
    "docs/security/DEPENDENCY_TRIAGE.md",
    "docs/DOCUMENTATION_INDEX.md",
    ".aegis_ai_context/02_OPERATIONAL_INVARIANTS_MATRIX.md",
    ".aegis_ai_context/04_FORMAL_SPECIFICATIONS_MAPPING.md",
    ".aegis_ai_context/05_DETERMINISTIC_RECIPES_PLAYBOOK.md",
    ".aegis_ai_context/08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md",
}


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_licence_is_the_commercial_text_and_matches_its_pin() -> None:
    text = read("LICENSE")
    assert "AEGIS COMMERCIAL LICENSE 1.0" in text
    assert COMMERCIAL in text
    assert "Licensed under the Apache License" not in text
    pinned = read("docs/legal/LICENSE.sha256").strip()
    assert hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest() == pinned


def test_notice_states_the_boundary_and_the_sdk_exception() -> None:
    notice = read("NOTICE")
    assert "Aegis Commercial License 1.0" in notice
    assert "v5.0.2 under Apache-2.0" in notice
    assert "sdk/python" in notice
    assert "sdk/typescript" in notice


def test_sdk_packages_stay_apache_and_ship_their_own_notice() -> None:
    for package in SDK_DIRS:
        licence = (ROOT / package / "LICENSE").read_text(encoding="utf-8")
        notice = (ROOT / package / "NOTICE").read_text(encoding="utf-8")
        assert "Apache License" in licence
        assert "Version 2.0" in licence
        assert "Apache License, Version 2.0" in notice
        assert COMMERCIAL not in licence


def test_python_manifests_declare_the_right_licence() -> None:
    root = tomllib.loads(read("pyproject.toml"))
    assert root["project"]["license"] == COMMERCIAL
    sdk = tomllib.loads(read("sdk/python/pyproject.toml"))
    assert sdk["project"]["license"] == APACHE
    npm = json.loads(read("sdk/typescript/package.json"))
    assert npm["license"] == APACHE


def test_header_tool_reports_the_tree_current() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/apply_license_headers.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_no_commercial_tree_source_carries_an_apache_header() -> None:
    offenders: list[str] = []
    for tree in OWN_TREES:
        for path in (ROOT / tree).rglob("*"):
            if path.suffix not in {".py", ".rs", ".sh", ".toml", ".ts", ".tsx", ".js", ".mjs"}:
                continue
            if any(part in EXCLUDED_PARTS for part in path.parts):
                continue
            if path.name in {
                "apply_license_headers.py",
                "test_license_headers.py",
                "test_license_policy.py",
            }:
                # These files define or assert both profiles; their own headers
                # are commercial, but the Apache literal is test data.
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if f"SPDX-License-Identifier: {APACHE}" in text:
                offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == [], f"Apache-2.0 headers in the commercial tree: {offenders[:10]}"


def test_representative_sources_carry_the_commercial_header() -> None:
    for rel in (
        "aegis/__init__.py",
        "aegis/core/mmr.py",
        "aegis_rust_v2/src/lib.rs",
        "deploy/docker/Dockerfile",
        "scripts/license/license_scan.py",
        "scripts/apply_license_headers.py",
    ):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert COMMERCIAL in text, rel


def test_documentation_outside_history_does_not_call_the_product_apache() -> None:
    """Published history may name Apache-2.0; current surfaces may not."""
    pattern = re.compile(r"Apache-2\.0|Apache License")
    offenders: list[str] = []
    for path in ROOT.rglob("*.md"):
        rel = path.relative_to(ROOT).as_posix()
        if any(rel.startswith(prefix) or rel == prefix.rstrip("/") for prefix in HISTORICAL):
            continue
        if rel in BOUNDARY_OR_THIRD_PARTY:
            continue
        if any(part in EXCLUDED_PARTS for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if pattern.search(text):
            offenders.append(rel)
    assert offenders == [], f"Apache-2.0 named on current surfaces: {offenders[:15]}"
