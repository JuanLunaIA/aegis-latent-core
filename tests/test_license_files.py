# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""The Apache-2.0 relicence must stay consistent across every surface that states it.

From 5.0.2 the source is licensed under the Apache License, Version 2.0. A licence
is only as good as the weakest place that contradicts it: a stale AGPL classifier
on a wheel, a package that ships without the licence text Apache-2.0 section 4(a)
requires, or an image label that still names the old terms would each tell a
downstream user something different from ``LICENSE``. These tests pin the
repository's own statements to one answer. They say nothing about what has been
published; releases up to and including 5.0.1 keep the terms they shipped under.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: SHA-256 of the verbatim Apache License 2.0 text published at
#: https://www.apache.org/licenses/LICENSE-2.0.txt. A reworded or truncated
#: licence changes this digest, so the text cannot drift unnoticed.
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

#: Directories whose packages are distributed on their own and so must carry the
#: licence text themselves (Apache-2.0 section 4(a)).
PACKAGE_DIRS = ("sdk/python", "sdk/typescript")

DOCKERFILES = (
    "deploy/docker/Dockerfile",
    "deploy/docker/Dockerfile.airgap",
    "dashboard/Dockerfile",
)

PYTHON_MANIFESTS = ("pyproject.toml", "sdk/python/pyproject.toml")

HEADER_LINES = (
    "Copyright (c) 2026 Juan Luna.",
    "SPDX-License-Identifier: Apache-2.0",
    "Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.",
)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_the_licence_is_the_verbatim_apache_2_0_text() -> None:
    digest = hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
    assert digest == APACHE_2_0_SHA256
    text = _read("LICENSE")
    assert "Apache License" in text
    assert "Version 2.0, January 2004" in text
    assert "GNU AFFERO" not in text.upper()


def test_notice_names_the_licence_and_reserves_the_marks() -> None:
    notice = _read("NOTICE")
    assert "Apache License, Version 2.0" in notice
    assert "Juan Luna" in notice
    assert "Section 6" in notice
    assert "AGPL" not in notice.upper().replace("AGPL-", "AGPL ")


@pytest.mark.parametrize("package_dir", PACKAGE_DIRS)
def test_standalone_packages_carry_identical_licence_and_notice(package_dir: str) -> None:
    """Apache-2.0 4(a) and 4(d): each distribution ships the License and the NOTICE."""

    for name in ("LICENSE", "NOTICE"):
        assert (ROOT / package_dir / name).read_bytes() == (ROOT / name).read_bytes(), (
            f"{package_dir}/{name} must be byte-identical to the repository {name}"
        )


@pytest.mark.parametrize("manifest", PYTHON_MANIFESTS)
def test_python_distributions_declare_apache_2_0_with_license_files(manifest: str) -> None:
    project = tomllib.loads(_read(manifest))["project"]
    assert project["license"] == "Apache-2.0"
    assert set(project["license-files"]) >= {"LICENSE", "NOTICE"}
    classifiers = project.get("classifiers", [])
    # PEP 639: a licence expression and a `License ::` classifier must not coexist.
    assert not [c for c in classifiers if c.startswith("License ::")]


def test_the_rust_extension_declares_apache_2_0() -> None:
    project = tomllib.loads(_read("aegis_rust_v2/pyproject.toml"))["project"]
    assert project["license"] == {"text": "Apache-2.0"}


@pytest.mark.parametrize(
    "manifest", ["aegis_rust_v2/Cargo.toml", "connectors/envoy-wasm/Cargo.toml"]
)
def test_cargo_crates_declare_apache_2_0(manifest: str) -> None:
    assert tomllib.loads(_read(manifest))["package"]["license"] == "Apache-2.0"


def test_the_typescript_sdk_declares_apache_2_0_and_ships_the_licence() -> None:
    package = json.loads(_read("sdk/typescript/package.json"))
    assert package["license"] == "Apache-2.0"
    assert {"LICENSE", "NOTICE"} <= set(package["files"])


@pytest.mark.parametrize("dockerfile", DOCKERFILES)
def test_every_image_carries_the_licence_texts(dockerfile: str) -> None:
    text = _read(dockerfile)
    assert re.search(r"^COPY LICENSE NOTICE /licenses/$", text, flags=re.MULTILINE), dockerfile
    for label in re.findall(r'org\.opencontainers\.image\.licenses="([^"]*)"', text):
        assert label == "Apache-2.0", f"{dockerfile}: OCI licence label is {label!r}"


@pytest.mark.parametrize("dockerfile", DOCKERFILES[:2])
def test_the_gateway_images_label_their_licence(dockerfile: str) -> None:
    assert 'org.opencontainers.image.licenses="Apache-2.0"' in _read(dockerfile)


def test_no_manifest_names_the_retired_licence_terms() -> None:
    """No package metadata may still advertise the AGPL-or-commercial licence."""

    retired = ("AGPL-3.0", "LicenseRef-Proprietary", "GNU Affero")
    manifests = (
        *PYTHON_MANIFESTS,
        "aegis_rust_v2/pyproject.toml",
        "aegis_rust_v2/Cargo.toml",
        "connectors/envoy-wasm/Cargo.toml",
        "sdk/typescript/package.json",
        "sdk/typescript/package-lock.json",
        "dashboard/package-lock.json",
    )
    for rel in manifests:
        text = _read(rel)
        for token in retired:
            assert token not in text, f"{rel} still contains {token!r}"


def test_the_header_tool_reports_the_tree_current() -> None:
    """``apply_license_headers.py`` is idempotent: a migrated tree has nothing left to change."""

    from scripts import apply_license_headers as tool

    stale: list[str] = []
    for path in tool._candidate_files():
        rel = path.relative_to(ROOT).as_posix()
        if rel.split("/", 1)[0] in tool.HISTORICAL_ROOTS or path.name in tool.SKIP_NAMES:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if tool.LEGACY_LICENSE_MARKER in text.split("\n\n", 1)[0]:
            stale.append(rel)
    assert not stale, f"files still carry the legacy header: {stale[:10]}"


@pytest.mark.parametrize(
    "rel",
    [
        "aegis/__init__.py",
        "aegis/core/mmr.py",
        "aegis_server/main.py",
        "aegis_rust_v2/src/lib.rs",
        "deploy/docker/Dockerfile",
        "scripts/license/license_scan.py",
    ],
)
def test_representative_sources_carry_the_three_line_header(rel: str) -> None:
    # Files that open with a module docstring carry the block directly after it.
    head = "\n".join(_read(rel).splitlines()[:40])
    for line in HEADER_LINES:
        assert line in head, f"{rel}: header is missing {line!r}"
    # The retired block named the AGPLv3 grant and a proprietary licence outright.
    assert "Licensed under the GNU Affero" not in head
    assert "Proprietary Commercial License. See LICENSE" not in head
    assert "All rights reserved" not in head
