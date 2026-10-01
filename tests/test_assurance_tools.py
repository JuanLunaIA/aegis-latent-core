# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""The assurance status must never run ahead of its evidence.

Covers ``docs/assurance/ASSURANCE_STATUS.json`` and the escrow manifest builder:
nothing may be ``COMPLETE`` without an evidence file that exists, the sales surface
must not use an item's forbidden wording, and the deposit manifest must refuse key
material and detect an altered restore.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATUS = json.loads((ROOT / "docs/assurance/ASSURANCE_STATUS.json").read_text(encoding="utf-8"))


def _load(name: str, rel: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


em = _load("escrow_manifest_mod", "tools/assurance/escrow_manifest.py")
lint = _load("lint_sales_copy_mod", "scripts/lint_sales_copy.py")


def test_every_state_is_a_declared_state():
    assert {i["state"] for i in STATUS["items"]} <= set(STATUS["states"])


def test_nothing_is_complete_without_evidence_that_exists():
    for item in STATUS["items"]:
        if item["state"] == "COMPLETE":
            assert item["evidence"], item["id"]
            assert (ROOT / item["evidence"]).exists(), item["id"]
        else:
            assert item["evidence"] is None, item["id"]


def test_every_prepared_artifact_exists():
    for item in STATUS["items"]:
        for rel in item["prepared"]:
            assert (ROOT / rel).exists(), f"{item['id']}: {rel}"


def test_no_independent_assurance_is_claimed_today():
    """As of the status date, the three headline items are not complete."""
    states = {i["id"]: i["state"] for i in STATUS["items"]}
    for key in ("pentest", "soc2_type1", "escrow"):
        assert states[key] != "COMPLETE"


def test_sales_surface_does_not_use_forbidden_wording_unnegated():
    files = [ROOT / "README.md", *sorted((ROOT / "site").glob("*.html"))]
    for item in STATUS["items"]:
        if item["state"] == "COMPLETE":
            continue
        for path in files:
            text = path.read_text(encoding="utf-8")
            for number, sentence in lint._sentences(lint._blank_non_copy(text)):
                for phrase in item["forbidden"]:
                    if phrase.lower() in sentence.lower() and not lint.NEGATION.search(sentence):
                        pytest.fail(f"{path.name}:{number} uses {phrase!r}: {sentence[:100]}")


def test_manifest_records_the_tracked_tree_and_refuses_key_material(tmp_path: Path):
    manifest = em.build("HEAD")
    assert manifest["file_count"] == len(manifest["files"])
    assert len(str(manifest["tree_sha256"])) == 64
    paths = {f["path"] for f in manifest["files"]}
    assert "LICENSE" in paths
    assert not any(p.endswith((".pem", ".key")) for p in paths)
    assert em.DENY.search("vendor-keys/aegis_license_root.key")
    assert em.DENY.search("deploy/tls/server.pem")
    assert not em.DENY.search("docs/legal/COMMERCIAL_LICENSE_TEMPLATE.md")


def test_verify_passes_a_faithful_restore_and_flags_alteration(tmp_path: Path):
    manifest = em.build("HEAD")
    manifest["files"] = manifest["files"][:40]
    manifest_path = tmp_path / "m.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    restore = tmp_path / "restore"
    for entry in manifest["files"]:
        target = restore / str(entry["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            subprocess.run(  # noqa: S603  # nosec B603 B607 - fixed git argv, shell=False
                ["git", "show", f"HEAD:{entry['path']}"], cwd=ROOT, check=True, capture_output=True
            ).stdout
        )
    assert em.verify(manifest_path, restore) == 0
    first = restore / str(manifest["files"][0]["path"])
    first.write_bytes(first.read_bytes() + b"x")
    assert em.verify(manifest_path, restore) == 1
