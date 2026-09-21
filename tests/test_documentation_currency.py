# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Documentation currency gates (AUD-19 / REG-D23).

Two classes of drift, both measured in this repository before the gates existed:

* navigation coverage — `docs/INDEX.md` declared "**Scope:** every maintained
  document" while 35 of the 109 tracked `docs/**/*.md` files were linked from
  nowhere in it, including the defect registry and its companions;
* baseline currency — the navigation and context artifacts answered "which
  baseline is checked out?" with `4.1.2` (source target), `v4.0.1` (published
  release) and `4.0.2`, contradicting `AGENTS.md`, while the release contract
  agreed with neither.

The version these tests compare against is read from `pyproject.toml` — the core
anchor of the fourteen the release contract checks — so a baseline bump fails
here until every navigation artifact says the same thing, and a stale artifact
cannot pass by agreeing with another stale artifact.

Boundaries, stated rather than implied: this pins *agreement on the baseline and
on coverage*, not the truth of any individual sentence. Historical statements
("parent `fdace884…` retains fourteen `4.0.0` anchors", "prior observation at
`4.0.0`") are expected to remain and are not compared.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _text(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def _anchor_version() -> str:
    """The checked-out source baseline, from the core anchor."""
    match = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', _text("pyproject.toml"), re.M)
    assert match, "pyproject.toml carries no version anchor"
    return match.group(1)


def _baseline_claims() -> dict[str, str | None]:
    """Baseline version asserted by each navigation artifact (None if absent)."""
    version = re.escape(_anchor_version())
    patterns = {
        "AGENTS.md": r"source baseline is \*\*(" + version + r")\*\*",
        "llms.txt": r"source baseline/release target: \*\*(" + version + r")\*\*",
        ".aegis_ai_context/01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv": r"SourceReleaseTarget\t[^\n]*?v("
        + version
        + r")\b",
        "docs/REPOSITORY_MAP.md": r"Source baseline:\*\*[^\n]*?at `v(" + version + r")`",
        "scripts/generate_ai_context_manifest.py": r'SOURCE_RELEASE_TARGET_VERSION\s*=\s*"('
        + version
        + r')"',
    }
    found: dict[str, str | None] = {}
    for name, pattern in patterns.items():
        match = re.search(pattern, _text(name))
        found[name] = match.group(1) if match else None
    return found


def test_every_navigation_artifact_agrees_on_the_baseline() -> None:
    claims = _baseline_claims()
    disagreeing = {name: claim for name, claim in claims.items() if claim is None}
    assert not disagreeing, (
        "navigation artifacts that do not name the checked-out baseline "
        f"({_anchor_version()}): {sorted(disagreeing)} — refresh them, or fix the "
        "pattern here if the sentence was reworded"
    )


def test_the_baseline_claims_are_not_vacuous() -> None:
    """Guard the gate: the anchor and at least four artifacts must be readable."""
    claims = _baseline_claims()
    assert len(claims) >= 5
    assert _anchor_version().count(".") == 2


@pytest.mark.parametrize(
    "relative",
    [
        "AGENTS.md",
        "llms.txt",
        ".aegis_ai_context/01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv",
        ".aegis_ai_context/00_CORE_ONTOLOGY_AND_BOUNDARIES.xml",
        ".aegis_ai_context/03_STATE_MACHINES_AND_DAGS.mermaid",
        ".aegis_ai_context/05_DETERMINISTIC_RECIPES_PLAYBOOK.md",
        ".aegis_ai_context/06_SECURITY_AND_SUPPLY_CHAIN_MANIFEST.xml",
        ".aegis_ai_context/07_SYSTEM_COMPACT_KERNEL.xml",
        ".aegis_ai_context/08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md",
        "docs/REPOSITORY_MAP.md",
        "docs/README.md",
        "scripts/generate_ai_context_manifest.py",
        # .aegis_ai_context/MANIFEST.json is generated from SOURCE_RELEASE_TARGET_VERSION /
        # PUBLISHED_GITHUB_RELEASE, which the first test already pins, so it is exempt here.
    ],
)
def test_no_artifact_still_names_the_previous_baseline_as_current(relative: str) -> None:
    """`4.1.2` may appear only where the sentence frames it as published/historical."""
    text = _text(relative)
    stale = [
        line
        for line in text.splitlines()
        if re.search(r"\b4\.1\.2\b", line)
        and not re.search(
            r"latest|published|prior|historical|most recent|readback|read back|found|as of|"
            r"4\.0\.0|gateway distribution|re-checked|not the checked-out baseline",
            line,
            re.I,
        )
    ]
    assert not stale, (
        f"{relative} names 4.1.2 without framing it as published/historical: {stale[:2]}"
    )


def test_every_tracked_document_is_reachable_from_the_index() -> None:
    index_text = _text("docs/INDEX.md")
    targets: set[str] = set()
    for match in re.finditer(r"\[[^\]]*\]\(([^)#]+)", index_text):
        href = match.group(1).strip()
        if href.startswith(("http://", "https://", "mailto:")):
            continue
        try:
            resolved = (REPO_ROOT / "docs" / href).resolve().relative_to(REPO_ROOT)
        except ValueError:
            continue
        targets.add(str(resolved))

    documents = sorted(
        path for path in subprocess_listing() if path.startswith("docs/") and path.endswith(".md")
    )
    # The index cannot link itself; everything else must be reachable.
    unlinked = [path for path in documents if path not in targets and path != "docs/INDEX.md"]
    assert not unlinked, (
        f"{len(unlinked)} tracked document(s) are linked from nowhere in docs/INDEX.md: "
        f"{unlinked[:10]}{' …' if len(unlinked) > 10 else ''} — add them to the index or "
        "narrow its scope statement"
    )


def subprocess_listing() -> list[str]:
    import subprocess

    out = subprocess.run(
        ["git", "ls-files", "docs/"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return out.stdout.split()
