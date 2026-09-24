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

The repository-wide scan below carries a *superseded-token set* — currently
`4.1.2` and `5.0.0` — and the set must be extended at each baseline bump: after
the `5.0.1` bump, `5.0.0` became the version no document may present as the
checked-out baseline (REG-D56).

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
        "docs/CLAIMS_MATRIX.md": r"Source baseline:\*\*[^\n]*?synchronized at `v("
        + version
        + r")`",
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


# The class REG-D23 was re-opened for: a survey of every tracked document found it
# alive at ~30 sites outside the navigation artifacts the first pass fixed, and it
# recurred at the next bump (REG-D56): the token set was pinned to `4.1.2`, so
# `5.0.0` sailed through as the "checked-out baseline" in 50 sentences. The rule
# that generalises is *framing*: a superseded version — `4.1.2` (the release PyPI
# still serves for the gateway distribution) or `5.0.0` (previous source target,
# most recent published release) — may appear as a published, read-back, or
# historical fact; it may not appear as the checked-out / source / current
# baseline, because that is `5.0.1`.
_FRAMED_WITH = re.compile(
    r"published|read ?back|most recent|latest|historical|prior|remains|still|"
    r"gateway distribution|PyPI|npm|registr(?:y|ies)|4\.0\.|version (?:list|history)|"
    # Each of the following names a way the line makes its own meaning explicit:
    # install behaviour that is true today, an upgrade span, a defect being
    # reported, a re-verification, or a dated measurement row.
    r"gets|install|serves|served|between|upgrad|migrat|stale|no longer describes|"
    r"re-checked|not the checked-out baseline|20\d\d-\d\d-\d\d",
    re.I,
)
_UNFRAMED_AS = re.compile(r"\bv?(?:4\.1\.2|5\.0\.0)\b", re.I)
_PRESENTS_AS_BASELINE = re.compile(r"source|checked-out|current|baseline", re.I)

# The warning-string family found by the same re-verification: user-facing
# "not wired in <version>" text must name the checked-out release, not a
# superseded one (REG-D56).
_STALE_WIRING = re.compile(
    r"(?:not wired in|not read by any code path in)\s+`?v?(?:4\.1\.2|5\.0\.0)\b", re.I
)

CURRENCY_SCAN_EXEMPT = {
    "docs/REGISTRY.md",  # the register itself, dated by its own rows
    "docs/ROADMAP.md",  # ticket text quotes the audit's findings verbatim
    "docs/CLAIMS_MATRIX.md",  # row text quotes the register's forbidden phrasing
    "docs/RELEASE_STATUS.md",  # the document that owns publication history
    "docs/commercial/CLAIM_LEDGER.md",  # its whole subject is cataloguing stale claim
    # surfaces; every one of its rows quotes the
    # stale text it reports as corrected
    "AUDIT_REPORT_v5.0.1_PREP.md",
    "IMPLEMENTATION_LOG_5.0.1.md",  # dated release-process record; quotes the
    # pre-bump state it describes
    "STATE_MANIFEST.md",  # dated measurement snapshot; every value is bound to
    # its commit and time
    "docs/commercial/ARTIFACT_INVENTORY.md",  # self-declared pre-change snapshot;
    # its markers read in the past tense
}


def _tracked_documents() -> list[str]:
    import subprocess

    out = subprocess.run(
        ["git", "ls-files", "*.md"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return [
        line
        for line in out.stdout.split()
        if not line.startswith("evidence/")
        and not line.startswith("CHANGELOG")
        and line not in CURRENCY_SCAN_EXEMPT
    ]


def test_repository_wide_no_document_presents_a_superseded_version_as_the_baseline() -> None:
    offenders: list[str] = []
    for relative in _tracked_documents():
        for number, line in enumerate(_text(relative).splitlines(), start=1):
            # Prose wraps: a paragraph that mentions a registry anywhere must not
            # license an unframed baseline claim in one of its sentences. Judge by
            # sentence, which is the unit a reader takes the claim from.
            for sentence in re.split(r"(?<=[.;])\s+", line):
                if _STALE_WIRING.search(sentence):
                    offenders.append(f"{relative}:{number}: {sentence.strip()[:170]}")
                    continue
                if not _UNFRAMED_AS.search(sentence) or not _PRESENTS_AS_BASELINE.search(sentence):
                    continue
                if _FRAMED_WITH.search(sentence):
                    continue
                offenders.append(f"{relative}:{number}: {sentence.strip()[:170]}")
    assert not offenders, (
        "documents present a superseded version (`4.1.2` / `5.0.0`) as the "
        "checked-out/source/current baseline without framing it as the "
        "published/historical release, or name one in a present-tense "
        '"not wired in" warning:\n  ' + "\n  ".join(offenders[:15])
    )


def test_the_repository_wide_scan_is_not_vacuous() -> None:
    documents = _tracked_documents()
    assert len(documents) > 100, f"only {len(documents)} documents scanned"


# ── baseline-carrying documents must name the current source baseline (REG-D64) ──
#
# The 2026-09-24 documentation sweep found six documents that either omitted the
# checked-out baseline or presented a superseded one as their headline: the three
# benchmark records still said "Release baseline: v3.1.0", the changelog header
# called v5.0.0 a "Release baseline", and the prospectus pair carried a stale
# baseline line (the Spanish edition contradicting its own English-parity clause).
# These pins are narrow on purpose: they fix the *specific* stale forms removed.
_BASELINE_DOCS = (
    "CHANGELOG.md",
    "docs/BENCHMARKS.md",
    "docs/benchmarks/BENCHMARK_RESULTS.md",
    "docs/benchmarks/README.md",
    "docs/PROSPECTUS.md",
    "docs/PROSPECTUS_ES.md",
)
_STALE_BASELINE_FORMS = (
    "Release baseline:** `v3.1.0`",
    "Release baseline:** `v5.0.0`",
    "Línea base de código:** `5.0.0`",
)


def test_baseline_carrying_documents_name_the_current_source_baseline() -> None:
    version = _anchor_version()
    for relative in _BASELINE_DOCS:
        text = _text(relative)
        assert version in text, f"{relative} never names the {version} source baseline"
        for form in _STALE_BASELINE_FORMS:
            assert form not in text, f"{relative} presents a superseded baseline: {form!r}"
