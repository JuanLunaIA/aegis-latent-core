# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The verification-first sales surface must stay reproducible and honest.

The pages, the verifier kit and the end-to-end demo are what a buyer runs first.
The demo once failed five of nine checks on ``main`` for weeks because nothing
executed it; these tests execute all of it. They also pin the copy discipline:
the banned superlatives fail unless a sentence negates them.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "tools" / "sales" / "prove_it"
# The verifier needs aegis_sdk; a checkout without it installed still has the source.
_ENV = {
    **os.environ,
    "PYTHONPATH": os.pathsep.join(
        filter(None, [str(ROOT / "sdk" / "python" / "src"), os.environ.get("PYTHONPATH", "")])
    ),
}


def _run(*args: str, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  # nosec B603 - fixed in-repo scripts, shell=False
        [sys.executable, *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=timeout,
        env=_ENV,
    )


def test_committed_fixtures_are_the_deterministic_output_of_the_generator():
    result = _run(str(KIT / "make_fixture.py"), "--check")
    assert result.returncode == 0, result.stdout


def test_demo_accepts_the_genuine_record_and_rejects_both_forgeries():
    result = _run(str(KIT / "prove_it.py"), "--demo")
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count("INCLUDED") >= 3
    assert "all 3 cases behaved as required" in result.stdout


def test_altered_record_exits_non_zero():
    root = (KIT / "TRUSTED_ROOT.txt").read_text().strip()
    result = _run(str(KIT / "prove_it.py"), "verify", str(KIT / "record_tampered.json"), root)
    assert result.returncode == 1
    assert "NOT INCLUDED" in result.stdout


def test_genuine_record_against_an_unrelated_root_exits_non_zero():
    result = _run(str(KIT / "prove_it.py"), "verify", str(KIT / "record.json"), "0" * 64)
    assert result.returncode == 1


def test_site_pages_match_the_builder_and_the_data_room_paths_exist():
    result = _run(str(ROOT / "tools" / "sales" / "build_site.py"), "--check")
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_sales_surface_passes_the_banned_word_lint():
    result = _run(str(ROOT / "scripts" / "lint_sales_copy.py"))
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize(
    "sentence",
    [
        "Military-grade encryption protects every record.",
        "Your logs are guaranteed to be tamper-proof.",
        "An unbreakable audit trail.",
        "Fully certified for production use.",
        "Catches 100% of injections.",
    ],
)
def test_lint_flags_each_banned_term(sentence: str):
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import lint_sales_copy
    finally:
        sys.path.pop(0)
    assert lint_sales_copy.lint_text(sentence)


@pytest.mark.parametrize(
    "sentence",
    [
        "No certification exists, and none is in progress.",
        "The product is not certified.",
        "Do not use: guaranteed, unbreakable.",
    ],
)
def test_lint_allows_a_banned_term_only_inside_a_negating_sentence(sentence: str):
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import lint_sales_copy
    finally:
        sys.path.pop(0)
    assert lint_sales_copy.lint_text(sentence) == []


def test_end_to_end_demo_passes_every_check():
    result = _run("-m", "examples.demo", timeout=120)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    assert "RESULT: 5/5 checks OK" in result.stdout
