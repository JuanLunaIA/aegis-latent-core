# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Gate-scope parity: the Makefile and CI must not disagree about ruff or bandit.

The gate this pins (AUD-18 / REG-D22): `make lint` ran `ruff format --check .`
while CI ran the same tool over a fixed path list, so the two reported different
verdicts at the same commit — the Makefile red on 11 files (2 `scripts/*.py` and
9 markdown fences) while CI was green, and `scripts/*.py` sat outside every
formatter gate entirely. `make security` had the same shape against CI's bandit
step (`aegis/` at `-ll` versus `aegis/ aegis_server/` at `-lll`).

What it asserts: for every `ruff` / `bandit` invocation that appears in both the
Makefile and `.github/workflows/ci.yml`, the argument (scope) set is identical
after normalising line continuations and whitespace. Adding a path to one file
and not the other now fails here.

What it deliberately does not cover, stated rather than implied: the mypy jobs.
CI runs two profiles on purpose — a narrow `mypy --config-file=mypy-ci.ini`
listing for proxy + core runtime, and `mypy --strict aegis` for the whole
package — so "one canonical invocation" is not the right rule there. The
Makefile's `type` target matches the strict job.

One mypy invocation is pinned, because it is the one that had no home at all
(AUD-29 / REG-D33): the strict check over `scripts/` and `tools/`, where the
gate programs themselves live. Both files must carry it with identical
arguments, so neither can quietly drop the directories back out of scope.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = REPO_ROOT / "Makefile"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# command prefix -> the subcommand tokens worth comparing as the scope
TOOLS = ("ruff", "bandit")


MAKE_VARS = {
    "$(RUFF)": "ruff",
    "$(BANDIT)": "bandit",
    "$(MYPY)": "mypy",
    "$(PYTEST)": "pytest",
}


def _normalise(text: str) -> str:
    """Expand the Makefile's tool variables so both files read the same way."""
    for variable, tool in MAKE_VARS.items():
        text = text.replace(variable, tool)
    return text


def _logical_lines(text: str) -> list[str]:
    """Join shell line continuations and drop comments/blank lines."""
    joined = re.sub(r"\\\n\s*", " ", _normalise(text))
    out = []
    for line in joined.splitlines():
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("#")
            or stripped.startswith("@")
            or stripped.endswith(":")
        ):
            continue
        if stripped:
            out.append(stripped)
    return out


def _tool_arg_strings(text: str, tools: tuple[str, ...] = TOOLS) -> dict[str, set[str]]:
    """Map tool name -> the set of argument strings it is invoked with."""
    found: dict[str, set[str]] = {}
    for line in _logical_lines(text):
        tokens = line.split()
        for index, token in enumerate(tokens):
            if token not in tools:
                continue
            args = " ".join(tokens[index + 1 :]).strip()
            if args:
                found.setdefault(token, set()).add(args)
            break
    return found


def test_makefile_and_ci_agree_on_ruff_and_bandit_scope() -> None:
    """Every invocation the Makefile runs, CI must run with the same arguments.

    This is the direction that matters: a CI invocation narrower than the
    Makefile's is exactly what made the two report different verdicts. CI may run
    *extra* invocations (the SDK job lints its own subtree with its own config),
    so the check is a subset, not an equality.
    """
    makefile_invocations = _tool_arg_strings(MAKEFILE.read_text(encoding="utf-8"))
    ci_invocations = _tool_arg_strings(CI_WORKFLOW.read_text(encoding="utf-8"))

    # Guard the gate itself: both files must yield invocations to compare.
    assert makefile_invocations.get("ruff"), "no ruff invocation parsed from the Makefile"
    assert ci_invocations.get("ruff"), "no ruff invocation parsed from ci.yml"

    not_run_by_ci = {
        tool: sorted(args - ci_invocations.get(tool, set()))
        for tool, args in makefile_invocations.items()
        if args - ci_invocations.get(tool, set())
    }
    assert not not_run_by_ci, (
        "the Makefile runs gate invocations CI never runs "
        f"(tool: make args missing from ci.yml): {not_run_by_ci} — one canonical "
        "invocation or neither"
    )


def test_ruff_format_is_not_scoped_narrower_in_ci_than_in_the_makefile() -> None:
    """The specific drift this row reported, pinned as its own case.

    Both files must invoke the formatter over the whole tree (`.`): a narrower CI
    invocation would silently exempt files the Makefile checks.
    """
    for label, text in (
        ("Makefile", MAKEFILE.read_text(encoding="utf-8")),
        ("ci.yml", CI_WORKFLOW.read_text(encoding="utf-8")),
    ):
        invocations = _tool_arg_strings(text)
        format_args = sorted(
            args for args in invocations.get("ruff", set()) if args.startswith("format")
        )
        assert format_args, f"{label} runs no `ruff format` command"
        for args in format_args:
            assert args == "format --check .", (
                f"{label} runs `ruff {args}` — expected `ruff format --check .`, the "
                "whole tree, which is what makes the two invocations unable to drift"
            )


GATE_PROGRAM_SCOPE = "--strict --explicit-package-bases --follow-imports=silent scripts tools"


def test_gate_programs_are_type_checked_by_both_make_and_ci() -> None:
    """`scripts/` and `tools/` hold the programs that police every claim.

    REG-D33 found them outside every type-check scope, and the first strict run
    over them found a real defect — `tools/forensic/diagnose_aegis.py` called the
    static `PQCSigner.verify` without its public key, so its round-trip check
    reported FAIL on every healthy install. Both entry points must keep them in
    scope, with the same arguments.
    """
    for label, text in (
        ("Makefile", MAKEFILE.read_text(encoding="utf-8")),
        ("ci.yml", CI_WORKFLOW.read_text(encoding="utf-8")),
    ):
        mypy_args = _tool_arg_strings(text, ("mypy",)).get("mypy", set())
        assert GATE_PROGRAM_SCOPE in mypy_args, (
            f"{label} does not run `mypy {GATE_PROGRAM_SCOPE}`; its mypy invocations "
            f"are {sorted(mypy_args)}"
        )
