# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""``pip install aegis-latent-core[all]`` installs no development tooling (REG-D74).

The 2026-09-24 gatekeeper pass read the built wheel's METADATA and found
``[all]`` pulling pytest, ruff, mypy, bandit, pip-audit and hypothesis through
the ``dev`` extra. The default wheel and the image were unaffected, but an
extra named "all" is what an operator reaches for, and test and lint tooling
has no place in a runtime install.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SELF = "aegis-latent-core["


def _extras() -> dict[str, list[str]]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    extras: dict[str, list[str]] = project["optional-dependencies"]
    return extras


def _expand(extras: dict[str, list[str]], name: str, seen: set[str]) -> set[str]:
    packages: set[str] = set()
    for requirement in extras[name]:
        if requirement.startswith(SELF):
            for nested in requirement[len(SELF) : requirement.index("]")].split(","):
                if nested not in seen:
                    seen.add(nested)
                    packages |= _expand(extras, nested, seen)
        else:
            for stop in "[<>=!~; ":
                requirement = requirement.split(stop, 1)[0]
            packages.add(requirement.lower())
    return packages


def test_all_does_not_include_the_dev_extra() -> None:
    extras = _extras()
    seen: set[str] = {"all"}
    _expand(extras, "all", seen)
    assert "dev" not in seen


def test_no_development_tool_is_reachable_from_all() -> None:
    extras = _extras()
    reachable = _expand(extras, "all", {"all"})
    development_only = _expand(extras, "dev", {"dev"}) - reachable
    tools = {"pytest", "ruff", "mypy", "bandit", "pip-audit", "hypothesis"}
    assert tools <= development_only, sorted(tools - development_only)
    assert not tools & reachable, sorted(tools & reachable)
