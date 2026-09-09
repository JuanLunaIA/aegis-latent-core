# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Supply-chain containment properties, asserted against the manifests.

Each test here pins a boundary that is easy to cross by accident and hard to
notice afterwards, because crossing it produces a working build:

- An evidence gateway that grows a hard dependency on a machine-learning stack
  inherits every ``pickle.loads`` and ``exec`` in it, and the install still
  succeeds.
- A dev-server convenience that downloads an unsigned binary and interpolates
  a hostname into a shell is harmless while nothing enables it, and the flag
  that enables it is one word long.
- A test runner with a path-traversal defect keeps running tests perfectly.

The manifests are the subject under test, so these run without a network and
without installing anything.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: Heavy inference stacks. Each carries deserialization or remote-code
#: primitives that have no business on an evidence path, and each is available
#: through an explicit extra for deployments that genuinely want it.
ML_DISTRIBUTIONS = frozenset({"torch", "transformers", "vllm", "sentencepiece", "tokenizers"})

#: `@vitest/mocker` registered a redirect mock's target without checking it
#: against the dev server's file-serving allowlist, so a client that could
#: reach Vite's unauthenticated HMR socket could read arbitrary local files.
#: Fixed in 4.1.11 (and 5.0.0-rc.2).
VITEST_FIXED_VERSION = (4, 1, 11)
VITEST_ADVISORY = "GHSA-82fw-gwwq-j7x9 / CVE-2026-84373"

JS_PROJECTS = ("sdk/typescript", "dashboard")


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _pyproject() -> dict[str, object]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        data: dict[str, object] = tomllib.load(handle)
    return data


def _requirement_names(specs: object) -> set[str]:
    if not isinstance(specs, list):
        return set()
    names: set[str] = set()
    for spec in specs:
        match = re.match(r"^\s*([A-Za-z0-9._-]+)", str(spec))
        if match:
            names.add(_normalise(match.group(1)))
    return names


class TestTheMlStackStaysOutOfTheCore:
    def test_no_ml_distribution_is_a_core_runtime_dependency(self) -> None:
        project = _pyproject().get("project", {})
        assert isinstance(project, dict)
        core = _requirement_names(project.get("dependencies"))
        offenders = sorted(core & ML_DISTRIBUTIONS)
        assert not offenders, (
            f"{offenders} became hard dependencies of the gateway. They belong in "
            "an optional extra: installing the evidence gateway must not pull an "
            "inference stack, and torch alone reaches pickle.loads and exec."
        )

    def test_no_ml_distribution_is_pinned_in_the_runtime_lock(self) -> None:
        """The lock is what a released image installs; the extras are not in it."""

        locked: set[str] = set()
        for line in (ROOT / "requirements.lock").read_text(encoding="utf-8").splitlines():
            match = re.match(r"^([A-Za-z0-9._-]+)==", line.strip())
            if match:
                locked.add(_normalise(match.group(1)))
        offenders = sorted(locked & ML_DISTRIBUTIONS)
        assert not offenders, f"{offenders} are pinned in requirements.lock"

    def test_the_ml_extras_still_exist_for_deployments_that_want_them(self) -> None:
        """Containment must not be mistaken for removal."""

        project = _pyproject().get("project", {})
        assert isinstance(project, dict)
        extras = project.get("optional-dependencies", {})
        assert isinstance(extras, dict)
        declared: set[str] = set()
        for group in extras.values():
            declared |= _requirement_names(group)
        assert "torch" in declared, "the gpu/hf/vllm extras should still offer torch"


class TestTheDashboardDevServerStaysOff:
    """Next's `--experimental-https` path fetches an unsigned binary and shells out.

    `next/dist/lib/mkcert.js` downloads a release binary over plain `fetch`
    with no signature or digest check, then runs it through `execSync` with the
    requested hosts interpolated into the command string. Nothing here enables
    that path; this test is what keeps it that way, because the change that
    would enable it is adding one flag to a script.
    """

    def _package_json(self, project: str) -> dict[str, object]:
        data: dict[str, object] = json.loads(
            (ROOT / project / "package.json").read_text(encoding="utf-8")
        )
        return data

    def test_no_script_enables_experimental_https(self) -> None:
        for project in JS_PROJECTS:
            scripts = self._package_json(project).get("scripts", {})
            assert isinstance(scripts, dict)
            for name, command in scripts.items():
                assert "experimental-https" not in str(command), (
                    f"{project} script {name!r} enables Next's experimental HTTPS "
                    "path, which downloads an unsigned mkcert binary and passes "
                    "the host list through execSync"
                )

    def test_the_next_config_does_not_enable_it(self) -> None:
        config = ROOT / "dashboard/next.config.ts"
        if not config.is_file():
            pytest.skip("dashboard/next.config.ts is absent")
        assert "experimentalHttps" not in config.read_text(encoding="utf-8")


class TestTheTestRunnerCarriesTheFix:
    """Regression test for the one advisory that affected a pinned version here."""

    def _declared_vitest(self, project: str) -> str | None:
        data = json.loads((ROOT / project / "package.json").read_text(encoding="utf-8"))
        for group in ("devDependencies", "dependencies"):
            found = (data.get(group) or {}).get("vitest")
            if found:
                return str(found)
        return None

    def _version_tuple(self, raw: str) -> tuple[int, ...]:
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", raw)
        assert match is not None, f"unparseable version {raw!r}"
        return tuple(int(part) for part in match.groups())

    @pytest.mark.parametrize("project", JS_PROJECTS)
    def test_the_declared_vitest_is_at_or_past_the_fix(self, project: str) -> None:
        declared = self._declared_vitest(project)
        if declared is None:
            pytest.skip(f"{project} does not use vitest")
        assert self._version_tuple(declared) >= VITEST_FIXED_VERSION, (
            f"{project} declares vitest {declared}; {VITEST_ADVISORY} is fixed in "
            f"{'.'.join(map(str, VITEST_FIXED_VERSION))}"
        )

    @pytest.mark.parametrize("project", JS_PROJECTS)
    def test_no_resolved_vitest_package_predates_the_fix(self, project: str) -> None:
        """The lock decides what installs, so the lock is what has to be checked.

        A fixed range in `package.json` over a stale lock still installs the
        vulnerable tree under `npm ci`.
        """

        lock_path = ROOT / project / "package-lock.json"
        if not lock_path.is_file():
            pytest.skip(f"{project} has no package-lock.json")
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        stale: list[str] = []
        for location, entry in lock.get("packages", {}).items():
            name = location.split("node_modules/")[-1]
            if name != "vitest" and not name.startswith("@vitest/"):
                continue
            version = entry.get("version")
            if version and self._version_tuple(str(version)) < VITEST_FIXED_VERSION:
                stale.append(f"{location}@{version}")
        assert not stale, f"{project} lock still resolves vulnerable vitest packages: {stale}"


class TestBuildToolingIsNotShipped:
    def test_the_dashboard_ships_no_test_or_lint_tooling_as_a_runtime_dependency(self) -> None:
        data = json.loads((ROOT / "dashboard/package.json").read_text(encoding="utf-8"))
        runtime = set((data.get("dependencies") or {}).keys())
        tooling = {
            name
            for name in runtime
            if name.startswith(("@testing-library/", "@types/", "@vitejs/"))
            or name in {"vitest", "typescript", "jsdom", "axe-core", "eslint", "prettier"}
        }
        assert not tooling, (
            f"{sorted(tooling)} are build/test tools declared as runtime dependencies; "
            "they would be installed into the production image"
        )
