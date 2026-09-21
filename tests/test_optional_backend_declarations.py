# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""An optional backend must be installable by the extra that advertises it.

`aegis/core/mlkem_session.py` imports `kyber_py` behind a try/except and tells
the operator to `pip install kyber-py`. For a long time the `pqc` extra declared
`oqs-python` instead — a different library that no module in this tree imports —
so `pip install aegis-latent-core[pqc]` installed something unused and left the
feature switched off. The failure was silent in both directions: the import
guard turned it into a graceful degradation, and the thirty-two tests covering
those paths skipped rather than failed.

These tests bind the extra to the import, so the two cannot drift apart again.
They read `pyproject.toml` and need none of the optional packages installed,
which is what lets them run on a CI job that installs only the dev extra.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
OPTIONAL = PYPROJECT["project"]["optional-dependencies"]


def _distributions(extra: str) -> set[str]:
    """Return the normalized distribution names declared by one extra."""
    names = set()
    for requirement in OPTIONAL[extra]:
        # Strip any version specifier, marker or extra suffix.
        name = re.split(r"[<>=!~;\[\s]", requirement, maxsplit=1)[0]
        names.add(name.strip().lower().replace("_", "-"))
    return names


class TestMLKEMBackendIsInstallable:
    def test_pqc_extra_declares_the_library_the_code_imports(self) -> None:
        """`pip install .[pqc]` must actually enable ML-KEM."""
        assert "kyber-py" in _distributions("pqc"), (
            "aegis/core/mlkem_session.py imports kyber_py, so the pqc extra must "
            "declare kyber-py; otherwise installing the extra leaves the backend off"
        )

    def test_dev_extra_declares_it_too_so_ci_exercises_those_paths(self) -> None:
        """Without this, the ML-KEM tests skip in CI instead of running.

        They skip silently, which is worse than failing: the suite stays green
        while the cryptographic paths it reports on are never executed.
        """
        assert "kyber-py" in _distributions("dev"), (
            "the dev extra must declare kyber-py, or CI installs a tree in which "
            "every ML-KEM test skips"
        )

    def test_the_operator_hint_names_the_declared_distribution(self) -> None:
        """The module's install hint and the extra must name the same package."""
        source = (ROOT / "aegis" / "core" / "mlkem_session.py").read_text(encoding="utf-8")
        hinted = set(re.findall(r"pip install ([A-Za-z0-9._-]+)", source))
        assert hinted, "mlkem_session.py should tell the operator what to install"
        declared = _distributions("pqc")
        for name in hinted:
            assert name.lower().replace("_", "-") in declared, (
                f"mlkem_session.py tells operators to install {name!r}, which the "
                f"pqc extra does not declare"
            )


class TestDeclaredOptionalBackendsAreReachable:
    @pytest.mark.parametrize("extra", sorted(OPTIONAL))
    def test_every_extra_declares_at_least_one_distribution(self, extra: str) -> None:
        """An empty extra is a promise with nothing behind it."""
        assert _distributions(extra), f"extra {extra!r} declares no distributions"


class TestLakehouseExportTestsAreExercised:
    """The Parquet exporter's twelve tests must not skip in every gate.

    `tests/connectors/test_parquet_exporter.py` module-skips on `pyarrow`, so
    the same failure mode the `pqc` extra had applies here: the tests exist and
    pass, but no job installs the library, so the exporter is never imported by
    any run — it sat at 0% statement coverage while `CLM-071` recorded the
    connector as `LOCALLY TESTED` and `docs/commercial/CONNECTOR_ECOSYSTEM.md`
    counted "12 tests over segments produced by a real ledger".
    """

    def test_lakehouse_extra_declares_the_library_the_exporter_imports(self) -> None:
        """`pip install .[lakehouse]` must actually enable the export."""
        assert "pyarrow" in _distributions("lakehouse"), (
            "aegis/connectors/lakehouse/parquet_exporter.py imports pyarrow, so "
            "the lakehouse extra must declare it"
        )

    def test_dev_extra_declares_it_too_so_the_export_tests_run(self) -> None:
        """Without this, the twelve export tests skip in CI instead of running."""
        assert "pyarrow" in _distributions("dev"), (
            "the dev extra must declare pyarrow, or every job installs a tree in "
            "which the Parquet export tests skip and the exporter is never imported"
        )

    def test_the_operator_hint_names_the_declared_extra(self) -> None:
        """The exporter's install hint and the declared extra must agree."""
        source = (ROOT / "aegis" / "connectors" / "lakehouse" / "parquet_exporter.py").read_text(
            encoding="utf-8"
        )
        extras = set(re.findall(r"aegis-latent-core\[([a-z,\-]+)\]", source))
        assert extras, "parquet_exporter.py should tell the operator which extra to install"
        for extra in extras:
            assert extra in OPTIONAL, (
                f"parquet_exporter.py tells operators to install the {extra!r} extra, "
                "which pyproject.toml does not declare"
            )
            assert "pyarrow" in _distributions(extra), (
                f"the {extra!r} extra must declare pyarrow, the library the exporter imports"
            )


# Offline-installable distributions are the ones the dev extra must carry, since
# the dev extra is what CI installs. These two are deliberately not: their suites
# are real-server integration tests that need a live endpoint, so installing the
# library alone would not let them run — the module-level skip is by design and
# the reason is recorded here rather than left implicit.
_REAL_SERVICE_SKIPS = {
    "asyncpg": "storage-postgres: needs a reachable PostgreSQL endpoint",
    "aioboto3": "storage-dynamodb: needs a reachable DynamoDB endpoint",
}

# Not PyPI distributions at all, so no extra can declare them.
_NOT_A_DISTRIBUTION = {
    "aegis_rust": "the in-tree extension, built by the rust job (maturin), not installed from PyPI",
    "aegis_sdk": "the SDK package in sdk/python, installed by the sdk-python job",
    "uvicorn": "a runtime dependency of the package itself, always installed",
}


def _module_distributions(module: str) -> set[str]:
    """Return the distribution names a module-level importorskip target needs."""
    return {module.split(".", 1)[0].replace("_", "-"), module.split(".", 1)[0]}


def _importorskip_targets() -> dict[str, list[str]]:
    """Map every module-level importorskip target to the files that need it."""
    targets: dict[str, list[str]] = {}
    for path in sorted((ROOT / "tests").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for module in re.findall(r"pytest\.importorskip\(\s*[\"\']([A-Za-z0-9_.]+)", source):
            targets.setdefault(module, []).append(path.relative_to(ROOT).as_posix())
    return targets


#: Availability gates the suite uses to skip work an environment cannot do.
#: A gate naming a PyPI distribution must have that distribution in `dev`, or
#: the tests behind it skip in every job -- which is how the `metrics` extra
#: went unexercised while CLAIMS_MATRIX cited one of those tests as proof.
#: A gate naming `None` is a hardware or kernel facility no install can supply,
#: and the reason string on its skip says so.
_AVAILABILITY_GATES: dict[str, tuple[str, str] | None] = {
    "prometheus_available": ("prometheus-client", "metrics"),
    "backend_available": ("kyber-py", "pqc"),
    "_is_tpm_available": None,  # TPM hardware
    "is_cgroups_v2_available": None,  # kernel facility
    "_libseccomp_available": None,  # system shared library
}


class TestAvailabilityGatesNameSomethingInstallableOrExplainThemselves:
    """Every skip-by-availability gate must be a package in `dev`, or hardware.

    The module-level `importorskip` sweep above only sees one skip idiom. This
    one covers the other: a helper the test calls and a `pytest.skip` when it
    says no. `prometheus-client` sat in the `metrics` extra alone, so seven
    tests skipped in every job while `CLM-013` and `CLM-102` were registered
    against them.
    """

    @pytest.mark.parametrize("gate", sorted(_AVAILABILITY_GATES))
    def test_the_gate_still_exists(self, gate: str) -> None:
        """The list must track code, not memory: a renamed gate fails here."""
        found = [
            path
            for root in (ROOT / "tests", ROOT / "aegis")
            for path in root.rglob("*.py")
            if f"def {gate}(" in path.read_text(encoding="utf-8")
        ]
        assert found, f"no definition of {gate}() in tests/ or aegis/"

    @pytest.mark.parametrize(
        ("gate", "distribution", "extra"),
        [
            (gate, pair[0], pair[1])
            for gate, pair in sorted(_AVAILABILITY_GATES.items())
            if pair is not None
        ],
    )
    def test_an_installable_gate_is_declared_by_its_extra_and_by_dev(
        self, gate: str, distribution: str, extra: str
    ) -> None:
        assert distribution in _distributions(extra), f"{extra} does not declare {distribution}"
        declared = _distributions("dev")
        assert distribution in declared, (
            f"{gate}() skips on {distribution}, which is not in the dev extra, "
            f"so every test behind that gate skips in CI"
        )


class TestOptionalSkipsAreDeliberate:
    def test_every_skippable_import_is_either_installed_or_explained(self) -> None:
        """A silent module-level skip is a claim with no run behind it.

        Anything an ordinary `pip install -e ".[dev]"` can satisfy must be in the
        dev extra; anything else must be named above with its reason. A new
        importorskip that is neither fails here instead of quietly reducing the
        suite CI actually executes.
        """
        dev = _distributions("dev")
        unexplained = {}
        for module, files in _importorskip_targets().items():
            root = module.split(".", 1)[0]
            if root in _NOT_A_DISTRIBUTION or root in _REAL_SERVICE_SKIPS:
                continue
            if _module_distributions(module) & dev:
                continue
            unexplained[module] = files
        assert not unexplained, (
            "these module-level skips are not satisfied by the dev extra and carry "
            f"no recorded reason: {unexplained}"
        )
