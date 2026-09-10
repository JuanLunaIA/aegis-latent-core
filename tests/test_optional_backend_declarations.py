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
