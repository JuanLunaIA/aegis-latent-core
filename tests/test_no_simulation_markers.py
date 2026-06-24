# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Ratchet guard against security-theater regressions (ROADMAP P0.1).

The 2026-06-24 audit found ~20% of `aegis/core` shipping *simulated* security
controls — code that returns success without performing the advertised function,
manufacturing false compliance evidence. This test makes the cleanup a one-way
ratchet:

* No **new** module may introduce a simulation marker (hard gate).
* When a module is de-simulated (made real or deleted), it **must** be removed
  from ``KNOWN_SIMULATION_DEBT`` (keeps the debt list honest and shrinking).

A "simulation marker" is a code/comment pattern that signals the module fakes a
control rather than performing it. The intent is detection of *false assurance*,
not banning the word "simulate" (e.g. WAF jailbreak patterns legitimately mention
it), so the pattern is deliberately specific.
"""

from __future__ import annotations

import re
from pathlib import Path

AEGIS_ROOT = Path(__file__).parent.parent / "aegis"

# Patterns that indicate the surrounding code is a stand-in, not the real control.
_MARKER = re.compile(
    r"# SIMULATION"
    r"|# Simulation"
    r"|In a real (system|implementation|environment),"
    r"|Simulation:"
    r"|is_cfi_enabled = True"
    r"|_simulated_"
    r"|Simulated success of"
)

# Modules that still contain simulation markers as of 2026-06-24. This set may
# only SHRINK. Each entry is tracked in docs/ROADMAP.md under P0.2–P0.4.
KNOWN_SIMULATION_DEBT: frozenset[str] = frozenset(
    {
        "core/build_reproducibility.py",
        "core/codeql_config.py",
        "core/dpdk_engine.py",
        "core/ebpf_monitor.py",
        "core/enclave_provider.py",
        "core/forensic_sealing.py",
        "core/fuzzing_harness.py",
        "core/red_team_framework.py",
        "core/sandbox.py",
        "core/state_snapshotter.py",
        "core/tee_manager.py",
        "core/tpm.py",
        "core/transparency_log.py",
        "core/tsa_provider.py",
    }
)


def _modules_with_markers() -> set[str]:
    found: set[str] = set()
    for path in AEGIS_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if _MARKER.search(text):
            found.add(path.relative_to(AEGIS_ROOT).as_posix())
    return found


def test_no_new_simulation_modules():
    """Hard gate: no module outside the known-debt allowlist may contain a marker."""
    current = _modules_with_markers()
    newly_introduced = current - KNOWN_SIMULATION_DEBT
    assert not newly_introduced, (
        "New simulated / false-assurance module(s) introduced: "
        f"{sorted(newly_introduced)}. Implement the real control (or quarantine it "
        "under an AEGIS_ALLOW_SIMULATION guard) — do not ship security theater."
    )


def test_allowlist_is_not_stale():
    """Ratchet: a de-simulated module must be removed from KNOWN_SIMULATION_DEBT."""
    current = _modules_with_markers()
    stale = KNOWN_SIMULATION_DEBT - current
    assert not stale, (
        "These modules no longer contain simulation markers — remove them from "
        f"KNOWN_SIMULATION_DEBT so the debt list stays honest: {sorted(stale)}"
    )


def test_debt_count_never_increases():
    """The simulation-debt count is a monotonically non-increasing budget."""
    assert len(_modules_with_markers()) <= len(KNOWN_SIMULATION_DEBT) == 14
