# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Startup clock-synchronisation check (``AEGIS_REQUIRE_CLOCK_SYNC``).

Evidence timestamps come from the host clock, so an operator can ask the
gateway to refuse a strict start when the clock is not confirmed synchronised.
``clock_integrity.py`` existed but nothing at startup called it. These tests
pin the wiring: strict refuses on unsynchronised and on undetermined status,
other modes only warn, and nothing runs when the setting is off.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from aegis.core.clock_integrity import ClockIntegrityAssertion, NTPSyncStatus
from aegis.proxy.app import _check_clock_sync


def _cfg(*, mode: str, required: bool = True) -> SimpleNamespace:
    return SimpleNamespace(security_enforcement_mode=mode, require_clock_sync=required)


def _status(synced: bool | None) -> NTPSyncStatus:
    return NTPSyncStatus(
        ntp_synchronized=synced, source="adjtimex", warning="" if synced else "not synced"
    )


@pytest.mark.parametrize("synced", [False, None])
def test_strict_refuses_to_start_unless_the_clock_is_confirmed_synchronised(synced) -> None:
    with patch.object(ClockIntegrityAssertion, "assert_startup", return_value=_status(synced)):
        with pytest.raises(RuntimeError, match="synchronised clock"):
            _check_clock_sync(_cfg(mode="strict"))


def test_strict_starts_on_a_synchronised_clock() -> None:
    with patch.object(ClockIntegrityAssertion, "assert_startup", return_value=_status(True)):
        _check_clock_sync(_cfg(mode="strict"))


def test_other_modes_warn_instead_of_refusing(caplog: pytest.LogCaptureFixture) -> None:
    with patch.object(ClockIntegrityAssertion, "assert_startup", return_value=_status(False)):
        _check_clock_sync(_cfg(mode="development"))

    assert "not confirmed synchronised" in caplog.text


def test_nothing_runs_when_the_setting_is_off() -> None:
    with patch.object(ClockIntegrityAssertion, "assert_startup") as probe:
        _check_clock_sync(_cfg(mode="strict", required=False))

    probe.assert_not_called()
