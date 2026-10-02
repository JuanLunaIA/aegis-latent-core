# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""Real post-lockdown terminal outbox lifecycle in an isolated interpreter."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from test_seccomp_runtime_paths import _LOCK, needs_filter


@needs_filter
def test_terminal_outbox_under_selected_filter(tmp_path: Path) -> None:
    script = (
        _LOCK
        + """
import asyncio
from aegis.core.seccomp_guard import SeccompGuard, profile_with, TERMINAL_OUTBOX_SYSCALLS
from aegis.proxy.terminal_outbox import TerminalOutbox, TerminalReplayContext, SpooledSummary
from pathlib import Path
outbox = TerminalOutbox.open(Path(sys.argv[2]), mac_key=b"fixture", max_bytes=100000)
ctx = TerminalReplayContext("id", "0"*64, 0, "t", "m", "e", False, "", False, "fixture")
summary = SpooledSummary("0"*64, 0, "client_disconnected", False, 0, 0.0, {})
async def main():
    guard = SeccompGuard(profile_with(TERMINAL_OUTBOX_SYSCALLS))
    guard._is_sandbox = False
    assert guard.apply_filter()
    import os
    original_write = os.write
    def short_write(fd, data):
        return original_write(fd, data[:10])
    os.write = short_write
    assert outbox.record(ctx, summary) is None
    os.write = original_write
    assert outbox.record(ctx, summary)
    await outbox.sync()
    outbox.compact()
    assert outbox.errors == 1  # the injected partial record, no later failures
    outbox.close()
    print("OUTBOX_OK")
asyncio.run(main())
"""
    )
    # Fixed interpreter and inline fixture code; no external input is executed.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script, "outbox", str(tmp_path / "outbox")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "OUTBOX_OK" in result.stdout
