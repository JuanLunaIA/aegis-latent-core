# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Load the real SeccompGuard filter in a child process and serve HTTP behind it.

Regression for a strict-mode outage: the profile lacked epoll_pwait/ioctl and used
SCMP_ACT_KILL, so the event-loop thread died right after lockdown while Tokio
threads kept the process alive — no socket, no error, liveness probes failing.
Mocked tests cannot catch that; only a loaded filter can.
"""

from __future__ import annotations

import ctypes
import importlib.util
import os
import signal
import socket
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest


def _libseccomp_available() -> bool:
    try:
        ctypes.CDLL("libseccomp.so.2")
    except OSError:
        return False
    return True


pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="seccomp is Linux-only"),
    pytest.mark.skipif(not _libseccomp_available(), reason="libseccomp.so.2 not installed"),
    pytest.mark.skipif(importlib.util.find_spec("uvicorn") is None, reason="uvicorn not installed"),
]

ROOT = Path(__file__).resolve().parents[1]

CHILD = textwrap.dedent(
    """
    import os, sys, threading
    from aegis.core.seccomp_guard import SeccompGuard

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            await receive()
            guard = SeccompGuard()
            guard._is_sandbox = False  # force the production path regardless of markers
            if not guard.apply_filter():
                await send({"type": "lifespan.startup.failed", "message": "filter not loaded"})
                return
            await send({"type": "lifespan.startup.complete"})
            await receive()
            await send({"type": "lifespan.shutdown.complete"})
            return
        path = scope["path"]
        if path == "/thread":
            t = threading.Thread(target=lambda: None)
            t.start()
            t.join()
        elif path == "/fork":
            os.fork()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": path.encode()})

    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[1]), loop=sys.argv[2], log_level="warning")
    """
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _get(port: int, path: str) -> int:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as resp:
        return int(resp.status)


def _loops() -> list[str]:
    loops = ["asyncio"]
    if importlib.util.find_spec("uvloop") is not None:
        loops.append("uvloop")
    return loops


@pytest.fixture(params=_loops())
def locked_server(request: pytest.FixtureRequest):
    port = _free_port()
    env = {**os.environ, "PYTHONPATH": str(ROOT), "UV_USE_IO_URING": "0"}
    env.pop("HERMES_SANDBOX", None)
    proc = subprocess.Popen(  # noqa: S603 - fixed argv: this interpreter and an in-file script
        [sys.executable, "-c", CHILD, str(port), request.param],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.fail(
                f"server exited early ({proc.returncode}): {proc.stderr.read().decode()[-2000:]}"
            )
        try:
            _get(port, "/ping")
            break
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("server behind the seccomp filter never answered (event loop killed?)")
    yield proc, port
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)


def test_filter_is_loaded_and_http_is_served(locked_server) -> None:
    proc, port = locked_server
    status = Path(f"/proc/{proc.pid}/status").read_text()
    assert "Seccomp:\t2" in status
    for _ in range(5):
        assert _get(port, "/ping") == 200


def test_threads_allowed_process_creation_kills_process(locked_server) -> None:
    proc, port = locked_server
    assert _get(port, "/thread") == 200
    with pytest.raises((urllib.error.URLError, ConnectionError, TimeoutError)):
        _get(port, "/fork")
    assert proc.wait(timeout=10) == -signal.SIGSYS
