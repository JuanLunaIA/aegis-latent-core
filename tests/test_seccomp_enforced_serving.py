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


# ── REG-D67 / REG-D68: the gateway itself, not a stub ─────────────────────────
#
# Everything above serves a trivial ASGI app with UV_USE_IO_URING=0 already set
# in the child's environment, so it could not see REG-D67: the real `aegis`
# entry point, launched the way the README quickstart launches it, loaded the
# filter and was killed with SIGSYS about two seconds later, before any request,
# because libuv had created an io_uring instance and called io_uring_enter on it.
# These tests launch the real gateway with io_uring left enabled in the
# environment and hold it to serving durable evidence behind a loaded filter.

_IO_URING_SETUP_NR = {"x86_64": 425, "aarch64": 425}.get(os.uname().machine)


def _create_io_uring() -> int | None:
    """Open a real io_uring instance via the raw syscall, or None if unavailable."""
    if _IO_URING_SETUP_NR is None:
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    params = ctypes.create_string_buffer(120)  # struct io_uring_params, zeroed
    fd = int(libc.syscall(_IO_URING_SETUP_NR, 4, params))
    return fd if fd >= 0 else None


class _MockUpstream:
    def __init__(self) -> None:
        import json
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        body = json.dumps(
            {
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "created": 1,
                "model": "mock-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        ).encode()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server API
                self.rfile.read(int(self.headers.get("content-length") or 0))
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self.server.server_address[1])
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _gateway_env(tmp_path: Path, upstream_port: int, port: int) -> dict[str, str]:
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        "AEGIS_SECURITY_ENFORCEMENT_MODE": "development",
        "AEGIS_DEBUG_MODE": "true",
        "AEGIS_AUTH_DISABLED": "true",
        "AEGIS_BACKEND_URL": f"http://127.0.0.1:{upstream_port}",
        "AEGIS_HOST": "127.0.0.1",
        "AEGIS_PORT": str(port),
        "AEGIS_WAL_PATH": str(tmp_path / "aegis.wal.jsonl"),
    }
    # The whole point: do not pre-disable io_uring the way the stub tests do.
    for name in ("UV_USE_IO_URING", "HERMES_SANDBOX"):
        env.pop(name, None)
    return env


def _wait_for_health(proc: subprocess.Popen[bytes], port: int, seconds: float = 90) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.fail(
                f"gateway exited early ({proc.returncode}): {proc.stderr.read().decode()[-3000:]}"
            )
        try:
            if _get(port, "/health") == 200:
                return
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        time.sleep(0.25)
    proc.kill()
    pytest.fail("gateway never answered /health")


def _post_chat(port: int) -> tuple[int, str | None]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=b'{"messages":[{"role":"user","content":"hi"}]}',
        headers={"content-type": "application/json", "x-session-id": "seccomp-regression"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed http://127.0.0.1 URL
        return int(resp.status), resp.headers.get("x-aegis-evidence-status")


def _stop(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_the_aegis_entry_point_serves_behind_the_filter_with_io_uring_available(
    tmp_path: Path,
) -> None:
    upstream = _MockUpstream()
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603 - fixed argv: this interpreter and the package entry point
        [sys.executable, "-c", "from aegis.proxy.app import main; main()"],
        env=_gateway_env(tmp_path, upstream.port, port),
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_health(proc, port)
        # The filter is really loaded — this is not the degraded path.
        assert "Seccomp:\t2" in Path(f"/proc/{proc.pid}/status").read_text()
        # The pre-fix process died ~2 s after startup with no request at all.
        time.sleep(4)
        assert proc.poll() is None, "gateway died behind its own filter (REG-D67)"
        status, evidence = _post_chat(port)
        assert (status, evidence) == (200, "durable")
        time.sleep(1)
        assert proc.poll() is None
    finally:
        _stop(proc)
        upstream.close()


def test_a_uvicorn_launch_with_io_uring_enabled_is_never_killed(tmp_path: Path) -> None:
    """Bypassing the entry point (plain `uvicorn … --loop uvloop`) may leave a live
    ring. Development mode must then skip the filter and say why — never die."""
    if importlib.util.find_spec("uvloop") is None:
        pytest.skip("uvloop not installed")
    upstream = _MockUpstream()
    port = _free_port()
    proc = subprocess.Popen(  # noqa: S603 - fixed argv: this interpreter and uvicorn
        [
            sys.executable,
            "-m",
            "uvicorn",
            "aegis.proxy.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--loop",
            "uvloop",
        ],
        env=_gateway_env(tmp_path, upstream.port, port),
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_health(proc, port)
        time.sleep(4)
        assert proc.poll() is None, "gateway died behind its own filter (REG-D67)"
        assert _post_chat(port)[0] == 200
        assert proc.poll() is None
    finally:
        _stop(proc)
        stderr = proc.stderr.read().decode() if proc.stderr else ""
        upstream.close()
    seccomp = "Seccomp:\t2" if "seccomp-BPF filter loaded" in stderr else "skipped"
    if seccomp == "skipped":
        assert "io_uring" in stderr, stderr[-3000:]


LOCKDOWN_OVER_A_RING = textwrap.dedent(
    """
    import ctypes, sys
    from aegis.core.seccomp_guard import IoUringActiveError, SeccompGuard
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.syscall(int(sys.argv[1]), 4, ctypes.create_string_buffer(120))
    if fd < 0:
        print("NO_RING"); sys.exit(0)
    guard = SeccompGuard()
    guard._is_sandbox = False
    try:
        guard.apply_filter()
        print("LOADED")
    except IoUringActiveError as exc:
        print("REFUSED", "UV_USE_IO_URING=0" in str(exc))
    status = open("/proc/self/status").read()
    print("SECCOMP", "Seccomp:\\t0" in status, "NNP", "NoNewPrivs:\\t0" in status)
    """
)


def test_lockdown_over_a_live_ring_is_refused_before_anything_changes() -> None:
    if _IO_URING_SETUP_NR is None:
        pytest.skip("io_uring syscall number unknown on this architecture")
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    env.pop("HERMES_SANDBOX", None)
    out = subprocess.run(  # noqa: S603 - fixed argv: this interpreter and an in-file script
        [sys.executable, "-c", LOCKDOWN_OVER_A_RING, str(_IO_URING_SETUP_NR)],
        env=env,
        capture_output=True,
        timeout=60,
        check=False,
    )
    lines = out.stdout.decode().split("\n")
    if lines and lines[0] == "NO_RING":
        pytest.skip("io_uring is disabled on this kernel")
    assert out.returncode == 0, out.stderr.decode()[-2000:]
    assert lines[0] == "REFUSED True"
    # Refused before PR_SET_NO_NEW_PRIVS and before any filter: nothing changed.
    assert lines[1] == "SECCOMP True NNP True"


def test_open_io_uring_fds_sees_a_real_ring() -> None:
    from aegis.core.seccomp_guard import open_io_uring_fds

    fd = _create_io_uring()
    if fd is None:
        pytest.skip("io_uring unavailable on this kernel")
    try:
        assert fd in open_io_uring_fds()
    finally:
        os.close(fd)
    assert fd not in open_io_uring_fds()
