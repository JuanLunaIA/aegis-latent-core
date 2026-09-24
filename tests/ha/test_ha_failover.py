# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Real gateway processes, real Redis, real kill: the multi-replica contract end to end.

Each replica is the ``aegis`` entry point (``main()``) in its own process, with
the production seccomp filter loaded (HERMES_SANDBOX is removed from its
environment), talking to a mock upstream.

Active-passive: two replicas point at one chain and one WAL. Only the lease
holder serves; the other answers ``/health`` as a standby and refuses everything
else. When the holder is killed with SIGKILL — no shutdown, no lease release —
the standby takes the chain over within the lease TTL, under a newer epoch, and
the WAL they shared verifies as one intact chain that records both handovers.

Active-active: two replicas, two chains, one global sequence. Both serve at
once; afterwards the sequence verifies, holds every node of both chains, and
each reference resolves to the node at that position in its replica's WAL.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.ha import SQLiteSequenceStore, verify_chain_references, verify_global_sequence

ROOT = Path(__file__).resolve().parents[2]


def free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(sys.platform != "linux", reason="seccomp-enforced replicas are Linux-only"),
]

COMPLETION = json.dumps(
    {
        "id": "chatcmpl-ha",
        "object": "chat.completion",
        "created": 1,
        "model": "m",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
).encode()


@pytest.fixture
def upstream() -> Any:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server API
            self.rfile.read(int(self.headers.get("content-length") or 0))
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(COMPLETION)))
            self.end_headers()
            self.wfile.write(COMPLETION)

        def log_message(self, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield int(server.server_address[1])
    server.shutdown()
    server.server_close()


def _request(port: int, method: str, path: str) -> tuple[int, dict[str, Any]]:
    body = (
        b'{"model":"m","messages":[{"role":"user","content":"hello"}]}'
        if method == "POST"
        else None
    )
    req = urllib.request.Request(  # noqa: S310 - fixed http://127.0.0.1 URL
        f"http://127.0.0.1:{port}{path}",
        data=body,
        headers={"content-type": "application/json", "x-session-id": "ha"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return int(resp.status), json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return int(exc.code), json.loads(exc.read() or b"{}")


def _replica(
    *, port: int, upstream: int, wal: Path, redis_url: str, extra: dict[str, str]
) -> subprocess.Popen[bytes]:
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        "AEGIS_SECURITY_ENFORCEMENT_MODE": "development",
        "AEGIS_DEBUG_MODE": "true",
        "AEGIS_AUTH_DISABLED": "true",
        "AEGIS_HOST": "127.0.0.1",
        "AEGIS_PORT": str(port),
        "AEGIS_BACKEND_URL": f"http://127.0.0.1:{upstream}",
        "AEGIS_WAL_PATH": str(wal),
        "AEGIS_REDIS_URL": redis_url,
        "AEGIS_HA_LEASE_TTL_SECONDS": "3",
        "AEGIS_HA_STANDBY_POLL_SECONDS": "0.3",
        **extra,
    }
    env.pop("HERMES_SANDBOX", None)  # the production filter, as deployed
    # A file, not a pipe: nobody drains a pipe while the test waits, and a full
    # one blocks the replica mid-log.
    log_path = wal.with_suffix(f".{port}.log")
    with open(log_path, "wb") as log:  # the child keeps its own descriptor
        proc = subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, "-c", "from aegis.proxy.app import main; main()"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=log,
        )
    proc.log_path = str(log_path)  # type: ignore[attr-defined]
    return proc


def _until(predicate: Any, proc: subprocess.Popen[bytes], seconds: float, what: str) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            err = Path(proc.log_path).read_text(errors="replace")[-3000:]  # type: ignore[attr-defined]
            pytest.fail(f"replica exited ({proc.returncode}) while waiting for {what}: {err}")
        try:
            if predicate():
                return
        except (urllib.error.URLError, ConnectionError, TimeoutError, json.JSONDecodeError):
            pass  # not answering yet; the deadline above bounds the wait
        time.sleep(0.2)
    pytest.fail(f"timed out waiting for {what}")


def _stop(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _handovers(wal: Path) -> list[dict[str, Any]]:
    records = []
    for line in wal.read_text().splitlines():
        node = json.loads(line)
        if str(node.get("state_id", "")).startswith("ha-lease-"):
            records.append(node)
    return records


def test_active_passive_failover_after_the_holder_is_killed(
    tmp_path: Path, redis_url: str, upstream: int
) -> None:
    wal = tmp_path / "shared.wal.jsonl"
    chain = f"shared-{uuid.uuid4().hex[:8]}"
    extra = {"AEGIS_HA_MODE": "active_passive", "AEGIS_HA_CHAIN_ID": chain}
    port_a, port_b = free_port(), free_port()
    a = _replica(port=port_a, upstream=upstream, wal=wal, redis_url=redis_url, extra=extra)
    b = None
    try:
        _until(lambda: _request(port_a, "GET", "/ready")[0] == 200, a, 60, "A ready")
        b = _replica(port=port_b, upstream=upstream, wal=wal, redis_url=redis_url, extra=extra)
        _until(
            lambda: _request(port_b, "GET", "/health")[1].get("status") == "standby",
            b,
            60,
            "B standby",
        )
        assert _request(port_b, "GET", "/ready")[0] == 503, "a standby must not be ready"
        assert _request(port_b, "POST", "/v1/chat/completions")[0] == 503
        assert _request(port_a, "POST", "/v1/chat/completions")[0] == 200

        a.send_signal(signal.SIGKILL)  # no shutdown path, no lease release
        a.wait(timeout=10)
        killed_at = time.monotonic()
        _until(lambda: _request(port_b, "GET", "/ready")[0] == 200, b, 60, "B takes over")
        takeover = time.monotonic() - killed_at
        assert takeover < 30, f"takeover took {takeover:.1f}s"
        assert _request(port_b, "POST", "/v1/chat/completions")[0] == 200
        status = _request(port_b, "GET", "/health")[1]["ha"]
        assert status["mode"] == "active_passive"
        assert status["admitting"] is True
    finally:
        for proc in (a, b):
            if proc is not None:
                _stop(proc)

    handovers = _handovers(wal)
    assert len(handovers) == 2, handovers
    epochs = [int(h["state_id"].rsplit("-", 1)[1]) for h in handovers]
    assert epochs[0] < epochs[1], "the new holder must write under a newer epoch"
    ledger = CryptographicAuditLedger(persistence_path=str(wal), signing_key="")
    ok, bad_index = ledger.verify_integrity()
    assert ok, f"the shared WAL does not verify as one chain (first bad index {bad_index})"
    ledger.close()


def test_active_active_replicas_share_one_verifiable_sequence(
    tmp_path: Path, redis_url: str, upstream: int
) -> None:
    db = tmp_path / "global-sequence.db"
    tag = uuid.uuid4().hex[:8]
    replicas = []
    try:
        for n in range(2):
            port = free_port()
            proc = _replica(
                port=port,
                upstream=upstream,
                wal=tmp_path / f"replica-{n}.wal.jsonl",
                redis_url=redis_url,
                extra={
                    "AEGIS_HA_MODE": "active_active",
                    "AEGIS_HA_CHAIN_ID": f"replica-{n}-{tag}",
                    "AEGIS_HA_SEQUENCER_URL": f"sqlite:///{db}",
                },
            )
            replicas.append((port, proc))
        for port, proc in replicas:
            _until(lambda p=port: _request(p, "GET", "/ready")[0] == 200, proc, 60, "ready")
            # The SQLite store's I/O runs under the production filter, not beside it.
            status = Path(f"/proc/{proc.pid}/status").read_text()
            assert "Seccomp:\t2" in status, "the replica is not under the seccomp filter"
        for _ in range(5):
            for port, _proc in replicas:
                assert _request(port, "POST", "/v1/chat/completions")[0] == 200
        for port, proc in replicas:
            _until(
                lambda p=port: _request(p, "GET", "/health")[1]["ha"]["sequence"]["backlog"] == 0,
                proc,
                30,
                "sequenced",
            )
    finally:
        for _, proc in replicas:
            _stop(proc)

    async def read() -> list[Any]:
        store = SQLiteSequenceStore(str(db))
        await store.open()
        try:
            return await store.entries(limit=10_000)
        finally:
            await store.close()

    entries = asyncio.run(read())
    report = verify_global_sequence(entries)
    assert report.valid, report.reason
    assert set(report.chains) == {f"replica-0-{tag}", f"replica-1-{tag}"}
    for n in range(2):
        ledger = CryptographicAuditLedger(
            persistence_path=str(tmp_path / f"replica-{n}.wal.jsonl"), signing_key=""
        )
        nodes = [(node.node_hash, node.prev_hash) for node in ledger.iter_wal_nodes()]
        ok, why = verify_chain_references(entries, f"replica-{n}-{tag}", nodes)
        assert ok, why
        # Every node the replica committed (handover + 5 requests at least) is sequenced.
        assert report.chains[f"replica-{n}-{tag}"] == len(nodes)
        ledger.close()
