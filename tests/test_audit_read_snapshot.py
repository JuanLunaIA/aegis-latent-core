# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""AUD-08 (REG-D12): audit reads take a snapshot, so a landing commit cannot
tear an iteration.

`CryptographicAuditLedger.chain` is a `deque` appended to from worker threads
(`asyncio.to_thread(state.ledger.commit_forensic, ...)`). Every read endpoint
used to iterate that deque directly, and a mutation landing between two
`__next__` calls raises `RuntimeError('deque mutated during iteration')` — a 500
with no audit data on a request that had already passed auth and scope checks.
The handlers now read `ledger.chain_snapshot()`, which copies under the same
lock the commit path appends under.

The tests are deliberately layered: a deterministic proof of the deque
mechanism (no threads), a threaded control showing the hostile workload, the
snapshot accessor's own semantics, and the endpoints driven over ASGI while a
committer thread appends.
"""

from __future__ import annotations

import sys
import threading
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from aegis.auth.principal import Principal, Role
from aegis.auth.scopes import SCOPE_AUDIT_EXPORT, SCOPE_AUDIT_READ
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.proxy.audit_api import build_audit_router

# ── 1. the mechanism, deterministically ──────────────────────────────────────


def test_deque_mutation_between_next_calls_raises() -> None:
    """The defect in one thread, with no scheduling luck involved.

    This is what a commit landing mid-iteration did to a read handler.
    """
    items: deque[int] = deque(range(4))
    iterator = iter(items)
    assert next(iterator) == 0
    items.append(4)  # the commit lands between two __next__ calls
    with pytest.raises(RuntimeError, match="mutated during iteration"):
        next(iterator)


def test_snapshot_is_immune_to_a_later_mutation() -> None:
    """A copy taken first keeps iterating no matter what happens to the deque."""
    items: deque[int] = deque(range(4))
    snapshot = list(items)
    items.append(4)
    assert snapshot == [0, 1, 2, 3]


# ── 2. the hostile workload, as a control ────────────────────────────────────


def test_live_deque_iteration_can_be_torn_by_a_writer_thread() -> None:
    """Control: the workload the accessor defends against really does tear.

    If this host never exposes the interleaving the test skips rather than
    asserting a race, so a green run is never read as proof the race exists.
    """
    items: deque[int] = deque(range(20_000))
    stop = threading.Event()

    def writer() -> None:
        while not stop.is_set():
            items.append(1)

    thread = threading.Thread(target=writer, daemon=True)
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        thread.start()
        for _ in range(200):
            try:
                sum(1 for _ in items)
            except RuntimeError:
                return  # torn — the control did its job
    finally:
        stop.set()
        thread.join(timeout=5)
        sys.setswitchinterval(previous)
    pytest.skip("this host did not expose the deque interleaving within 200 attempts")


# ── 3. the accessor's semantics ──────────────────────────────────────────────


def _ledger(tmp_path: Any) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(
        persistence_path=str(tmp_path / "audit.jsonl"),
        signing_key="test-signing-key",
    )


def _commit(ledger: CryptographicAuditLedger, number: int) -> None:
    ledger.commit_forensic(
        state_id=f"state-{number}",
        request_bytes=b"request",
        response_bytes=b"response",
        tenant_id="tenant-a",
    )


def test_chain_snapshot_is_a_copy_and_carries_committed_nodes(tmp_path: Any) -> None:
    ledger = _ledger(tmp_path)
    try:
        _commit(ledger, 1)
        _commit(ledger, 2)
        snapshot = ledger.chain_snapshot()
        assert [node.state_id for node in snapshot] == ["state-1", "state-2"]
        # A copy, not the live deque: editing it cannot touch the ledger.
        snapshot.clear()
        assert len(ledger.chain) == 2
        assert len(ledger.chain_snapshot()) == 2
    finally:
        ledger.close()


def test_chain_snapshot_never_tears_while_commits_land(tmp_path: Any) -> None:
    """The property the read paths depend on, under a real committer thread."""
    ledger = _ledger(tmp_path)
    stop = threading.Event()
    failures: list[BaseException] = []

    def writer() -> None:
        number = 0
        while not stop.is_set():
            number += 1
            try:
                _commit(ledger, number)
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                failures.append(exc)
                return

    thread = threading.Thread(target=writer, daemon=True)
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        thread.start()
        for _ in range(300):
            snapshot = ledger.chain_snapshot()
            assert isinstance(snapshot, list)
            # One snapshot, one consistent view: the walk below cannot be torn.
            for node in reversed(snapshot):
                assert node.node_hash
            time.sleep(0)
    finally:
        stop.set()
        thread.join(timeout=10)
        sys.setswitchinterval(previous)
        ledger.close()
    assert failures == []


# ── 4. the endpoints, over ASGI, with commits landing ────────────────────────


def _app(ledger: CryptographicAuditLedger) -> FastAPI:
    async def _auth() -> Principal:
        return Principal(
            subject="auditor",
            tenant_id="tenant-a",
            roles=frozenset({Role.AUDIT_READER, Role.ADMIN}),
            scopes=frozenset({SCOPE_AUDIT_READ, SCOPE_AUDIT_EXPORT}),
            auth_method="test",
            credential_id="test-credential",
        )

    app = FastAPI()
    app.include_router(build_audit_router(ledger, auth_dependency=_auth), prefix="/v1/audit")
    return app


@pytest.mark.asyncio
async def test_read_endpoints_survive_concurrent_commits(tmp_path: Any) -> None:
    ledger = _ledger(tmp_path)
    for number in range(1, 201):
        _commit(ledger, number)
    app = _app(ledger)
    stop = threading.Event()

    def writer() -> None:
        number = 200
        while not stop.is_set():
            number += 1
            _commit(ledger, number)

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    now = datetime.now(UTC)
    paths = [
        "/v1/audit/health",
        "/v1/audit/integrity",
        "/v1/audit/nodes?limit=50",
        "/v1/audit/tenants",
        "/v1/audit/export/part11",
        "/v1/audit/proofs/state-150",
        f"/v1/audit/nodes/{ledger.chain_snapshot()[0].node_hash}",
    ]
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            for _ in range(6):
                for path in paths:
                    response = await client.get(path)
                    assert response.status_code == 200, (path, response.status_code, response.text)
                export = await client.post(
                    "/v1/audit/forensics/export",
                    json={
                        "start_time": (now - timedelta(minutes=5)).isoformat(),
                        "end_time": (now + timedelta(minutes=5)).isoformat(),
                        "operator": "Examiner A",
                        "acquisition_reason": "Authorized test",
                    },
                )
                assert export.status_code == 200, export.text
    finally:
        stop.set()
        thread.join(timeout=10)
        ledger.close()


@pytest.mark.asyncio
async def test_health_counts_and_integrity_tail_agree_within_a_response(tmp_path: Any) -> None:
    """One snapshot per handler: count and tail describe the same chain."""
    ledger = _ledger(tmp_path)
    for number in range(1, 21):
        _commit(ledger, number)
    app = _app(ledger)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            integrity = (await client.get("/v1/audit/integrity")).json()
            health = (await client.get("/v1/audit/health")).json()
        snapshot = ledger.chain_snapshot()
        assert integrity["node_count"] == len(snapshot) == 20
        assert integrity["tail_hash"] == snapshot[-1].node_hash
        assert health["node_count"] == 20
    finally:
        ledger.close()
