# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""The chain writer lease, against a real Redis.

A chain may have one writer. These tests hold the lease to that: a second
holder is refused while the first holds it, a holder that was superseded can
never renew its way back, epochs only increase, an abandoned lease expires so a
standby can take over, and a holder's own view of the lease ends *before*
Redis's does.
"""

from __future__ import annotations

import threading
import time
import uuid

import pytest

from aegis.core.ha import (
    MAX_EPOCH,
    ChainLease,
    HAController,
    LeaseKeeper,
    LeaseUnavailableError,
    highest_recorded_epoch,
    wait_for_lease,
)


def _chain() -> str:
    return f"chain-{uuid.uuid4().hex[:10]}"


def _lease(client: object, chain: str, holder: str, ttl: float = 5.0) -> ChainLease:
    return ChainLease(client, chain, holder, ttl)


def test_one_holder_at_a_time_and_epochs_only_increase(redis_client: object) -> None:
    chain = _chain()
    first, second = _lease(redis_client, chain, "a:1"), _lease(redis_client, chain, "b:2")
    assert first.acquire() == 1
    assert second.acquire() is None, "a second replica took a lease that was held"
    assert first.holds()
    first.release()
    assert not first.holds()
    assert second.acquire() == 2
    second.release()
    assert first.acquire() == 3, "epochs must order every holder the chain has had"


def test_a_superseded_holder_cannot_renew_its_way_back(redis_client: object) -> None:
    chain = _chain()
    old, new = _lease(redis_client, chain, "old:1", ttl=2.0), _lease(redis_client, chain, "new:2")
    assert old.acquire() == 1
    # Simulate old being paused past its TTL: the key expires, new takes it.
    redis_client.delete(old.key)  # type: ignore[attr-defined]
    assert new.acquire() == 2
    assert old.renew() is False
    assert not old.holds()
    assert new.renew() is True
    assert new.holds()


def test_an_abandoned_lease_expires_and_a_standby_takes_over(redis_client: object) -> None:
    chain = _chain()
    crashed = _lease(redis_client, chain, "crashed:1", ttl=1.0)
    standby = _lease(redis_client, chain, "standby:2", ttl=1.0)
    assert crashed.acquire() == 1
    assert standby.acquire() is None
    time.sleep(1.3)  # no renewal: the process "died"
    assert standby.acquire() == 2


def test_a_holders_own_view_ends_before_redis_expiry(redis_client: object) -> None:
    now = [100.0]
    chain = _chain()
    lease = ChainLease(redis_client, chain, "h:1", 10.0, clock=lambda: now[0])
    assert lease.acquire() == 1
    # Measured from before the command was sent, minus a fifth of the TTL.
    assert lease.seconds_remaining() == pytest.approx(8.0)
    now[0] += 7.9
    assert lease.holds()
    now[0] += 0.2
    assert not lease.holds(), "the holder must stop before Redis could hand the lease on"
    ttl_ms = redis_client.pttl(lease.key)  # type: ignore[attr-defined]
    assert ttl_ms > 0, "Redis still holds it: the local view is the conservative one"


def test_the_keeper_renews_and_reports_a_takeover(redis_client: object) -> None:
    chain = _chain()
    lease = _lease(redis_client, chain, "kept:1", ttl=1.5)
    assert lease.acquire() == 1
    lost: list[str] = []
    keeper = LeaseKeeper(lease, lost.append)
    keeper.start()
    try:
        time.sleep(2.5)  # longer than the TTL: only renewal keeps it
        assert lease.holds()
        assert not lost
        redis_client.set(lease.key, "intruder:9|99")  # type: ignore[attr-defined]
        keeper.join(timeout=3)
        assert lost
        assert "took it over" in lost[0]
        assert not lease.holds()
    finally:
        keeper.stop()


def test_a_standby_waits_until_the_lease_is_released(redis_client: object) -> None:
    chain = _chain()
    holder, standby = _lease(redis_client, chain, "h:1"), _lease(redis_client, chain, "s:2")
    assert holder.acquire() == 1
    got: list[int] = []
    waiter = threading.Thread(target=lambda: got.append(wait_for_lease(standby, 0.1)))
    waiter.start()
    time.sleep(0.5)
    assert not got, "the standby acquired a lease that was held"
    holder.release()
    waiter.join(timeout=5)
    assert got == [2]


def test_a_stopped_standby_gives_up_without_the_lease(redis_client: object) -> None:
    chain = _chain()
    holder, standby = _lease(redis_client, chain, "h:1"), _lease(redis_client, chain, "s:2")
    holder.acquire()
    stop = threading.Event()
    stop.set()
    with pytest.raises(LeaseUnavailableError):
        wait_for_lease(standby, 0.05, stop)


@pytest.mark.parametrize("chain", ["", "a|b", "line\nbreak"])
def test_chain_ids_that_could_forge_a_lease_value_are_refused(chain: str) -> None:
    class Stub:
        def register_script(self, _: str) -> object:
            return object()

    with pytest.raises(ValueError, match="chain_id"):
        ChainLease(Stub(), chain, "h:1", 5.0)


# ── the epoch floor: a counter that restarted must not go backwards ─────────


def test_a_fresh_draw_is_lifted_above_the_floor(redis_client: object) -> None:
    chain = _chain()
    first = _lease(redis_client, chain, "a:1")
    assert first.acquire(floor=41) == 42
    first.release()
    # The counter moved with the draw, so a holder that knows no floor still
    # draws above it.
    assert _lease(redis_client, chain, "b:2").acquire() == 43


def test_raising_above_a_lower_floor_changes_nothing(redis_client: object) -> None:
    chain = _chain()
    lease = _lease(redis_client, chain, "a:1")
    assert lease.acquire() == 1
    assert lease.raise_epoch_above(0) == 1
    assert redis_client.get(lease.key) == b"a:1|1"  # type: ignore[attr-defined]


def test_a_raised_lease_is_the_one_redis_holds(redis_client: object) -> None:
    chain = _chain()
    lease = _lease(redis_client, chain, "a:1")
    assert lease.acquire() == 1
    assert lease.raise_epoch_above(7) == 8
    assert lease.epoch == 8
    assert redis_client.get(lease.key) == b"a:1|8"  # type: ignore[attr-defined]
    assert lease.renew() is True
    assert lease.holds()
    lease.release()
    assert _lease(redis_client, chain, "b:2").acquire() == 9


def test_a_lease_taken_over_cannot_be_raised(redis_client: object) -> None:
    chain = _chain()
    lease = _lease(redis_client, chain, "a:1")
    assert lease.acquire() == 1
    redis_client.set(lease.key, "intruder:9|99")  # type: ignore[attr-defined]
    with pytest.raises(LeaseUnavailableError):
        lease.raise_epoch_above(5)
    assert not lease.holds()
    assert redis_client.get(lease.key) == b"intruder:9|99"  # type: ignore[attr-defined]


def test_a_lease_never_acquired_cannot_be_raised(redis_client: object) -> None:
    with pytest.raises(LeaseUnavailableError):
        _lease(redis_client, _chain(), "a:1").raise_epoch_above(1)


@pytest.mark.parametrize("floor", [-1, True, MAX_EPOCH + 1, 1.5])
def test_an_out_of_range_floor_is_refused(redis_client: object, floor: object) -> None:
    lease = _lease(redis_client, _chain(), "a:1")
    with pytest.raises(ValueError, match="floor"):
        lease.acquire(floor=floor)  # type: ignore[arg-type]
    assert lease.acquire() == 1
    with pytest.raises(ValueError, match="floor"):
        lease.raise_epoch_above(floor)  # type: ignore[arg-type]


def test_raising_while_the_keeper_renews_never_reads_as_a_loss(redis_client: object) -> None:
    # Without serialising the scripts, a renewal that read the old epoch could
    # reach Redis after the raise replaced the value and report the lease lost,
    # which shuts the holder down.
    chain = _chain()
    lease = _lease(redis_client, chain, "kept:1", ttl=1.0)
    assert lease.acquire() == 1
    lost: list[str] = []
    keeper = LeaseKeeper(lease, lost.append)
    keeper.start()
    try:
        # Raise back to back for several renewal intervals, so that renewals
        # land inside a raise's round trip.
        deadline = time.monotonic() + 2.5
        floor = 1
        while time.monotonic() < deadline:
            floor = lease.raise_epoch_above(floor)
        assert not lost, lost
        assert lease.holds()
        assert redis_client.get(lease.key) == f"kept:1|{lease.epoch}".encode()  # type: ignore[attr-defined]
    finally:
        keeper.stop()
        keeper.join(timeout=3)


class _Node:
    def __init__(self, state_id: str, tenant_id: str = "aegis-system") -> None:
        self.state_id = state_id
        self.tenant_id = tenant_id


def test_the_highest_recorded_epoch_reads_only_this_chains_handovers() -> None:
    nodes = [
        _Node("ha-lease-main-3"),
        _Node("request-1", tenant_id="tenant-a"),
        _Node("ha-lease-main-12"),
        _Node("ha-lease-main-9"),
        _Node("ha-lease-main-other-40"),  # a different chain whose id extends this one
        _Node("ha-lease-other-50"),
        _Node("ha-lease-main-60", tenant_id="tenant-a"),  # not a system record
        _Node("ha-lease-main-x7"),
        _Node("ha-lease-main-" + "9" * 17),  # past what the scripts can hold exactly
    ]
    assert highest_recorded_epoch(nodes, "main") == 12
    assert highest_recorded_epoch([], "main") == 0


def test_the_handover_is_recorded_above_every_epoch_the_chain_holds(
    redis_client: object, tmp_path: object
) -> None:
    # The integration the finding needs: a WAL whose last handover is epoch 7,
    # a Redis whose counter restarted, and the gateway's handover step.
    from types import SimpleNamespace

    from aegis.core.crypto_audit import CryptographicAuditLedger
    from aegis.proxy.app import _record_writer_handover

    chain = _chain()
    wal = f"{tmp_path}/chain.jsonl"
    with CryptographicAuditLedger(wal, signing_key="ha-epoch-test") as earlier:
        earlier.commit_state(f"ha-lease-{chain}-7", 0.0, b"{}", tenant_id="aegis-system")
        earlier.commit_state("request-1", 0.0, b"payload", tenant_id="tenant-a")

    lease = _lease(redis_client, chain, "new:1")
    assert lease.acquire() == 1  # the restarted counter
    controller = HAController("active_passive", chain, lease, None)
    with CryptographicAuditLedger(wal, signing_key="ha-epoch-test") as ledger:
        _record_writer_handover(SimpleNamespace(ha=controller, ledger=ledger))
        assert lease.epoch == 8
        assert ledger.chain[-1].state_id == f"ha-lease-{chain}-8"
        assert ledger.chain[-1].tenant_id == "aegis-system"
    assert redis_client.get(lease.key) == b"new:1|8"  # type: ignore[attr-defined]


def test_a_faulted_chain_starts_without_a_handover_record(
    redis_client: object, tmp_path: object
) -> None:
    # The ledger refuses commits while faulted, so the handover step must not
    # turn a corrupt WAL into a failed start: the replica comes up as a single
    # one does, reporting the fault and refusing governed traffic.
    from pathlib import Path
    from types import SimpleNamespace

    from aegis.core.crypto_audit import CryptographicAuditLedger
    from aegis.proxy.app import _record_writer_handover

    chain = _chain()
    wal = Path(f"{tmp_path}/chain.jsonl")
    with CryptographicAuditLedger(str(wal), signing_key="ha-epoch-test") as earlier:
        earlier.commit_state(f"ha-lease-{chain}-4", 0.0, b"{}", tenant_id="aegis-system")
    with wal.open("a") as handle:
        handle.write('{"torn": ')
    size_before = wal.stat().st_size

    lease = _lease(redis_client, chain, "new:1")
    assert lease.acquire() == 1
    controller = HAController("active_passive", chain, lease, None)
    with CryptographicAuditLedger(str(wal), signing_key="ha-epoch-test") as ledger:
        assert ledger._fault_state == "wal_corrupt"
        _record_writer_handover(SimpleNamespace(ha=controller, ledger=ledger))
        assert lease.epoch == 5  # still lifted above what the chain records
        assert all(not node.state_id.endswith("-5") for node in ledger.chain)
    assert wal.stat().st_size == size_before
